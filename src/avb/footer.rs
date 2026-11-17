//! The AVB footer that locates vbmeta at the end of a partition image.

use serde::{Deserialize, Serialize};
use std::{
    io::{Seek, SeekFrom, Write},
    path::Path,
};

use super::{Descriptor, Signature, VbMeta, signing_key, update_hash};
use crate::{
    Error, Result,
    util::{align, be64, slice},
};

pub const FOOTER_SIZE: usize = 64;
const BLOCK_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Footer {
    pub original_image_size: u64,
    pub vbmeta_offset: u64,
    pub vbmeta_size: u64,
}

impl Footer {
    pub fn parse(image: &[u8]) -> Option<Self> {
        let footer = image.get(image.len().checked_sub(FOOTER_SIZE)?..)?;
        (&footer[..4] == b"AVBf").then(|| Self {
            original_image_size: be64(footer, 12),
            vbmeta_offset: be64(footer, 20),
            vbmeta_size: be64(footer, 28),
        })
    }

    /// The image the footer protects, without the vbmeta blob and padding.
    pub fn payload<'a>(&self, image: &'a [u8]) -> Result<&'a [u8]> {
        slice(image, 0, self.original_image_size, "AVB footer image")
    }

    pub fn vbmeta<'a>(&self, image: &'a [u8]) -> Result<&'a [u8]> {
        slice(
            image,
            self.vbmeta_offset,
            self.vbmeta_size,
            "AVB footer vbmeta",
        )
    }

    fn encode(&self) -> [u8; FOOTER_SIZE] {
        let mut out = [0; FOOTER_SIZE];
        out[..4].copy_from_slice(b"AVBf");
        out[4..8].copy_from_slice(&1u32.to_be_bytes());
        out[12..20].copy_from_slice(&self.original_image_size.to_be_bytes());
        out[20..28].copy_from_slice(&self.vbmeta_offset.to_be_bytes());
        out[28..36].copy_from_slice(&self.vbmeta_size.to_be_bytes());
        out
    }
}

/// What an AVB hash footer holds: the vbmeta signing the image, and the size of
/// the partition the footer ends.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HashFooter {
    pub partition_size: u64,
    pub vbmeta: VbMeta,
}

impl HashFooter {
    /// Splits `image` into the image the footer protects and the footer, with
    /// whether its signature verifies. An image without a footer is all payload,
    /// and unsigned.
    pub fn split(image: &[u8]) -> Result<(&[u8], Option<Self>, Signature)> {
        let Some(footer) = Footer::parse(image) else {
            return Ok((image, None, Signature::Unsigned));
        };
        let (vbmeta, signature) = VbMeta::parse(footer.vbmeta(image)?)?;
        let hash_footer = Self {
            partition_size: image.len() as u64,
            vbmeta,
        };
        Ok((footer.payload(image)?, Some(hash_footer), signature))
    }

    /// Hashes `payload`, which `out` holds from its start, into the footer's
    /// hash descriptor, signs the vbmeta with `key` or the AOSP test key of the
    /// original key's size, and writes it and the footer to `out`. Returns the
    /// new hash descriptor, for a vbmeta image that chains to this partition.
    pub fn write(
        &mut self,
        out: &mut (impl Write + Seek),
        payload: &[u8],
        key: Option<&Path>,
    ) -> Result<Descriptor> {
        let descriptor = self
            .vbmeta
            .descriptors
            .iter_mut()
            .find(|descriptor| matches!(descriptor, Descriptor::Hash { .. }))
            .ok_or(Error::NoHashDescriptor)?;
        update_hash(descriptor, payload)?;
        let descriptor = descriptor.clone();
        let key = signing_key(self.vbmeta.algorithm, key)?;
        let blob = self.vbmeta.encode(key.as_ref())?;
        write_footer(out, payload.len() as u64, &blob, self.partition_size)?;
        Ok(descriptor)
    }
}

/// Writes a vbmeta blob and footer after the `image_size` bytes of image at the
/// start of `out`, ending it at `partition_size`, exactly as `avbtool
/// add_hash_footer` lays it out. The padding between is only seeked over: in a
/// new file it reads as zeros without being written.
pub fn write_footer(
    out: &mut (impl Write + Seek),
    image_size: u64,
    vbmeta: &[u8],
    partition_size: u64,
) -> Result<()> {
    let footer = Footer {
        original_image_size: image_size,
        vbmeta_offset: align(image_size, BLOCK_SIZE),
        vbmeta_size: vbmeta.len() as u64,
    };
    if !partition_size.is_multiple_of(BLOCK_SIZE) {
        return Err(Error::invalid(
            "AVB partition size",
            format!("{partition_size} is not a multiple of {BLOCK_SIZE}"),
        ));
    }
    if footer.vbmeta_offset + align(footer.vbmeta_size, BLOCK_SIZE) + BLOCK_SIZE > partition_size {
        return Err(Error::PartitionFull {
            size: image_size,
            partition_size,
        });
    }
    out.seek(SeekFrom::Start(footer.vbmeta_offset))?;
    out.write_all(vbmeta)?;
    out.seek(SeekFrom::Start(partition_size - FOOTER_SIZE as u64))?;
    out.write_all(&footer.encode())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn footer_locates_the_appended_vbmeta() {
        let mut image = Cursor::new(vec![1; 5000]);
        write_footer(&mut image, 5000, b"AVB0 vbmeta", 16384).unwrap();
        let image = image.into_inner();
        assert_eq!(image.len(), 16384);
        let footer = Footer::parse(&image).unwrap();
        assert_eq!(
            footer,
            Footer {
                original_image_size: 5000,
                vbmeta_offset: 8192,
                vbmeta_size: 11,
            }
        );
        assert_eq!(footer.vbmeta(&image).unwrap(), b"AVB0 vbmeta");
        assert!(image[5000..8192].iter().all(|&b| b == 0));
        let mut full = Cursor::new(vec![1; 12289]);
        assert!(write_footer(&mut full, 12289, b"AVB0", 16384).is_err());
    }
}
