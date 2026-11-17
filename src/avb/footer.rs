//! The AVB footer that locates vbmeta at the end of a partition image.

use anyhow::{Result, bail};

use crate::util::{align, be64, slice};

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
}

/// Appends a vbmeta blob and footer to `image`, padding it to `partition_size`,
/// exactly as `avbtool add_hash_footer` lays it out.
pub fn append_footer(image: &mut Vec<u8>, vbmeta: &[u8], partition_size: u64) -> Result<()> {
    let original_image_size = image.len() as u64;
    let vbmeta_offset = align(original_image_size, BLOCK_SIZE);
    let vbmeta_end = vbmeta_offset + align(vbmeta.len() as u64, BLOCK_SIZE);
    if !partition_size.is_multiple_of(BLOCK_SIZE) || vbmeta_end + BLOCK_SIZE > partition_size {
        bail!(
            "image ({original_image_size} bytes) and its AVB metadata do not fit the \
             {partition_size}-byte partition; the edited image is too large"
        );
    }
    image.resize(vbmeta_offset as usize, 0);
    image.extend_from_slice(vbmeta);
    image.resize(partition_size as usize - FOOTER_SIZE, 0);
    image.extend_from_slice(b"AVBf");
    image.extend_from_slice(&1u32.to_be_bytes());
    image.extend_from_slice(&0u32.to_be_bytes());
    image.extend_from_slice(&original_image_size.to_be_bytes());
    image.extend_from_slice(&vbmeta_offset.to_be_bytes());
    image.extend_from_slice(&(vbmeta.len() as u64).to_be_bytes());
    image.resize(partition_size as usize, 0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footer_locates_the_appended_vbmeta() {
        let mut image = vec![1; 5000];
        append_footer(&mut image, b"AVB0 vbmeta", 16384).unwrap();
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
        assert!(append_footer(&mut vec![1; 12289], b"AVB0", 16384).is_err());
    }
}
