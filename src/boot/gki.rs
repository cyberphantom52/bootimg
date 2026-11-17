//! GKI boot signatures (boot header v4).

use std::path::Path;

use super::Components;
use crate::{
    Result,
    avb::{self, Descriptor, VbMeta},
    util::{be64, too_long},
};

/// Regenerates the boot signature at the end of a built v4 boot `image`: the
/// vbmeta blobs covering the boot image ("boot") and the kernel
/// ("generic_kernel") are re-hashed and re-signed, as Google's certificate
/// can't stay valid after edits. Returns whether the signature held vbmeta to
/// regenerate; one that does not is left alone.
pub fn resign_gki(image: &mut [u8], components: &Components, key: Option<&Path>) -> Result<bool> {
    let Some(signature) = components.get("boot_signature") else {
        return Ok(false);
    };
    let signature_area = signature.len().div_ceil(4096) * 4096;
    let signed_len = image.len() - signature_area;
    let mut blobs = Vec::new();
    let mut offset = 0;
    while signature[offset..].starts_with(b"AVB0") {
        let header = &signature[offset..];
        let (mut vbmeta, _) = VbMeta::parse(header)?;
        offset += (256 + be64(header, 12) + be64(header, 20)) as usize;
        for descriptor in &mut vbmeta.descriptors {
            if let Descriptor::Hash { partition_name, .. } = descriptor {
                let covered = match partition_name.as_str() {
                    "boot" => &image[..signed_len],
                    "generic_kernel" => components.get("kernel").map_or(&[][..], Vec::as_slice),
                    _ => continue,
                };
                avb::update_hash(descriptor, covered)?;
            }
        }
        let key = avb::signing_key(vbmeta.algorithm, key)?;
        blobs.extend(vbmeta.encode(key.as_ref())?);
    }
    if blobs.is_empty() {
        return Ok(false);
    }
    if blobs.len() > signature.len() {
        return Err(too_long(
            "regenerated boot signature",
            blobs.len(),
            signature.len(),
        ));
    }
    blobs.resize(signature.len(), 0);
    image[signed_len..signed_len + blobs.len()].copy_from_slice(&blobs);
    Ok(true)
}
