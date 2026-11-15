//! GKI boot signatures (boot header v4).

use anyhow::{Result, ensure};
use std::path::Path;

use crate::{
    avb::{self, Descriptor, VbMeta},
    bootimg::Components,
    util::{align, be64},
};

/// Regenerates the boot signature of a v4 boot `image`: the vbmeta blobs
/// covering the boot image ("boot") and the kernel ("generic_kernel") are
/// re-hashed and re-signed, as Google's certificate can't stay valid after
/// edits. Signatures that are not vbmeta are left alone.
pub(super) fn resign(
    image: &mut [u8],
    signature: &[u8],
    components: &Components,
    key: Option<&Path>,
) -> Result<()> {
    let signature_area = align(signature.len() as u64, 4096) as usize;
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
        return Ok(());
    }
    ensure!(
        blobs.len() <= signature.len(),
        "the regenerated boot signature does not fit its {}-byte area",
        signature.len()
    );
    blobs.resize(signature.len(), 0);
    image[signed_len..signed_len + blobs.len()].copy_from_slice(&blobs);
    say!("Regenerated the GKI boot signature");
    Ok(())
}
