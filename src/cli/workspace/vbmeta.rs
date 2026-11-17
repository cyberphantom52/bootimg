//! Updating a partition's hash in a separate vbmeta image.

use anyhow::{Context, Result};
use std::{fs, path::Path};

use bootimgctl::avb::{self, Descriptor, VbMeta};

/// Replaces the hash descriptor for `descriptor`'s partition in the vbmeta
/// image at `path`, re-signs it and writes `<name>.signed` next to `output`.
pub(super) fn update(
    path: &Path,
    descriptor: &Descriptor,
    key: Option<&Path>,
    output: &Path,
) -> Result<()> {
    let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let (mut vbmeta, _) = VbMeta::parse(&data).context("parsing the --vbmeta image")?;
    let Descriptor::Hash { partition_name, .. } = descriptor else {
        unreachable!()
    };
    match vbmeta.hash_descriptor_mut(partition_name) {
        Some(slot) => *slot = descriptor.clone(),
        None => {
            let chained = vbmeta.descriptors.iter().any(|d| {
                matches!(d,
                Descriptor::ChainPartition { partition_name: name, .. } if name == partition_name)
            });
            if chained {
                say!(
                    "{} chains to {partition_name}; it needs no update",
                    path.display()
                );
            } else {
                eprintln!(
                    "warning: {} has no descriptor for {partition_name}",
                    path.display()
                );
            }
            return Ok(());
        }
    }
    let key = avb::signing_key(vbmeta.algorithm, key)?;
    let mut image = vbmeta.encode(key.as_ref())?;
    if image.len() < data.len() {
        image.resize(data.len(), 0);
    }
    let name = path
        .file_name()
        .map_or("vbmeta.img".into(), |n| n.to_string_lossy().into_owned());
    let destination = output.with_file_name(format!("{name}.signed"));
    fs::write(&destination, image)?;
    say!(
        "Updated {partition_name} in {} and wrote {}",
        path.display(),
        destination.display()
    );
    Ok(())
}
