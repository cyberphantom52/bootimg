use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
};

use super::{AvbInfo, ImageInfo, Workspace, split_footer};
use crate::{
    avb,
    bootimg::{self, Components},
};

pub struct PackOptions<'a> {
    pub output: Option<&'a Path>,
    pub key: Option<&'a Path>,
}

pub fn pack(dir: &Path, options: &PackOptions) -> Result<()> {
    let ws = Workspace::open(dir)?;
    let original = ws.original()?;
    let (original_payload, _) = split_footer(&original)?;
    let info: ImageInfo = ws.read_json("image.json")?;
    let avb_info: Option<AvbInfo> = ws
        .exists("avb.json")
        .then(|| ws.read_json("avb.json"))
        .transpose()?;

    let changed = ws.changed_files()?;
    let output = match options.output {
        Some(path) => path.to_path_buf(),
        None => PathBuf::from(format!("{}.signed", ws.state.source)),
    };
    if changed.is_empty() && options.key.is_none() {
        fs::write(&output, &original)?;
        say!(
            "No changes; wrote the original image to {}",
            output.display()
        );
        return Ok(());
    }
    if !changed.is_empty() {
        say!("Changed: {}", changed.join(", "));
    }

    // Only AVB metadata edits keep the original payload.
    let payload_changed = changed.iter().any(|name| name != "avb.json");
    let mut image = if payload_changed {
        build_payload(&ws, &info)?
    } else {
        original_payload.to_vec()
    };

    if let Some(AvbInfo {
        partition_size,
        mut vbmeta,
    }) = avb_info
    {
        let key = avb::signing_key(vbmeta.algorithm, options.key)?;
        let partition = vbmeta
            .first_hash_partition()
            .context("the AVB footer has no hash descriptor")?
            .to_string();
        let descriptor = vbmeta.hash_descriptor_mut(&partition).unwrap();
        avb::update_hash(descriptor, &image)?;
        let blob = vbmeta.encode(key.as_ref())?;
        avb::append_footer(&mut image, &blob, partition_size)?;
        match &key {
            Some(key) => say!("Signed {:?} with {}", vbmeta.algorithm, key.description),
            None => say!("AVB metadata updated (algorithm NONE, unsigned)"),
        }
    }

    fs::write(&output, &image).with_context(|| format!("writing {}", output.display()))?;
    say!("Wrote {}", output.display());
    Ok(())
}

fn build_payload(ws: &Workspace, info: &ImageInfo) -> Result<Vec<u8>> {
    let mut components = Components::new();
    let mut add = |name: &str, data: Option<Vec<u8>>| {
        if let Some(data) = data {
            components.insert(name.to_string(), data);
        }
    };
    Ok(match info {
        ImageInfo::Boot { header } => {
            for name in ["kernel", "second", "recovery_dtbo", "dtb", "boot_signature"] {
                add(name, ws.read_optional(name)?);
            }
            add("ramdisk", ws.pack_ramdisk("ramdisk")?);
            bootimg::build_boot(header, &components)?
        }
        ImageInfo::VendorBoot { header } => {
            if header.ramdisks.is_empty() {
                add("vendor_ramdisk", ws.pack_ramdisk("vendor_ramdisk")?);
            }
            for entry in &header.ramdisks {
                let data = ws.pack_ramdisk(&entry.file)?;
                ensure!(
                    data.is_some(),
                    "{}.img for the ramdisk table row {:?} is missing",
                    entry.file,
                    entry.name
                );
                add(&entry.file, data);
            }
            for name in ["dtb", "bootconfig"] {
                add(name, ws.read_optional(name)?);
            }
            bootimg::build_vendor_boot(header, &components)?
        }
    })
}
