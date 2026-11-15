use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
};

use super::{AvbInfo, ImageInfo, Workspace, gki, split_footer};
use crate::{
    avb,
    bootimg::{self, Components},
    dtbo,
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

    // Only AVB metadata edits keep the original payload; a vbmeta image is
    // nothing but its metadata.
    let payload_changed = changed.iter().any(|name| name != "avb.json");
    let mut image = if matches!(info, ImageInfo::Vbmeta) {
        Vec::new()
    } else if payload_changed {
        build_payload(&ws, &info, options.key)?
    } else {
        original_payload.to_vec()
    };

    if let Some(AvbInfo {
        partition_size,
        mut vbmeta,
    }) = avb_info
    {
        let key = avb::signing_key(vbmeta.algorithm, options.key)?;
        if matches!(info, ImageInfo::Vbmeta) {
            image = vbmeta.encode(key.as_ref())?;
            if (image.len() as u64) < partition_size {
                image.resize(partition_size as usize, 0);
            }
        } else {
            let partition = vbmeta
                .first_hash_partition()
                .context("the AVB footer has no hash descriptor")?
                .to_string();
            let descriptor = vbmeta.hash_descriptor_mut(&partition).unwrap();
            avb::update_hash(descriptor, &image)?;
            let blob = vbmeta.encode(key.as_ref())?;
            avb::append_footer(&mut image, &blob, partition_size)?;
        }
        match &key {
            Some(key) => say!("Signed {:?} with {}", vbmeta.algorithm, key.description),
            None => say!("AVB metadata updated (algorithm NONE, unsigned)"),
        }
    }

    fs::write(&output, &image).with_context(|| format!("writing {}", output.display()))?;
    say!("Wrote {}", output.display());
    Ok(())
}

fn build_payload(ws: &Workspace, info: &ImageInfo, key: Option<&Path>) -> Result<Vec<u8>> {
    let mut components = Components::new();
    let mut add = |name: &str, data: Option<Vec<u8>>| {
        if let Some(data) = data {
            components.insert(name.to_string(), data);
        }
    };
    Ok(match info {
        ImageInfo::Boot { header } => {
            for name in ["kernel", "second", "recovery_dtbo", "boot_signature"] {
                add(name, ws.read_optional(name)?);
            }
            add("ramdisk", ws.pack_ramdisk("ramdisk")?);
            add("dtb", ws.pack_dtb("dtb")?);
            let signature_edited = ws.recorded("boot_signature") && ws.changed("boot_signature")?;
            let mut image = bootimg::build_boot(header, &components)?;
            if header.header_version == 4
                && !signature_edited
                && let Some(signature) = components.get("boot_signature")
            {
                gki::resign(&mut image, signature, &components, key)?;
            }
            image
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
            add("dtb", ws.pack_dtb("dtb")?);
            add("bootconfig", ws.read_optional("bootconfig")?);
            bootimg::build_vendor_boot(header, &components)?
        }
        ImageInfo::Dtbo { table } => {
            let mut trees = Vec::new();
            for entry in &table.entries {
                trees.push(
                    ws.pack_dtb(&entry.file)?
                        .with_context(|| format!("{} is missing", entry.file))?,
                );
            }
            dtbo::build_dtbo(table, &trees)?
        }
        ImageInfo::Dtb => ws.pack_dtb("dtb")?.context("dtb is missing")?,
        ImageInfo::Vbmeta => unreachable!(),
    })
}
