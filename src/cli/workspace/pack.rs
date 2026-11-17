use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use super::{AvbInfo, ImageInfo, Workspace, vbmeta};
use crate::cli::{Error, IoAt, Result};
use bootimgctl::{
    avb::{self, Descriptor},
    bootimg::{self, Components},
    dtbo,
};

pub struct PackOptions<'a> {
    pub output: Option<&'a Path>,
    pub key: Option<&'a Path>,
    pub vbmeta: Option<&'a Path>,
}

pub fn pack(dir: &Path, options: &PackOptions) -> Result<()> {
    let ws = Workspace::open(dir)?;
    let original = ws.original()?;
    let (original_payload, ..) = avb::HashFooter::split(&original)?;
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
        fs::write(&output, &original).at(&output)?;
        say!(
            "No changes; wrote the original image to {}",
            output.display()
        );
        if let Some(path) = options.vbmeta {
            let descriptor = avb_info
                .and_then(|info| info.vbmeta.descriptors.into_iter().find(is_hash))
                .ok_or(Error::NoFooterForVbmeta)?;
            vbmeta::update(path, &descriptor, options.key, &output)?;
        }
        return Ok(());
    }
    if !changed.is_empty() {
        say!("Changed: {}", changed.join(", "));
    }

    // Only AVB metadata edits keep the original payload; a vbmeta image is
    // nothing but its metadata.
    let payload_changed = changed.iter().any(|name| name != "avb.json");
    let image = if matches!(info, ImageInfo::Vbmeta) {
        Vec::new()
    } else if payload_changed {
        build_payload(&ws, &info, options.key)?
    } else {
        original_payload.to_vec()
    };

    let mut file = fs::File::create(&output).at(&output)?;
    let mut new_descriptor = None;
    match avb_info {
        Some(mut avb_info) => {
            let key = avb::signing_key(avb_info.vbmeta.algorithm, options.key)?;
            if matches!(info, ImageInfo::Vbmeta) {
                let mut blob = avb_info.vbmeta.encode(key.as_ref())?;
                if (blob.len() as u64) < avb_info.partition_size {
                    blob.resize(avb_info.partition_size as usize, 0);
                }
                file.write_all(&blob).at(&output)?;
            } else {
                file.write_all(&image).at(&output)?;
                new_descriptor = Some(avb_info.write(&mut file, &image, options.key)?);
            }
            match &key {
                Some(key) => say!(
                    "Signed {:?} with {}",
                    avb_info.vbmeta.algorithm,
                    key.description
                ),
                None => say!("AVB metadata updated (algorithm NONE, unsigned)"),
            }
        }
        None => file.write_all(&image).at(&output)?,
    }
    say!("Wrote {}", output.display());

    if let Some(path) = options.vbmeta {
        let descriptor = new_descriptor.ok_or(Error::NoFooterForVbmeta)?;
        vbmeta::update(path, &descriptor, options.key, &output)?;
    }
    Ok(())
}

fn is_hash(descriptor: &Descriptor) -> bool {
    matches!(descriptor, Descriptor::Hash { .. })
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
                && bootimg::resign_gki(&mut image, &components, key)?
            {
                say!("Regenerated the GKI boot signature");
            }
            image
        }
        ImageInfo::VendorBoot { header } => {
            if header.ramdisks.is_empty() {
                add("vendor_ramdisk", ws.pack_ramdisk("vendor_ramdisk")?);
            }
            for entry in &header.ramdisks {
                let data = ws.pack_ramdisk(&entry.file)?;
                let data = data.ok_or_else(|| Error::Missing(format!("{}.img", entry.file)))?;
                add(&entry.file, Some(data));
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
                        .ok_or_else(|| Error::Missing(entry.file.clone()))?,
                );
            }
            dtbo::build_dtbo(table, &trees)?
        }
        ImageInfo::Dtb => ws
            .pack_dtb("dtb")?
            .ok_or_else(|| Error::Missing("dtb".into()))?,
        ImageInfo::Vbmeta => unreachable!(),
    })
}
