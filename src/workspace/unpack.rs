use anyhow::{Context, Result, ensure};
use std::{collections::BTreeMap, fs, path::Path};

use super::{ImageInfo, STATE_DIR, State, Workspace, detect, split_footer};
use crate::{
    avb::{self, VbMeta},
    bootimg,
};

pub fn unpack(input: &Path, dir: &Path, force: bool) -> Result<()> {
    let data = fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let (payload, footer) = split_footer(&data)?;
    let format = detect(payload)?;

    if dir.exists() {
        let empty = fs::read_dir(dir)?.next().is_none();
        ensure!(
            empty || (force && dir.join(STATE_DIR).is_dir()),
            "{} already exists; use --force to replace a previous workspace",
            dir.display()
        );
        if !empty {
            fs::remove_dir_all(dir)?;
        }
    }
    fs::create_dir_all(dir.join(STATE_DIR))?;
    let mut ws = Workspace {
        dir: dir.to_path_buf(),
        state: State {
            source: input
                .file_name()
                .map_or("image".into(), |name| name.to_string_lossy().into_owned()),
            hashes: BTreeMap::new(),
        },
    };
    // Kept so an unchanged workspace packs back to the exact original.
    fs::write(dir.join(STATE_DIR).join("original.img"), &data)?;

    let mut contents = Vec::new();
    let info = match format {
        "boot" => {
            let (header, layout) = bootimg::parse_boot(payload)?;
            report_tail(payload, bootimg::content_end(&layout, header.page_size));
            for (name, offset, size) in layout {
                let bytes = &payload[offset as usize..(offset + size) as usize];
                contents.push(match name.as_str() {
                    "ramdisk" => ws.unpack_ramdisk(&name, bytes)?,
                    "dtb" => ws.unpack_dtb(&name, bytes)?,
                    _ => {
                        ws.write(&name, bytes)?;
                        name
                    }
                });
            }
            ImageInfo::Boot { header }
        }
        "vendor_boot" => {
            let (header, layout) = bootimg::parse_vendor_boot(payload)?;
            report_tail(payload, bootimg::content_end(&layout, header.page_size));
            for (name, offset, size) in layout {
                let bytes = &payload[offset as usize..(offset + size) as usize];
                contents.push(match name.as_str() {
                    "dtb" => ws.unpack_dtb(&name, bytes)?,
                    "bootconfig" => {
                        ws.write(&name, bytes)?;
                        name
                    }
                    _ => ws.unpack_ramdisk(&name, bytes)?,
                });
            }
            ImageInfo::VendorBoot { header }
        }
        _ => unreachable!(),
    };
    if let Some(footer) = &footer {
        ws.write_json("avb.json", footer)?;
        contents.push(format!("avb.json ({})", describe_vbmeta(&footer.vbmeta)));
    }
    ws.write_json("image.json", &info)?;
    ws.save_state()?;

    say!(
        "Unpacked {} ({format}) into {}",
        input.display(),
        dir.display()
    );
    for line in contents {
        say!("  {line}");
    }
    Ok(())
}

fn report_tail(payload: &[u8], end: u64) {
    let tail = payload.get(end as usize..).unwrap_or_default();
    if tail.iter().any(|&b| b != 0) {
        eprintln!(
            "warning: {} bytes of unrecognized data follow the image (e.g. a vendor or \
             VB1 signature); they are kept only while the image is left unchanged",
            tail.len()
        );
    }
}

fn describe_vbmeta(vbmeta: &VbMeta) -> String {
    let key = match vbmeta.algorithm {
        avb::Algorithm::NONE => String::new(),
        _ => match avb::known_key(&vbmeta.public_key) {
            Some(name) => format!(", {name}"),
            None => ", vendor key".into(),
        },
    };
    format!("{:?}{key}", vbmeta.algorithm)
}
