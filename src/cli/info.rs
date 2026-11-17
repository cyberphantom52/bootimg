//! `bootimg info`: a readable summary of an image, including AVB verification.

use std::{fs, path::Path};

use bootimg::{
    avb::{self, Descriptor, Footer, Signature, VbMeta},
    boot,
    compress::Compression,
    dtb, dtbo,
};

use crate::cli::{IoAt, Result};

pub fn show(path: &Path) -> Result<()> {
    let data = fs::read(path).at(path)?;
    let footer = Footer::parse(&data);
    let payload = match footer {
        Some(footer) => footer.payload(&data)?,
        None => &data[..],
    };

    match payload.get(..4) {
        Some(b"ANDR") => {
            let (header, layout) = boot::parse_boot(payload)?;
            say!(
                "Boot image, header v{}, page size {}",
                header.header_version,
                header.page_size
            );
            say!(
                "  OS version {}, patch level {}",
                header.os_version,
                header.os_patch_level
            );
            print_cmdline(&header.cmdline);
            print_layout(payload, &layout);
            if let Some((_, offset, size)) =
                layout.iter().find(|(name, ..)| name == "boot_signature")
            {
                let signature = &payload[*offset as usize..(offset + size) as usize];
                if signature.starts_with(b"AVB0") {
                    say!("  GKI boot signature:");
                    print_vbmeta(signature, "    ")?;
                }
            }
        }
        Some(b"VNDR") => {
            let (header, layout) = boot::parse_vendor_boot(payload)?;
            say!(
                "Vendor boot image, header v{}, page size {}",
                header.header_version,
                header.page_size
            );
            print_cmdline(&header.cmdline);
            print_layout(payload, &layout);
            for entry in &header.ramdisks {
                say!(
                    "  {}: type {}, name {:?}",
                    entry.file,
                    entry.ramdisk_type,
                    entry.name
                );
            }
        }
        Some(b"AVB0") => {
            say!("vbmeta image");
            print_vbmeta(payload, "  ")?;
        }
        Some([0xd7, 0xb7, 0xab, 0x1e]) => {
            let (table, _) = dtbo::parse_dtbo(payload)?;
            say!(
                "DTBO image, version {}, {} entries",
                table.version,
                table.entries.len()
            );
            for entry in &table.entries {
                say!("  {}: id {:#x}, rev {:#x}", entry.file, entry.id, entry.rev);
            }
        }
        Some([0xd0, 0x0d, 0xfe, 0xed]) => {
            say!("Device tree blob, {} trees", dtb::split(payload).len());
        }
        _ => {
            let format = "a boot, vendor_boot, vbmeta, dtbo or dtb image";
            return Err(bootimg::Error::Format(format).into());
        }
    }

    if let Some(footer) = footer {
        say!(
            "AVB footer: partition size {}, image size {}",
            data.len(),
            footer.original_image_size
        );
        let vbmeta = footer.vbmeta(&data)?;
        print_vbmeta(vbmeta, "  ")?;
        let (vbmeta, _) = VbMeta::parse(vbmeta)?;
        for descriptor in &vbmeta.descriptors {
            if let Descriptor::Hash {
                hash_algorithm,
                salt,
                digest,
                image_size,
                partition_name,
                ..
            } = descriptor
            {
                let matches = *image_size == payload.len() as u64
                    && avb::hash(hash_algorithm, salt, payload).ok().as_ref() == Some(digest);
                say!(
                    "  {partition_name} hash: {}",
                    if matches {
                        "matches the image"
                    } else {
                        "DOES NOT match the image"
                    }
                );
            }
        }
    }
    Ok(())
}

fn print_cmdline(cmdline: &str) {
    if !cmdline.is_empty() {
        say!("  cmdline: {cmdline}");
    }
}

fn print_layout(payload: &[u8], layout: &boot::Layout) {
    for (name, offset, size) in layout {
        let data = &payload[*offset as usize..(offset + size) as usize];
        let detail = if name.contains("ramdisk") {
            Compression::detect(data).map_or(String::new(), |c| format!(", {}", c.name()))
        } else {
            String::new()
        };
        say!("  {name}: {size} bytes at {offset:#x}{detail}");
    }
}

fn print_vbmeta(data: &[u8], indent: &str) -> Result<()> {
    let (vbmeta, signature) = VbMeta::parse(data)?;
    let key = avb::known_key(&vbmeta.public_key).unwrap_or_else(|| "a vendor key".into());
    let signature = match signature {
        Signature::Unsigned => "unsigned".to_string(),
        Signature::Valid => format!("valid signature by {key}"),
        Signature::Invalid => "INVALID signature".to_string(),
    };
    say!("{indent}{:?}, {signature}", vbmeta.algorithm);
    say!(
        "{indent}rollback index {} (location {}), flags {}",
        vbmeta.rollback_index,
        vbmeta.rollback_index_location,
        vbmeta.flags
    );
    for descriptor in &vbmeta.descriptors {
        let line = match descriptor {
            Descriptor::Property { key, value } => format!("property {key} = {value}"),
            Descriptor::Hash {
                partition_name,
                image_size,
                hash_algorithm,
                ..
            } => {
                format!("hash {partition_name}: {image_size} bytes, {hash_algorithm}")
            }
            Descriptor::Hashtree {
                partition_name,
                image_size,
                ..
            } => {
                format!("hashtree {partition_name}: {image_size} bytes")
            }
            Descriptor::KernelCmdline { cmdline, .. } => format!("cmdline {cmdline}"),
            Descriptor::ChainPartition {
                partition_name,
                rollback_index_location,
                ..
            } => {
                format!("chain {partition_name} (rollback location {rollback_index_location})")
            }
            Descriptor::Unknown { tag, data } => format!("unknown tag {tag}, {} bytes", data.len()),
        };
        say!("{indent}{line}");
    }
    Ok(())
}
