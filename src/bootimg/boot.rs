use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use super::{
    Components, Layout, check_page_size, component, decode_os_version, encode_os_version, size32,
};
use crate::util::{align, cstr, hex32, hex64, le32, le64, push_padded, put_cstr, slice};

const BOOT_MAGIC: &[u8; 8] = b"ANDROID!";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BootHeader {
    pub header_version: u32,
    pub page_size: u32,
    /// Android version, e.g. "14.0.0".
    pub os_version: String,
    /// Security patch level, "YYYY-MM".
    pub os_patch_level: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub cmdline: String,
    /// Load addresses (header v0-v2 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Addresses>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Addresses {
    #[serde(with = "hex32")]
    pub kernel: u32,
    #[serde(with = "hex32")]
    pub ramdisk: u32,
    #[serde(with = "hex32")]
    pub second: u32,
    #[serde(with = "hex32")]
    pub tags: u32,
    #[serde(with = "hex64", default, skip_serializing_if = "is_zero")]
    pub dtb: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

pub fn parse_boot(data: &[u8]) -> Result<(BootHeader, Layout)> {
    let version = le32(slice(data, 0, 44, "boot header")?, 40);
    ensure!(version <= 4, "unsupported boot header version {version}");
    let header_size = [1632, 1648, 1660, 1580, 1584][version as usize];
    let header = slice(data, 0, header_size, "boot header")?;
    let modern = version >= 3;
    let page_size = if modern { 4096 } else { le32(header, 36) };
    check_page_size(page_size.into())?;
    let page = u64::from(page_size);
    let raw_os_version = le32(header, if modern { 16 } else { 44 });
    let (os_version, os_patch_level) = decode_os_version(raw_os_version);

    // Components follow the header page in a fixed order, each page-aligned.
    let mut layout = Layout::new();
    let mut offset = page;
    let mut add = |name: &str, size: u32, at: Option<u64>| {
        if let Some(at) = at {
            offset = at;
        }
        if size != 0 {
            layout.push((name.into(), offset, u64::from(size)));
        }
        offset += align(u64::from(size), page);
    };
    add("kernel", le32(header, 8), None);
    add("ramdisk", le32(header, if modern { 12 } else { 16 }), None);

    let parsed = if modern {
        if version == 4 {
            add("boot_signature", le32(header, 1580), None);
        }
        BootHeader {
            header_version: version,
            page_size,
            os_version,
            os_patch_level,
            name: None,
            cmdline: cstr(&header[44..44 + 1536]),
            addresses: None,
        }
    } else {
        add("second", le32(header, 24), None);
        if version >= 1 {
            let size = le32(header, 1632);
            add(
                "recovery_dtbo",
                size,
                (size != 0).then(|| le64(header, 1636)),
            );
        }
        if version >= 2 {
            add("dtb", le32(header, 1648), None);
        }
        BootHeader {
            header_version: version,
            page_size,
            os_version,
            os_patch_level,
            name: Some(cstr(&header[48..64])),
            cmdline: cstr(&header[64..576]) + &cstr(&header[608..1632]),
            addresses: Some(Addresses {
                kernel: le32(header, 12),
                ramdisk: le32(header, 20),
                second: le32(header, 28),
                tags: le32(header, 32),
                dtb: if version >= 2 { le64(header, 1652) } else { 0 },
            }),
        }
    };
    for (name, start, size) in &layout {
        slice(data, *start, *size, name)?;
    }
    Ok((parsed, layout))
}

/// Builds a boot image like mkbootimg. For v4, `boot_signature` is written
/// as given; GKI signatures are regenerated separately.
pub fn build_boot(header: &BootHeader, components: &Components) -> Result<Vec<u8>> {
    let version = header.header_version;
    ensure!(version <= 4, "unsupported boot header version {version}");
    let page = if version >= 3 {
        4096
    } else {
        header.page_size as usize
    };
    check_page_size(page as u64)?;
    let os_version = encode_os_version(&header.os_version, &header.os_patch_level)?;
    let get = |name| component(components, name);
    let (kernel, ramdisk) = (get("kernel"), get("ramdisk"));

    let mut out = vec![0u8; page];
    let h = &mut out;
    let put = |h: &mut Vec<u8>, at: usize, value: u32| {
        h[at..at + 4].copy_from_slice(&value.to_le_bytes())
    };
    h[..8].copy_from_slice(BOOT_MAGIC);
    put(h, 8, size32(kernel, "kernel")?);
    put(h, 40, version);
    if version >= 3 {
        put(h, 12, size32(ramdisk, "ramdisk")?);
        put(h, 16, os_version);
        put(h, 20, if version == 4 { 1584 } else { 1580 });
        put_cstr(&mut h[44..44 + 1536], &header.cmdline, "cmdline")?;
        if version == 4 {
            put(h, 1580, size32(get("boot_signature"), "boot signature")?);
        }
        for name in ["kernel", "ramdisk", "boot_signature"] {
            push_padded(h, get(name), page);
        }
        return Ok(out);
    }

    let addresses = header.addresses.clone().unwrap_or_default();
    let (second, recovery_dtbo, dtb) = (get("second"), get("recovery_dtbo"), get("dtb"));
    put(h, 12, addresses.kernel);
    put(h, 16, size32(ramdisk, "ramdisk")?);
    put(h, 20, addresses.ramdisk);
    put(h, 24, size32(second, "second")?);
    put(h, 28, addresses.second);
    put(h, 32, addresses.tags);
    put(h, 36, page as u32);
    put(h, 44, os_version);
    put_cstr(&mut h[48..64], header.name.as_deref().unwrap_or(""), "name")?;
    // The command line spills from the 512-byte field into extra_cmdline.
    let cmdline = header.cmdline.as_bytes();
    ensure!(
        cmdline.len() <= 511 + 1023,
        "cmdline is longer than 1534 bytes"
    );
    let mut split = cmdline.len().min(511);
    while !header.cmdline.is_char_boundary(split) {
        split -= 1;
    }
    let (first, extra) = header.cmdline.split_at(split);
    put_cstr(&mut h[64..576], first, "cmdline")?;
    put_cstr(&mut h[608..1632], extra, "cmdline")?;

    // The id is a SHA-1 of every component and its size, as mkbootimg computes it.
    let mut id = Sha1::new();
    let mut parts = vec![kernel, ramdisk, second];
    if version >= 1 {
        let offset = page
            + [kernel, ramdisk, second]
                .iter()
                .map(|c| align(c.len() as u64, page as u64) as usize)
                .sum::<usize>();
        put(h, 1632, size32(recovery_dtbo, "recovery_dtbo")?);
        let offset = if recovery_dtbo.is_empty() {
            0
        } else {
            offset as u64
        };
        h[1636..1644].copy_from_slice(&offset.to_le_bytes());
        put(h, 1644, if version == 1 { 1648 } else { 1660 });
        parts.push(recovery_dtbo);
    }
    if version >= 2 {
        put(h, 1648, size32(dtb, "dtb")?);
        h[1652..1660].copy_from_slice(&addresses.dtb.to_le_bytes());
        parts.push(dtb);
    }
    for part in &parts {
        id.update(part);
        id.update((part.len() as u32).to_le_bytes());
    }
    h[576..596].copy_from_slice(&id.finalize());
    for part in parts {
        push_padded(&mut out, part, page);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_images_parse_back_for_every_header_version() {
        for version in 0..=4 {
            let header = BootHeader {
                header_version: version,
                page_size: if version >= 3 { 4096 } else { 2048 },
                os_version: "13.0.0".into(),
                os_patch_level: "2023-02".into(),
                name: (version < 3).then(|| "board".into()),
                cmdline: "x".repeat(if version < 3 { 700 } else { 1000 }),
                addresses: (version < 3).then(|| Addresses {
                    kernel: 0x8000,
                    dtb: if version == 2 { 0x1f00000 } else { 0 },
                    ..Default::default()
                }),
            };
            let mut components = Components::new();
            components.insert("kernel".into(), vec![1; 5000]);
            components.insert("ramdisk".into(), vec![2; 100]);
            if version == 1 || version == 2 {
                components.insert("recovery_dtbo".into(), vec![3; 10]);
            }
            if version == 4 {
                components.insert("boot_signature".into(), vec![4; 4096]);
            }
            let image = build_boot(&header, &components).unwrap();
            let (parsed, layout) = parse_boot(&image).unwrap();
            assert_eq!(parsed, header, "v{version}");
            for (name, offset, size) in layout {
                let data = &image[offset as usize..(offset + size) as usize];
                assert_eq!(data, components[&name], "v{version} {name}");
            }
        }
    }
}
