use serde::{Deserialize, Serialize};

use super::{Components, Layout, check_page_size, component, size32};
use crate::{
    Error, Result,
    util::{align, cstr, hex32, hex64, le32, le64, push_padded, put_cstr, slice},
};

const VENDOR_BOOT_MAGIC: &[u8; 8] = b"VNDRBOOT";
const VENDOR_V3_HEADER: u64 = 2112;
const VENDOR_V4_HEADER: u64 = 2128;
const TABLE_ENTRY_SIZE: u64 = 108;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VendorBootHeader {
    pub header_version: u32,
    pub page_size: u32,
    pub name: String,
    pub cmdline: String,
    #[serde(with = "hex32")]
    pub kernel_addr: u32,
    #[serde(with = "hex32")]
    pub ramdisk_addr: u32,
    #[serde(with = "hex32")]
    pub tags_addr: u32,
    #[serde(with = "hex64")]
    pub dtb_addr: u64,
    /// The vendor ramdisk table (v4). Rows can be added, removed or reordered;
    /// each names its ramdisk in the workspace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ramdisks: Vec<VendorRamdisk>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VendorRamdisk {
    pub file: String,
    /// 0 none, 1 platform, 2 recovery, 3 dlkm.
    pub ramdisk_type: u32,
    pub name: String,
    pub board_id: [u32; 16],
}

pub fn parse_vendor_boot(data: &[u8]) -> Result<(VendorBootHeader, Layout)> {
    let header = slice(data, 0, VENDOR_V3_HEADER, "vendor_boot header")?;
    let version = le32(header, 8);
    if !matches!(version, 3 | 4) {
        return Err(Error::unsupported("vendor_boot header version", version));
    }
    let header = if version == 4 {
        slice(data, 0, VENDOR_V4_HEADER, "vendor_boot header")?
    } else {
        header
    };
    let page_size = le32(header, 12);
    check_page_size(page_size.into())?;
    let page = u64::from(page_size);
    let header_size = u64::from(le32(header, 2096));
    let ramdisk_offset = align(header_size, page);
    let ramdisk_size = u64::from(le32(header, 24));
    let dtb_offset = ramdisk_offset + align(ramdisk_size, page);
    let dtb_size = u64::from(le32(header, 2100));
    let table_offset = dtb_offset + align(dtb_size, page);
    let table_size = u64::from(le32(header, 2112));
    let mut layout = Layout::new();
    let mut ramdisks = Vec::new();

    if version == 4 && le32(header, 2116) > 0 {
        // Each table row is one ramdisk within the vendor ramdisk section.
        let (count, entry_size) = (le32(header, 2116), u64::from(le32(header, 2120)));
        if entry_size < TABLE_ENTRY_SIZE {
            return Err(Error::invalid(
                "vendor ramdisk table entry size",
                entry_size,
            ));
        }
        let table = slice(data, table_offset, table_size, "vendor ramdisk table")?;
        for index in 0..count as u64 {
            let entry = slice(
                table,
                index * entry_size,
                TABLE_ENTRY_SIZE,
                "vendor ramdisk table entry",
            )?;
            let (size, offset) = (u64::from(le32(entry, 0)), u64::from(le32(entry, 4)));
            if offset + size > ramdisk_size {
                return Err(Error::Truncated {
                    what: format!("vendor ramdisk {index}"),
                    offset,
                    len: size,
                    size: ramdisk_size,
                });
            }
            let file = format!("vendor_ramdisk.{index}");
            layout.push((file.clone(), ramdisk_offset + offset, size));
            ramdisks.push(VendorRamdisk {
                file,
                ramdisk_type: le32(entry, 8),
                name: cstr(&entry[12..44]),
                board_id: std::array::from_fn(|i| le32(entry, 44 + 4 * i)),
            });
        }
    } else if ramdisk_size != 0 {
        layout.push(("vendor_ramdisk".into(), ramdisk_offset, ramdisk_size));
    }
    if version == 4 {
        let bootconfig_offset = table_offset + align(table_size, page);
        let bootconfig_size = u64::from(le32(header, 2124));
        if bootconfig_size != 0 {
            layout.push(("bootconfig".into(), bootconfig_offset, bootconfig_size));
        }
    }
    if dtb_size != 0 {
        layout.push(("dtb".into(), dtb_offset, dtb_size));
    }
    for (name, start, size) in &layout {
        slice(data, *start, *size, name)?;
    }
    layout.sort_by_key(|(_, start, _)| *start);
    Ok((
        VendorBootHeader {
            header_version: version,
            page_size,
            name: cstr(&header[2080..2096]),
            cmdline: cstr(&header[28..2076]),
            kernel_addr: le32(header, 16),
            ramdisk_addr: le32(header, 20),
            tags_addr: le32(header, 2076),
            dtb_addr: le64(header, 2104),
            ramdisks,
        },
        layout,
    ))
}

pub fn build_vendor_boot(header: &VendorBootHeader, components: &Components) -> Result<Vec<u8>> {
    let version = header.header_version;
    if !matches!(version, 3 | 4) {
        return Err(Error::unsupported("vendor_boot header version", version));
    }
    let page = header.page_size as usize;
    check_page_size(page as u64)?;
    let get = |name| component(components, name);

    // Vendor ramdisks are concatenated without padding; the table records where each starts.
    let mut ramdisk = Vec::new();
    let mut table = Vec::new();
    if header.ramdisks.is_empty() {
        ramdisk.extend_from_slice(get("vendor_ramdisk"));
    }
    for entry in &header.ramdisks {
        let data = get(&entry.file);
        let mut row = [0u8; TABLE_ENTRY_SIZE as usize];
        row[0..4].copy_from_slice(&size32(data, &entry.file)?.to_le_bytes());
        row[4..8].copy_from_slice(&size32(&ramdisk, "vendor ramdisk")?.to_le_bytes());
        row[8..12].copy_from_slice(&entry.ramdisk_type.to_le_bytes());
        put_cstr(&mut row[12..44], &entry.name, "vendor ramdisk name")?;
        for (i, id) in entry.board_id.iter().enumerate() {
            row[44 + 4 * i..48 + 4 * i].copy_from_slice(&id.to_le_bytes());
        }
        table.extend_from_slice(&row);
        ramdisk.extend_from_slice(data);
    }
    let (dtb, bootconfig) = (get("dtb"), get("bootconfig"));

    let header_size = if version == 4 {
        VENDOR_V4_HEADER
    } else {
        VENDOR_V3_HEADER
    } as u32;
    let mut out = vec![0u8; align(u64::from(header_size), page as u64) as usize];
    let h = &mut out;
    let put = |h: &mut Vec<u8>, at: usize, value: u32| {
        h[at..at + 4].copy_from_slice(&value.to_le_bytes())
    };
    h[..8].copy_from_slice(VENDOR_BOOT_MAGIC);
    put(h, 8, version);
    put(h, 12, page as u32);
    put(h, 16, header.kernel_addr);
    put(h, 20, header.ramdisk_addr);
    put(h, 24, size32(&ramdisk, "vendor ramdisk")?);
    put_cstr(&mut h[28..2076], &header.cmdline, "cmdline")?;
    put(h, 2076, header.tags_addr);
    put_cstr(&mut h[2080..2096], &header.name, "name")?;
    put(h, 2096, header_size);
    put(h, 2100, size32(dtb, "dtb")?);
    h[2104..2112].copy_from_slice(&header.dtb_addr.to_le_bytes());
    if version == 4 {
        put(h, 2112, table.len() as u32);
        put(h, 2116, header.ramdisks.len() as u32);
        put(h, 2120, TABLE_ENTRY_SIZE as u32);
        put(h, 2124, size32(bootconfig, "bootconfig")?);
    }
    push_padded(&mut out, &ramdisk, page);
    push_padded(&mut out, dtb, page);
    if version == 4 {
        push_padded(&mut out, &table, page);
        push_padded(&mut out, bootconfig, page);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ramdisk_table_rows_locate_their_ramdisks() {
        let row = |file: &str, ramdisk_type, name: &str| VendorRamdisk {
            file: file.into(),
            ramdisk_type,
            name: name.into(),
            board_id: std::array::from_fn(|i| i as u32),
        };
        let header = VendorBootHeader {
            header_version: 4,
            page_size: 4096,
            name: "vendor".into(),
            cmdline: "loglevel=4".into(),
            kernel_addr: 0x8000,
            ramdisk_addr: 0x1000000,
            tags_addr: 0x100,
            dtb_addr: 0x1f00000,
            ramdisks: vec![row("platform", 1, ""), row("modules", 3, "dlkm")],
        };
        let mut components = Components::new();
        components.insert("platform".into(), vec![1; 3000]);
        components.insert("modules".into(), vec![2; 5000]);
        components.insert("dtb".into(), vec![3; 100]);
        components.insert("bootconfig".into(), b"a=b\n".to_vec());
        let image = build_vendor_boot(&header, &components).unwrap();

        let (parsed, layout) = parse_vendor_boot(&image).unwrap();
        assert_eq!(parsed.ramdisks[1].name, "dlkm");
        assert_eq!(parsed.ramdisks[1].board_id, header.ramdisks[1].board_id);
        let files = ["vendor_ramdisk.0", "vendor_ramdisk.1", "dtb", "bootconfig"];
        for ((name, offset, size), (file, original)) in
            layout.iter().zip(
                files
                    .iter()
                    .zip(["platform", "modules", "dtb", "bootconfig"]),
            )
        {
            assert_eq!(name, file);
            assert_eq!(
                &image[*offset as usize..(offset + size) as usize],
                components[original]
            );
        }
    }
}
