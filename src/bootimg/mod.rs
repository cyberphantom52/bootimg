//! Android boot (v0-v4) and vendor_boot (v3-v4) image headers and layouts, as
//! defined by AOSP `system/tools/mkbootimg/include/bootimg/bootimg.h`.

mod boot;
mod gki;
mod image;
mod vendor;

pub use boot::{Addresses, BootHeader, build_boot, parse_boot};
pub use gki::resign_gki;
pub use image::{Header, Image};
pub use vendor::{VendorBootHeader, VendorRamdisk, build_vendor_boot, parse_vendor_boot};

use std::collections::BTreeMap;

use crate::{
    Error, Result,
    util::{align, too_long},
};

/// Component name to contents.
pub type Components = BTreeMap<String, Vec<u8>>;

/// A component's name and byte range within the image.
pub type Layout = Vec<(String, u64, u64)>;

/// Splits the packed `os_version` field into a version and a patch level.
fn decode_os_version(raw: u32) -> (String, String) {
    let version = raw >> 11;
    let patch = raw & 0x7ff;
    (
        format!(
            "{}.{}.{}",
            version >> 14,
            (version >> 7) & 0x7f,
            version & 0x7f
        ),
        format!("{}-{:02}", (patch >> 4) + 2000, patch & 0xf),
    )
}

fn encode_os_version(version: &str, patch: &str) -> Result<u32> {
    let invalid = || {
        Error::invalid(
            "os_version and os_patch_level (like \"14.0.0\" and \"2024-05\")",
            format!("{version:?} and {patch:?}"),
        )
    };
    let numbers = |text: &str, separator: char| -> Result<Vec<u32>> {
        text.split(separator)
            .map(|part| part.trim().parse().map_err(|_| invalid()))
            .collect()
    };
    let v = numbers(version, '.')?;
    let p = numbers(patch, '-')?;
    let (&[a, b, c], &[year, month]) = (&v[..], &p[..]) else {
        return Err(invalid());
    };
    if a >= 128 || b >= 128 || c >= 128 || !(2000..2128).contains(&year) || month >= 16 {
        return Err(invalid());
    }
    Ok((((a << 14) | (b << 7) | c) << 11) | ((year - 2000) << 4) | month)
}

/// The end of the last component in `layout`, page-aligned: everything after is
/// signatures or padding.
pub fn content_end(layout: &Layout, page_size: u32) -> u64 {
    let end = layout
        .iter()
        .map(|(_, start, size)| start + size)
        .max()
        .unwrap_or(0);
    align(end.max(1), u64::from(page_size))
}

fn component<'a>(components: &'a Components, name: &str) -> &'a [u8] {
    components.get(name).map_or(&[], Vec::as_slice)
}

fn size32(data: &[u8], name: &str) -> Result<u32> {
    u32::try_from(data.len()).map_err(|_| too_long(name, data.len(), u32::MAX as usize))
}

fn check_page_size(page: u64) -> Result<()> {
    if !page.is_power_of_two() || page < 2048 {
        return Err(Error::invalid("page size", page));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_version_round_trips_every_bit_pattern() {
        for raw in [0, 0x18000199, 0xc75d263c, u32::MAX] {
            let (version, patch) = decode_os_version(raw);
            assert_eq!(encode_os_version(&version, &patch).unwrap(), raw);
        }
        assert_eq!(
            decode_os_version(0x1c000184),
            ("14.0.0".into(), "2024-04".into())
        );
    }
}
