//! DTBO partition images: a table of device tree overlays (libufdt's
//! `dt_table.h`, as written by mkdtboimg).

use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::{
    Error, Result,
    util::{be32, hex32, slice},
};

pub const DTBO_MAGIC: [u8; 4] = [0xd7, 0xb7, 0xab, 0x1e];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dtbo {
    pub page_size: u32,
    pub version: u32,
    pub entries: Vec<DtboEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DtboEntry {
    pub file: String,
    #[serde(with = "hex32")]
    pub id: u32,
    #[serde(with = "hex32")]
    pub rev: u32,
    /// custom[0] holds the compression flags in version 1 tables.
    pub custom: [u32; 4],
}

impl DtboEntry {
    fn compression(&self, version: u32) -> u32 {
        if version >= 1 {
            self.custom[0] & 0xf
        } else {
            0
        }
    }
}

const DTBO_HEADER_SIZE: u32 = 32;
const DTBO_ENTRY_SIZE: u32 = 32;

/// Parses a DTBO image into its table and (decompressed) device trees.
pub fn parse_dtbo(data: &[u8]) -> Result<(Dtbo, Vec<Vec<u8>>)> {
    if !data.starts_with(&DTBO_MAGIC) {
        return Err(Error::Format("a DTBO image"));
    }
    let header = slice(data, 0, DTBO_HEADER_SIZE as u64, "DTBO header")?;
    let (entry_size, count, entries_offset) =
        (be32(header, 12), be32(header, 16), be32(header, 20));
    let (page_size, version) = (be32(header, 24), be32(header, 28));
    if entry_size < DTBO_ENTRY_SIZE {
        return Err(Error::invalid("DTBO entry size", entry_size));
    }
    let mut entries = Vec::new();
    let mut trees = Vec::new();
    for index in 0..count {
        let offset = entries_offset as u64 + u64::from(index) * u64::from(entry_size);
        let raw = slice(data, offset, DTBO_ENTRY_SIZE as u64, "DTBO entry")?;
        let entry = DtboEntry {
            file: format!("dtbo.{index}.dtb"),
            id: be32(raw, 8),
            rev: be32(raw, 12),
            custom: std::array::from_fn(|i| be32(raw, 16 + 4 * i)),
        };
        let blob = slice(
            data,
            be32(raw, 4).into(),
            be32(raw, 0).into(),
            "DTBO device tree",
        )?;
        let tree = match entry.compression(version) {
            0 => blob.to_vec(),
            1 | 2 => {
                let mut out = Vec::new();
                if entry.compression(version) == 1 {
                    flate2::read::ZlibDecoder::new(blob).read_to_end(&mut out)
                } else {
                    flate2::read::GzDecoder::new(blob).read_to_end(&mut out)
                }
                .map_err(|source| Error::Compression("DTBO device tree", source))?;
                out
            }
            other => return Err(Error::unsupported("DTBO compression", other)),
        };
        entries.push(entry);
        trees.push(tree);
    }
    Ok((
        Dtbo {
            page_size,
            version,
            entries,
        },
        trees,
    ))
}

/// Builds a DTBO image like mkdtboimg: header, entry table, then the trees with
/// identical entries sharing one copy.
pub fn build_dtbo(dtbo: &Dtbo, trees: &[Vec<u8>]) -> Result<Vec<u8>> {
    let count = dtbo.entries.len() as u32;
    let mut blobs: Vec<u8> = Vec::new();
    let mut table = Vec::new();
    let mut seen: Vec<(u32, Vec<u8>, u32, u32)> = Vec::new();
    let data_start = DTBO_HEADER_SIZE + count * DTBO_ENTRY_SIZE;
    for (entry, tree) in dtbo.entries.iter().zip(trees) {
        let compression = entry.compression(dtbo.version);
        let (offset, size) = match seen
            .iter()
            .find(|(c, t, ..)| *c == compression && t == tree)
        {
            Some(&(_, _, offset, size)) => (offset, size),
            None => {
                let blob = compress_tree(tree, compression)
                    .map_err(|source| Error::Compression("DTBO device tree", source))?;
                let offset = data_start + blobs.len() as u32;
                blobs.extend_from_slice(&blob);
                seen.push((compression, tree.clone(), offset, blob.len() as u32));
                (offset, blob.len() as u32)
            }
        };
        for value in [size, offset, entry.id, entry.rev]
            .into_iter()
            .chain(entry.custom)
        {
            table.extend_from_slice(&value.to_be_bytes());
        }
    }
    let total_size = data_start + blobs.len() as u32;
    let mut out = DTBO_MAGIC.to_vec();
    for value in [
        total_size,
        DTBO_HEADER_SIZE,
        DTBO_ENTRY_SIZE,
        count,
        DTBO_HEADER_SIZE,
        dtbo.page_size,
        dtbo.version,
    ] {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(&table);
    out.extend_from_slice(&blobs);
    Ok(out)
}

fn compress_tree(tree: &[u8], compression: u32) -> std::io::Result<Vec<u8>> {
    use std::io::Write;
    Ok(match compression {
        0 => tree.to_vec(),
        1 => {
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(tree)?;
            encoder.finish()?
        }
        _ => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(tree)?;
            encoder.finish()?
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dtb::FDT_MAGIC;

    fn tree(fill: u8) -> Vec<u8> {
        let mut tree = FDT_MAGIC.to_vec();
        tree.extend_from_slice(&48u32.to_be_bytes());
        tree.resize(48, fill);
        tree
    }

    #[test]
    fn dtbo_round_trips_and_shares_identical_trees() {
        let dtbo = Dtbo {
            page_size: 4096,
            version: 1,
            entries: (0..3)
                .map(|i| DtboEntry {
                    file: format!("dtbo.{i}.dtb"),
                    id: i,
                    rev: 7,
                    custom: [if i == 2 { 1 } else { 0 }, 0, 0, i],
                })
                .collect(),
        };
        let trees = vec![tree(1), tree(1), tree(2)];
        let image = build_dtbo(&dtbo, &trees).unwrap();
        let (parsed, parsed_trees) = parse_dtbo(&image).unwrap();
        assert_eq!(parsed_trees, trees);
        assert_eq!(parsed.entries[2].custom, [1, 0, 0, 2]);
        assert_eq!(build_dtbo(&parsed, &parsed_trees).unwrap(), image);
        // Entries 0 and 1 share one copy.
        assert_eq!(image[32 + 4..32 + 8], image[64 + 4..64 + 8]);
    }
}
