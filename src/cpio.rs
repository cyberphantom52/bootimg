//! The "newc" cpio format used by initramfs.

use anyhow::{Result, bail};

use crate::util::align;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

const TRAILER: &str = "TRAILER!!!";

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Entry {
    pub name: String,
    pub ino: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u32,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub data: Vec<u8>,
}

/// Parses every entry, continuing across concatenated archives as the kernel does.
pub fn parse(data: &[u8]) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut offset = 0;
    loop {
        while data.get(offset) == Some(&0) {
            offset += 1;
        }
        if offset >= data.len() {
            break;
        }
        let header = match data.get(offset..offset + 110) {
            Some(header) if header.starts_with(b"070701") || header.starts_with(b"070702") => {
                header
            }
            _ if entries.is_empty() => bail!("not a newc cpio archive"),
            // Trailing non-cpio data after the last archive is ignored, like the kernel's
            // "junk in compressed archive" handling.
            _ => break,
        };
        let field = |index: usize| -> Result<u32> {
            let text = std::str::from_utf8(&header[6 + index * 8..14 + index * 8])?;
            Ok(u32::from_str_radix(text, 16)?)
        };
        let name_size = field(11)? as usize;
        let file_size = field(6)? as usize;
        let name_start = offset + 110;
        let data_start = align((name_start + name_size) as u64, 4) as usize;
        let data_end = data_start + file_size;
        if name_size == 0 || data_end > data.len() {
            bail!("truncated cpio entry at offset {offset}");
        }
        let name = &data[name_start..name_start + name_size - 1];
        let name = String::from_utf8_lossy(name).into_owned();
        offset = align(data_end as u64, 4) as usize;
        if name == TRAILER {
            continue;
        }
        entries.push(Entry {
            name,
            ino: field(0)?,
            mode: field(1)?,
            uid: field(2)?,
            gid: field(3)?,
            nlink: field(4)?,
            mtime: field(5)?,
            dev_major: field(7)?,
            dev_minor: field(8)?,
            rdev_major: field(9)?,
            rdev_minor: field(10)?,
            data: data[data_start..data_end].to_vec(),
        });
    }
    Ok(entries)
}

pub fn write(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    let trailer = Entry {
        name: TRAILER.into(),
        nlink: 1,
        ..Default::default()
    };
    for entry in entries.iter().chain([&trailer]) {
        let fields = [
            entry.ino,
            entry.mode,
            entry.uid,
            entry.gid,
            entry.nlink,
            entry.mtime,
            entry.data.len() as u32,
            entry.dev_major,
            entry.dev_minor,
            entry.rdev_major,
            entry.rdev_minor,
            entry.name.len() as u32 + 1,
            0,
        ];
        out.extend_from_slice(b"070701");
        for value in fields {
            out.extend_from_slice(format!("{value:08x}").as_bytes());
        }
        out.extend_from_slice(entry.name.as_bytes());
        out.push(0);
        out.resize(align(out.len() as u64, 4) as usize, 0);
        out.extend_from_slice(&entry.data);
        out.resize(align(out.len() as u64, 4) as usize, 0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archives_round_trip_and_concatenate() {
        let entries = vec![
            Entry {
                name: "init".into(),
                ino: 1,
                mode: S_IFREG | 0o750,
                nlink: 1,
                data: b"#!/bin/sh\n".to_vec(),
                ..Default::default()
            },
            Entry {
                name: "dev/console".into(),
                ino: 2,
                mode: 0o020600,
                nlink: 1,
                rdev_major: 5,
                rdev_minor: 1,
                ..Default::default()
            },
        ];
        let archive = write(&entries);
        assert_eq!(archive.len() % 4, 0);
        assert_eq!(parse(&archive).unwrap(), entries);

        // A second archive appended after padding, as bootloaders and patchers do.
        let mut combined = archive.clone();
        combined.extend([0; 12]);
        combined.extend(write(&entries[..1]));
        assert_eq!(parse(&combined).unwrap().len(), 3);
        assert!(parse(b"not cpio").is_err());
    }
}
