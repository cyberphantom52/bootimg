//! Extracting a cpio ramdisk to a directory and rebuilding it from that directory.
//!
//! Ownership, full modes, mtimes and device nodes cannot be represented by an
//! unprivileged host tree, so they are kept in a JSON file next to it.
//! Entries present there keep their metadata on rebuild; new files get root
//! ownership and 0644/0755 modes, unless an entry for them is added to the JSON.

mod extract;
mod rebuild;

pub use rebuild::tree_digest;

use serde::{Deserialize, Serialize};
use std::path::Path;

use bootimg::{
    compress::Compression,
    cpio::{self, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG},
};

use crate::cli::{Error, Result};

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    pub compression: Compression,
    pub entries: Vec<EntryMeta>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntryMeta {
    pub path: String,
    #[serde(with = "octal")]
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub mtime: u32,
    /// Device number of character and block devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdev: Option<[u32; 2]>,
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

mod octal {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(mode: &u32, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{mode:o}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
        let text = String::deserialize(deserializer)?;
        u32::from_str_radix(&text, 8)
            .map_err(|_| serde::de::Error::custom(format!("invalid octal mode {text:?}")))
    }
}

fn json(value: &impl Serialize) -> String {
    serde_json::to_string(value).expect("ramdisk metadata serializes")
}

impl Metadata {
    /// Pretty JSON with one entry per line, so diffs stay readable.
    pub fn to_json(&self) -> String {
        let mut out = format!(
            "{{\n  \"compression\": {},\n  \"entries\": [\n",
            json(&self.compression)
        );
        for (index, entry) in self.entries.iter().enumerate() {
            let separator = if index + 1 == self.entries.len() {
                ""
            } else {
                ","
            };
            out += &format!("    {}{separator}\n", json(entry));
        }
        out += "  ]\n}\n";
        out
    }
}

/// The host-relative path for an archive name, or None for the archive root.
fn host_path(name: &str) -> Result<Option<String>> {
    let mut parts = Vec::new();
    for part in name.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err(Error::EscapingPath(name.to_string())),
            part => parts.push(part),
        }
    }
    Ok((!parts.is_empty()).then(|| parts.join("/")))
}

/// Device nodes, FIFOs and sockets, which are kept only in the metadata.
fn is_special(mode: u32) -> bool {
    !matches!(mode & S_IFMT, S_IFDIR | S_IFREG | S_IFLNK)
}

/// The permissions an entry gets on the host: its own, plus owner access.
fn host_mode(mode: u32) -> u32 {
    let owner = if mode & S_IFMT == S_IFDIR {
        0o700
    } else {
        0o600
    };
    (mode & 0o777) | owner
}

/// Unpacks a ramdisk: `bytes` must be cpio (optionally compressed).
pub fn unpack(bytes: &[u8], root: &Path) -> Result<Metadata> {
    let (compression, raw) = bootimg::compress::detect_and_decompress(bytes)?;
    let entries = cpio::parse(&raw)?;
    Ok(Metadata {
        compression,
        entries: extract::extract(entries, root)?,
    })
}

pub fn pack(root: &Path, metadata: &Metadata) -> Result<Vec<u8>> {
    let archive = cpio::write(&rebuild::rebuild(root, metadata)?);
    Ok(metadata.compression.compress(&archive)?)
}
