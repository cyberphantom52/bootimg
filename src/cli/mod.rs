//! The command-line tool: editable workspaces on disk, built on the library.

pub mod dtc;
pub mod info;
pub mod ramdisk;
pub mod workspace;

use sha2::{Digest, Sha256};

pub fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(Sha256::digest(data))
}
