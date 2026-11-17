//! Ramdisks in a workspace: `NAME.img` holds the ramdisk as stored in the
//! image, `NAME/` the extracted tree and `NAME.cpio.json` its metadata.

use anyhow::{Result, ensure};
use std::fs;

use super::Workspace;
use crate::cli::ramdisk;

impl Workspace {
    pub(super) fn unpack_ramdisk(&mut self, name: &str, data: &[u8]) -> Result<String> {
        self.write(&format!("{name}.img"), data)?;
        if data.is_empty() {
            return Ok(format!("{name}.img (empty)"));
        }
        match ramdisk::unpack(data, &self.path(name)) {
            Ok(metadata) => {
                self.write(&format!("{name}.cpio.json"), metadata.to_json()?.as_bytes())?;
                let digest = ramdisk::tree_digest(&self.path(name))?;
                self.state.hashes.insert(format!("{name}/"), digest);
                Ok(format!(
                    "{name}/ ({}, {} entries)",
                    metadata.compression.name(),
                    metadata.entries.len()
                ))
            }
            Err(error) => {
                let _ = fs::remove_dir_all(self.path(name));
                eprintln!("warning: {name} kept as raw {name}.img: {error:#}");
                Ok(format!("{name}.img (raw)"))
            }
        }
    }

    /// The ramdisk to pack: rebuilt from the tree if it or its metadata was
    /// edited, otherwise `NAME.img` (original or replaced).
    pub(super) fn pack_ramdisk(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let image = format!("{name}.img");
        let metadata = format!("{name}.cpio.json");
        let tree = format!("{name}/");
        let tree_edited = if self.recorded(&tree) {
            self.exists(&tree) && (self.changed(&tree)? || self.changed(&metadata)?)
        } else {
            // A new ramdisk given as a tree.
            !self.exists(&image) && self.exists(&tree) && self.exists(&metadata)
        };
        if tree_edited {
            ensure!(
                !self.recorded(&image) || !self.changed(&image)?,
                "both {name}/ and {image} were changed; keep only one of the edits"
            );
            let metadata: ramdisk::Metadata = self.read_json(&metadata)?;
            say!(
                "Rebuilding {name} from {name}/ ({})",
                metadata.compression.name()
            );
            return Ok(Some(ramdisk::pack(&self.path(name), &metadata)?));
        }
        if self.exists(&image) {
            return Ok(Some(self.read(&image)?));
        }
        ensure!(!self.recorded(&image), "{image} was deleted");
        Ok(None)
    }
}
