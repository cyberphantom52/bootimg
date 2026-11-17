//! Unpacking images into editable workspaces and packing them back.
//!
//! A workspace holds `image.json` (editable header fields), `avb.json` (AVB
//! metadata, when present), one file per image component, expanded ramdisks
//! and decompiled device trees. Unpack records a
//! hash of everything it writes; pack rebuilds only what changed and otherwise
//! reuses the original bytes, so an untouched workspace repacks to an identical
//! image.

mod device_trees;
mod gki;
mod pack;
mod ramdisks;
mod unpack;
mod vbmeta;

pub use pack::{PackOptions, pack};
pub use unpack::unpack;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use crate::cli::{ramdisk, sha256_hex};
use bootimgctl::{
    avb::{self, Footer, VbMeta},
    bootimg::{BootHeader, VendorBootHeader},
    dtbo::Dtbo,
};

const STATE_DIR: &str = ".bootimgctl";

#[derive(Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum ImageInfo {
    Boot { header: BootHeader },
    VendorBoot { header: VendorBootHeader },
    Vbmeta,
    Dtbo { table: Dtbo },
    Dtb,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AvbInfo {
    /// Partition size the footer is placed at, or the padded size of a vbmeta image.
    pub partition_size: u64,
    pub vbmeta: VbMeta,
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    source: String,
    /// Hash of every file and ramdisk tree as unpack wrote it.
    hashes: BTreeMap<String, String>,
}

pub struct Workspace {
    dir: PathBuf,
    state: State,
}

impl Workspace {
    fn open(dir: &Path) -> Result<Self> {
        let state = fs::read(dir.join(STATE_DIR).join("state.json"))
            .with_context(|| format!("{} is not a bootimgctl workspace", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            state: serde_json::from_slice(&state)?,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn write(&mut self, name: &str, data: &[u8]) -> Result<()> {
        let path = self.path(name);
        fs::write(&path, data).with_context(|| format!("writing {}", path.display()))?;
        self.state.hashes.insert(name.into(), sha256_hex(data));
        Ok(())
    }

    fn write_json<T: Serialize>(&mut self, name: &str, value: &T) -> Result<()> {
        let mut json = serde_json::to_string_pretty(value)?;
        json.push('\n');
        self.write(name, json.as_bytes())
    }

    fn read(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.path(name);
        fs::read(&path).with_context(|| format!("reading {}", path.display()))
    }

    fn read_optional(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.exists(name).then(|| self.read(name)).transpose()
    }

    fn read_json<T: DeserializeOwned>(&self, name: &str) -> Result<T> {
        serde_json::from_slice(&self.read(name)?).with_context(|| format!("parsing {name}"))
    }

    fn exists(&self, name: &str) -> bool {
        self.path(name).symlink_metadata().is_ok()
    }

    fn recorded(&self, name: &str) -> bool {
        self.state.hashes.contains_key(name)
    }

    /// The hash of a file, or of a ramdisk tree for names ending in `/`.
    fn current_hash(&self, name: &str) -> Result<Option<String>> {
        if !self.exists(name) {
            return Ok(None);
        }
        Ok(Some(match name.strip_suffix('/') {
            Some(tree) => ramdisk::tree_digest(&self.path(tree))?,
            None => sha256_hex(&self.read(name)?),
        }))
    }

    /// Whether a recorded file was edited, replaced or deleted.
    fn changed(&self, name: &str) -> Result<bool> {
        Ok(self.current_hash(name)?.as_ref() != self.state.hashes.get(name))
    }

    fn changed_files(&self) -> Result<Vec<String>> {
        let mut changed = Vec::new();
        for name in self.state.hashes.keys() {
            if self.changed(name)? {
                changed.push(name.clone());
            }
        }
        Ok(changed)
    }

    fn original(&self) -> Result<Vec<u8>> {
        self.read(&format!("{STATE_DIR}/original.img"))
    }

    fn save_state(&self) -> Result<()> {
        fs::write(
            self.dir.join(STATE_DIR).join("state.json"),
            serde_json::to_vec_pretty(&self.state)?,
        )?;
        Ok(())
    }
}

/// Detected input format, from the payload's magic bytes.
fn detect(payload: &[u8]) -> Result<&'static str> {
    Ok(match payload {
        [b'A', b'N', b'D', b'R', b'O', b'I', b'D', b'!', ..] => "boot",
        [b'V', b'N', b'D', b'R', b'B', b'O', b'O', b'T', ..] => "vendor_boot",
        [b'A', b'V', b'B', b'0', ..] => "vbmeta",
        [0xd7, 0xb7, 0xab, 0x1e, ..] => "dtbo",
        [0xd0, 0x0d, 0xfe, 0xed, ..] => "dtb",
        _ => bail!("not a boot, vendor_boot, vbmeta, dtbo or dtb image"),
    })
}

/// The image without its AVB footer and the parsed footer metadata.
fn split_footer(data: &[u8]) -> Result<(&[u8], Option<AvbInfo>)> {
    let Some(footer) = Footer::parse(data) else {
        return Ok((data, None));
    };
    let (vbmeta, signature) = VbMeta::parse(footer.vbmeta(data)?)?;
    if signature == avb::Signature::Invalid {
        eprintln!("warning: the AVB footer signature does not verify");
    }
    let payload = footer.payload(data)?;
    Ok((
        payload,
        Some(AvbInfo {
            partition_size: data.len() as u64,
            vbmeta,
        }),
    ))
}
