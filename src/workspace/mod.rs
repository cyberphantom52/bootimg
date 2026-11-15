//! Unpacking images into editable workspaces and packing them back.
//!
//! A workspace holds `image.json` (editable header fields), `avb.json` (AVB
//! metadata, when present) and one file per image component. Unpack records a
//! hash of everything it writes, so pack can tell what was edited.

mod unpack;

pub use unpack::unpack;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::PathBuf};

use crate::{
    avb::{self, Footer, VbMeta},
    bootimg::{BootHeader, VendorBootHeader},
    util::{sha256_hex, slice},
};

const STATE_DIR: &str = ".bootimgctl";

#[derive(Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum ImageInfo {
    Boot { header: BootHeader },
    VendorBoot { header: VendorBootHeader },
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
        _ => bail!("not a boot or vendor_boot image"),
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
    let payload = slice(data, 0, footer.original_image_size, "AVB footer image")?;
    Ok((
        payload,
        Some(AvbInfo {
            partition_size: data.len() as u64,
            vbmeta,
        }),
    ))
}
