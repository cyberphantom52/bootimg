//! A boot or vendor_boot image taken apart into its header, components and
//! AVB hash footer, to change components and build it back.

use std::{
    io::{Seek, Write},
    path::Path,
};

use super::{
    BootHeader, Components, Layout, VendorBootHeader, build_boot, build_vendor_boot, parse_boot,
    parse_vendor_boot, resign_gki,
};
use crate::{
    Error, Result,
    avb::{Descriptor, HashFooter},
};

#[derive(Clone, Debug, PartialEq)]
pub enum Header {
    Boot(BootHeader),
    VendorBoot(VendorBootHeader),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Image {
    pub header: Header,
    /// Every component by name: `kernel`, `ramdisk`, `dtb`, `vendor_ramdisk.0`, ...
    pub components: Components,
    pub footer: Option<HashFooter>,
}

impl Image {
    /// Takes apart a boot or vendor_boot image, with or without an AVB hash
    /// footer. Bytes after the last component, such as a vendor signature, are
    /// not kept.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (payload, footer, _) = HashFooter::split(data)?;
        let (header, layout): (Header, Layout) = if payload.starts_with(b"ANDROID!") {
            let (header, layout) = parse_boot(payload)?;
            (Header::Boot(header), layout)
        } else if payload.starts_with(b"VNDRBOOT") {
            let (header, layout) = parse_vendor_boot(payload)?;
            (Header::VendorBoot(header), layout)
        } else {
            return Err(Error::Format("a boot or vendor_boot image"));
        };
        let components = layout
            .into_iter()
            .map(|(name, offset, size)| {
                let bytes = payload[offset as usize..(offset + size) as usize].to_vec();
                (name, bytes)
            })
            .collect();
        Ok(Self {
            header,
            components,
            footer,
        })
    }

    /// The names of the components that are ramdisks, in the order they load.
    pub fn ramdisks(&self) -> Vec<&str> {
        let names: Vec<&str> = match &self.header {
            Header::Boot(_) => vec!["ramdisk"],
            Header::VendorBoot(header) if header.ramdisks.is_empty() => vec!["vendor_ramdisk"],
            Header::VendorBoot(header) => header.ramdisks.iter().map(|r| r.file.as_str()).collect(),
        };
        names
            .into_iter()
            .filter(|name| self.components.contains_key(*name))
            .collect()
    }

    /// Builds the image without its footer, regenerating a GKI boot signature
    /// with `key` or the AOSP test keys.
    pub fn build(&self, key: Option<&Path>) -> Result<Vec<u8>> {
        Ok(match &self.header {
            Header::Boot(header) => {
                let mut image = build_boot(header, &self.components)?;
                if header.header_version == 4 {
                    resign_gki(&mut image, &self.components, key)?;
                }
                image
            }
            Header::VendorBoot(header) => build_vendor_boot(header, &self.components)?,
        })
    }

    /// Builds the image into `out` from its start, followed by its footer
    /// re-signed with `key` or the AOSP test key of the original key's size.
    /// Returns the footer's new hash descriptor.
    pub fn write(
        &mut self,
        out: &mut (impl Write + Seek),
        key: Option<&Path>,
    ) -> Result<Option<Descriptor>> {
        let payload = self.build(key)?;
        out.write_all(&payload)?;
        self.footer
            .as_mut()
            .map(|footer| footer.write(out, &payload, key))
            .transpose()
    }
}
