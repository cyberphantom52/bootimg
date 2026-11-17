//! Android boot image formats: boot and vendor_boot images, AVB metadata,
//! ramdisk compression and cpio archives, DTB bundles and DTBO tables.
//!
//! Everything works on bytes in memory. Building reproduces what the AOSP
//! tools (mkbootimg, avbtool, mkdtboimg) write for the same inputs, so an
//! image that is parsed and rebuilt unchanged comes out identical.
//!
//! The `cli` feature (on by default) builds the `bootimg` binary, with its
//! on-disk workspaces and the bundled dtc; disable default features to use
//! only the library.

pub mod avb;
pub mod boot;
pub mod compress;
pub mod cpio;
pub mod dtb;
pub mod dtbo;
mod error;
mod util;

pub use error::{Error, Result};
