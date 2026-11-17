//! Android Verified Boot 2.0 metadata: vbmeta structs, descriptors and footers.
//!
//! Encoding follows avbtool so that re-signed images are byte-identical to what
//! `avbtool add_hash_footer` / `make_vbmeta_image` produce for the same inputs.

mod descriptor;
mod footer;
mod key;
mod vbmeta;

pub use descriptor::{Descriptor, hash, update_hash};
pub use footer::{Footer, HashFooter, write_footer};
pub use key::{Key, known_key, signing_key};
pub use vbmeta::{Signature, VbMeta};

use crate::{Error, Result};
use rsa::Pkcs1v15Sign;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum Algorithm {
    NONE,
    SHA256_RSA2048,
    SHA256_RSA4096,
    SHA256_RSA8192,
    SHA512_RSA2048,
    SHA512_RSA4096,
    SHA512_RSA8192,
}

impl Algorithm {
    const ALL: [Self; 7] = [
        Self::NONE,
        Self::SHA256_RSA2048,
        Self::SHA256_RSA4096,
        Self::SHA256_RSA8192,
        Self::SHA512_RSA2048,
        Self::SHA512_RSA4096,
        Self::SHA512_RSA8192,
    ];

    fn from_id(id: u32) -> Result<Self> {
        Self::ALL
            .get(id as usize)
            .copied()
            .ok_or_else(|| Error::unsupported("AVB algorithm type", id))
    }

    fn id(self) -> u32 {
        Self::ALL.iter().position(|&a| a == self).unwrap() as u32
    }

    pub fn key_bits(self) -> usize {
        match self {
            Self::NONE => 0,
            Self::SHA256_RSA2048 | Self::SHA512_RSA2048 => 2048,
            Self::SHA256_RSA4096 | Self::SHA512_RSA4096 => 4096,
            Self::SHA256_RSA8192 | Self::SHA512_RSA8192 => 8192,
        }
    }

    fn sha512(self) -> bool {
        matches!(
            self,
            Self::SHA512_RSA2048 | Self::SHA512_RSA4096 | Self::SHA512_RSA8192
        )
    }

    fn hash_size(self) -> usize {
        match self {
            Self::NONE => 0,
            _ if self.sha512() => 64,
            _ => 32,
        }
    }

    /// The algorithm with the same digest as `self` for a key of `bits`.
    pub fn with_key_bits(self, bits: usize) -> Result<Self> {
        Ok(match (self.sha512(), bits) {
            (false, 2048) => Self::SHA256_RSA2048,
            (false, 4096) => Self::SHA256_RSA4096,
            (false, 8192) => Self::SHA256_RSA8192,
            (true, 2048) => Self::SHA512_RSA2048,
            (true, 4096) => Self::SHA512_RSA4096,
            (true, 8192) => Self::SHA512_RSA8192,
            _ => return Err(Error::KeySize(bits)),
        })
    }

    fn digest(self, message: &[u8]) -> Vec<u8> {
        if self.sha512() {
            Sha512::digest(message).to_vec()
        } else {
            Sha256::digest(message).to_vec()
        }
    }

    fn scheme(self) -> Pkcs1v15Sign {
        if self.sha512() {
            Pkcs1v15Sign::new::<Sha512>()
        } else {
            Pkcs1v15Sign::new::<Sha256>()
        }
    }
}
