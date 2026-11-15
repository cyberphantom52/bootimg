//! The vbmeta struct: header, authentication block and auxiliary block.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::{Algorithm, Descriptor, key::decode_public_key};
use crate::util::{be32, be64, cstr, hex, slice};

const HEADER_SIZE: usize = 256;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VbMeta {
    pub required_libavb_version_major: u32,
    pub required_libavb_version_minor: u32,
    pub algorithm: Algorithm,
    pub rollback_index: u64,
    /// 1 disables hashtree verification, 2 disables verification entirely.
    pub flags: u32,
    pub rollback_index_location: u32,
    pub release_string: String,
    pub descriptors: Vec<Descriptor>,
    /// The signer's public key. Replaced with the signing key's on re-signing.
    #[serde(with = "hex")]
    pub public_key: Vec<u8>,
    #[serde(with = "hex", default, skip_serializing_if = "Vec::is_empty")]
    pub public_key_metadata: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signature {
    Unsigned,
    Valid,
    Invalid,
}

impl VbMeta {
    /// Parses a vbmeta blob, returning it with the result of checking its signature.
    pub fn parse(data: &[u8]) -> Result<(Self, Signature)> {
        let header = slice(data, 0, HEADER_SIZE as u64, "vbmeta header")?;
        ensure!(&header[..4] == b"AVB0", "missing AVB0 vbmeta magic");
        let auth_size = be64(header, 12);
        let aux_size = be64(header, 20);
        let algorithm = Algorithm::from_id(be32(header, 28))?;
        let auth = slice(
            data,
            HEADER_SIZE as u64,
            auth_size,
            "vbmeta authentication block",
        )?;
        let aux = slice(
            data,
            HEADER_SIZE as u64 + auth_size,
            aux_size,
            "vbmeta auxiliary block",
        )?;
        // A field located by an (offset, size) pair in the header.
        let field = |block: &[u8], offset_at: usize, what: &str| -> Result<Vec<u8>> {
            Ok(slice(
                block,
                be64(header, offset_at),
                be64(header, offset_at + 8),
                what,
            )?
            .to_vec())
        };

        let descriptor_data = field(aux, 96, "vbmeta descriptors")?;
        let mut descriptors = Vec::new();
        let mut offset = 0;
        while offset + 16 <= descriptor_data.len() {
            let tag = be64(&descriptor_data, offset);
            let len = be64(&descriptor_data, offset + 8);
            let body = slice(
                &descriptor_data,
                offset as u64 + 16,
                len,
                "vbmeta descriptor",
            )?;
            descriptors.push(Descriptor::parse(tag, body).unwrap_or_else(|_| {
                Descriptor::Unknown {
                    tag,
                    data: body.to_vec(),
                }
            }));
            offset += 16 + len as usize;
        }

        let public_key = field(aux, 64, "vbmeta public key")?;
        let vbmeta = Self {
            required_libavb_version_major: be32(header, 4),
            required_libavb_version_minor: be32(header, 8),
            algorithm,
            rollback_index: be64(header, 112),
            flags: be32(header, 120),
            rollback_index_location: be32(header, 124),
            release_string: cstr(&header[128..176]),
            descriptors,
            public_key_metadata: field(aux, 80, "vbmeta public key metadata")?,
            public_key,
        };

        let signature = if algorithm == Algorithm::NONE {
            Signature::Unsigned
        } else {
            let hash = field(auth, 32, "vbmeta hash")?;
            let sig = field(auth, 48, "vbmeta signature")?;
            let message = [header, aux].concat();
            let valid = hash == algorithm.digest(&message)
                && decode_public_key(&vbmeta.public_key)
                    .and_then(|key| Ok(key.verify(algorithm.scheme(), &hash, &sig)?))
                    .is_ok();
            if valid {
                Signature::Valid
            } else {
                Signature::Invalid
            }
        };
        Ok((vbmeta, signature))
    }

    pub fn hash_descriptor_mut(&mut self, partition: &str) -> Option<&mut Descriptor> {
        self.descriptors.iter_mut().find(|d| {
            matches!(d, Descriptor::Hash { partition_name, .. } | Descriptor::Hashtree { partition_name, .. }
                if partition_name == partition)
        })
    }

    /// The partition name of the first hash descriptor, used for footers.
    pub fn first_hash_partition(&self) -> Option<&str> {
        self.descriptors.iter().find_map(|d| match d {
            Descriptor::Hash { partition_name, .. } => Some(partition_name.as_str()),
            _ => None,
        })
    }
}
