//! vbmeta descriptors, as defined by libavb's `avb_*_descriptor.h`.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::util::{align, be32, be64, cstr, hex, put_cstr, slice};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Descriptor {
    Property {
        key: String,
        value: String,
    },
    Hashtree {
        dm_verity_version: u32,
        image_size: u64,
        tree_offset: u64,
        tree_size: u64,
        data_block_size: u32,
        hash_block_size: u32,
        fec_num_roots: u32,
        fec_offset: u64,
        fec_size: u64,
        hash_algorithm: String,
        partition_name: String,
        #[serde(with = "hex")]
        salt: Vec<u8>,
        #[serde(with = "hex")]
        root_digest: Vec<u8>,
        flags: u32,
    },
    Hash {
        image_size: u64,
        hash_algorithm: String,
        partition_name: String,
        #[serde(with = "hex")]
        salt: Vec<u8>,
        #[serde(with = "hex")]
        digest: Vec<u8>,
        flags: u32,
    },
    KernelCmdline {
        flags: u32,
        cmdline: String,
    },
    ChainPartition {
        rollback_index_location: u32,
        partition_name: String,
        #[serde(with = "hex")]
        public_key: Vec<u8>,
        flags: u32,
    },
    /// Descriptors of other types, or that fail to parse, are kept as they are.
    Unknown {
        tag: u64,
        #[serde(with = "hex")]
        data: Vec<u8>,
    },
}

/// Reads the variable-length fields after a descriptor's fixed part.
struct Fields<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Fields<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let field = slice(
            self.data,
            self.offset as u64,
            len as u64,
            "AVB descriptor field",
        )?;
        self.offset += len;
        Ok(field)
    }

    fn text(&mut self, len: usize) -> Result<String> {
        Ok(String::from_utf8(self.take(len)?.to_vec())?)
    }
}

impl Descriptor {
    /// Parses a descriptor body (after its tag and length).
    pub(super) fn parse(tag: u64, body: &[u8]) -> Result<Self> {
        let fields = |offset| Fields { data: body, offset };
        let parsed = match tag {
            0 if body.len() >= 16 => {
                let key_len = be64(body, 0) as usize;
                let value_len = be64(body, 8) as usize;
                let mut f = fields(16);
                let key = f.text(key_len)?;
                f.take(1)?;
                let value = f.text(value_len)?;
                Self::Property { key, value }
            }
            1 if body.len() >= 164 => {
                let mut f = fields(164);
                let (name_len, salt_len, digest_len) = (
                    be32(body, 88) as usize,
                    be32(body, 92) as usize,
                    be32(body, 96) as usize,
                );
                Self::Hashtree {
                    dm_verity_version: be32(body, 0),
                    image_size: be64(body, 4),
                    tree_offset: be64(body, 12),
                    tree_size: be64(body, 20),
                    data_block_size: be32(body, 28),
                    hash_block_size: be32(body, 32),
                    fec_num_roots: be32(body, 36),
                    fec_offset: be64(body, 40),
                    fec_size: be64(body, 48),
                    hash_algorithm: cstr(&body[56..88]),
                    partition_name: f.text(name_len)?,
                    salt: f.take(salt_len)?.to_vec(),
                    root_digest: f.take(digest_len)?.to_vec(),
                    flags: be32(body, 100),
                }
            }
            2 if body.len() >= 116 => {
                let mut f = fields(116);
                let (name_len, salt_len, digest_len) = (
                    be32(body, 40) as usize,
                    be32(body, 44) as usize,
                    be32(body, 48) as usize,
                );
                Self::Hash {
                    image_size: be64(body, 0),
                    hash_algorithm: cstr(&body[8..40]),
                    partition_name: f.text(name_len)?,
                    salt: f.take(salt_len)?.to_vec(),
                    digest: f.take(digest_len)?.to_vec(),
                    flags: be32(body, 52),
                }
            }
            3 if body.len() >= 8 => Self::KernelCmdline {
                flags: be32(body, 0),
                cmdline: fields(8).text(be32(body, 4) as usize)?,
            },
            4 if body.len() >= 76 => {
                let mut f = fields(76);
                let (name_len, key_len) = (be32(body, 4) as usize, be32(body, 8) as usize);
                Self::ChainPartition {
                    rollback_index_location: be32(body, 0),
                    partition_name: f.text(name_len)?,
                    public_key: f.take(key_len)?.to_vec(),
                    flags: be32(body, 12),
                }
            }
            _ => bail!("unrecognized descriptor"),
        };
        Ok(parsed)
    }

    /// Encodes the descriptor with its tag and length, padded to 8 bytes.
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        let u32 = |b: &mut Vec<u8>, v: u32| b.extend_from_slice(&v.to_be_bytes());
        let u64 = |b: &mut Vec<u8>, v: u64| b.extend_from_slice(&v.to_be_bytes());
        let algorithm_field = |b: &mut Vec<u8>, name: &str| -> Result<()> {
            let mut field = [0u8; 32];
            put_cstr(&mut field, name, "hash algorithm name")?;
            b.extend_from_slice(&field);
            Ok(())
        };
        let tag = match self {
            Self::Property { key, value } => {
                u64(&mut body, key.len() as u64);
                u64(&mut body, value.len() as u64);
                body.extend_from_slice(key.as_bytes());
                body.push(0);
                body.extend_from_slice(value.as_bytes());
                body.push(0);
                0
            }
            Self::Hashtree {
                dm_verity_version,
                image_size,
                tree_offset,
                tree_size,
                data_block_size,
                hash_block_size,
                fec_num_roots,
                fec_offset,
                fec_size,
                hash_algorithm,
                partition_name,
                salt,
                root_digest,
                flags,
            } => {
                u32(&mut body, *dm_verity_version);
                u64(&mut body, *image_size);
                u64(&mut body, *tree_offset);
                u64(&mut body, *tree_size);
                u32(&mut body, *data_block_size);
                u32(&mut body, *hash_block_size);
                u32(&mut body, *fec_num_roots);
                u64(&mut body, *fec_offset);
                u64(&mut body, *fec_size);
                algorithm_field(&mut body, hash_algorithm)?;
                u32(&mut body, partition_name.len() as u32);
                u32(&mut body, salt.len() as u32);
                u32(&mut body, root_digest.len() as u32);
                u32(&mut body, *flags);
                body.resize(body.len() + 60, 0);
                body.extend_from_slice(partition_name.as_bytes());
                body.extend_from_slice(salt);
                body.extend_from_slice(root_digest);
                1
            }
            Self::Hash {
                image_size,
                hash_algorithm,
                partition_name,
                salt,
                digest,
                flags,
            } => {
                u64(&mut body, *image_size);
                algorithm_field(&mut body, hash_algorithm)?;
                u32(&mut body, partition_name.len() as u32);
                u32(&mut body, salt.len() as u32);
                u32(&mut body, digest.len() as u32);
                u32(&mut body, *flags);
                body.resize(body.len() + 60, 0);
                body.extend_from_slice(partition_name.as_bytes());
                body.extend_from_slice(salt);
                body.extend_from_slice(digest);
                2
            }
            Self::KernelCmdline { flags, cmdline } => {
                u32(&mut body, *flags);
                u32(&mut body, cmdline.len() as u32);
                body.extend_from_slice(cmdline.as_bytes());
                3
            }
            Self::ChainPartition {
                rollback_index_location,
                partition_name,
                public_key,
                flags,
            } => {
                u32(&mut body, *rollback_index_location);
                u32(&mut body, partition_name.len() as u32);
                u32(&mut body, public_key.len() as u32);
                u32(&mut body, *flags);
                body.resize(body.len() + 60, 0);
                body.extend_from_slice(partition_name.as_bytes());
                body.extend_from_slice(public_key);
                4
            }
            Self::Unknown { tag, data } => {
                body.extend_from_slice(data);
                *tag
            }
        };
        body.resize(align(body.len() as u64, 8) as usize, 0);
        let mut out = Vec::with_capacity(16 + body.len());
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&(body.len() as u64).to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// Sets a hash descriptor's size and digest for `image`.
pub fn update_hash(descriptor: &mut Descriptor, image: &[u8]) -> Result<()> {
    let Descriptor::Hash {
        image_size,
        hash_algorithm,
        salt,
        digest,
        ..
    } = descriptor
    else {
        bail!("expected a hash descriptor");
    };
    *image_size = image.len() as u64;
    *digest = hash(hash_algorithm, salt, image)?;
    Ok(())
}

/// The salted digest a hash descriptor records.
pub fn hash(algorithm: &str, salt: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    Ok(match algorithm {
        "sha256" => Sha256::new()
            .chain_update(salt)
            .chain_update(data)
            .finalize()
            .to_vec(),
        "sha512" => Sha512::new()
            .chain_update(salt)
            .chain_update(data)
            .finalize()
            .to_vec(),
        "sha1" => sha1::Sha1::new()
            .chain_update(salt)
            .chain_update(data)
            .finalize()
            .to_vec(),
        other => bail!("unsupported hash algorithm {other:?}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_descriptor_type_round_trips() {
        let descriptors = [
            Descriptor::Property {
                key: "com.android.build.boot.os_version".into(),
                value: "14".into(),
            },
            Descriptor::Hashtree {
                dm_verity_version: 1,
                image_size: 1 << 20,
                tree_offset: 1 << 20,
                tree_size: 8192,
                data_block_size: 4096,
                hash_block_size: 4096,
                fec_num_roots: 2,
                fec_offset: (1 << 20) + 8192,
                fec_size: 16384,
                hash_algorithm: "sha1".into(),
                partition_name: "system".into(),
                salt: vec![1, 2, 3],
                root_digest: vec![4; 20],
                flags: 0,
            },
            Descriptor::Hash {
                image_size: 12345,
                hash_algorithm: "sha256".into(),
                partition_name: "boot".into(),
                salt: vec![0xaa; 32],
                digest: vec![0xbb; 32],
                flags: 1,
            },
            Descriptor::KernelCmdline {
                flags: 2,
                cmdline: "dm=\"1 vroot\"".into(),
            },
            Descriptor::ChainPartition {
                rollback_index_location: 3,
                partition_name: "vbmeta_system".into(),
                public_key: vec![7; 520],
                flags: 0,
            },
            Descriptor::Unknown {
                tag: 99,
                data: vec![5; 16],
            },
        ];
        for descriptor in descriptors {
            let encoded = descriptor.encode().unwrap();
            assert_eq!(encoded.len() % 8, 0);
            assert_eq!(be64(&encoded, 8) as usize, encoded.len() - 16);
            let parsed = match descriptor {
                Descriptor::Unknown { .. } => descriptor.clone(),
                _ => Descriptor::parse(be64(&encoded, 0), &encoded[16..]).unwrap(),
            };
            assert_eq!(parsed, descriptor);
        }
    }
}
