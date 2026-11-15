//! The vbmeta struct: header, authentication block and auxiliary block.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{
    Algorithm, Descriptor,
    key::{Key, decode_public_key},
};
use crate::util::{align, be32, be64, cstr, hex, put_cstr, slice};

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

    /// Encodes the vbmeta blob. A key is required unless the algorithm is NONE;
    /// the algorithm's key size is adjusted to match the key.
    pub fn encode(&mut self, key: Option<&Key>) -> Result<Vec<u8>> {
        if self.algorithm != Algorithm::NONE {
            let key = key.context("signing key required")?;
            self.algorithm = self.algorithm.with_key_bits(key.bits())?;
            self.public_key = key.avb_public_key();
        }
        let algorithm = self.algorithm;

        let mut descriptors = Vec::new();
        for descriptor in &self.descriptors {
            descriptors.extend(descriptor.encode()?);
        }
        let mut aux = [
            &descriptors[..],
            &self.public_key,
            &self.public_key_metadata,
        ]
        .concat();
        aux.resize(align(aux.len() as u64, 64) as usize, 0);

        let hash_size = algorithm.hash_size();
        let signature_size = algorithm.key_bits() / 8;
        let auth_size = align((hash_size + signature_size) as u64, 64);

        // Offsets in the auxiliary block are laid out as avbtool does, including
        // the public key metadata offset when there is no metadata.
        let mut header = vec![0u8; HEADER_SIZE];
        let put32 =
            |h: &mut Vec<u8>, at: usize, v: u32| h[at..at + 4].copy_from_slice(&v.to_be_bytes());
        let put64 =
            |h: &mut Vec<u8>, at: usize, v: u64| h[at..at + 8].copy_from_slice(&v.to_be_bytes());
        header[..4].copy_from_slice(b"AVB0");
        put32(&mut header, 4, self.required_libavb_version_major);
        put32(&mut header, 8, self.required_libavb_version_minor);
        put64(&mut header, 12, auth_size);
        put64(&mut header, 20, aux.len() as u64);
        put32(&mut header, 28, algorithm.id());
        put64(&mut header, 32, 0);
        put64(&mut header, 40, hash_size as u64);
        put64(&mut header, 48, hash_size as u64);
        put64(&mut header, 56, signature_size as u64);
        put64(&mut header, 64, descriptors.len() as u64);
        put64(&mut header, 72, self.public_key.len() as u64);
        put64(
            &mut header,
            80,
            (descriptors.len() + self.public_key.len()) as u64,
        );
        put64(&mut header, 88, self.public_key_metadata.len() as u64);
        put64(&mut header, 96, 0);
        put64(&mut header, 104, descriptors.len() as u64);
        put64(&mut header, 112, self.rollback_index);
        put32(&mut header, 120, self.flags);
        put32(&mut header, 124, self.rollback_index_location);
        put_cstr(
            &mut header[128..175],
            &self.release_string,
            "release string",
        )?;

        let mut auth = Vec::with_capacity(auth_size as usize);
        if let (Some(key), true) = (key, algorithm != Algorithm::NONE) {
            let message = [&header[..], &aux].concat();
            let hash = algorithm.digest(&message);
            auth.extend_from_slice(&hash);
            auth.extend_from_slice(&key.sign(algorithm, &hash)?);
        }
        auth.resize(auth_size as usize, 0);
        Ok([header, auth, aux].concat())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn vbmeta(algorithm: Algorithm) -> VbMeta {
        VbMeta {
            required_libavb_version_major: 1,
            required_libavb_version_minor: 0,
            algorithm,
            rollback_index: 3,
            flags: 0,
            rollback_index_location: 1,
            release_string: "avbtool 1.2.0".into(),
            descriptors: vec![Descriptor::Property {
                key: "a".into(),
                value: "b".into(),
            }],
            public_key: Vec::new(),
            public_key_metadata: Vec::new(),
        }
    }

    #[test]
    fn signed_metadata_round_trips_and_detects_tampering() {
        let key = Key::test_key(2048).unwrap();
        let mut original = vbmeta(Algorithm::SHA512_RSA4096);
        let mut blob = original.encode(Some(&key)).unwrap();
        // The algorithm follows the key size and keeps its digest.
        assert_eq!(original.algorithm, Algorithm::SHA512_RSA2048);
        let (parsed, signature) = VbMeta::parse(&blob).unwrap();
        assert_eq!((parsed, signature), (original, Signature::Valid));

        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert_eq!(VbMeta::parse(&blob).unwrap().1, Signature::Invalid);
    }

    #[test]
    fn unsigned_metadata_needs_no_key() {
        let mut original = vbmeta(Algorithm::NONE);
        let blob = original.encode(None).unwrap();
        assert_eq!(
            VbMeta::parse(&blob).unwrap(),
            (original, Signature::Unsigned)
        );
    }
}
