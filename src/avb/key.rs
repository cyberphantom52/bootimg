//! RSA keys and AVB's public key encoding.

use rsa::{
    BigUint, RsaPrivateKey, RsaPublicKey, pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey,
    traits::PublicKeyParts,
};
use std::path::Path;

use super::Algorithm;
use crate::{
    Error, Result,
    util::{be32, slice},
};

/// An RSA signing key.
pub struct Key {
    key: RsaPrivateKey,
    pub description: String,
}

const TEST_KEYS: [(usize, &str); 3] = [
    (2048, include_str!("../../keys/testkey_rsa2048.pem")),
    (4096, include_str!("../../keys/testkey_rsa4096.pem")),
    (8192, include_str!("../../keys/testkey_rsa8192.pem")),
];

impl Key {
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).map_err(|source| Error::ReadKey {
            path: path.to_path_buf(),
            source,
        })?;
        let key = match std::str::from_utf8(&data) {
            Ok(text) if text.contains("-----BEGIN") => RsaPrivateKey::from_pkcs1_pem(text)
                .ok()
                .or_else(|| RsaPrivateKey::from_pkcs8_pem(text).ok()),
            _ => RsaPrivateKey::from_pkcs8_der(&data)
                .ok()
                .or_else(|| RsaPrivateKey::from_pkcs1_der(&data).ok()),
        }
        .ok_or_else(|| Error::NotAKey(path.to_path_buf()))?;
        Ok(Self {
            key,
            description: path.display().to_string(),
        })
    }

    /// The AOSP test key (`external/avb/test/data/testkey_rsa*.pem`) of the given size.
    pub fn test_key(bits: usize) -> Result<Self> {
        let (_, pem) = TEST_KEYS
            .iter()
            .find(|(size, _)| *size == bits)
            .ok_or(Error::KeySize(bits))?;
        Ok(Self {
            key: RsaPrivateKey::from_pkcs1_pem(pem).expect("the AOSP test keys parse"),
            description: format!("AOSP test key testkey_rsa{bits}"),
        })
    }

    pub fn bits(&self) -> usize {
        self.key.size() * 8
    }

    /// The key in AVB's public key format (`avbtool extract_public_key`).
    pub fn avb_public_key(&self) -> Vec<u8> {
        encode_public_key(self.key.n())
    }

    /// Signs a precomputed digest with PKCS#1 v1.5 padding.
    pub(super) fn sign(&self, algorithm: Algorithm, digest: &[u8]) -> Result<Vec<u8>> {
        Ok(self.key.sign(algorithm.scheme(), digest)?)
    }
}

/// Encodes the modulus with the Montgomery constants libavb verifies with.
fn encode_public_key(n: &BigUint) -> Vec<u8> {
    let bits = n.bits();
    let bytes = bits / 8;
    let n_low = n.to_bytes_le();
    let n0 = u32::from_le_bytes(std::array::from_fn(|i| *n_low.get(i).unwrap_or(&0)));
    // Newton iteration for n0^-1 mod 2^32 (n is odd).
    let mut inverse: u32 = 1;
    for _ in 0..5 {
        inverse = inverse.wrapping_mul(2u32.wrapping_sub(n0.wrapping_mul(inverse)));
    }
    let n0inv = 0u32.wrapping_sub(inverse);
    let rr = (BigUint::from(1u8) << (2 * bits)) % n;
    let mut out = Vec::with_capacity(8 + 2 * bytes);
    out.extend_from_slice(&(bits as u32).to_be_bytes());
    out.extend_from_slice(&n0inv.to_be_bytes());
    out.extend_from_slice(&left_pad(&n.to_bytes_be(), bytes));
    out.extend_from_slice(&left_pad(&rr.to_bytes_be(), bytes));
    out
}

fn left_pad(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0; len - bytes.len()];
    out.extend_from_slice(bytes);
    out
}

pub(super) fn decode_public_key(blob: &[u8]) -> Result<RsaPublicKey> {
    slice(blob, 0, 8, "AVB public key header")?;
    let bytes = be32(blob, 0) as usize / 8;
    let n = slice(blob, 8, bytes as u64, "AVB public key modulus")?;
    // The default limit is 4096 bits; AVB also uses 8192-bit keys.
    Ok(RsaPublicKey::new_with_max_size(
        BigUint::from_bytes_be(n),
        BigUint::from(65537u32),
        8192,
    )?)
}

/// Names the AOSP test key matching `public_key`, if any.
pub fn known_key(public_key: &[u8]) -> Option<String> {
    TEST_KEYS.iter().find_map(|(bits, _)| {
        let key = Key::test_key(*bits).ok()?;
        (key.avb_public_key() == public_key).then(|| format!("AOSP testkey_rsa{bits}"))
    })
}

/// Selects the key for re-signing metadata that used `algorithm`: the user's
/// key, else the AOSP test key of the size the original key had.
pub fn signing_key(algorithm: Algorithm, user_key: Option<&Path>) -> Result<Option<Key>> {
    if algorithm == Algorithm::NONE {
        return Ok(None);
    }
    Ok(Some(match user_key {
        Some(path) => Key::load(path)?,
        None => Key::test_key(algorithm.key_bits())?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn public_keys_encode_like_avbtool_extract_public_key() {
        // sha256sum of `avbtool extract_public_key --key keys/testkey_rsa<bits>.pem`.
        for (bits, expected) in [
            (
                2048,
                "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c",
            ),
            (
                4096,
                "7728e30f50bfa5cea165f473175a08803f6a8346642b5aa10913e9d9e6defef6",
            ),
            (
                8192,
                "e15e2365469ce672a91d02cc8d9c2f29b787481e574d3b56ac774153d7ced614",
            ),
        ] {
            let encoded = Key::test_key(bits).unwrap().avb_public_key();
            let digest: String = Sha256::digest(&encoded)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(digest, expected, "testkey_rsa{bits}");
            assert_eq!(decode_public_key(&encoded).unwrap().size() * 8, bits);
        }
    }
}
