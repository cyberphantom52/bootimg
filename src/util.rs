use anyhow::{Result, bail};

pub fn align(value: u64, to: u64) -> u64 {
    value.div_ceil(to) * to
}

/// Appends `data` and zero-pads `out` to a multiple of `page`.
pub fn push_padded(out: &mut Vec<u8>, data: &[u8], page: usize) {
    out.extend_from_slice(data);
    out.resize(align(out.len() as u64, page as u64) as usize, 0);
}

pub fn le32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

pub fn le64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

pub fn be32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
}

pub fn be64(data: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap())
}

/// Reads `len` bytes at `offset`, failing with a readable message instead of panicking.
pub fn slice<'a>(data: &'a [u8], offset: u64, len: u64, what: &str) -> Result<&'a [u8]> {
    match offset.checked_add(len) {
        Some(end) if end <= data.len() as u64 => Ok(&data[offset as usize..end as usize]),
        _ => bail!(
            "{what} ({len} bytes at offset {offset}) extends past the end of the image ({} bytes)",
            data.len()
        ),
    }
}

/// Decodes a NUL-terminated fixed-size string field.
pub fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Encodes `text` into a fixed-size NUL-padded field.
pub fn put_cstr(out: &mut [u8], text: &str, what: &str) -> Result<()> {
    if text.len() > out.len() {
        bail!("{what} is {} bytes; at most {} fit", text.len(), out.len());
    }
    out.fill(0);
    out[..text.len()].copy_from_slice(text.as_bytes());
    Ok(())
}

pub mod hex {
    use anyhow::{Result, bail};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn decode(text: &str) -> Result<Vec<u8>> {
        if !text.len().is_multiple_of(2) {
            bail!("hex string has an odd number of digits");
        }
        (0..text.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&text[i..i + 2], 16)
                    .map_err(|_| anyhow::anyhow!("invalid hex string {text:?}"))
            })
            .collect()
    }

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        decode(&text).map_err(serde::de::Error::custom)
    }
}
