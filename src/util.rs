use crate::{Error, Result};

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
        _ => Err(Error::Truncated {
            what: what.to_string(),
            offset,
            len,
            size: data.len() as u64,
        }),
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
        return Err(too_long(what, text.len(), out.len()));
    }
    out.fill(0);
    out[..text.len()].copy_from_slice(text.as_bytes());
    Ok(())
}

pub fn too_long(what: &str, len: usize, max: usize) -> Error {
    Error::TooLong {
        what: what.to_string(),
        len: len as u64,
        max: max as u64,
    }
}

pub mod hex {
    use crate::{Error, Result};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn decode(text: &str) -> Result<Vec<u8>> {
        if !text.len().is_multiple_of(2) {
            return Err(Error::invalid("hex string", text));
        }
        (0..text.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&text[i..i + 2], 16)
                    .map_err(|_| Error::invalid("hex string", text))
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

/// Serializes a u32 as a `0x`-prefixed hex string, accepting decimal or hex on input.
pub mod hex32 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u32, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{value:#010x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
        super::parse_number::<D, u32>(deserializer)
    }
}

pub mod hex64 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{value:#x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        super::parse_number::<D, u64>(deserializer)
    }
}

fn parse_number<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: TryFrom<u64>,
{
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Number {
        Int(u64),
        Text(String),
    }
    let value = match Number::deserialize(deserializer)? {
        Number::Int(value) => value,
        Number::Text(text) => {
            let text = text.trim();
            let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                Some(digits) => u64::from_str_radix(digits, 16),
                None => text.parse(),
            };
            parsed.map_err(|_| serde::de::Error::custom(format!("invalid number {text:?}")))?
        }
    };
    T::try_from(value).map_err(|_| serde::de::Error::custom(format!("{value:#x} is out of range")))
}
