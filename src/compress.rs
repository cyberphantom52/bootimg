//! Ramdisk compression formats, detected by magic and re-encoded with the same settings.

use anyhow::{Context, Result, bail};
use liblzma::stream::{Check, LzmaOptions, Stream};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    None,
    Gzip,
    /// `lz4 -l`: the legacy format the kernel's initramfs decompressor reads.
    Lz4Legacy,
    Lz4Frame,
    Xz {
        check: XzCheck,
    },
    Lzma,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XzCheck {
    None,
    Crc32,
    Crc64,
    Sha256,
}

const LZ4_LEGACY_MAGIC: [u8; 4] = [0x02, 0x21, 0x4c, 0x18];
const LZ4_LEGACY_BLOCK: usize = 8 << 20;

impl Compression {
    pub fn detect(data: &[u8]) -> Option<Self> {
        Some(match data {
            [0x1f, 0x8b, ..] => Self::Gzip,
            [0x02, 0x21, 0x4c, 0x18, ..] => Self::Lz4Legacy,
            [0x04, 0x22, 0x4d, 0x18, ..] => Self::Lz4Frame,
            [0xfd, b'7', b'z', b'X', b'Z', 0, _, check, ..] => Self::Xz {
                check: match check & 0x0f {
                    0 => XzCheck::None,
                    1 => XzCheck::Crc32,
                    4 => XzCheck::Crc64,
                    10 => XzCheck::Sha256,
                    _ => return None,
                },
            },
            // LZMA-alone: properties byte (0x5d for every preset) and a dictionary size.
            [0x5d, 0, 0, ..] => Self::Lzma,
            [b'0', b'7', b'0', b'7', b'0', b'1' | b'2', ..] => Self::None,
            _ => return None,
        })
    }

    pub fn decompress(self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::None => out.extend_from_slice(data),
            Self::Gzip => {
                // Concatenated members, possibly followed by zero padding.
                let mut input = data;
                loop {
                    let mut decoder = flate2::bufread::GzDecoder::new(input);
                    decoder.read_to_end(&mut out)?;
                    input = decoder.into_inner();
                    let next = input.iter().position(|&b| b != 0).unwrap_or(input.len());
                    input = &input[next..];
                    if !input.starts_with(&[0x1f, 0x8b]) {
                        break;
                    }
                }
            }
            Self::Lz4Legacy => {
                let mut input = &data[4..];
                let mut block = vec![0; LZ4_LEGACY_BLOCK];
                // Blocks until EOF, a zero size or trailing padding; repeated magic
                // numbers start concatenated streams.
                while input.len() >= 4 {
                    let magic = input[..4] == LZ4_LEGACY_MAGIC;
                    let size = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
                    input = &input[4..];
                    if magic {
                        continue;
                    }
                    if size == 0 || size > input.len() {
                        break;
                    }
                    let len = lz4::block::decompress_to_buffer(
                        &input[..size],
                        Some(LZ4_LEGACY_BLOCK as i32),
                        &mut block,
                    )?;
                    out.extend_from_slice(&block[..len]);
                    input = &input[size..];
                }
            }
            Self::Lz4Frame => {
                lz4::Decoder::new(data)?.read_to_end(&mut out)?;
            }
            Self::Xz { .. } => {
                liblzma::read::XzDecoder::new_multi_decoder(data).read_to_end(&mut out)?;
            }
            Self::Lzma => {
                let stream = Stream::new_lzma_decoder(u64::MAX)?;
                liblzma::read::XzDecoder::new_stream(data, stream).read_to_end(&mut out)?;
            }
        }
        Ok(out)
    }

    pub fn compress(self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(match self {
            Self::None => data.to_vec(),
            Self::Gzip => {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
                encoder.write_all(data)?;
                encoder.finish()?
            }
            Self::Lz4Legacy => {
                let mut out = LZ4_LEGACY_MAGIC.to_vec();
                for chunk in data.chunks(LZ4_LEGACY_BLOCK) {
                    let block = lz4::block::compress(
                        chunk,
                        Some(lz4::block::CompressionMode::HIGHCOMPRESSION(12)),
                        false,
                    )?;
                    out.extend_from_slice(&(block.len() as u32).to_le_bytes());
                    out.extend_from_slice(&block);
                }
                out
            }
            Self::Lz4Frame => {
                let mut encoder = lz4::EncoderBuilder::new().level(12).build(Vec::new())?;
                encoder.write_all(data)?;
                let (out, result) = encoder.finish();
                result?;
                out
            }
            Self::Xz { check } => {
                let check = match check {
                    XzCheck::None => Check::None,
                    XzCheck::Crc32 => Check::Crc32,
                    XzCheck::Crc64 => Check::Crc64,
                    XzCheck::Sha256 => Check::Sha256,
                };
                let stream = Stream::new_easy_encoder(6, check)?;
                encode_stream(stream, data)?
            }
            Self::Lzma => encode_stream(
                Stream::new_lzma_encoder(&LzmaOptions::new_preset(6)?)?,
                data,
            )?,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::None => "uncompressed",
            Self::Gzip => "gzip",
            Self::Lz4Legacy => "lz4 (legacy)",
            Self::Lz4Frame => "lz4",
            Self::Xz { .. } => "xz",
            Self::Lzma => "lzma",
        }
    }
}

fn encode_stream(stream: Stream, data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = liblzma::write::XzEncoder::new_stream(Vec::new(), stream);
    encoder.write_all(data)?;
    encoder.finish().context("compressing ramdisk")
}

/// Decompresses `data` if it is in a known format.
pub fn detect_and_decompress(data: &[u8]) -> Result<(Compression, Vec<u8>)> {
    let Some(compression) = Compression::detect(data) else {
        bail!("unrecognized compression format");
    };
    Ok((compression, compression.decompress(data)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_format_round_trips_and_is_detected() {
        let data: Vec<u8> = (0..(LZ4_LEGACY_BLOCK as u32 + 5000))
            .map(|i| (i % 251) as u8 ^ (i / 7919) as u8)
            .collect();
        let mut cpio = b"070701".to_vec();
        cpio.extend_from_slice(&data);
        for compression in [
            Compression::None,
            Compression::Gzip,
            Compression::Lz4Legacy,
            Compression::Lz4Frame,
            Compression::Xz {
                check: XzCheck::Crc32,
            },
            Compression::Lzma,
        ] {
            let packed = compression.compress(&cpio).unwrap();
            assert_eq!(Compression::detect(&packed), Some(compression));
            assert_eq!(
                compression.decompress(&packed).unwrap(),
                cpio,
                "{compression:?}"
            );
        }
    }

    #[test]
    fn concatenated_streams_decode_like_the_kernel() {
        for compression in [Compression::Gzip, Compression::Lz4Legacy] {
            let mut packed = compression.compress(b"first ").unwrap();
            packed.extend(compression.compress(b"second").unwrap());
            packed.extend([0; 16]);
            assert_eq!(compression.decompress(&packed).unwrap(), b"first second");
        }
    }
}
