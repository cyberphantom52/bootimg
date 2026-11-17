use std::{io, path::PathBuf};
use thiserror::Error;

use crate::avb::Algorithm;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not {0}")]
    Format(&'static str),
    #[error("unsupported {what} {value}")]
    Unsupported { what: &'static str, value: String },
    #[error("invalid {what}: {value}")]
    Invalid { what: &'static str, value: String },
    #[error(
        "{what} ({len} bytes at offset {offset}) extends past the end of its data ({size} bytes)"
    )]
    Truncated {
        what: String,
        offset: u64,
        len: u64,
        size: u64,
    },
    #[error("{what} is {len} bytes; at most {max} fit")]
    TooLong { what: String, len: u64, max: u64 },
    #[error(
        "the image ({size} bytes) and its AVB metadata do not fit the {partition_size}-byte partition"
    )]
    PartitionFull { size: u64, partition_size: u64 },
    #[error("unsupported RSA key size {0}; AVB needs 2048, 4096 or 8192 bits")]
    KeySize(usize),
    #[error("signing {0:?} metadata needs a key")]
    NoKey(Algorithm),
    #[error("cannot read key {path}")]
    ReadKey {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{0} is not an RSA private key (PEM or DER)")]
    NotAKey(PathBuf),
    #[error("the AVB metadata has no hash descriptor")]
    NoHashDescriptor,
    #[error("RSA")]
    Rsa(#[from] rsa::Error),
    #[error("cannot compress or decompress {0}")]
    Compression(&'static str, #[source] io::Error),
    #[error("cannot write the image")]
    Write(#[from] io::Error),
}

impl Error {
    pub(crate) fn unsupported(what: &'static str, value: impl ToString) -> Self {
        Self::Unsupported {
            what,
            value: value.to_string(),
        }
    }

    pub(crate) fn invalid(what: &'static str, value: impl ToString) -> Self {
        Self::Invalid {
            what,
            value: value.to_string(),
        }
    }
}
