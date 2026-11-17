use std::{
    io,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Image(#[from] bootimg::Error),
    #[error("cannot access {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid {path}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("{0} is not a bootimg workspace")]
    NotAWorkspace(PathBuf),
    #[error("{0} already exists; use --force to replace a previous workspace")]
    WorkspaceExists(PathBuf),
    #[error("a vbmeta image with an AVB footer")]
    FooterOnVbmeta,
    #[error("invalid --vbmeta image {path}")]
    VbmetaImage {
        path: PathBuf,
        #[source]
        source: bootimg::Error,
    },
    #[error("--vbmeta needs an image with an AVB hash footer to take the hash from")]
    NoFooterForVbmeta,
    #[error("both {0} and {1} were changed; keep only one of the edits")]
    ConflictingEdits(String, String),
    #[error("{0} was deleted")]
    Deleted(String),
    #[error("{0} is missing")]
    Missing(String),
    #[error("archive path {0:?} escapes the ramdisk root")]
    EscapingPath(String),
    #[error("{0} has a non-UTF-8 name")]
    NonUtf8Path(PathBuf),
    #[error("{0} is not a file, directory or symlink, which is all a ramdisk tree may hold")]
    SpecialFile(PathBuf),
    #[error("cannot run dtc")]
    RunDtc(#[source] io::Error),
    #[error("dtc failed:\n{0}")]
    Dtc(String),
}

/// An I/O result with the path it was about attached to its error.
pub trait IoAt<T> {
    fn at(self, path: impl AsRef<Path>) -> Result<T>;
}

impl<T> IoAt<T> for io::Result<T> {
    fn at(self, path: impl AsRef<Path>) -> Result<T> {
        self.map_err(|source| Error::Io {
            path: path.as_ref().to_path_buf(),
            source,
        })
    }
}

/// An error and its causes, joined like `cannot access x: No such file`.
pub fn report(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text = format!("{text}: {cause}");
        source = cause.source();
    }
    text
}
