use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
};

use super::{EntryMeta, Metadata, host_mode, host_path, is_special};
use crate::cli::{Error, IoAt, Result};
use bootimgctl::cpio::{Entry, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};

/// Every path under `root`, parents before children, in sorted order.
fn walk(root: &Path) -> Result<Vec<(String, fs::Metadata)>> {
    fn visit(root: &Path, relative: &str, out: &mut Vec<(String, fs::Metadata)>) -> Result<()> {
        let directory = if relative.is_empty() {
            root.to_path_buf()
        } else {
            root.join(relative)
        };
        let mut names: Vec<_> = fs::read_dir(&directory)
            .at(&directory)?
            .map(|entry| Ok(entry.at(&directory)?.file_name()))
            .collect::<Result<_>>()?;
        names.sort();
        for name in names {
            let name = name
                .into_string()
                .map_err(|name| Error::NonUtf8Path(directory.join(name)))?;
            let path = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            let metadata = fs::symlink_metadata(root.join(&path)).at(root.join(&path))?;
            let is_dir = metadata.is_dir();
            out.push((path.clone(), metadata));
            if is_dir {
                visit(root, &path, out)?;
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    visit(root, "", &mut out)?;
    Ok(out)
}

fn host_type(path: &Path, metadata: &fs::Metadata) -> Result<u32> {
    let kind = metadata.file_type();
    Ok(if kind.is_dir() {
        S_IFDIR
    } else if kind.is_symlink() {
        S_IFLNK
    } else if kind.is_file() {
        S_IFREG
    } else {
        return Err(Error::SpecialFile(path.to_path_buf()));
    })
}

fn contents(root: &Path, path: &str, kind: u32) -> Result<Vec<u8>> {
    let full = root.join(path);
    Ok(match kind {
        S_IFREG => fs::read(&full).at(&full)?,
        S_IFLNK => fs::read_link(&full)
            .at(&full)?
            .into_os_string()
            .into_encoded_bytes(),
        _ => Vec::new(),
    })
}

/// Rebuilds the archive entries from the tree at `root` and its metadata.
///
/// Recorded entries keep their order and metadata; new paths follow in
/// sorted order. A recorded entry whose host permissions differ from those
/// it was extracted with takes the host's (it was chmod'ed).
pub fn rebuild(root: &Path, metadata: &Metadata) -> Result<Vec<Entry>> {
    let walked = walk(root)?;
    let host: HashMap<&str, &fs::Metadata> = walked.iter().map(|(p, m)| (p.as_str(), m)).collect();
    let mut order: Vec<(String, Option<&EntryMeta>)> = Vec::new();
    let mut emitted = HashSet::new();
    for meta in &metadata.entries {
        let path = host_path(&meta.path)?.unwrap_or_default();
        if (path.is_empty() || is_special(meta.mode) || host.contains_key(path.as_str()))
            && emitted.insert(path.clone())
        {
            order.push((path, Some(meta)));
        }
    }
    for (path, _) in &walked {
        if emitted.insert(path.clone()) {
            order.push((path.clone(), None));
        }
    }

    let mut entries = Vec::with_capacity(order.len());
    for (index, (path, meta)) in order.into_iter().enumerate() {
        let host = host.get(path.as_str());
        let (mode, uid, gid, mtime, rdev, name) = match (meta, host) {
            // The archive root and device nodes have no host file.
            (Some(meta), None) => (
                meta.mode,
                meta.uid,
                meta.gid,
                meta.mtime,
                meta.rdev,
                meta.path.clone(),
            ),
            (Some(meta), Some(host)) => {
                let kind = host_type(&root.join(&path), host)?;
                let host_permissions = host.permissions().mode() & 0o777;
                let mode = if kind != meta.mode & S_IFMT {
                    kind | host_permissions
                } else if host_permissions == host_mode(meta.mode) & 0o777 {
                    meta.mode
                } else {
                    kind | host_permissions
                };
                (
                    mode,
                    meta.uid,
                    meta.gid,
                    meta.mtime,
                    None,
                    meta.path.clone(),
                )
            }
            (None, Some(host)) => {
                let kind = host_type(&root.join(&path), host)?;
                let executable = host.permissions().mode() & 0o111 != 0;
                let permissions = if kind == S_IFLNK {
                    0o777
                } else if kind == S_IFDIR || executable {
                    0o755
                } else {
                    0o644
                };
                (kind | permissions, 0, 0, 0, None, path.clone())
            }
            (None, None) => unreachable!(),
        };
        let [rdev_major, rdev_minor] = rdev.unwrap_or_default();
        entries.push(Entry {
            name,
            ino: 300000 + index as u32,
            mode,
            uid,
            gid,
            nlink: 1,
            mtime,
            rdev_major,
            rdev_minor,
            data: contents(root, &path, mode & S_IFMT)?,
            ..Default::default()
        });
    }
    Ok(entries)
}

/// A digest of names, types, permissions and contents, for detecting edits.
pub fn tree_digest(root: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    for (path, metadata) in walk(root)? {
        let kind = host_type(&root.join(&path), &metadata)?;
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update((kind | metadata.permissions().mode() & 0o7777).to_le_bytes());
        hasher.update(Sha256::digest(contents(root, &path, kind)?));
    }
    Ok(crate::cli::hex(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ramdisk::extract::extract;
    use bootimgctl::compress::Compression;

    #[test]
    fn rebuilding_keeps_recorded_metadata_and_picks_up_edits() {
        let entry = |name: &str, mode: u32, uid: u32, data: &[u8]| Entry {
            name: name.into(),
            mode,
            uid,
            nlink: 1,
            data: data.to_vec(),
            ..Default::default()
        };
        let original = vec![
            entry("system", S_IFDIR | 0o755, 0, b""),
            entry("system/bin", S_IFDIR | 0o751, 2000, b""),
            entry("init", S_IFREG | 0o4750, 0, b"init"),
            entry("dev", S_IFDIR | 0o755, 0, b""),
            Entry {
                rdev_major: 5,
                rdev_minor: 1,
                ..entry("dev/console", 0o020600, 0, b"")
            },
            entry("old", S_IFREG | 0o644, 0, b"gone"),
        ];
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let metadata = Metadata {
            compression: Compression::None,
            entries: extract(original.clone(), &root).unwrap(),
        };
        let before = tree_digest(&root).unwrap();

        let unchanged = rebuild(&root, &metadata).unwrap();
        let strip = |e: &Entry| (e.name.clone(), e.mode, e.uid, e.rdev_major, e.data.clone());
        assert_eq!(
            unchanged.iter().map(strip).collect::<Vec<_>>(),
            original.iter().map(strip).collect::<Vec<_>>()
        );

        fs::remove_file(root.join("old")).unwrap();
        fs::write(root.join("system/bin/tool"), "#!/bin/sh\n").unwrap();
        fs::set_permissions(
            root.join("system/bin/tool"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(root.join("system"), fs::Permissions::from_mode(0o750)).unwrap();
        assert_ne!(tree_digest(&root).unwrap(), before);

        let edited = rebuild(&root, &metadata).unwrap();
        let names: Vec<_> = edited.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "system",
                "system/bin",
                "init",
                "dev",
                "dev/console",
                "system/bin/tool"
            ]
        );
        assert_eq!(edited[0].mode, S_IFDIR | 0o750, "chmod is picked up");
        assert_eq!(edited[2].mode, S_IFREG | 0o4750, "setuid survives");
        assert_eq!((edited[5].mode, edited[5].uid), (S_IFREG | 0o755, 0));
    }
}
