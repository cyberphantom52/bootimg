use anyhow::{Context, Result};
use std::{
    collections::{HashMap, HashSet},
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
};

use super::{EntryMeta, host_mode, host_path, is_special};
use bootimgctl::cpio::{Entry, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};

/// Writes `entries` under `root` (which must not exist) and returns their metadata.
pub fn extract(entries: Vec<Entry>, root: &Path) -> Result<Vec<EntryMeta>> {
    fs::create_dir(root).with_context(|| format!("creating {}", root.display()))?;

    // Hardlinked files carry their data in only one of the links.
    let mut linked: HashMap<u32, Vec<u8>> = HashMap::new();
    for entry in &entries {
        if entry.mode & S_IFMT == S_IFREG && entry.nlink > 1 && !entry.data.is_empty() {
            linked.insert(entry.ino, entry.data.clone());
        }
    }

    let mut metadata: Vec<EntryMeta> = Vec::new();
    let mut positions: HashMap<String, usize> = HashMap::new();
    let mut symlinks: HashSet<String> = HashSet::new();
    let mut directories = Vec::new();
    for entry in entries {
        let path = match host_path(&entry.name) {
            Ok(path) => path,
            Err(error) => {
                eprintln!("warning: skipping {error}");
                continue;
            }
        };
        let meta = EntryMeta {
            path: entry.name.clone(),
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            mtime: entry.mtime,
            rdev: matches!(entry.mode & S_IFMT, 0o020000 | 0o060000)
                .then_some([entry.rdev_major, entry.rdev_minor]),
        };
        let key = path.clone().unwrap_or_default();
        // A repeated path replaces the earlier entry, as when the kernel unpacks it.
        match positions.get(&key) {
            Some(&index) => metadata[index] = meta,
            None => {
                positions.insert(key, metadata.len());
                metadata.push(meta);
            }
        }
        let Some(path) = path else { continue };
        if is_special(entry.mode) {
            continue;
        }
        // Writing through a symlink could land outside the tree.
        if let Some(link) = ancestors(&path).find(|a| symlinks.contains(*a)) {
            eprintln!("warning: not extracting {path:?}: its parent {link:?} is a symlink");
            continue;
        }
        let target = root.join(&path);
        if let Ok(existing) = fs::symlink_metadata(&target) {
            if existing.is_dir() && entry.mode & S_IFMT == S_IFDIR {
                directories.push((target, entry.mode));
                continue;
            }
            if existing.is_dir() {
                fs::remove_dir_all(&target)?;
            } else {
                fs::remove_file(&target)?;
            }
        }
        let context = || format!("extracting {}", target.display());
        match entry.mode & S_IFMT {
            S_IFDIR => {
                fs::create_dir_all(&target).with_context(context)?;
                directories.push((target, entry.mode));
            }
            S_IFLNK => {
                symlink(String::from_utf8_lossy(&entry.data).as_ref(), &target)
                    .with_context(context)?;
                symlinks.insert(path);
            }
            _ => {
                let data = match linked.get(&entry.ino) {
                    Some(data) if entry.nlink > 1 && entry.data.is_empty() => data,
                    _ => &entry.data,
                };
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).with_context(context)?;
                }
                fs::write(&target, data).with_context(context)?;
                fs::set_permissions(&target, fs::Permissions::from_mode(host_mode(entry.mode)))?;
            }
        }
    }
    // Directory modes last, so read-only directories don't block their contents.
    for (path, mode) in directories.into_iter().rev() {
        fs::set_permissions(&path, fs::Permissions::from_mode(host_mode(mode)))?;
    }
    Ok(metadata)
}

fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/').map(|(index, _)| &path[..index])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, mode: u32, data: &[u8]) -> Entry {
        Entry {
            name: name.into(),
            mode,
            nlink: 1,
            data: data.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn extracts_links_and_records_what_the_host_cannot_hold() {
        let link = |name: &str, data: &[u8]| Entry {
            ino: 7,
            nlink: 2,
            ..entry(name, S_IFREG | 0o644, data)
        };
        let entries = vec![
            entry(".", S_IFDIR | 0o755, b""),
            entry("bin", S_IFDIR | 0o751, b""),
            entry("bin/init", S_IFREG | 0o750, b"init"),
            link("bin/a", b""),
            link("bin/b", b"shared"),
            entry("sh", S_IFLNK | 0o777, b"/system/bin/sh"),
            entry("sh/escape", S_IFREG | 0o644, b"x"),
            entry("../escape", S_IFREG | 0o644, b"x"),
            Entry {
                rdev_major: 5,
                rdev_minor: 1,
                ..entry("console", 0o020600, b"")
            },
        ];
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let metadata = extract(entries, &root).unwrap();

        let mode = |path: &str| fs::metadata(root.join(path)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode("bin"), 0o751);
        assert_eq!(mode("bin/init"), 0o750);
        assert_eq!(fs::read(root.join("bin/a")).unwrap(), b"shared");
        assert_eq!(
            fs::read_link(root.join("sh")).unwrap(),
            Path::new("/system/bin/sh")
        );
        assert!(!root.join("console").exists());
        assert!(!tmp.path().join("escape").exists());

        let paths: Vec<_> = metadata.iter().map(|m| m.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                ".",
                "bin",
                "bin/init",
                "bin/a",
                "bin/b",
                "sh",
                "sh/escape",
                "console"
            ]
        );
        assert_eq!(metadata[7].rdev, Some([5, 1]));
    }
}
