//! Device trees in a workspace: the raw blob plus one decompiled source per
//! tree (`dtb.dts`, or `dtb.N.dts` for a blob holding several).

use anyhow::{Result, ensure};

use super::Workspace;
use crate::{dtb, dtc};

impl Workspace {
    fn dts_names(raw: &str, count: usize) -> Vec<String> {
        let stem = raw.strip_suffix(".dtb").unwrap_or(raw);
        if count == 1 {
            return vec![format!("{stem}.dts")];
        }
        (0..count).map(|i| format!("{stem}.{i}.dts")).collect()
    }

    pub(super) fn unpack_dtb(&mut self, raw: &str, data: &[u8]) -> Result<String> {
        self.write(raw, data)?;
        let trees = dtb::split(data);
        let names = Self::dts_names(raw, trees.len());
        let mut decompiled = 0;
        for (tree, name) in trees.iter().zip(&names) {
            match dtc::decompile(&data[tree.clone()]) {
                Ok(dts) => {
                    self.write(name, dts.as_bytes())?;
                    decompiled += 1;
                }
                Err(error) => eprintln!("warning: not decompiling {name}: {error:#}"),
            }
        }
        Ok(match decompiled {
            0 => raw.to_string(),
            1 => format!("{raw} -> {}", names[0]),
            n => format!("{raw} -> {n} trees ({})", names.join(", ")),
        })
    }

    /// The blob to pack: the raw file if it was replaced, otherwise the
    /// original with edited sources compiled in place of their trees.
    pub(super) fn pack_dtb(&self, raw: &str) -> Result<Option<Vec<u8>>> {
        if !self.exists(raw) {
            ensure!(!self.recorded(raw), "{raw} was deleted");
            return Ok(None);
        }
        let data = self.read(raw)?;
        if self.recorded(raw) && self.changed(raw)? {
            let stem = raw.strip_suffix(".dtb").unwrap_or(raw);
            for name in self.state.hashes.keys() {
                let source = name
                    .strip_prefix(stem)
                    .and_then(|rest| rest.strip_suffix(".dts"));
                let ours = source.is_some_and(|rest| {
                    rest.is_empty()
                        || rest
                            .strip_prefix('.')
                            .is_some_and(|n| n.parse::<usize>().is_ok())
                });
                ensure!(
                    !ours || !self.exists(name) || !self.changed(name)?,
                    "both {raw} and {name} were changed; keep only one of the edits"
                );
            }
            return Ok(Some(data));
        }
        let trees = dtb::split(&data);
        let names = Self::dts_names(raw, trees.len());
        let mut edited = false;
        let mut replacements = Vec::new();
        for (tree, name) in trees.iter().zip(&names) {
            if self.recorded(name) && self.exists(name) && self.changed(name)? {
                say!("Compiling {name}");
                replacements.push(dtc::compile(&self.path(name))?);
                edited = true;
            } else {
                replacements.push(data[tree.clone()].to_vec());
            }
        }
        Ok(Some(if edited {
            dtb::splice(&data, &trees, &replacements)
        } else {
            data
        }))
    }
}
