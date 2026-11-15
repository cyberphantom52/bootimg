//! Flattened device tree blobs, which may hold several concatenated trees.

use std::ops::Range;

use crate::util::be32;

pub const FDT_MAGIC: [u8; 4] = [0xd0, 0x0d, 0xfe, 0xed];

/// Locates the trees in a (possibly concatenated) DTB blob, skipping any padding
/// or unrecognized bytes between them.
pub fn split(data: &[u8]) -> Vec<Range<usize>> {
    let mut trees = Vec::new();
    let mut offset = 0;
    while let Some(found) = data[offset..].windows(4).position(|w| w == FDT_MAGIC) {
        let start = offset + found;
        let size = data.get(start + 4..start + 8).map(|s| be32(s, 0) as usize);
        match size {
            Some(size) if size >= 40 && start + size <= data.len() => {
                trees.push(start..start + size);
                offset = start + size;
            }
            _ => offset = start + 4,
        }
    }
    trees
}

/// Replaces trees in `original`, keeping everything between and around them.
pub fn splice(original: &[u8], trees: &[Range<usize>], replacements: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(original.len());
    let mut offset = 0;
    for (range, tree) in trees.iter().zip(replacements) {
        out.extend_from_slice(&original[offset..range.start]);
        out.extend_from_slice(tree);
        offset = range.end;
    }
    out.extend_from_slice(&original[offset..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(fill: u8) -> Vec<u8> {
        let mut tree = FDT_MAGIC.to_vec();
        tree.extend_from_slice(&48u32.to_be_bytes());
        tree.resize(48, fill);
        tree
    }

    #[test]
    fn bundles_split_and_splice_keeping_padding() {
        let original = [tree(1), vec![0; 8], tree(2), vec![0xff; 3]].concat();
        let trees = split(&original);
        assert_eq!(trees, [0..48, 56..104]);
        assert_eq!(splice(&original, &trees, &[tree(1), tree(2)]), original);
        let edited = splice(&original, &trees, &[tree(1), tree(9)]);
        assert_eq!(&edited[56..104], tree(9));
        assert_eq!(edited.len(), original.len());
    }
}
