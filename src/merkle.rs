//! Merkle tree over transactions with inclusion proofs. No external crates.
//!
//! Leaves are hashed with a leaf-domain tag and internal nodes with a node-domain
//! tag, which prevents second-preimage attacks that swap a leaf for an internal
//! node. When a level has an odd number of nodes the last node is duplicated,
//! the same rule used by Bitcoin. The root of an empty transaction list is
//! defined as 32 zero bytes.

use crate::sha256::Sha256;

const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;

pub const EMPTY_ROOT: [u8; 32] = [0u8; 32];

/// Hash a leaf value with the leaf-domain tag.
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&[LEAF_TAG]);
    h.update(data);
    h.finalize()
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&[NODE_TAG]);
    h.update(left);
    h.update(right);
    h.finalize()
}

/// Compute the Merkle root over a list of already-hashed leaves.
pub fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return EMPTY_ROOT;
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        if let Some(&last) = level.last() {
            if !level.len().is_multiple_of(2) {
                level.push(last);
            }
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(hash_node(&pair[0], &pair[1]));
        }
        level = next;
    }
    level[0]
}

/// An inclusion proof: sibling hashes bottom-up, each tagged with its side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub index: usize,
    /// Tuple of (sibling hash, sibling is on the right).
    pub siblings: Vec<([u8; 32], bool)>,
}

/// Build an inclusion proof for the leaf at `index`.
pub fn prove(leaves: &[[u8; 32]], index: usize) -> Option<Proof> {
    if index >= leaves.len() {
        return None;
    }
    let mut level = leaves.to_vec();
    let mut idx = index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        if let Some(&last) = level.last() {
            if !level.len().is_multiple_of(2) {
                level.push(last);
            }
        }
        let (sib_idx, sib_is_right) = if idx.is_multiple_of(2) {
            (idx + 1, true)
        } else {
            (idx - 1, false)
        };
        siblings.push((level[sib_idx], sib_is_right));
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(hash_node(&pair[0], &pair[1]));
        }
        level = next;
        idx /= 2;
    }
    Some(Proof { index, siblings })
}

/// Verify an inclusion proof: does `leaf` sit at `proof.index` under `root`?
pub fn verify(root_hash: &[u8; 32], leaf: &[u8; 32], proof: &Proof) -> bool {
    let mut node = *leaf;
    for (sibling, sib_is_right) in &proof.siblings {
        node = if *sib_is_right {
            hash_node(&node, sibling)
        } else {
            hash_node(sibling, &node)
        };
    }
    &node == root_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| hash_leaf(&(i as u64).to_le_bytes()))
            .collect()
    }

    #[test]
    fn empty_root_is_zero() {
        assert_eq!(root(&[]), EMPTY_ROOT);
    }

    #[test]
    fn single_leaf_proof() {
        let ls = leaves(1);
        let r = root(&ls);
        assert_eq!(r, ls[0]); // size-1 root is the leaf itself
        let p = prove(&ls, 0).unwrap();
        assert!(verify(&r, &ls[0], &p));
    }

    #[test]
    fn included_proof_verifies_all_sizes() {
        for n in 1..=17usize {
            let ls = leaves(n);
            let r = root(&ls);
            for i in 0..n {
                let p = prove(&ls, i).unwrap();
                assert!(verify(&r, &ls[i], &p), "size {n} index {i}");
            }
        }
    }

    #[test]
    fn non_included_leaf_fails() {
        let ls = leaves(6);
        let r = root(&ls);
        let outsider = hash_leaf(b"not in the tree");
        let p = prove(&ls, 2).unwrap();
        assert!(!verify(&r, &outsider, &p));
    }

    #[test]
    fn wrong_index_proof_fails() {
        let ls = leaves(7);
        let r = root(&ls);
        // Prove index 3 but present leaf 4.
        let p = prove(&ls, 3).unwrap();
        assert!(!verify(&r, &ls[4], &p));
    }

    #[test]
    fn out_of_range_proof_is_none() {
        let ls = leaves(4);
        assert!(prove(&ls, 4).is_none());
    }
}
