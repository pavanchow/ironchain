//! Hash-based digital signatures built only on SHA-256. No external crates.
//!
//! This is a Lamport one-time signature scheme wrapped in a Merkle key tree,
//! an XMSS-style construction. One Lamport key signs one message. The Merkle
//! tree lets a single address (the Merkle root) sign `2^height` times, once per
//! leaf. Because the only primitive is SHA-256 this signature scheme is
//! post-quantum: its security rests on the preimage and collision resistance of
//! the hash, not on any number-theoretic assumption.
//!
//! Message: a 32-byte digest, treated as 256 bits, most-significant bit first
//! within each byte.
//!
//! One-time discipline: reusing a leaf for two different messages leaks secrets
//! and breaks security. The chain enforces this by binding the leaf index to the
//! account nonce, so each index is spent exactly once.

use crate::sha256::sha256;

/// Number of bits in the signed digest.
const MSG_BITS: usize = 256;

const SK_DOMAIN: &[u8] = b"IRONCHAIN-OTS-SK";
const LEAF_DOMAIN: u8 = 0x00;
const NODE_DOMAIN: u8 = 0x01;

/// A hash-based signature: a Lamport signature plus a Merkle authentication path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// Leaf index used to produce this signature.
    pub index: u32,
    /// Revealed secret for each message bit.
    pub reveals: Vec<[u8; 32]>,
    /// Public hash of the unrevealed side for each message bit.
    pub complements: Vec<[u8; 32]>,
    /// Sibling hashes from the leaf up to the root.
    pub auth_path: Vec<[u8; 32]>,
}

/// Derive a single Lamport secret: `SK_DOMAIN || seed || leaf || bit_index || side`.
fn derive_sk(seed: &[u8; 32], leaf: u32, bit_index: usize, side: u8) -> [u8; 32] {
    let mut h = crate::sha256::Sha256::new();
    h.update(SK_DOMAIN);
    h.update(seed);
    h.update(&leaf.to_le_bytes());
    h.update(&(bit_index as u16).to_le_bytes());
    h.update(&[side]);
    h.finalize()
}

/// Compressed Lamport public key for a leaf: hash of all 512 secret-hashes.
fn leaf_public_key(seed: &[u8; 32], leaf: u32) -> [u8; 32] {
    let mut h = crate::sha256::Sha256::new();
    h.update(&[LEAF_DOMAIN]);
    for bit in 0..MSG_BITS {
        for side in 0..2u8 {
            let sk = derive_sk(seed, leaf, bit, side);
            h.update(&sha256(&sk));
        }
    }
    h.finalize()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = crate::sha256::Sha256::new();
    h.update(&[NODE_DOMAIN]);
    h.update(left);
    h.update(right);
    h.finalize()
}

/// Return true if bit `i` of the digest is set (MSB-first within each byte).
fn bit_set(msg: &[u8; 32], i: usize) -> bool {
    (msg[i / 8] >> (7 - (i % 8))) & 1 == 1
}

/// Compute all leaf public keys for a tree of the given height.
fn all_leaves(seed: &[u8; 32], height: u32) -> Vec<[u8; 32]> {
    let count = 1usize << height;
    (0..count as u32).map(|l| leaf_public_key(seed, l)).collect()
}

/// The address for a seed and tree height: the Merkle root over all leaf keys.
pub fn compute_root(seed: &[u8; 32], height: u32) -> [u8; 32] {
    let mut level = all_leaves(seed, height);
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        level = next;
    }
    level[0]
}

/// Build the authentication path (sibling per level) for `index`.
fn auth_path(seed: &[u8; 32], height: u32, index: u32) -> Vec<[u8; 32]> {
    let mut level = all_leaves(seed, height);
    let mut idx = index as usize;
    let mut path = Vec::with_capacity(height as usize);
    while level.len() > 1 {
        let sibling = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
        path.push(level[sibling]);
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        level = next;
        idx /= 2;
    }
    path
}

/// Sign a 32-byte digest with leaf `index` of the key tree at `seed`/`height`.
pub fn sign(seed: &[u8; 32], height: u32, index: u32, msg: &[u8; 32]) -> Signature {
    assert!((index as u64) < (1u64 << height), "leaf index out of range");
    let mut reveals = Vec::with_capacity(MSG_BITS);
    let mut complements = Vec::with_capacity(MSG_BITS);
    for i in 0..MSG_BITS {
        let b = bit_set(msg, i) as u8;
        reveals.push(derive_sk(seed, index, i, b));
        complements.push(sha256(&derive_sk(seed, index, i, 1 - b)));
    }
    Signature {
        index,
        reveals,
        complements,
        auth_path: auth_path(seed, height, index),
    }
}

/// Verify a signature against an address (Merkle root) and a 32-byte digest.
pub fn verify(address: &[u8; 32], msg: &[u8; 32], sig: &Signature) -> bool {
    if sig.reveals.len() != MSG_BITS || sig.complements.len() != MSG_BITS {
        return false;
    }
    let height = sig.auth_path.len() as u32;
    if (sig.index as u64) >= (1u64 << height) {
        return false;
    }

    // Reconstruct the leaf public key from the revealed secrets and complements.
    let mut leaf_hasher = crate::sha256::Sha256::new();
    leaf_hasher.update(&[LEAF_DOMAIN]);
    for i in 0..MSG_BITS {
        let b = bit_set(msg, i) as u8;
        let revealed_pk = sha256(&sig.reveals[i]);
        let (side0, side1) = if b == 0 {
            (revealed_pk, sig.complements[i])
        } else {
            (sig.complements[i], revealed_pk)
        };
        leaf_hasher.update(&side0);
        leaf_hasher.update(&side1);
    }
    let mut node = leaf_hasher.finalize();

    // Fold the authentication path up to the root.
    let mut idx = sig.index as usize;
    for sibling in &sig.auth_path {
        node = if idx.is_multiple_of(2) {
            node_hash(&node, sibling)
        } else {
            node_hash(sibling, &node)
        };
        idx /= 2;
    }
    &node == address
}

impl Signature {
    /// Serialize to bytes: index, sizes, reveals, complements, auth path.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.index.to_le_bytes());
        out.push(self.auth_path.len() as u8);
        for r in &self.reveals {
            out.extend_from_slice(r);
        }
        for c in &self.complements {
            out.extend_from_slice(c);
        }
        for a in &self.auth_path {
            out.extend_from_slice(a);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256::{sha256, to_hex};

    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn round_trip() {
        let s = seed(7);
        let root = compute_root(&s, 3);
        let msg = sha256(b"hello ironchain");
        let sig = sign(&s, 3, 0, &msg);
        assert!(verify(&root, &msg, &sig));
    }

    #[test]
    fn deterministic_address_kat() {
        // Known-answer vector: the address for the all-0x01 seed at height 4 is
        // fixed. Recomputing must give the identical root.
        let s = seed(1);
        let a = compute_root(&s, 4);
        let b = compute_root(&s, 4);
        assert_eq!(a, b);
        assert_eq!(
            to_hex(&a),
            "b982e00dadad0328db976b657ff345652fda3c70377298743380e61c4bad9e80"
        );
    }

    #[test]
    fn flipped_message_bit_fails() {
        let s = seed(9);
        let root = compute_root(&s, 3);
        let msg = sha256(b"pay 10 to bob");
        let sig = sign(&s, 3, 1, &msg);
        assert!(verify(&root, &msg, &sig));
        let mut bad = msg;
        bad[0] ^= 0x01;
        assert!(!verify(&root, &bad, &sig));
    }

    #[test]
    fn flipped_signature_bit_fails() {
        let s = seed(3);
        let root = compute_root(&s, 3);
        let msg = sha256(b"transfer");
        let mut sig = sign(&s, 3, 2, &msg);
        assert!(verify(&root, &msg, &sig));
        sig.reveals[100][0] ^= 0x80;
        assert!(!verify(&root, &msg, &sig));
    }

    #[test]
    fn wrong_index_path_fails() {
        let s = seed(5);
        let root = compute_root(&s, 3);
        let msg = sha256(b"m");
        let mut sig = sign(&s, 3, 0, &msg);
        // Claim a different leaf while keeping leaf-0 material.
        sig.index = 1;
        assert!(!verify(&root, &msg, &sig));
    }

    #[test]
    fn different_leaves_same_address() {
        let s = seed(11);
        let root = compute_root(&s, 3);
        for idx in 0..8u32 {
            let msg = sha256(&idx.to_le_bytes());
            let sig = sign(&s, 3, idx, &msg);
            assert!(verify(&root, &msg, &sig), "leaf {idx} failed");
        }
    }
}
