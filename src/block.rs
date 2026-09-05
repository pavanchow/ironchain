//! Blocks, headers, and proof of work. No external crates.
//!
//! Difficulty is expressed as a number of required leading zero bits in the
//! double-SHA-256 block hash. A block is valid under proof of work when its hash
//! has at least `difficulty_bits` leading zero bits. Cumulative work for fork
//! choice is `2^difficulty_bits` summed over a chain, which is the expected
//! number of hashes needed to build it.

use crate::merkle;
use crate::sha256::sha256d;
use crate::tx::Transaction;

pub type Address = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub parent_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u64,
    pub difficulty_bits: u32,
    pub miner: Address,
    pub nonce: u64,
}

impl Header {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(32 + 32 + 8 + 4 + 32 + 8);
        b.extend_from_slice(&self.parent_hash);
        b.extend_from_slice(&self.merkle_root);
        b.extend_from_slice(&self.timestamp.to_le_bytes());
        b.extend_from_slice(&self.difficulty_bits.to_le_bytes());
        b.extend_from_slice(&self.miner);
        b.extend_from_slice(&self.nonce.to_le_bytes());
        b
    }

    /// The block hash: double SHA-256 of the serialized header.
    pub fn hash(&self) -> [u8; 32] {
        sha256d(&self.to_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: Header,
    pub transactions: Vec<Transaction>,
}

/// Count the number of leading zero bits in a 32-byte hash.
pub fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut count = 0;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Does the hash satisfy the target difficulty?
pub fn meets_target(hash: &[u8; 32], difficulty_bits: u32) -> bool {
    leading_zero_bits(hash) >= difficulty_bits
}

/// Expected work to produce a block of the given difficulty.
pub fn block_work(difficulty_bits: u32) -> u128 {
    1u128 << difficulty_bits
}

impl Block {
    /// Recompute the Merkle root over this block's transactions.
    pub fn compute_merkle_root(&self) -> [u8; 32] {
        let leaves: Vec<[u8; 32]> = self
            .transactions
            .iter()
            .map(|t| merkle::hash_leaf(&t.to_bytes()))
            .collect();
        merkle::root(&leaves)
    }

    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }

    /// True when the stored Merkle root matches the transactions.
    pub fn merkle_root_valid(&self) -> bool {
        self.header.merkle_root == self.compute_merkle_root()
    }

    /// True when the header hash satisfies the header's own difficulty.
    pub fn pow_valid(&self) -> bool {
        meets_target(&self.hash(), self.header.difficulty_bits)
    }
}

/// Mine: search nonces until the header hash meets its difficulty. Returns the
/// number of attempts made. The header's `nonce` is updated in place.
pub fn mine(header: &mut Header) -> u64 {
    let mut attempts: u64 = 0;
    loop {
        attempts += 1;
        if meets_target(&header.hash(), header.difficulty_bits) {
            return attempts;
        }
        header.nonce = header.nonce.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zeros_counts() {
        let mut h = [0u8; 32];
        assert_eq!(leading_zero_bits(&h), 256);
        h[0] = 0xff;
        assert_eq!(leading_zero_bits(&h), 0);
        h[0] = 0x00;
        h[1] = 0x0f;
        assert_eq!(leading_zero_bits(&h), 12);
    }

    #[test]
    fn mining_finds_valid_nonce() {
        let mut header = Header {
            parent_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1,
            difficulty_bits: 10,
            miner: [1u8; 32],
            nonce: 0,
        };
        let attempts = mine(&mut header);
        assert!(meets_target(&header.hash(), header.difficulty_bits));
        assert!(attempts >= 1);
    }
}
