//! Light-client simplified payment verification (SPV). No external crates.
//!
//! A light client does not store the chain or replay the state. To convince one
//! that a transaction is committed, a full node hands over three things: the
//! block header that contains the transaction, the transaction itself, and a
//! Merkle inclusion proof from the transaction leaf up to the header's committed
//! `merkle_root`. The client then checks two properties locally.
//!
//! 1. Proof of work. The header hash carries `difficulty_bits` leading zero
//!    bits, so producing the header burned on the order of `2^difficulty_bits`
//!    hashes.
//! 2. Inclusion. Folding the transaction's leaf hash with the sibling hashes
//!    reaches exactly the header's `merkle_root`.
//!
//! Because the header commits to the transaction set and the header is
//! work-locked, a fraudulent inclusion claim would require either breaking
//! SHA-256 preimage resistance or re-mining the block, which is the same trust
//! assumption as full validation, at constant client cost.
//!
//! What an SPV proof deliberately does not prove: that the difficulty level is
//! the one consensus requires (checking that needs the full header chain), and
//! that the transaction's inputs were valid (that needs the state). Use
//! [`verify_spv_full`] when the client also wants the transaction's own
//! signature checked.

use crate::block::{meets_target, Block, Header};
use crate::merkle::{self, Proof};
use crate::tx::Transaction;

/// Maximum authentication-path length accepted when deserializing. A Merkle
/// tree over `2^64` leaves is beyond any conceivable block, so 64 bounds the
/// allocation a hostile blob can force.
const MAX_PROOF_HEIGHT: usize = 64;

/// A self-contained proof that `tx` is committed under `header` at `tx_index`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpvProof {
    /// The work-locked header committing to the transaction set.
    pub header: Header,
    /// Position of the transaction inside the block.
    pub tx_index: u64,
    /// Sibling hashes from the leaf to the root, each tagged with its side.
    pub siblings: Vec<([u8; 32], bool)>,
    /// The committed transaction, full serialization included.
    pub tx: Transaction,
}

/// Build an SPV proof for the transaction at `tx_index` of `block`.
pub fn prove_tx(block: &Block, tx_index: usize) -> Option<SpvProof> {
    let leaves: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .map(|t| merkle::hash_leaf(&t.to_bytes()))
        .collect();
    let proof: Proof = merkle::prove(&leaves, tx_index)?;
    #[allow(clippy::cast_possible_truncation)]
    // A block position is bounded by transaction counts far below u64::MAX.
    let tx_index_u64 = tx_index as u64;
    Some(SpvProof {
        header: block.header.clone(),
        tx_index: tx_index_u64,
        siblings: proof.siblings,
        tx: block.transactions[tx_index].clone(),
    })
}

/// Verify an SPV proof: the header must carry valid proof of work at its own
/// claimed difficulty, and the transaction must fold to the header's committed
/// Merkle root.
pub fn verify_spv(proof: &SpvProof) -> bool {
    // 1. Work lock. A header that does not meet its own target commits nothing.
    if !meets_target(&proof.header.hash(), proof.header.difficulty_bits) {
        return false;
    }
    // 2. Inclusion. The leaf is the domain-tagged hash of the full transaction
    //    bytes, exactly the leaf the block's Merkle root was computed over.
    let leaf = merkle::hash_leaf(&proof.tx.to_bytes());
    #[allow(clippy::cast_possible_truncation)]
    // The index only routes the fold; block positions fit usize on every
    // target that can hold the block itself.
    let p = Proof {
        index: proof.tx_index as usize,
        siblings: proof.siblings.clone(),
    };
    merkle::verify(&proof.header.merkle_root, &leaf, &p)
}

/// [`verify_spv`] plus the transaction's own signature check against its
/// claimed sender. A light client that only tracks balances can use this to
/// reject structurally invalid payments without any state.
pub fn verify_spv_full(proof: &SpvProof) -> bool {
    verify_spv(proof) && proof.tx.verify_signature()
}

impl SpvProof {
    /// Compact serialization: header, index, sibling list, then the length
    /// prefixed transaction.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&self.tx_index.to_le_bytes());
        #[allow(clippy::cast_possible_truncation)]
        // Paths are capped at 64 on construction and on parse.
        let count = self.siblings.len() as u32;
        out.extend_from_slice(&count.to_le_bytes());
        for (sibling, is_right) in &self.siblings {
            out.extend_from_slice(sibling);
            out.push(u8::from(*is_right));
        }
        let tx_bytes = self.tx.to_bytes();
        #[allow(clippy::cast_possible_truncation)]
        // A serialized transaction with its 16 KB signature far exceeds the
        // reach of u32 truncation on any target that can hold it.
        let tx_len = tx_bytes.len() as u32;
        out.extend_from_slice(&tx_len.to_le_bytes());
        out.extend_from_slice(&tx_bytes);
        out
    }

    /// Strict inverse of [`SpvProof::to_bytes`]. Returns `None` on truncation,
    /// trailing bytes, an oversized sibling list, or a malformed transaction.
    pub fn from_bytes(bytes: &[u8]) -> Option<SpvProof> {
        use crate::ByteCursor;
        let mut b = bytes;
        let header = Header::from_bytes(b.take(116)?)?;
        let tx_index = u64::from_le_bytes(b.take(8)?.try_into().ok()?);
        let count = u32::from_le_bytes(b.take(4)?.try_into().ok()?) as usize;
        if count > MAX_PROOF_HEIGHT {
            return None;
        }
        let mut siblings = Vec::with_capacity(count);
        for _ in 0..count {
            let sibling = b.take(32)?.try_into().ok()?;
            let flag = b.take(1)?[0];
            if flag > 1 {
                // Canonical encoding: the side flag is a bool, not a number.
                return None;
            }
            siblings.push((sibling, flag == 1));
        }
        #[allow(clippy::cast_possible_truncation)]
        // u32 lengths only truncate on 16-bit targets, which cannot hold the
        // 8 KB of signature data a valid transaction already requires.
        let tx_len = u32::from_le_bytes(b.take(4)?.try_into().ok()?) as usize;
        let tx = Transaction::from_bytes(b.take(tx_len)?)?;
        if !b.is_empty() {
            return None;
        }
        Some(SpvProof {
            header,
            tx_index,
            siblings,
            tx,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{validate_chain, Blockchain, Config};
    use crate::sha256::sha256;
    use crate::sig::compute_root;
    use crate::tx::build_signed;

    const BITS: u32 = 8;

    /// A real mined block carrying two signed transactions, built through the
    /// node so every layer (mempool, selection, mining, connection) runs.
    fn block_with_two_txs() -> (Config, Vec<(crate::tx::Address, u64)>, Block) {
        let cfg = Config {
            genesis_difficulty: BITS,
            subsidy: 50,
            retarget_interval: 0,
            target_spacing: 10,
        };
        let seed = [0xa5u8; 32];
        let alice = compute_root(&seed, 4);
        let mut bc = Blockchain::new(cfg.clone(), vec![(alice, 1000)], 0);
        assert!(bc.submit_tx(build_signed(&seed, 4, alice, [1u8; 32], 10, 1, 0)));
        assert!(bc.submit_tx(build_signed(&seed, 4, alice, [2u8; 32], 20, 2, 1)));
        bc.mine_next([7u8; 32], 10).unwrap();
        let chain = bc.best_chain();
        validate_chain(&cfg, &[(alice, 1000)], &chain).unwrap();
        let blk = chain.last().unwrap().clone();
        assert_eq!(blk.transactions.len(), 2);
        (cfg, vec![(alice, 1000)], blk)
    }

    #[test]
    fn proof_verifies_for_included_tx() {
        let (_cfg, _alloc, blk) = block_with_two_txs();
        for i in 0..blk.transactions.len() {
            let proof = prove_tx(&blk, i).expect("proof for an included tx");
            assert!(verify_spv(&proof), "inclusion must verify at index {i}");
            assert!(verify_spv_full(&proof), "full proof must verify at index {i}");
        }
    }

    #[test]
    fn non_included_tx_fails() {
        let (_cfg, _alloc, blk) = block_with_two_txs();
        let proof = prove_tx(&blk, 0).unwrap();
        // A transaction that was never in the block.
        let mut outsider = proof.tx.clone();
        outsider.to = [0xdeu8; 32];
        outsider.amount = 999;
        outsider.nonce = 42;
        outsider.signature.index = 42;
        let bad = SpvProof {
            header: proof.header.clone(),
            tx_index: proof.tx_index,
            siblings: proof.siblings.clone(),
            tx: outsider,
        };
        assert!(!verify_spv(&bad));
        assert!(!verify_spv_full(&bad));
    }

    #[test]
    fn header_failing_pow_fails() {
        let (_cfg, _alloc, blk) = block_with_two_txs();
        let proof = prove_tx(&blk, 0).unwrap();
        // A nonce that fails the target, keeping everything else honest.
        let mut bad_header = proof.header.clone();
        let bits = bad_header.difficulty_bits;
        let mut cand = 0u64;
        loop {
            bad_header.nonce = cand;
            if !meets_target(&bad_header.hash(), bits) {
                break;
            }
            cand += 1;
        }
        let bad = SpvProof {
            header: bad_header,
            tx_index: proof.tx_index,
            siblings: proof.siblings,
            tx: proof.tx,
        };
        assert!(!verify_spv(&bad));
    }

    #[test]
    fn tampered_sibling_or_tx_fails() {
        let (_cfg, _alloc, blk) = block_with_two_txs();
        let proof = prove_tx(&blk, 1).unwrap();

        let mut bad_sib = proof.clone();
        bad_sib.siblings[0].0[3] ^= 0x10;
        assert!(!verify_spv(&bad_sib));

        let mut bad_tx = proof.clone();
        bad_tx.tx.amount += 1;
        assert!(!verify_spv(&bad_tx));
        // The tampered amount also breaks the signature, so full mode agrees.
        assert!(!verify_spv_full(&bad_tx));

        // A swapped side flag points the fold the wrong way.
        let mut bad_side = proof;
        bad_side.siblings[0].1 = !bad_side.siblings[0].1;
        assert!(!verify_spv(&bad_side));
    }

    #[test]
    fn proof_serialization_round_trips() {
        let (_cfg, _alloc, blk) = block_with_two_txs();
        let proof = prove_tx(&blk, 1).unwrap();
        let bytes = proof.to_bytes();
        let back = SpvProof::from_bytes(&bytes).expect("canonical bytes reparse");
        assert_eq!(back, proof);
        assert!(verify_spv(&back));
    }

    #[test]
    fn single_tx_proof_has_no_siblings_and_round_trips() {
        // A one-leaf Merkle tree commits the leaf directly: the root equals the
        // leaf hash and the proof carries zero siblings, which exercises the
        // empty sibling list in both serialization directions.
        let cfg = Config {
            genesis_difficulty: BITS,
            subsidy: 50,
            retarget_interval: 0,
            target_spacing: 10,
        };
        let seed = [0x3cu8; 32];
        let alice = compute_root(&seed, 4);
        let mut bc = Blockchain::new(cfg.clone(), vec![(alice, 500)], 0);
        assert!(bc.submit_tx(build_signed(&seed, 4, alice, [4u8; 32], 15, 1, 0)));
        bc.mine_next([6u8; 32], 10).unwrap();
        let blk = bc.best_chain().last().unwrap().clone();
        assert_eq!(blk.transactions.len(), 1);

        let proof = prove_tx(&blk, 0).unwrap();
        assert!(proof.siblings.is_empty(), "a one-leaf proof has no siblings");
        assert!(verify_spv(&proof));
        assert!(verify_spv_full(&proof));
        let back = SpvProof::from_bytes(&proof.to_bytes()).unwrap();
        assert_eq!(back, proof);
        assert!(verify_spv(&back));

        // A different transaction under the same header and empty proof fails.
        let mut outsider = proof.clone();
        outsider.tx.to = [0x77u8; 32];
        assert!(!verify_spv(&outsider));
    }

    #[test]
    fn malformed_proof_blobs_are_rejected() {
        let (_cfg, _alloc, blk) = block_with_two_txs();
        let proof = prove_tx(&blk, 1).unwrap();
        let bytes = proof.to_bytes();

        // Every truncation must be rejected.
        for cut in 0..bytes.len() {
            assert!(
                SpvProof::from_bytes(&bytes[..cut]).is_none(),
                "truncated blob of {cut} bytes parsed"
            );
        }
        // Trailing garbage must be rejected.
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(SpvProof::from_bytes(&trailing).is_none());
        // A non-canonical side flag must be rejected.
        let mut flag = bytes.clone();
        let sib_off = 116 + 8 + 4 + 32;
        flag[sib_off] = 2;
        assert!(SpvProof::from_bytes(&flag).is_none());
        // An oversized sibling count must be rejected before allocating.
        let mut huge = bytes.clone();
        let count_off = 116 + 8;
        huge[count_off..count_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(SpvProof::from_bytes(&huge).is_none());
        // A deterministic garbage blob must be rejected, not misparsed.
        let mut garbage = [0u8; 200];
        garbage[..32].copy_from_slice(&sha256(b"garbage"));
        garbage[32..64].copy_from_slice(&sha256(b"more garbage"));
        assert!(SpvProof::from_bytes(&garbage).is_none());
    }

    #[test]
    fn prove_tx_out_of_range_is_none() {
        let (_cfg, _alloc, blk) = block_with_two_txs();
        assert!(prove_tx(&blk, blk.transactions.len()).is_none());
        assert!(prove_tx(&blk, 999).is_none());
    }
}
