//! Transactions: signed value transfers in the account model. No external crates.
//!
//! An address is a 32-byte Merkle-tree root (see `sig`). Each transaction spends
//! one one-time signature leaf, and the leaf index is bound to the account nonce.
//! So the n-th transaction from an address always uses nonce `n` and OTS leaf
//! `n`. This ties replay protection and one-time-signature discipline together:
//! a replayed or reused nonce is exactly a reused signing leaf, and both are
//! rejected.

use crate::sha256::{sha256, Sha256};
use crate::sig::{self, Signature};

pub type Address = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub from: Address,
    pub to: Address,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    pub signature: Signature,
}

/// The bytes covered by the signature (everything except the signature itself).
pub fn signing_bytes(from: &Address, to: &Address, amount: u64, fee: u64, nonce: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(32 + 32 + 24);
    b.extend_from_slice(from);
    b.extend_from_slice(to);
    b.extend_from_slice(&amount.to_le_bytes());
    b.extend_from_slice(&fee.to_le_bytes());
    b.extend_from_slice(&nonce.to_le_bytes());
    b
}

impl Transaction {
    /// The digest that the signature commits to.
    pub fn signing_hash(&self) -> [u8; 32] {
        sha256(&signing_bytes(
            &self.from,
            &self.to,
            self.amount,
            self.fee,
            self.nonce,
        ))
    }

    /// Full serialization including the signature, used for the Merkle leaf.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = signing_bytes(&self.from, &self.to, self.amount, self.fee, self.nonce);
        b.extend_from_slice(&self.signature.to_bytes());
        b
    }

    /// Transaction id: hash of the full serialization.
    pub fn id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.to_bytes());
        h.finalize()
    }

    /// Verify the signature commits to this transaction under `from`.
    pub fn verify_signature(&self) -> bool {
        // The signing leaf index must equal the nonce.
        if self.signature.index as u64 != self.nonce {
            return false;
        }
        sig::verify(&self.from, &self.signing_hash(), &self.signature)
    }
}

/// Build and sign a transaction from a wallet seed.
pub fn build_signed(
    seed: &[u8; 32],
    height: u32,
    from: Address,
    to: Address,
    amount: u64,
    fee: u64,
    nonce: u64,
) -> Transaction {
    let msg = sha256(&signing_bytes(&from, &to, amount, fee, nonce));
    let signature = sig::sign(seed, height, nonce as u32, &msg);
    Transaction {
        from,
        to,
        amount,
        fee,
        nonce,
        signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::compute_root;

    #[test]
    fn signed_tx_verifies() {
        let seed = [42u8; 32];
        let from = compute_root(&seed, 4);
        let to = [9u8; 32];
        let tx = build_signed(&seed, 4, from, to, 100, 1, 0);
        assert!(tx.verify_signature());
    }

    #[test]
    fn tampered_amount_breaks_signature() {
        let seed = [7u8; 32];
        let from = compute_root(&seed, 4);
        let mut tx = build_signed(&seed, 4, from, [1u8; 32], 50, 0, 0);
        assert!(tx.verify_signature());
        tx.amount = 51;
        assert!(!tx.verify_signature());
    }

    #[test]
    fn nonce_index_mismatch_rejected() {
        let seed = [8u8; 32];
        let from = compute_root(&seed, 4);
        let mut tx = build_signed(&seed, 4, from, [2u8; 32], 10, 0, 1);
        assert!(tx.verify_signature());
        // Same signature, lie about the nonce.
        tx.nonce = 2;
        assert!(!tx.verify_signature());
    }
}
