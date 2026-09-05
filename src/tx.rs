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
        if u64::from(self.signature.index) != self.nonce {
            return false;
        }
        sig::verify(&self.from, &self.signing_hash(), &self.signature)
    }

    /// Strict inverse of [`Transaction::to_bytes`]: the header fields are fixed
    /// width and the signature must consume the remaining bytes exactly.
    /// Returns `None` on truncation, trailing bytes, or a malformed signature.
    pub fn from_bytes(bytes: &[u8]) -> Option<Transaction> {
        use crate::ByteCursor;
        let mut b = bytes;
        let from = b.take(32)?.try_into().ok()?;
        let to = b.take(32)?.try_into().ok()?;
        let amount = u64::from_le_bytes(b.take(8)?.try_into().ok()?);
        let fee = u64::from_le_bytes(b.take(8)?.try_into().ok()?);
        let nonce = u64::from_le_bytes(b.take(8)?.try_into().ok()?);
        let signature = Signature::from_bytes(b)?;
        Some(Transaction {
            from,
            to,
            amount,
            fee,
            nonce,
            signature,
        })
    }
}

/// Build and sign a transaction from a wallet seed.
///
/// # Panics
///
/// Panics when `nonce` exceeds the leaf space of a `u32` index or the key
/// tree bounds, via [`sig::sign`]. Such a nonce could never verify anyway,
/// because the leaf index must equal the nonce.
pub fn build_signed(
    seed: &[u8; 32],
    height: u32,
    from: Address,
    to: Address,
    amount: u64,
    fee: u64,
    nonce: u64,
) -> Transaction {
    assert!(
        u32::try_from(nonce).is_ok(),
        "nonce beyond the one-time-key leaf space"
    );
    let msg = sha256(&signing_bytes(&from, &to, amount, fee, nonce));
    #[allow(clippy::cast_possible_truncation)]
    // Bounded by the assertion above.
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

    #[test]
    fn tx_bytes_round_trip() {
        let seed = [15u8; 32];
        let from = compute_root(&seed, 4);
        let tx = build_signed(&seed, 4, from, [3u8; 32], 77, 3, 2);
        let bytes = tx.to_bytes();
        let back = Transaction::from_bytes(&bytes).unwrap();
        assert_eq!(back, tx);
        assert!(back.verify_signature());
        assert_eq!(back.id(), tx.id());
        // Truncation never parses.
        for cut in 0..bytes.len() {
            assert!(Transaction::from_bytes(&bytes[..cut]).is_none(), "cut at {cut}");
        }
    }
}
