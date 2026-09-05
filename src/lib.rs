//! Ironchain: a from-scratch, zero-dependency proof-of-work blockchain.
//!
//! Everything here is built on the Rust standard library and a single primitive,
//! SHA-256, implemented in this crate. Digital signatures are hash-based
//! (Lamport one-time signatures inside a Merkle key tree, an XMSS-style scheme),
//! which makes the chain post-quantum: its security rests only on the hardness of
//! reversing or colliding SHA-256.
//!
//! Module map:
//! - [`sha256`]: SHA-256 from scratch, with known-answer tests.
//! - [`sig`]: hash-based Lamport + Merkle-tree signatures.
//! - [`merkle`]: transaction Merkle tree and inclusion proofs.
//! - [`tx`]: signed transactions in the account model.
//! - [`block`]: block headers, hashing, and proof of work.
//! - [`state`]: account world state and the state transition.
//! - [`chain`]: fork choice, reorg, retargeting, mempool, and mining.
//! - [`spv`]: light-client simplified payment verification proofs.
//! - [`rng`]: a deterministic PRNG for tests and the demo.

// Every public function returns a value, so annotating each pure function with
// `#[must_use]` would add dozens of attributes without changing behavior. The
// security-critical predicates below are annotated explicitly instead.
#![allow(clippy::must_use_candidate)]

pub mod block;
pub mod chain;
pub mod merkle;
pub mod rng;
pub mod sha256;
pub mod sig;
pub mod spv;
pub mod state;
pub mod tx;

pub use sha256::{sha256, sha256d, to_hex};

/// Byte-cursor helper for strict deserialization: take `n` bytes off the front
/// of a slice, or `None` when the slice is too short. Checking the length
/// before slicing keeps every parser overflow-free.
pub(crate) trait ByteCursor {
    fn take(&mut self, n: usize) -> Option<&[u8]>;
}

impl ByteCursor for &[u8] {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        if self.len() < n {
            return None;
        }
        let (head, rest) = self.split_at(n);
        *self = rest;
        Some(head)
    }
}
