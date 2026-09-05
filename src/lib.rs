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
//! - [`rng`]: a deterministic PRNG for tests and the demo.

pub mod block;
pub mod chain;
pub mod merkle;
pub mod rng;
pub mod sha256;
pub mod sig;
pub mod state;
pub mod tx;

pub use sha256::{sha256, sha256d, to_hex};
