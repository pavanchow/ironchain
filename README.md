<img src="docs/logo.svg" alt="Ironchain logo" width="96">

# Ironchain

A from-scratch proof-of-work blockchain written in pure Rust with zero external dependencies. Standard library only, edition 2021. The only cryptographic primitive is SHA-256, implemented in this repository, and digital signatures are hash-based, so Ironchain is a post-quantum, hash-only chain.

Live playground: https://pavanchow.github.io/ironchain/

## What it is

Ironchain is a complete small blockchain you can read end to end. It has SHA-256 from scratch, hash-based one-time signatures inside a Merkle key tree (an XMSS-style scheme), a transaction Merkle tree with inclusion proofs, proof-of-work blocks with a difficulty target, an account-model world state, a mempool, a miner, difficulty retargeting, and fork choice by most cumulative work with correct chain reorganization.

## The gap it fills

Most blockchain teaching code is either a toy that skips the parts that make a chain actually safe, or a production node that is far too large to learn from. Ironchain sits in the middle. Every rule that makes the chain tamper-evident is present and is proven by a machine-checkable test, yet the whole engine is small enough to read in an afternoon.

A person learning how a blockchain really works can trace a single transaction from signing through mining, validation, and a reorg, with no framework or dependency in the way. An AI agent that needs a correct, self-contained reference implementation can rely on the tamper oracle as ground truth. The chain accepts a valid history and rejects every single-field mutation, and that property is enforced by tests rather than by prose.

The signatures are the different angle. Instead of the usual elliptic-curve keys, Ironchain signs with Lamport one-time signatures arranged under a Merkle tree. Security rests only on the hardness of reversing or colliding SHA-256, which means the chain stays secure even against a quantum adversary.

## Quickstart

```
cargo build --release
cargo test
./target/release/ironchain
```

The demo mines a short chain with random valid transactions, prints the blocks and balances, validates the honest chain, then tampers with a transaction and shows validation rejecting it.

## API

The crate is a library plus a binary. Core modules:

- `sha256`: `sha256(bytes)`, `sha256d(bytes)`, and a streaming `Sha256` hasher.
- `sig`: `compute_root(seed, height)` derives an address, `sign(seed, height, index, msg)` produces a `Signature`, and `verify(address, msg, sig)` checks it. Signatures serialize and reparse strictly. Derived leaf keys are memoized per wallet, so repeated signing from one wallet costs one tree derivation total rather than one per signature.
- `merkle`: `root(leaves)`, `prove(leaves, index)`, and `verify(root, leaf, proof)`.
- `tx`: `Transaction`, `build_signed(...)`, `verify_signature()`, and strict `from_bytes`.
- `block`: `Header`, `Block`, `mine(header)`, `meets_target(hash, bits)`, and strict header deserialization.
- `state`: `State`, `Account`, `apply_block`, and `apply_tx`.
- `chain`: `Blockchain` with `mine_next`, `submit_tx`, `add_block`, `state`, and `validate_chain`, the full-chain validator.
- `spv`: light-client proof construction and verification for a single block, no chain required.

Small example:

```rust
use ironchain::chain::{Blockchain, Config};
use ironchain::sig::compute_root;
use ironchain::tx::build_signed;

let seed = [1u8; 32];
let alice = compute_root(&seed, 4);
let mut bc = Blockchain::new(Config::default(), vec![(alice, 1000)], 0);
let bob = [9u8; 32];
bc.submit_tx(build_signed(&seed, 4, alice, bob, 100, 1, 0));
bc.mine_next([7u8; 32], 10).unwrap();
assert_eq!(bc.state().balance(&bob), 100);
```

A light client proves a payment without storing the chain:

```rust
use ironchain::spv;

// From a full node or a peer: the containing block and the tx position.
let proof = spv::prove_tx(&block, tx_index).unwrap();
assert!(spv::verify_spv(&proof));
```

## The correctness gate

The point of Ironchain is that its safety is machine-checked, not asserted. Six gates plus an adversarial suite and a soak live in the test suite.

1. Tamper oracle. Build a valid multi-block chain with random valid transactions and confirm full-chain validation accepts it. Then, for every mutable field (a transaction amount, a fee, a signature, a sender, a receiver, a nonce, the Merkle root, the parent hash, the proof-of-work nonce, the timestamp, the difficulty, and the miner) mutate one copy and confirm validation rejects it. Valid accepts, any tamper rejects. See `tests/tamper_oracle.rs`.
2. Signatures. Sign and verify over random messages, confirm a single flipped bit in the message or the signature fails verification, and pin known-answer vectors for SHA-256 and for the derived address. See `tests/gates.rs` and `src/sig.rs`.
3. Merkle. An inclusion proof verifies for an included transaction and fails for a non-included one, across random trees including size one and non-power-of-two sizes. A flipped sibling hash and a side-swapped proof also fail. See `tests/gates.rs` and `src/merkle.rs`.
4. Fork choice and reorg. Given two competing branches, the node selects the most-work chain deterministically, and the resulting account state matches an independent recomputation on the winning branch. See `tests/gates.rs` and `src/chain.rs`.
5. Retarget consistency. The incremental validator and the full-chain validator must recompute the same difficulty at every retarget boundary, including right at the decision threshold, for chains that speed up and chains that slow down. See `tests/gates.rs`.
6. Signature malleability. Every bit of the first byte of every reveal, every complement, and the whole authentication path is flipped in turn and must fail verification, plus wrong leaf indices and truncated paths. See `tests/gates.rs`.

The adversarial suite in `tests/adversarial.rs` states one rule per test at the full-chain level: unfunded senders, overspends, overspends via fee, duplicate nonces in one block, exact duplicate transactions, replay across blocks, future nonces, signature leaf index mismatches, invalid Merkle roots, blocks below the target, wrong difficulty, non-monotonic timestamps, broken parent links, easy genesis blocks, and fee-total overflow are all rejected, while exact-balance spends, zero-value transactions, empty blocks, zero-subsidy blocks that pay fees only, and twelve-transaction blocks are accepted.

Light-client proofs carry their own tests in `src/spv.rs`: proofs verify for included transactions, including a single-transaction block whose proof needs no siblings, and fail for non-included transactions, tampered or side-swapped siblings, and headers that fail their own proof of work. The compact serialization round trips, and every truncation, trailing byte, non-canonical side flag, and oversized sibling count is rejected.

`tests/soak.rs` is the long-horizon gate. Run `IRONCHAIN_SOAK=1 cargo test --release --test soak` to mine hundreds of blocks while a rival miner repeatedly forks three blocks back and overtakes the chain, with the state revalidated against an independent recomputation after every round.

The tamper oracle and the gates are bounded for CI but their size and seed are controllable. Set `IRONCHAIN_FUZZ_OPS` to build a longer chain and `IRONCHAIN_SEED` to change the random draw. At large values the oracle grows its wallets' one-time-key budgets (up to tree height 8) so long chains keep carrying transactions, and its genesis difficulty of 12 makes proof of work the dominant cost, so a max-scale run is a mining and validation stress rather than a fixture-setup benchmark.

```
IRONCHAIN_FUZZ_OPS=12 IRONCHAIN_SEED=7 cargo test
```

## Design

See DESIGN.md for the architecture, the exact block, transaction, signature, and Merkle formats, the proof-of-work and difficulty rules, the fork-choice rule, and an explanation of why each gate proves what it claims.

## License

MIT
