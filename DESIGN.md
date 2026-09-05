# Ironchain design

This document describes how Ironchain works and why each correctness gate proves what it claims. The guiding rule is that every property that keeps the chain honest is machine-checked by a test, not merely asserted in prose.

## Architecture

The engine is a set of small layers, each in its own module, built bottom up.

1. `sha256`. SHA-256 from scratch, the single primitive everything else stands on.
2. `sig`. Hash-based signatures. Lamport one-time keys under a Merkle tree.
3. `merkle`. A Merkle tree over transactions with inclusion proofs.
4. `tx`. Signed transactions in the account model.
5. `block`. Block headers, block hashing, and proof of work.
6. `state`. The account world state and the block state transition.
7. `chain`. Mempool, miner, difficulty retargeting, fork choice, reorg, and the full-chain validator.

Nothing above the SHA-256 layer uses any other cryptographic primitive. There are no external crates anywhere.

## Hashing

SHA-256 follows FIPS 180-4 and is verified against the standard vectors, including the empty string giving `e3b0c442...` and `abc` giving `ba7816bf...`, plus a multi-block message and the one-million-`a` vector. A streaming hasher is also tested to match the one-shot function across odd chunk boundaries.

Block hashes use double SHA-256, written `sha256d`, matching Bitcoin practice. Domain-separated single SHA-256 is used inside the Merkle trees.

## Signatures, the different angle

Ironchain signs with hash-based signatures rather than elliptic-curve keys. The construction is Lamport one-time signatures wrapped in a Merkle key tree, an XMSS-style scheme. Because the only assumption is that SHA-256 is hard to reverse or collide, the scheme is post-quantum.

Message. A signature commits to a 32-byte digest, treated as 256 bits, most-significant bit first within each byte.

Lamport one-time key. For a given leaf, and for each of the 256 message bits, there are two secret values, one for a zero bit and one for a one bit. Each secret is derived deterministically as `SHA256(domain, seed, leaf, bit_index, side)`, so a wallet stores only a 32-byte seed rather than kilobytes of key material. The public value for each secret is its hash. The compressed leaf public key is the hash of all 512 public values with a leaf-domain tag.

Signing. To sign a digest with a leaf, reveal, for each bit, the secret on the side selected by that message bit, and include the public hash of the unrevealed side. Add the Merkle authentication path from that leaf up to the root.

Verification. Recompute each revealed side by hashing the revealed secret, place it and the provided complement in bit order, hash the full set to rebuild the leaf public key, then fold the authentication path to a root and check that the root equals the address.

Why this is sound. To make the rebuilt leaf key match a leaf committed under the address, every one of the 512 public values must be the genuine one, otherwise the leaf hash changes and the Merkle fold no longer reaches the address. So an attacker must supply genuine reveals for the message they claim. For any bit where a forged message differs from a signed one, the needed secret was never revealed, and finding it means reversing SHA-256.

One-time discipline. Reusing a leaf for two different messages can reveal secrets on both sides of a differing bit, which breaks security. Ironchain binds the leaf index to the account nonce, so the n-th transaction from an address always uses nonce n and leaf n. A reused nonce is exactly a reused signing leaf, and both are rejected by the same check. An address at tree height h can therefore sign 2^h times.

Address. An address is the 32-byte Merkle root of a wallet key tree. It is derived by `compute_root(seed, height)` and is deterministic, which the tests pin as a known-answer vector.

## Transaction format

A transaction is:

- `from`, a 32-byte address.
- `to`, a 32-byte address.
- `amount`, a `u64`.
- `fee`, a `u64` paid to the miner.
- `nonce`, a `u64` that also selects the signing leaf.
- `signature`, the hash-based signature over the signing digest.

The signing digest is `SHA256(from, to, amount, fee, nonce)` with little-endian integers. Signature verification also requires that the signature leaf index equals the nonce, which ties one-time-key use to replay protection.

## Account model

Ironchain uses an account model, address to `(balance, nonce)`, rather than UTXO. The account model is the defensible choice here because it pairs directly with the one-time signatures. The nonce that orders an account's transactions is the same counter that selects its signing leaf, so replay protection and one-time-key discipline collapse into a single check. Genesis allocations seed initial balances, and each mined block pays the miner a fixed subsidy plus the fees of the transactions it includes.

Applying a transaction checks four things in order. The signature must verify, the nonce must equal the account's current nonce, the balance must cover amount plus fee, and amount plus fee must not overflow. On success the sender loses amount plus fee and gains one nonce, and the receiver gains amount. Amounts are unsigned, so a negative balance cannot be represented, and the balance check forbids overspending.

## Block format and proof of work

A block header is:

- `parent_hash`, the hash of the previous block.
- `merkle_root`, the Merkle root of the block's transactions.
- `timestamp`, a `u64`.
- `difficulty_bits`, the required number of leading zero bits.
- `miner`, the address that receives the reward.
- `nonce`, the proof-of-work counter.

The block hash is `sha256d` of the serialized header. Proof of work is satisfied when the block hash has at least `difficulty_bits` leading zero bits. This leading-zero-bits form is chosen for clarity, since it makes both the check and the retarget easy to read, and cumulative work is simply the sum of `2^difficulty_bits` over the chain, the expected number of hashes needed to build it.

## Merkle tree over transactions

Transaction leaves are the domain-tagged hash of the full serialized transaction, signature included. Internal nodes use a different domain tag, which blocks second-preimage attacks that swap a leaf for an internal node. When a level has an odd number of nodes the last node is duplicated, the same rule as Bitcoin. The root of an empty transaction list is defined as 32 zero bytes. Inclusion proofs carry the sibling hash and side at each level, and they work for a single leaf, for power-of-two sizes, and for non-power-of-two sizes.

## Difficulty retargeting

Every `retarget_interval` blocks the difficulty is recomputed from the timestamps of the last interval of blocks. If the observed timespan is far shorter than expected the difficulty rises by one bit, if it is far longer it falls by one bit, and otherwise it holds. The change is clamped to a single bit per retarget and floored at one bit. Validation recomputes the expected difficulty for every block and rejects any block whose difficulty does not match, which is what makes the difficulty a tamper-evident field.

## Fork choice and reorg

Every connected block is stored with its height and cumulative work. The active tip is the block with the greatest cumulative work. When a heavier branch appears, the tip switches to it, which is a reorganization. World state for any tip is produced by replaying the branch from genesis through that tip, so after a reorg the balances and nonces are exactly those of the winning branch and nothing from the discarded branch leaks through.

## Why each gate proves what it claims

Gate one, the tamper oracle, is the central property. It first confirms that a freshly built valid chain is accepted. It then mutates exactly one field at a time on a fresh copy and confirms rejection. Each field is caught by a specific rule. A changed amount, sender, receiver, nonce, or signature changes the transaction bytes, so the recomputed Merkle root no longer matches the stored one. A changed Merkle root fails the same check directly. A changed parent hash breaks the link to the previous block. A changed proof-of-work nonce breaks the leading-zero requirement. A changed difficulty fails the recomputed-difficulty check or the proof-of-work check. Because the honest chain is accepted and every single-field mutation is rejected, the test demonstrates that validation depends on all of these fields at once.

Gate two shows the signatures are both correct and strict. Random messages sign and verify, a single flipped bit in either the message or the signature fails, and fixed vectors pin the hash outputs and the derived address so a future change that alters the scheme is caught.

Gate three shows the Merkle proofs are sound in both directions. An included leaf verifies and a random non-included leaf fails, across sizes that include one and several non-power-of-two values, which exercises the odd-level duplication path.

Gate four shows fork choice is deterministic and that state is recomputed correctly. Two branches are built, the heavier one is selected, and the resulting state is compared against an independent full-chain revalidation of the winning branch. Equality of those two states is the proof that a reorg rewrites balances to the winning history rather than mixing branches.
