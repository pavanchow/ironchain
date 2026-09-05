//! Adversarial and boundary gates: the negative controls that a chain validator
//! must enforce beyond the single-field tamper oracle. Every test here states
//! one rule in isolation at the full-chain level.
//!
//! Hand-built chains use a low genesis difficulty (4) so the proof of work is
//! instant and the test isolates the rule under test. Signatures use wallet
//! tree height 4 throughout.

// Wallet bytes are derived from fixed u8 seeds and counts stay far below any
// truncation bound, so narrowing casts are safe.
#![allow(clippy::cast_possible_truncation)]

use ironchain::block::{meets_target, mine, Block, Header};
use ironchain::chain::{validate_chain, ChainError, Config};
use ironchain::merkle;
use ironchain::sha256::sha256;
use ironchain::sig::{compute_root, sign, Signature};
use ironchain::state::StateError;
use ironchain::tx::{build_signed, Address, Transaction};

const BITS: u32 = 4;
const HEIGHT: u32 = 4;

fn config(subsidy: u64) -> Config {
    Config {
        genesis_difficulty: BITS,
        subsidy,
        retarget_interval: 0,
        target_spacing: 10,
    }
}

fn wallet(seed_byte: u8) -> ([u8; 32], Address) {
    let seed = [seed_byte; 32];
    let addr = compute_root(&seed, HEIGHT);
    (seed, addr)
}

fn empty_root_header(parent: [u8; 32], ts: u64, bits: u32, miner: Address) -> Header {
    Header {
        parent_hash: parent,
        merkle_root: merkle::EMPTY_ROOT,
        timestamp: ts,
        difficulty_bits: bits,
        miner,
        nonce: 0,
    }
}

/// Mine a header in place until its hash meets `bits`, starting from nonce 0.
fn grind(header: &mut Header) {
    mine(header);
}

/// A header whose hash provably fails `bits`.
fn unmineable_header(mut header: Header) -> Header {
    let mut cand = 0u64;
    loop {
        header.nonce = cand;
        if !meets_target(&header.hash(), header.difficulty_bits) {
            return header;
        }
        cand += 1;
    }
}

fn sealed_block(parent: &Block, ts: u64, miner: Address, txs: Vec<Transaction>) -> Block {
    let leaves: Vec<[u8; 32]> = txs.iter().map(|t| merkle::hash_leaf(&t.to_bytes())).collect();
    let mut header = Header {
        parent_hash: parent.hash(),
        merkle_root: merkle::root(&leaves),
        timestamp: ts,
        difficulty_bits: parent.header.difficulty_bits,
        miner,
        nonce: 0,
    };
    grind(&mut header);
    Block { header, transactions: txs }
}

fn genesis_block() -> Block {
    let mut header = empty_root_header([0u8; 32], 0, BITS, [0u8; 32]);
    grind(&mut header);
    Block { header, transactions: vec![] }
}

/// A syntactically complete but bogus signature (lengths are valid, contents
/// are zeros). Used to prove ordering: some checks must fire before signature
/// verification would.
fn bogus_signature() -> Signature {
    Signature {
        index: 0,
        reveals: vec![[0u8; 32]; 256],
        complements: vec![[0u8; 32]; 256],
        auth_path: vec![],
    }
}

fn accepts(cfg: &Config, alloc: &[(Address, u64)], chain: &[Block]) -> bool {
    validate_chain(cfg, alloc, chain).is_ok()
}

// ---- Funding rules ---------------------------------------------------------

#[test]
fn tx_from_unfunded_wallet_rejected() {
    let g = genesis_block();
    let (_seed, funded) = wallet(1);
    let (_s2, unfunded) = wallet(200);
    let (_s3, receiver) = wallet(3);
    // A perfectly signed transaction from an address with no balance.
    let tx = build_signed(&[200u8; 32], HEIGHT, unfunded, receiver, 1, 0, 0);
    let blk = sealed_block(&g, 1, funded, vec![tx]);
    let err = validate_chain(&config(50), &[(funded, 100)], &[g, blk]).unwrap_err();
    assert!(
        matches!(err, ChainError::State(StateError::InsufficientBalance { .. })),
        "unexpected error: {err}"
    );
}

#[test]
fn overspend_rejected() {
    let g = genesis_block();
    let (seed, sender) = wallet(1);
    let receiver = [9u8; 32];
    let tx = build_signed(&seed, HEIGHT, sender, receiver, 101, 0, 0);
    let blk = sealed_block(&g, 1, [8u8; 32], vec![tx]);
    let err = validate_chain(&config(50), &[(sender, 100)], &[g, blk]).unwrap_err();
    assert!(
        matches!(err, ChainError::State(StateError::InsufficientBalance { .. })),
        "unexpected error: {err}"
    );
}

#[test]
fn overspend_via_fee_rejected() {
    // Balance covers the amount but not amount plus fee.
    let g = genesis_block();
    let (seed, sender) = wallet(1);
    let tx = build_signed(&seed, HEIGHT, sender, [9u8; 32], 100, 1, 0);
    let blk = sealed_block(&g, 1, [8u8; 32], vec![tx]);
    let err = validate_chain(&config(50), &[(sender, 100)], &[g, blk]).unwrap_err();
    assert!(
        matches!(err, ChainError::State(StateError::InsufficientBalance { .. })),
        "unexpected error: {err}"
    );
}

#[test]
fn exact_balance_spend_accepted() {
    let g = genesis_block();
    let (seed, sender) = wallet(1);
    let tx = build_signed(&seed, HEIGHT, sender, [9u8; 32], 100, 0, 0);
    let blk = sealed_block(&g, 1, [8u8; 32], vec![tx]);
    assert!(accepts(&config(50), &[(sender, 100)], &[g, blk]));
}

#[test]
fn zero_amount_zero_fee_tx_accepted() {
    // A no-value transaction still burns a one-time leaf and a nonce.
    let g = genesis_block();
    let (seed, sender) = wallet(1);
    let tx = build_signed(&seed, HEIGHT, sender, [9u8; 32], 0, 0, 0);
    let blk = sealed_block(&g, 1, [8u8; 32], vec![tx]);
    assert!(accepts(&config(50), &[(sender, 100)], &[g, blk]));
}

#[test]
fn amount_plus_fee_overflow_rejected() {
    let g = genesis_block();
    let (seed, sender) = wallet(1);
    let tx = build_signed(&seed, HEIGHT, sender, [9u8; 32], u64::MAX, 1, 0);
    let blk = sealed_block(&g, 1, [8u8; 32], vec![tx]);
    let err = validate_chain(&config(50), &[(sender, 100)], &[g, blk]).unwrap_err();
    assert!(
        matches!(err, ChainError::State(StateError::AmountOverflow)),
        "unexpected error: {err}"
    );
}

#[test]
fn block_fee_total_overflow_rejected_without_panicking() {
    // Two garbage-signature transactions whose fees sum above u64::MAX. The fee
    // total is computed before signature checks, so this must come back as a
    // clean rejection. (Before the fix this panicked in debug builds.)
    let g = genesis_block();
    let mk = |fee: u64, nonce: u64| Transaction {
        from: [1u8; 32],
        to: [2u8; 32],
        amount: 0,
        fee,
        nonce,
        signature: bogus_signature(),
    };
    let blk = sealed_block(&g, 1, [8u8; 32], vec![mk(u64::MAX, 0), mk(1, 1)]);
    let err = validate_chain(&config(50), &[], &[g, blk]).unwrap_err();
    assert!(
        matches!(err, ChainError::State(StateError::FeeOverflow)),
        "unexpected error: {err}"
    );
}

// ---- Nonce and replay rules ------------------------------------------------

#[test]
fn duplicate_nonce_in_same_block_rejected() {
    let g = genesis_block();
    let (seed, sender) = wallet(1);
    let tx_a = build_signed(&seed, HEIGHT, sender, [10u8; 32], 1, 0, 0);
    let tx_b = build_signed(&seed, HEIGHT, sender, [11u8; 32], 1, 0, 0);
    let blk = sealed_block(&g, 1, [8u8; 32], vec![tx_a, tx_b]);
    let err = validate_chain(&config(50), &[(sender, 100)], &[g, blk]).unwrap_err();
    assert!(
        matches!(err, ChainError::State(StateError::WrongNonce { expected: 1, got: 0 })),
        "unexpected error: {err}"
    );
}

#[test]
fn exact_duplicate_tx_in_same_block_rejected() {
    let g = genesis_block();
    let (seed, sender) = wallet(1);
    let tx = build_signed(&seed, HEIGHT, sender, [10u8; 32], 1, 0, 0);
    let blk = sealed_block(&g, 1, [8u8; 32], vec![tx.clone(), tx]);
    assert!(!accepts(&config(50), &[(sender, 100)], &[g, blk]));
}

#[test]
fn tx_replay_across_blocks_rejected() {
    let g = genesis_block();
    let (seed, sender) = wallet(1);
    let miner = [8u8; 32];
    let tx = build_signed(&seed, HEIGHT, sender, [10u8; 32], 1, 0, 0);
    let blk1 = sealed_block(&g, 1, miner, vec![tx.clone()]);
    // The identical transaction included again in the very next block.
    let blk2 = sealed_block(&blk1, 2, miner, vec![tx]);
    assert!(!accepts(&config(50), &[(sender, 100)], &[g, blk1, blk2]));
}

#[test]
fn future_nonce_rejected() {
    let g = genesis_block();
    let (seed, sender) = wallet(1);
    let tx = build_signed(&seed, HEIGHT, sender, [10u8; 32], 1, 0, 1);
    let blk = sealed_block(&g, 1, [8u8; 32], vec![tx]);
    let err = validate_chain(&config(50), &[(sender, 100)], &[g, blk]).unwrap_err();
    assert!(
        matches!(err, ChainError::State(StateError::WrongNonce { expected: 0, got: 1 })),
        "unexpected error: {err}"
    );
}

#[test]
fn signature_index_mismatch_rejected() {
    // A genuine signature produced with leaf 1 attached to a nonce-0
    // transaction: the one-time leaf must equal the nonce.
    let g = genesis_block();
    let (seed, sender) = wallet(1);
    let msg = sha256(&ironchain::tx::signing_bytes(&sender, &[10u8; 32], 1, 0, 0));
    let tx = Transaction {
        from: sender,
        to: [10u8; 32],
        amount: 1,
        fee: 0,
        nonce: 0,
        signature: sign(&seed, HEIGHT, 1, &msg),
    };
    let blk = sealed_block(&g, 1, [8u8; 32], vec![tx]);
    let err = validate_chain(&config(50), &[(sender, 100)], &[g, blk]).unwrap_err();
    assert!(
        matches!(err, ChainError::State(StateError::BadSignature)),
        "unexpected error: {err}"
    );
}

// ---- Header rules ----------------------------------------------------------

#[test]
fn invalid_merkle_root_rejected() {
    let g = genesis_block();
    let (seed, sender) = wallet(1);
    let tx = build_signed(&seed, HEIGHT, sender, [10u8; 32], 1, 0, 0);
    let mut blk = sealed_block(&g, 1, [8u8; 32], vec![tx]);
    blk.header.merkle_root = [7u8; 32];
    assert!(!accepts(&config(50), &[(sender, 100)], &[g, blk]));
}

#[test]
fn block_not_meeting_difficulty_rejected() {
    let g = genesis_block();
    let header = unmineable_header(empty_root_header(g.hash(), 1, BITS, [8u8; 32]));
    let blk = Block { header, transactions: vec![] };
    let err = validate_chain(&config(50), &[], &[g, blk]).unwrap_err();
    assert!(matches!(err, ChainError::BadPow), "unexpected error: {err}");
}

#[test]
fn wrong_difficulty_rejected() {
    // PoW is valid for the header's own claimed difficulty, but the claimed
    // difficulty does not match the retargeting rule (here: constant).
    let g = genesis_block();
    let mut header = empty_root_header(g.hash(), 1, BITS + 1, [8u8; 32]);
    grind(&mut header);
    let blk = Block { header, transactions: vec![] };
    let err = validate_chain(&config(50), &[], &[g, blk]).unwrap_err();
    assert!(
        matches!(
            err,
            ChainError::BadDifficulty { expected, got }
                if expected == BITS && got == BITS + 1
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn non_monotonic_timestamp_rejected() {
    let g = genesis_block();
    // Block 1 at ts 5, block 2 at ts 4: the child timestamp must not go back.
    let b1 = sealed_block(&g, 5, [8u8; 32], vec![]);
    let mut header = empty_root_header(b1.hash(), 4, BITS, [8u8; 32]);
    grind(&mut header);
    let b2 = Block { header, transactions: vec![] };
    let err = validate_chain(&config(50), &[], &[g, b1, b2]).unwrap_err();
    assert!(
        matches!(err, ChainError::NonMonotonicTimestamp),
        "unexpected error: {err}"
    );
}

#[test]
fn broken_parent_link_rejected() {
    let g = genesis_block();
    let mut header = empty_root_header([9u8; 32], 1, BITS, [8u8; 32]);
    grind(&mut header);
    let blk = Block { header, transactions: vec![] };
    let err = validate_chain(&config(50), &[], &[g, blk]).unwrap_err();
    assert!(matches!(err, ChainError::BadParentLink), "unexpected error: {err}");
}

// ---- Genesis rules ---------------------------------------------------------

#[test]
fn genesis_with_wrong_difficulty_rejected() {
    // A chain mined entirely at difficulty 1 under a config demanding 8.
    let cfg = config(50);
    let mut g = Header {
        parent_hash: [0u8; 32],
        merkle_root: merkle::EMPTY_ROOT,
        timestamp: 0,
        difficulty_bits: 1,
        miner: [0u8; 32],
        nonce: 0,
    };
    grind(&mut g);
    let mut b1 = Header {
        parent_hash: g.hash(),
        merkle_root: merkle::EMPTY_ROOT,
        timestamp: 1,
        difficulty_bits: 1,
        miner: [9u8; 32],
        nonce: 0,
    };
    grind(&mut b1);
    let chain = vec![
        Block { header: g, transactions: vec![] },
        Block { header: b1, transactions: vec![] },
    ];
    let err = validate_chain(&cfg, &[], &chain).unwrap_err();
    assert!(matches!(err, ChainError::BadGenesis), "unexpected error: {err}");
}

#[test]
fn genesis_with_nonzero_parent_rejected() {
    let mut g = empty_root_header([5u8; 32], 0, BITS, [0u8; 32]);
    grind(&mut g);
    let blk = Block { header: g, transactions: vec![] };
    let err = validate_chain(&config(50), &[], &[blk]).unwrap_err();
    assert!(matches!(err, ChainError::BadGenesis), "unexpected error: {err}");
}

#[test]
fn empty_chain_rejected() {
    let err = validate_chain(&config(50), &[], &[]).unwrap_err();
    assert!(matches!(err, ChainError::EmptyChain), "unexpected error: {err}");
}

// ---- Throughput boundary ---------------------------------------------------

#[test]
fn empty_blocks_accepted() {
    // Blocks with no transactions are legal: they still pay the subsidy and
    // extend the chain, and two in a row prove it is not a one-off.
    let g = genesis_block();
    let b1 = sealed_block(&g, 1, [8u8; 32], vec![]);
    let b2 = sealed_block(&b1, 2, [8u8; 32], vec![]);
    let st = validate_chain(&config(50), &[], &[g, b1, b2]).unwrap();
    assert_eq!(st.balance(&[8u8; 32]), 100);
    // The genesis miner holds exactly the genesis subsidy and nothing more.
    assert_eq!(st.balance(&[0u8; 32]), 50);
}

#[test]
fn zero_subsidy_chain_pays_fees_only() {
    // With subsidy 0 the miner earns exactly the fees and nothing else, so a
    // configuration that turns off inflation still validates.
    let g = genesis_block();
    let (seed, sender) = wallet(1);
    let tx = build_signed(&seed, HEIGHT, sender, [9u8; 32], 5, 2, 0);
    let blk = sealed_block(&g, 1, [8u8; 32], vec![tx]);
    let st = validate_chain(&config(0), &[(sender, 100)], &[g, blk]).unwrap();
    assert_eq!(st.balance(&[8u8; 32]), 2);
    assert_eq!(st.balance(&[9u8; 32]), 5);
    assert_eq!(st.balance(&sender), 93);
}

#[test]
fn block_with_many_transactions_accepted_and_fees_paid() {
    // Twelve funded wallets, twelve transactions in one block. The miner must
    // collect the subsidy plus every fee.
    const N: u64 = 12;
    let g = genesis_block();
    let mut alloc = Vec::new();
    let mut txs = Vec::new();
    for i in 0..N {
        let (seed, addr) = wallet(20 + i as u8);
        alloc.push((addr, 1000));
        txs.push(build_signed(&seed, HEIGHT, addr, [99u8; 32], 10, i + 1, 0));
    }
    let miner = [8u8; 32];
    let blk = sealed_block(&g, 1, miner, txs);
    assert_eq!(blk.transactions.len(), N as usize);
    let st = validate_chain(&config(50), &alloc, &[g, blk]).unwrap();
    assert_eq!(st.balance(&miner), 50 + N * (N + 1) / 2);
    assert_eq!(st.balance(&[99u8; 32]), 10 * N);
}
