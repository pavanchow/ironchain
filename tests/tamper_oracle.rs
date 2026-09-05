//! The tamper oracle: the central machine-checkable property of Ironchain.
//!
//! Build a valid multi-block chain carrying random valid transactions and assert
//! full-chain validation ACCEPTS it. Then, for every mutable field, mutate one
//! copy and assert validation REJECTS it. Valid accepts, any tamper rejects.
//!
//! Size and seed are controllable: `IRONCHAIN_FUZZ_OPS` (blocks to build) and
//! `IRONCHAIN_SEED`. Defaults are bounded for CI. At large values the
//! one-time-key budget of the fixture wallets grows with the requested block
//! count (capped at tree height 8), so long chains keep carrying transactions
//! instead of draining the key budget after a handful of blocks.
//!
//! The fixture is expensive at scale, so it is built once per process and
//! shared by every test below. Each test still mutates its own copy of the
//! chain and runs its own full validation.

// Scale parameters arrive from the environment as u64 and feed bounded loop
// counts, indices, and PRNG draws, so narrowing casts are safe.
#![allow(clippy::cast_possible_truncation)]

use std::sync::OnceLock;

use ironchain::block::{meets_target, Block};
use ironchain::chain::{validate_chain, Blockchain, Config};
use ironchain::rng::Rng;
use ironchain::sig::compute_root;
use ironchain::tx::{build_signed, Address};

const WALLET_HEIGHT: u32 = 4;
const MAX_WALLET_HEIGHT: u32 = 8;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

struct Fixture {
    config: Config,
    allocations: Vec<(Address, u64)>,
    chain: Vec<Block>,
}

static FIXTURE: OnceLock<Fixture> = OnceLock::new();

fn fixture() -> &'static Fixture {
    FIXTURE.get_or_init(build_fixture)
}

fn build_fixture() -> Fixture {
    let blocks = env_u64("IRONCHAIN_FUZZ_OPS", 6).max(2);
    let seed = env_u64("IRONCHAIN_SEED", 12345);

    let config = Config {
        genesis_difficulty: 8,
        subsidy: 100,
        retarget_interval: 0,
        target_spacing: 10,
    };

    // Grow the one-time-key budget with the requested scale: each wallet needs
    // on the order of `blocks` leaves to keep two transactions per block flowing
    // through the whole run. Height 4 matches the historical CI fixture.
    let mut wallet_height = WALLET_HEIGHT;
    while (1u64 << wallet_height) < blocks && wallet_height < MAX_WALLET_HEIGHT {
        wallet_height += 1;
    }

    // Four funded wallets so we can keep sending within the one-time-key budget.
    let seeds: Vec<[u8; 32]> = (0..4u8)
        .map(|i| {
            let mut s = [0u8; 32];
            s[0] = i;
            s[1] = seed as u8;
            s[2] = (seed >> 8) as u8;
            s
        })
        .collect();
    let addrs: Vec<Address> = seeds
        .iter()
        .map(|s| compute_root(s, wallet_height))
        .collect();
    let allocations: Vec<(Address, u64)> = addrs.iter().map(|a| (*a, 100_000)).collect();

    let mut bc = Blockchain::new(config.clone(), allocations.clone(), 0);
    let mut rng = Rng::new(seed);
    let mut nonces = [0u64; 4];
    let leaf_budget = 1u64 << wallet_height;

    for _ in 0..blocks {
        for _ in 0..2 {
            let from_i = (rng.below(4)) as usize;
            if nonces[from_i] >= leaf_budget {
                continue;
            }
            let mut to_i = (rng.below(4)) as usize;
            if to_i == from_i {
                to_i = (to_i + 1) % 4;
            }
            let amount = 10 + rng.below(500);
            let fee = rng.below(4);
            let tx = build_signed(
                &seeds[from_i],
                wallet_height,
                addrs[from_i],
                addrs[to_i],
                amount,
                fee,
                nonces[from_i],
            );
            if bc.submit_tx(tx) {
                nonces[from_i] += 1;
            }
        }
        let ts = bc.height(&bc.best_tip).unwrap() * 10 + 10;
        bc.mine_next(addrs[0], ts).unwrap();
    }

    Fixture {
        config,
        allocations,
        chain: bc.best_chain(),
    }
}

/// Index of the first block that carries at least one transaction.
fn first_tx_block(chain: &[Block]) -> usize {
    chain
        .iter()
        .position(|b| !b.transactions.is_empty())
        .expect("fixture must contain a block with transactions")
}

fn accepts(f: &Fixture, chain: &[Block]) -> bool {
    validate_chain(&f.config, &f.allocations, chain).is_ok()
}

#[test]
fn honest_chain_is_accepted() {
    let f = fixture();
    assert!(
        accepts(f, &f.chain),
        "the honest chain must validate: {:?}",
        validate_chain(&f.config, &f.allocations, &f.chain).err()
    );
    assert!(f.chain.len() >= 2, "need a multi-block chain");
}

#[test]
fn tamper_tx_amount_rejected() {
    let f = fixture();
    let bi = first_tx_block(&f.chain);
    let mut c = f.chain.clone();
    c[bi].transactions[0].amount += 1;
    assert!(!accepts(f, &c), "mutating a tx amount must be rejected");
}

#[test]
fn tamper_tx_fee_rejected() {
    let f = fixture();
    let bi = first_tx_block(&f.chain);
    let mut c = f.chain.clone();
    c[bi].transactions[0].fee += 1;
    assert!(!accepts(f, &c), "mutating a tx fee must be rejected");
}

#[test]
fn tamper_tx_signature_rejected() {
    let f = fixture();
    let bi = first_tx_block(&f.chain);
    let mut c = f.chain.clone();
    c[bi].transactions[0].signature.reveals[0][0] ^= 0x80;
    assert!(!accepts(f, &c), "mutating a tx signature must be rejected");
}

#[test]
fn tamper_tx_sender_rejected() {
    let f = fixture();
    let bi = first_tx_block(&f.chain);
    let mut c = f.chain.clone();
    c[bi].transactions[0].from[0] ^= 0x01;
    assert!(!accepts(f, &c), "mutating a tx sender must be rejected");
}

#[test]
fn tamper_tx_nonce_rejected() {
    let f = fixture();
    let bi = first_tx_block(&f.chain);
    let mut c = f.chain.clone();
    c[bi].transactions[0].nonce = c[bi].transactions[0].nonce.wrapping_add(1);
    assert!(!accepts(f, &c), "mutating a tx nonce must be rejected");
}

#[test]
fn tamper_merkle_root_rejected() {
    let f = fixture();
    let bi = first_tx_block(&f.chain);
    let mut c = f.chain.clone();
    c[bi].header.merkle_root[0] ^= 0x01;
    assert!(!accepts(f, &c), "mutating the merkle root must be rejected");
}

#[test]
fn tamper_parent_hash_rejected() {
    let f = fixture();
    let mut c = f.chain.clone();
    // Any non-genesis block.
    c[1].header.parent_hash[0] ^= 0x01;
    assert!(!accepts(f, &c), "mutating a parent hash must be rejected");
}

#[test]
fn tamper_pow_nonce_rejected() {
    let f = fixture();
    let mut c = f.chain.clone();
    // Choose a nonce that fails proof of work on block 1, keeping parent links
    // intact so the rejection is specifically due to proof of work.
    let bits = c[1].header.difficulty_bits;
    let mut cand = 1u64;
    loop {
        c[1].header.nonce = cand;
        if !meets_target(&c[1].hash(), bits) {
            break;
        }
        cand += 1;
    }
    assert!(!accepts(f, &c), "a non-satisfying PoW nonce must be rejected");
}

#[test]
fn tamper_difficulty_rejected() {
    let f = fixture();
    let mut c = f.chain.clone();
    c[1].header.difficulty_bits += 1;
    assert!(!accepts(f, &c), "mutating the difficulty must be rejected");
}

#[test]
fn tamper_miner_rejected() {
    let f = fixture();
    let mut c = f.chain.clone();
    // Redirecting the coinbase changes the header hash, so the stored PoW no
    // longer matches, and the reward would land at a different address.
    c[1].header.miner[0] ^= 0x01;
    assert!(!accepts(f, &c), "mutating the miner must be rejected");
}

#[test]
fn every_single_field_mutation_rejected() {
    type Mutation = Box<dyn Fn(&mut Vec<Block>)>;
    // A tighter statement of the whole property in one test: build once, apply
    // each mutation to a fresh copy, and require every one to be rejected while
    // the untouched chain is accepted.
    let f = fixture();
    assert!(accepts(f, &f.chain));
    let bi = first_tx_block(&f.chain);

    let mutations: Vec<(&str, Mutation)> = vec![
        ("amount", Box::new(move |c: &mut Vec<Block>| c[bi].transactions[0].amount += 1)),
        ("fee", Box::new(move |c: &mut Vec<Block>| c[bi].transactions[0].fee += 1)),
        (
            "signature",
            Box::new(move |c: &mut Vec<Block>| c[bi].transactions[0].signature.reveals[1][0] ^= 0x40),
        ),
        ("sender", Box::new(move |c: &mut Vec<Block>| c[bi].transactions[0].from[1] ^= 0x01)),
        ("receiver", Box::new(move |c: &mut Vec<Block>| c[bi].transactions[0].to[1] ^= 0x01)),
        ("nonce", Box::new(move |c: &mut Vec<Block>| c[bi].transactions[0].nonce ^= 0x01)),
        ("merkle_root", Box::new(|c: &mut Vec<Block>| c[1].header.merkle_root[3] ^= 0x01)),
        ("parent_hash", Box::new(|c: &mut Vec<Block>| c[1].header.parent_hash[3] ^= 0x01)),
        ("timestamp", Box::new(|c: &mut Vec<Block>| c[1].header.timestamp = 0)),
        ("difficulty", Box::new(|c: &mut Vec<Block>| c[1].header.difficulty_bits += 2)),
        ("miner", Box::new(|c: &mut Vec<Block>| c[1].header.miner[5] ^= 0x01)),
        (
            "pow_nonce",
            Box::new(|c: &mut Vec<Block>| {
                // Land on a nonce that provably fails the target, so the
                // mutation always changes the block regardless of the draw.
                let bits = c[1].header.difficulty_bits;
                let mut cand = 0u64;
                loop {
                    c[1].header.nonce = cand;
                    if !meets_target(&c[1].hash(), bits) {
                        break;
                    }
                    cand += 1;
                }
            }),
        ),
    ];

    for (name, mutate) in mutations {
        let mut c = f.chain.clone();
        mutate(&mut c);
        assert!(!accepts(f, &c), "mutation of `{name}` was not rejected");
    }
}
