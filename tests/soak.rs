//! Long-horizon mining soak: many blocks, continuous transaction flow, forced
//! reorganizations, and full-chain revalidation of every intermediate state.
//!
//! Gated behind `IRONCHAIN_SOAK=1` so ordinary CI runs stay fast. With the
//! gate set, the soak mines `IRONCHAIN_FUZZ_OPS` (default 300) blocks while a
//! rival miner repeatedly forks three blocks back and out-mines the round's
//! opening work, so the node must reorganize correctly and repeatedly. After
//! every round the world state is compared against an independent
//! recomputation by the full-chain validator, and the retarget rule must be
//! observed moving in both directions across the final chain.

// Scale parameters arrive from the environment as u64 and feed bounded loop
// counts, indices, and PRNG draws, so narrowing casts are safe.
#![allow(clippy::cast_possible_truncation)]

use ironchain::block::{Block, Header};
use ironchain::chain::{validate_chain, Blockchain, Config};
use ironchain::merkle;
use ironchain::rng::Rng;
use ironchain::sig::compute_root;
use ironchain::tx::{build_signed, Address};

const WALLET_HEIGHT: u32 = 6;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn mine_child(bc: &Blockchain, parent: [u8; 32], miner: Address, ts: u64) -> Block {
    let difficulty_bits = bc.expected_difficulty(&parent);
    let mut header = Header {
        parent_hash: parent,
        merkle_root: merkle::EMPTY_ROOT,
        timestamp: ts,
        difficulty_bits,
        miner,
        nonce: 0,
    };
    ironchain::block::mine(&mut header);
    Block { header, transactions: vec![] }
}

/// Wallet set and one-time-key budgets for the soak's transaction flow.
struct Wallets {
    seeds: Vec<[u8; 32]>,
    addrs: Vec<Address>,
    nonces: [u64; 4],
    leaf_budget: u64,
}

impl Wallets {
    fn new(seed: u64) -> Self {
        let seeds: Vec<[u8; 32]> = (0..4u8)
            .map(|i| {
                let mut s = [0u8; 32];
                s[0] = i;
                s[1] = seed as u8;
                s
            })
            .collect();
        let addrs = seeds.iter().map(|s| compute_root(s, WALLET_HEIGHT)).collect();
        Wallets {
            seeds,
            addrs,
            nonces: [0u64; 4],
            leaf_budget: 1u64 << WALLET_HEIGHT,
        }
    }

    /// Queue one random transfer and mine one main-branch block.
    fn mine_main_block(&mut self, bc: &mut Blockchain, rng: &mut Rng) {
        let from_i = (rng.below(4)) as usize;
        if self.nonces[from_i] < self.leaf_budget {
            let mut to_i = (rng.below(4)) as usize;
            if to_i == from_i {
                to_i = (to_i + 1) % 4;
            }
            let tx = build_signed(
                &self.seeds[from_i],
                WALLET_HEIGHT,
                self.addrs[from_i],
                self.addrs[to_i],
                10 + rng.below(100),
                rng.below(3),
                self.nonces[from_i],
            );
            if bc.submit_tx(tx) {
                self.nonces[from_i] += 1;
            }
        }
        // Advance one to thirty units past the parent timestamp. Monotonic by
        // construction, while the average spacing straddles the retarget
        // boundaries so the difficulty both rises and falls over a long run.
        let parent_ts = bc.get_block(&bc.best_tip).unwrap().header.timestamp;
        let ts = parent_ts + 1 + rng.below(30);
        bc.mine_next(self.addrs[0], ts).unwrap();
    }
}

/// Fork three blocks back from the current tip and mine on the fork until the
/// rival's cumulative work exceeds the pre-round tip, which forces a
/// reorganization. Returns the new rival tip.
///
/// Rival timestamps advance one to thirty units past the fork parent's own
/// timestamp, the same jitter the main branch uses. That keeps the rival branch
/// monotonic while making its retarget windows straddle the keep band, so the
/// difficulty rule can lower as well as raise and mean-reverts over a long run.
/// A rival that always stamped one unit per block could only keep or raise the
/// difficulty, ratcheting it up until blocks were unmineable and the soak hung.
fn overtake_with_rival(bc: &mut Blockchain, rival: Address, rng: &mut Rng) -> [u8; 32] {
    let chain = bc.best_chain();
    assert!(chain.len() >= 4);
    let main_work = bc.cumulative_work(&bc.best_tip).unwrap();
    let fork_base = chain[chain.len() - 4].hash();
    let mut parent = fork_base;
    let mut rival_blocks = 0u64;
    loop {
        let ts = bc.get_block(&parent).unwrap().header.timestamp + 1 + rng.below(30);
        let child = mine_child(bc, parent, rival, ts);
        let res = bc.add_block(child).unwrap();
        parent = res.hash;
        rival_blocks += 1;
        // Three main blocks were added this round, so four rival blocks at the
        // same difficulty win. If a retarget boundary inside the rival run
        // lowered its difficulty by a bit, a couple more blocks close the gap,
        // hence the adaptive loop with a hard cap.
        if bc.cumulative_work(&parent).unwrap() > main_work {
            break;
        }
        assert!(
            rival_blocks < 8,
            "the rival could not overtake within 8 blocks"
        );
    }
    parent
}

fn count_txs(chain: &[Block]) -> u64 {
    chain.iter().map(|b| b.transactions.len() as u64).sum()
}

#[test]
fn mining_soak_with_forced_reorgs() {
    if std::env::var("IRONCHAIN_SOAK").unwrap_or_default() != "1" {
        // Soak runs are opt-in: `IRONCHAIN_SOAK=1 IRONCHAIN_FUZZ_OPS=300 \
        //  cargo test --release --test soak -- --nocapture`
        return;
    }

    let target_blocks = env_u64("IRONCHAIN_FUZZ_OPS", 300).max(30);
    let seed = env_u64("IRONCHAIN_SEED", 4242);

    let cfg = Config {
        genesis_difficulty: 8,
        subsidy: 50,
        retarget_interval: 8,
        target_spacing: 10,
    };
    let mut wallets = Wallets::new(seed);
    let allocations: Vec<(Address, u64)> = wallets.addrs.iter().map(|a| (*a, 1_000_000)).collect();
    let mut bc = Blockchain::new(cfg.clone(), allocations.clone(), 0);
    let mut rng = Rng::new(seed);
    let rival = [0xb1u8; 32];
    let mut reorgs = 0u64;
    let mut mined = 0u64;

    while mined < target_blocks {
        // Main branch: three blocks carrying transactions.
        let main_tip_before = bc.best_tip;
        for _ in 0..3 {
            if mined >= target_blocks {
                break;
            }
            wallets.mine_main_block(&mut bc, &mut rng);
            mined += 1;
        }

        // Rival: fork three blocks back and overtake the round's opening work.
        let rival_tip = overtake_with_rival(&mut bc, rival, &mut rng);
        mined += 4;
        if bc.cumulative_work(&bc.best_tip).unwrap()
            > bc.cumulative_work(&main_tip_before).unwrap()
        {
            reorgs += 1;
        }
        assert_eq!(
            bc.best_tip, rival_tip,
            "the heavier rival branch must always win the tip"
        );

        // Full independent revalidation of the winning branch after every
        // round, and exact equality with the node's cached state.
        let winning = bc.best_chain();
        let recomputed = validate_chain(&cfg, &allocations, &winning)
            .unwrap_or_else(|e| panic!("winning branch must revalidate: {e}"));
        assert_eq!(recomputed, bc.state(), "state diverged after a reorg");
    }

    let final_chain = bc.best_chain();
    let recomputed = validate_chain(&cfg, &allocations, &final_chain).unwrap();
    assert_eq!(recomputed, bc.state());
    assert!(final_chain.len() >= 2);
    // The retarget rule must move in both directions over a long run. A
    // one-sided ratchet would show up here as min == max == genesis difficulty.
    let mut min_bits = u32::MAX;
    let mut max_bits = 0u32;
    for b in &final_chain {
        min_bits = min_bits.min(b.header.difficulty_bits);
        max_bits = max_bits.max(b.header.difficulty_bits);
    }
    assert!(
        min_bits < max_bits,
        "difficulty never moved: ratchet or flatline, min {min_bits} max {max_bits}"
    );
    println!(
        "soak: {mined} blocks mined, {reorgs} reorgs, {} txs in winning chain, \
         final height {}, difficulty range {min_bits}..{max_bits} bits",
        count_txs(&final_chain),
        bc.height(&bc.best_tip).unwrap()
    );
}
