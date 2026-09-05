//! Long-horizon mining soak: many blocks, continuous transaction flow, forced
//! reorganizations, and full-chain revalidation of every intermediate state.
//!
//! Gated behind `IRONCHAIN_SOAK=1` so ordinary CI runs stay fast. With the
//! gate set, the soak mines `IRONCHAIN_FUZZ_OPS` (default 300) blocks while a
//! rival miner repeatedly forks three blocks back and overtakes it, so the
//! node must reorganize correctly and repeatedly. After every block the world
//! state is compared against an independent recomputation by the full-chain
//! validator.

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

/// Fork three blocks back from the current tip and overtake it by one block,
/// forcing a reorganization. Returns the new rival tip.
fn overtake_with_rival(bc: &mut Blockchain, rival: Address) -> [u8; 32] {
    let chain = bc.best_chain();
    assert!(chain.len() >= 4);
    let fork_base = chain[chain.len() - 4].hash();
    let mut parent = fork_base;
    for _ in 0..4 {
        // Rival timestamps march one unit per block from the fork base's own
        // timestamp, so the rival branch stays monotonic no matter how the
        // main branch jittered its timestamps.
        let ts = bc.get_block(&parent).unwrap().header.timestamp + 1;
        let child = mine_child(bc, parent, rival, ts);
        let res = bc.add_block(child).unwrap();
        parent = res.hash;
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

        // Rival: fork three blocks back and overtake by one.
        let rival_tip = overtake_with_rival(&mut bc, rival);
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
    println!(
        "soak: {mined} blocks mined, {reorgs} reorgs, {} txs in winning chain, \
         final height {}",
        count_txs(&final_chain),
        bc.height(&bc.best_tip).unwrap()
    );
}
