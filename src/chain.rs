//! The blockchain: genesis, block connection, difficulty retargeting, mempool,
//! mining, fork choice by most cumulative work, and chain reorganization. No
//! external crates.
//!
//! Fork choice selects the tip with the greatest cumulative proof of work. When
//! a heavier branch appears the active tip switches to it, and world state is
//! recomputed by replaying the winning branch from genesis, which is a reorg.

use std::collections::HashMap;

use crate::block::{block_work, Block, Header};
use crate::merkle;
use crate::state::{State, StateError};
use crate::tx::{Address, Transaction};

#[derive(Clone, Debug)]
pub struct Config {
    pub genesis_difficulty: u32,
    pub subsidy: u64,
    pub retarget_interval: u64,
    pub target_spacing: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            genesis_difficulty: 12,
            subsidy: 50,
            retarget_interval: 8,
            target_spacing: 10,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    UnknownParent,
    BadParentLink,
    BadPow,
    BadMerkleRoot,
    BadDifficulty { expected: u32, got: u32 },
    NonMonotonicTimestamp,
    EmptyChain,
    BadGenesis,
    State(StateError),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::UnknownParent => write!(f, "parent block not known"),
            ChainError::BadParentLink => write!(f, "parent hash does not match parent block"),
            ChainError::BadPow => write!(f, "block hash does not meet difficulty target"),
            ChainError::BadMerkleRoot => write!(f, "merkle root does not match transactions"),
            ChainError::BadDifficulty { expected, got } => {
                write!(f, "wrong difficulty, expected {expected} got {got}")
            }
            ChainError::NonMonotonicTimestamp => write!(f, "timestamp not after parent"),
            ChainError::EmptyChain => write!(f, "chain has no blocks"),
            ChainError::BadGenesis => write!(f, "invalid genesis block"),
            ChainError::State(e) => write!(f, "state transition failed: {e}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Meta {
    height: u64,
    cum_work: u128,
}

pub struct Blockchain {
    pub config: Config,
    pub allocations: Vec<(Address, u64)>,
    blocks: HashMap<[u8; 32], Block>,
    meta: HashMap<[u8; 32], Meta>,
    pub genesis_hash: [u8; 32],
    pub best_tip: [u8; 32],
    pub mempool: Vec<Transaction>,
}

/// Outcome of adding a block.
#[derive(Debug, PartialEq, Eq)]
pub struct AddResult {
    pub hash: [u8; 32],
    pub became_tip: bool,
    pub reorged: bool,
}

fn clamp_bits(bits: i64) -> u32 {
    bits.clamp(1, 240) as u32
}

impl Blockchain {
    /// Create a chain with a mined genesis block.
    pub fn new(config: Config, allocations: Vec<(Address, u64)>, genesis_timestamp: u64) -> Self {
        let mut header = Header {
            parent_hash: [0u8; 32],
            merkle_root: merkle::EMPTY_ROOT,
            timestamp: genesis_timestamp,
            difficulty_bits: config.genesis_difficulty,
            miner: [0u8; 32],
            nonce: 0,
        };
        crate::block::mine(&mut header);
        let genesis = Block {
            header,
            transactions: Vec::new(),
        };
        let ghash = genesis.hash();
        let mut blocks = HashMap::new();
        let mut meta = HashMap::new();
        blocks.insert(ghash, genesis);
        meta.insert(
            ghash,
            Meta {
                height: 0,
                cum_work: block_work(config.genesis_difficulty),
            },
        );
        Blockchain {
            config,
            allocations,
            blocks,
            meta,
            genesis_hash: ghash,
            best_tip: ghash,
            mempool: Vec::new(),
        }
    }

    pub fn get_block(&self, hash: &[u8; 32]) -> Option<&Block> {
        self.blocks.get(hash)
    }

    pub fn height(&self, hash: &[u8; 32]) -> Option<u64> {
        self.meta.get(hash).map(|m| m.height)
    }

    pub fn cumulative_work(&self, hash: &[u8; 32]) -> Option<u128> {
        self.meta.get(hash).map(|m| m.cum_work)
    }

    /// The active best chain from genesis to the current tip.
    pub fn best_chain(&self) -> Vec<Block> {
        self.chain_to(&self.best_tip)
    }

    fn chain_to(&self, tip: &[u8; 32]) -> Vec<Block> {
        let mut out = Vec::new();
        let mut cur = *tip;
        loop {
            let b = self.blocks.get(&cur).expect("known block");
            out.push(b.clone());
            if cur == self.genesis_hash {
                break;
            }
            cur = b.header.parent_hash;
        }
        out.reverse();
        out
    }

    /// Walk back `k` blocks from `hash`, returning the ancestor's block.
    fn ancestor(&self, hash: &[u8; 32], k: u64) -> &Block {
        let mut cur = *hash;
        for _ in 0..k {
            let b = &self.blocks[&cur];
            cur = b.header.parent_hash;
        }
        &self.blocks[&cur]
    }

    /// Expected difficulty for the child of `parent_hash`.
    pub fn expected_difficulty(&self, parent_hash: &[u8; 32]) -> u32 {
        let pm = self.meta[parent_hash];
        let parent = &self.blocks[parent_hash];
        let child_height = pm.height + 1;
        let parent_bits = parent.header.difficulty_bits;
        let interval = self.config.retarget_interval;
        if interval == 0 || !child_height.is_multiple_of(interval) {
            return parent_bits;
        }
        let anchor = self.ancestor(parent_hash, interval - 1);
        let actual = parent.header.timestamp.saturating_sub(anchor.header.timestamp);
        let expected = self.config.target_spacing * (interval - 1);
        retarget(parent_bits, actual, expected)
    }

    /// World state after replaying the branch ending at `tip`.
    pub fn state_at(&self, tip: &[u8; 32]) -> State {
        let mut st = State::with_allocations(&self.allocations);
        for block in self.chain_to(tip) {
            st.apply_block(&block, self.config.subsidy)
                .expect("stored blocks are valid");
        }
        st
    }

    /// World state at the current best tip.
    pub fn state(&self) -> State {
        self.state_at(&self.best_tip)
    }

    /// Validate and connect a block. On success, updates fork choice.
    pub fn add_block(&mut self, block: Block) -> Result<AddResult, ChainError> {
        let ph = block.header.parent_hash;
        let pm = *self.meta.get(&ph).ok_or(ChainError::UnknownParent)?;
        let parent = self.blocks[&ph].clone();

        if block.header.parent_hash != parent.hash() {
            return Err(ChainError::BadParentLink);
        }
        if !block.pow_valid() {
            return Err(ChainError::BadPow);
        }
        if !block.merkle_root_valid() {
            return Err(ChainError::BadMerkleRoot);
        }
        let expected = self.expected_difficulty(&ph);
        if block.header.difficulty_bits != expected {
            return Err(ChainError::BadDifficulty {
                expected,
                got: block.header.difficulty_bits,
            });
        }
        if block.header.timestamp < parent.header.timestamp {
            return Err(ChainError::NonMonotonicTimestamp);
        }

        // State-transition validity, applied on the parent's state.
        let mut st = self.state_at(&ph);
        st.apply_block(&block, self.config.subsidy)
            .map_err(ChainError::State)?;

        let height = pm.height + 1;
        let cum_work = pm.cum_work + block_work(block.header.difficulty_bits);
        let hash = block.hash();
        self.blocks.insert(hash, block);
        self.meta.insert(hash, Meta { height, cum_work });

        let old_tip = self.best_tip;
        let best_work = self.meta[&old_tip].cum_work;
        let mut became_tip = false;
        let mut reorged = false;
        if cum_work > best_work {
            became_tip = true;
            reorged = ph != old_tip;
            self.best_tip = hash;
        }
        Ok(AddResult {
            hash,
            became_tip,
            reorged,
        })
    }

    /// Add a transaction to the mempool if its signature is well formed.
    pub fn submit_tx(&mut self, tx: Transaction) -> bool {
        if !tx.verify_signature() {
            return false;
        }
        self.mempool.push(tx);
        true
    }

    /// Select mempool transactions valid on top of the current tip state.
    fn select_transactions(&self) -> Vec<Transaction> {
        let mut working = self.state();
        let mut chosen = Vec::new();
        for tx in &self.mempool {
            if working.apply_tx(tx).is_ok() {
                chosen.push(tx.clone());
            }
        }
        chosen
    }

    /// Assemble, mine, connect a block on the current tip, and clear the
    /// included transactions from the mempool. Returns the block hash and the
    /// number of hashing attempts.
    pub fn mine_next(
        &mut self,
        miner: Address,
        timestamp: u64,
    ) -> Result<([u8; 32], u64), ChainError> {
        let parent = self.best_tip;
        let difficulty_bits = self.expected_difficulty(&parent);
        let txs = self.select_transactions();
        let leaves: Vec<[u8; 32]> = txs
            .iter()
            .map(|t| merkle::hash_leaf(&t.to_bytes()))
            .collect();
        let merkle_root = merkle::root(&leaves);
        let mut header = Header {
            parent_hash: parent,
            merkle_root,
            timestamp,
            difficulty_bits,
            miner,
            nonce: 0,
        };
        let attempts = crate::block::mine(&mut header);
        let block = Block {
            header,
            transactions: txs.clone(),
        };
        let result = self.add_block(block)?;
        let included: std::collections::HashSet<[u8; 32]> = txs.iter().map(|t| t.id()).collect();
        self.mempool.retain(|t| !included.contains(&t.id()));
        Ok((result.hash, attempts))
    }
}

/// Adjust difficulty bits given the actual and expected timespans, clamped to a
/// single bit of change per retarget.
fn retarget(parent_bits: u32, actual: u64, expected: u64) -> u32 {
    if expected == 0 {
        return parent_bits;
    }
    if actual < expected / 2 {
        clamp_bits(parent_bits as i64 + 1)
    } else if actual > expected * 2 {
        clamp_bits(parent_bits as i64 - 1)
    } else {
        parent_bits
    }
}

/// Difficulty expected for the block at position `i` of a linear chain.
fn expected_bits_linear(chain: &[Block], i: usize, cfg: &Config) -> u32 {
    let parent_bits = chain[i - 1].header.difficulty_bits;
    let interval = cfg.retarget_interval;
    if interval == 0 || !(i as u64).is_multiple_of(interval) {
        return parent_bits;
    }
    let anchor = i - (interval as usize - 1);
    let actual = chain[i - 1]
        .header
        .timestamp
        .saturating_sub(chain[anchor].header.timestamp);
    let expected = cfg.target_spacing * (interval - 1);
    retarget(parent_bits, actual, expected)
}

/// Validate an explicit linear chain (genesis first) from scratch and return the
/// resulting world state. This is the full-chain validator used by the tamper
/// oracle: it re-derives every check rather than trusting stored metadata.
pub fn validate_chain(
    cfg: &Config,
    allocations: &[(Address, u64)],
    chain: &[Block],
) -> Result<State, ChainError> {
    if chain.is_empty() {
        return Err(ChainError::EmptyChain);
    }
    let genesis = &chain[0];
    if genesis.header.parent_hash != [0u8; 32] {
        return Err(ChainError::BadGenesis);
    }
    if !genesis.pow_valid() || !genesis.merkle_root_valid() {
        return Err(ChainError::BadGenesis);
    }
    let mut st = State::with_allocations(allocations);
    st.apply_block(genesis, cfg.subsidy)
        .map_err(ChainError::State)?;

    for i in 1..chain.len() {
        let b = &chain[i];
        let parent = &chain[i - 1];
        if b.header.parent_hash != parent.hash() {
            return Err(ChainError::BadParentLink);
        }
        if !b.pow_valid() {
            return Err(ChainError::BadPow);
        }
        if !b.merkle_root_valid() {
            return Err(ChainError::BadMerkleRoot);
        }
        let expected = expected_bits_linear(chain, i, cfg);
        if b.header.difficulty_bits != expected {
            return Err(ChainError::BadDifficulty {
                expected,
                got: b.header.difficulty_bits,
            });
        }
        if b.header.timestamp < parent.header.timestamp {
            return Err(ChainError::NonMonotonicTimestamp);
        }
        st.apply_block(b, cfg.subsidy).map_err(ChainError::State)?;
    }
    Ok(st)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::compute_root;
    use crate::tx::build_signed;

    fn test_config() -> Config {
        Config {
            genesis_difficulty: 8,
            subsidy: 50,
            retarget_interval: 0,
            target_spacing: 10,
        }
    }

    #[test]
    fn mine_and_grow() {
        let seed = [1u8; 32];
        let addr = compute_root(&seed, 4);
        let mut bc = Blockchain::new(test_config(), vec![(addr, 1000)], 0);
        let miner = [9u8; 32];
        let (_h, _a) = bc.mine_next(miner, 10).unwrap();
        assert_eq!(bc.height(&bc.best_tip), Some(1));
        assert_eq!(bc.state().balance(&miner), 50);
    }

    #[test]
    fn tx_flows_through_mempool_into_block() {
        let seed = [2u8; 32];
        let addr = compute_root(&seed, 4);
        let mut bc = Blockchain::new(test_config(), vec![(addr, 1000)], 0);
        let to = [7u8; 32];
        let tx = build_signed(&seed, 4, addr, to, 200, 5, 0);
        assert!(bc.submit_tx(tx));
        bc.mine_next([9u8; 32], 10).unwrap();
        assert_eq!(bc.state().balance(&to), 200);
        assert_eq!(bc.state().balance(&addr), 795);
        assert!(bc.mempool.is_empty());
    }

    #[test]
    fn heavier_branch_triggers_reorg() {
        // Build a base, fork it, and make the fork heavier.
        let cfg = test_config();
        let mut bc = Blockchain::new(cfg.clone(), vec![], 0);
        let a = [1u8; 32];
        let b = [2u8; 32];

        // Branch 1: two blocks mined onto genesis.
        let (h1, _) = bc.mine_next(a, 10).unwrap();
        let (_h2, _) = bc.mine_next(a, 20).unwrap();
        assert_eq!(bc.height(&bc.best_tip), Some(2));

        // Branch 2: build off genesis directly to create a competing fork.
        let g = bc.genesis_hash;
        let block_b1 = mine_child(&bc, g, b, 11);
        let r1 = bc.add_block(block_b1.clone()).unwrap();
        assert!(!r1.became_tip); // equal-or-less work, tip unchanged

        // Extend branch 2 to height 3 so it has more cumulative work.
        let block_b2 = mine_child(&bc, block_b1.hash(), b, 12);
        bc.add_block(block_b2.clone()).unwrap();
        let block_b3 = mine_child(&bc, block_b2.hash(), b, 13);
        let r3 = bc.add_block(block_b3.clone()).unwrap();
        assert!(r3.became_tip);
        assert!(r3.reorged);
        assert_eq!(bc.best_tip, block_b3.hash());

        // State matches an independent recomputation on the winning branch.
        let recomputed = validate_chain(&cfg, &[], &bc.best_chain()).unwrap();
        assert_eq!(bc.state(), recomputed);
        assert_eq!(bc.state().balance(&b), 150);
        assert_eq!(bc.state().balance(&a), 0);
        // Both branches forked from genesis.
        assert_eq!(bc.get_block(&h1).unwrap().header.parent_hash, g);
        assert_eq!(block_b1.header.parent_hash, g);
    }

    // Helper to mine a block onto an explicit parent (for building forks).
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
        crate::block::mine(&mut header);
        Block {
            header,
            transactions: vec![],
        }
    }
}
