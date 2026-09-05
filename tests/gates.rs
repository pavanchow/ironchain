//! Correctness gates 2 to 4: signatures, Merkle inclusion, and fork choice.
//! Bounded for CI, seed/size controllable via IRONCHAIN_FUZZ_OPS / IRONCHAIN_SEED.

use ironchain::block::{Block, Header};
use ironchain::chain::{validate_chain, Blockchain, Config};
use ironchain::merkle;
use ironchain::rng::Rng;
use ironchain::sha256::sha256;
use ironchain::sig::{compute_root, sign, verify};
use ironchain::tx::Address;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

// ---- Gate 2: signatures ---------------------------------------------------

#[test]
fn signature_round_trip_and_bit_flips() {
    let ops = env_u64("IRONCHAIN_FUZZ_OPS", 6).max(4);
    let seed = env_u64("IRONCHAIN_SEED", 999);
    let mut rng = Rng::new(seed);

    let height = 3u32;
    let key_seed = [0x5au8; 32];
    let address = compute_root(&key_seed, height);
    let leaf_budget = 1u32 << height;

    for i in 0..ops.min(leaf_budget as u64) {
        let mut msg_src = [0u8; 32];
        rng.fill(&mut msg_src);
        let msg = sha256(&msg_src);
        let sig = sign(&key_seed, height, i as u32, &msg);

        // Round trip.
        assert!(verify(&address, &msg, &sig), "round trip failed at leaf {i}");

        // A single flipped bit in the message fails.
        let mut bad_msg = msg;
        let bit = (rng.below(256)) as usize;
        bad_msg[bit / 8] ^= 1 << (bit % 8);
        assert!(!verify(&address, &bad_msg, &sig), "flipped message verified");

        // A single flipped bit in the signature fails.
        let mut bad_sig = sig.clone();
        let idx = (rng.below(256)) as usize;
        bad_sig.reveals[idx][0] ^= 0x01;
        assert!(!verify(&address, &msg, &bad_sig), "flipped signature verified");
    }
}

#[test]
fn signature_known_answer_vector() {
    // SHA-256 known-answer vectors.
    assert_eq!(
        ironchain::to_hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        ironchain::to_hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // Signature scheme determinism: the address derived from a fixed seed is
    // stable, and a fixed message signs and verifies under it.
    let key_seed = [0x11u8; 32];
    let a1 = compute_root(&key_seed, 4);
    let a2 = compute_root(&key_seed, 4);
    assert_eq!(a1, a2);
    let msg = sha256(b"ironchain known answer");
    let sig = sign(&key_seed, 4, 0, &msg);
    assert!(verify(&a1, &msg, &sig));
}

// ---- Gate 3: Merkle inclusion --------------------------------------------

#[test]
fn merkle_inclusion_random_sizes() {
    let seed = env_u64("IRONCHAIN_SEED", 7);
    let mut rng = Rng::new(seed);

    // Include size 1 and several non-power-of-two sizes.
    let sizes = [1usize, 2, 3, 5, 6, 7, 9, 13, 16, 17];
    for &n in &sizes {
        let leaves: Vec<[u8; 32]> = (0..n)
            .map(|_| {
                let mut b = [0u8; 32];
                rng.fill(&mut b);
                merkle::hash_leaf(&b)
            })
            .collect();
        let root = merkle::root(&leaves);

        for i in 0..n {
            let proof = merkle::prove(&leaves, i).expect("proof exists");
            assert!(merkle::verify(&root, &leaves[i], &proof), "size {n} idx {i}");

            // A non-included leaf fails against this proof.
            let mut outsider = [0u8; 32];
            rng.fill(&mut outsider);
            let outsider = merkle::hash_leaf(&outsider);
            assert!(
                !merkle::verify(&root, &outsider, &proof),
                "non-included leaf verified at size {n} idx {i}"
            );
        }
    }
}

// ---- Gate 4: fork choice and reorg ---------------------------------------

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
    Block {
        header,
        transactions: vec![],
    }
}

#[test]
fn fork_choice_selects_most_work_and_state_matches() {
    let cfg = Config {
        genesis_difficulty: 8,
        subsidy: 50,
        retarget_interval: 0,
        target_spacing: 10,
    };
    let mut bc = Blockchain::new(cfg.clone(), vec![], 0);
    let miner_a = [0xa1u8; 32];
    let miner_b = [0xb2u8; 32];

    // Branch A: genesis -> a1 -> a2 (height 2).
    bc.mine_next(miner_a, 10).unwrap();
    bc.mine_next(miner_a, 20).unwrap();
    let tip_a = bc.best_tip;
    assert_eq!(bc.height(&tip_a), Some(2));

    // Branch B off genesis, extended to height 3 (more cumulative work).
    let g = bc.genesis_hash;
    let b1 = mine_child(&bc, g, miner_b, 11);
    assert!(!bc.add_block(b1.clone()).unwrap().became_tip);
    let b2 = mine_child(&bc, b1.hash(), miner_b, 12);
    assert!(!bc.add_block(b2.clone()).unwrap().became_tip);
    let b3 = mine_child(&bc, b2.hash(), miner_b, 13);
    let res = bc.add_block(b3.clone()).unwrap();

    // Deterministic reorg to branch B.
    assert!(res.became_tip);
    assert!(res.reorged);
    assert_eq!(bc.best_tip, b3.hash());

    // State on the winning branch matches an independent recomputation.
    let recomputed = validate_chain(&cfg, &[], &bc.best_chain()).unwrap();
    assert_eq!(bc.state(), recomputed);
    // Branch B mined three blocks of subsidy 50, branch A's rewards are gone.
    assert_eq!(bc.state().balance(&miner_b), 150);
    assert_eq!(bc.state().balance(&miner_a), 0);
}

#[test]
fn lighter_branch_does_not_reorg() {
    let cfg = Config {
        genesis_difficulty: 8,
        subsidy: 50,
        retarget_interval: 0,
        target_spacing: 10,
    };
    let mut bc = Blockchain::new(cfg, vec![], 0);
    let a = [1u8; 32];
    let b = [2u8; 32];
    bc.mine_next(a, 10).unwrap();
    bc.mine_next(a, 20).unwrap();
    let tip = bc.best_tip;

    // A single competing block off genesis has less work, no reorg.
    let g = bc.genesis_hash;
    let lone = mine_child(&bc, g, b, 11);
    let res = bc.add_block(lone).unwrap();
    assert!(!res.became_tip);
    assert_eq!(bc.best_tip, tip);
}
