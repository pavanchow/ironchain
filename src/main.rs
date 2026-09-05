//! Ironchain command-line demo.
//!
//! Mines a short chain with random valid transactions, prints it, shows wallet
//! balances, then tampers with a transaction and shows full-chain validation
//! rejecting the result.

use ironchain::block::{leading_zero_bits, Block};
use ironchain::chain::{validate_chain, Blockchain, Config};
use ironchain::rng::Rng;
use ironchain::sig::compute_root;
use ironchain::tx::{build_signed, Address};
use ironchain::to_hex;

const WALLET_HEIGHT: u32 = 4;

fn short(hash: &[u8; 32]) -> String {
    to_hex(&hash[..6])
}

fn print_block(bc: &Blockchain, block: &Block) {
    let h = block.hash();
    println!(
        "  block #{:<2} {}  parent {}  txs {:<2}  bits {:<2}  zeros {:<3}  nonce {}",
        bc.height(&h).unwrap(),
        short(&h),
        short(&block.header.parent_hash),
        block.transactions.len(),
        block.header.difficulty_bits,
        leading_zero_bits(&h),
        block.header.nonce,
    );
}

fn main() {
    let seed_base: u64 = std::env::var("IRONCHAIN_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2024);

    // Four wallets, each a hash-based key tree seeded deterministically.
    let seeds: Vec<[u8; 32]> = (0..4u8)
        .map(|i| {
            let mut s = [0u8; 32];
            s[0] = i;
            s[1] = (seed_base & 0xff) as u8;
            s[2] = (seed_base >> 8) as u8;
            s
        })
        .collect();
    let addrs: Vec<Address> = seeds.iter().map(|s| compute_root(s, WALLET_HEIGHT)).collect();
    let names = ["alice", "bob", "carol", "dave"];

    println!("Ironchain demo");
    println!("==============");
    println!("Wallets (address = Merkle root of a hash-based key tree):");
    for (i, a) in addrs.iter().enumerate() {
        println!("  {:<6} {}", names[i], short(a));
    }
    println!();

    let config = Config {
        genesis_difficulty: 12,
        subsidy: 100,
        retarget_interval: 0,
        target_spacing: 10,
    };
    // Fund alice at genesis so she can pay the others.
    let mut bc = Blockchain::new(config.clone(), vec![(addrs[0], 10_000)], 0);
    println!("Genesis mined:");
    print_block(&bc, &bc.get_block(&bc.genesis_hash).unwrap().clone());
    println!();

    let mut rng = Rng::new(seed_base);
    let mut nonces = [0u64; 4];

    println!("Mining blocks with random valid transactions:");
    let mut total_attempts = 0u64;
    for _ in 0..5 {
        // Queue a couple of random transfers alice -> someone she can pay.
        for _ in 0..2 {
            let from_i = 0usize; // alice holds the funds in this demo
            let mut to_i = (rng.below(4)) as usize;
            if to_i == from_i {
                to_i = (to_i + 1) % 4;
            }
            let amount = 100 + rng.below(400);
            let fee = rng.below(5);
            let tx = build_signed(
                &seeds[from_i],
                WALLET_HEIGHT,
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
        let (hash, attempts) = bc.mine_next(addrs[1], ts).unwrap();
        total_attempts += attempts;
        print_block(&bc, &bc.get_block(&hash).unwrap().clone());
    }
    println!("  total hashing attempts across mined blocks: {total_attempts}");
    println!();

    println!("Final balances:");
    let state = bc.state();
    for (i, a) in addrs.iter().enumerate() {
        println!(
            "  {:<6} balance {:<6} nonce {}",
            names[i],
            state.balance(a),
            state.nonce(a)
        );
    }
    println!();

    // Validate the honest chain.
    let chain = bc.best_chain();
    match validate_chain(&config, &bc.allocations, &chain) {
        Ok(_) => println!("Full-chain validation of the honest chain: ACCEPTED"),
        Err(e) => println!("Unexpected validation failure: {e}"),
    }

    // Tamper: bump an amount in the first non-empty block and revalidate.
    let mut tampered = chain.clone();
    let mut done = false;
    for block in tampered.iter_mut() {
        let bheight = bc.height(&block.hash()).unwrap_or(0);
        if let Some(tx) = block.transactions.first_mut() {
            println!(
                "\nTampering: block #{} tx amount {} -> {}",
                bheight,
                tx.amount,
                tx.amount + 1
            );
            tx.amount += 1;
            done = true;
            break;
        }
    }
    if done {
        match validate_chain(&config, &bc.allocations, &tampered) {
            Ok(_) => println!("Tampered chain validation: ACCEPTED (this would be a bug)"),
            Err(e) => println!("Tampered chain validation: REJECTED ({e})"),
        }
    }
}
