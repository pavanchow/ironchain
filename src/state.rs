//! Account-model world state and the block state-transition. No external crates.
//!
//! Ironchain uses an account model, address to (balance, nonce), rather than
//! UTXO. The account model pairs naturally with the one-time-signature scheme:
//! the nonce that orders an account's transactions is the same counter that
//! selects its signing leaf, so replay protection and one-time-key discipline
//! are a single check.

use std::collections::HashMap;

use crate::block::Block;
use crate::tx::Address;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Account {
    pub balance: u64,
    pub nonce: u64,
}

/// World state: balances and nonces keyed by address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub accounts: HashMap<Address, Account>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StateError {
    BadSignature,
    WrongNonce { expected: u64, got: u64 },
    InsufficientBalance { need: u64, have: u64 },
    AmountOverflow,
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::BadSignature => write!(f, "invalid transaction signature"),
            StateError::WrongNonce { expected, got } => {
                write!(f, "wrong nonce, expected {expected} got {got}")
            }
            StateError::InsufficientBalance { need, have } => {
                write!(f, "insufficient balance, need {need} have {have}")
            }
            StateError::AmountOverflow => write!(f, "amount plus fee overflowed"),
        }
    }
}

impl State {
    pub fn new() -> Self {
        State::default()
    }

    /// Seed initial balances (genesis allocation).
    pub fn with_allocations(alloc: &[(Address, u64)]) -> Self {
        let mut s = State::new();
        for (addr, bal) in alloc {
            s.accounts.insert(
                *addr,
                Account {
                    balance: *bal,
                    nonce: 0,
                },
            );
        }
        s
    }

    pub fn balance(&self, addr: &Address) -> u64 {
        self.accounts.get(addr).map(|a| a.balance).unwrap_or(0)
    }

    pub fn nonce(&self, addr: &Address) -> u64 {
        self.accounts.get(addr).map(|a| a.nonce).unwrap_or(0)
    }

    fn entry(&mut self, addr: &Address) -> &mut Account {
        self.accounts.entry(*addr).or_default()
    }

    /// Apply a whole block: coinbase reward plus every transaction, in order.
    /// The miner collects the fixed subsidy plus all transaction fees.
    pub fn apply_block(&mut self, block: &Block, subsidy: u64) -> Result<(), StateError> {
        let total_fees: u64 = block.transactions.iter().map(|t| t.fee).sum();
        let reward = subsidy.saturating_add(total_fees);
        {
            let miner = self.entry(&block.header.miner);
            miner.balance = miner.balance.saturating_add(reward);
        }
        for tx in &block.transactions {
            self.apply_tx(tx)?;
        }
        Ok(())
    }

    /// Apply a single transaction with full validation.
    pub fn apply_tx(&mut self, tx: &crate::tx::Transaction) -> Result<(), StateError> {
        if !tx.verify_signature() {
            return Err(StateError::BadSignature);
        }
        let sender = *self.accounts.get(&tx.from).unwrap_or(&Account::default());
        if sender.nonce != tx.nonce {
            return Err(StateError::WrongNonce {
                expected: sender.nonce,
                got: tx.nonce,
            });
        }
        let debit = tx
            .amount
            .checked_add(tx.fee)
            .ok_or(StateError::AmountOverflow)?;
        if sender.balance < debit {
            return Err(StateError::InsufficientBalance {
                need: debit,
                have: sender.balance,
            });
        }
        {
            let s = self.entry(&tx.from);
            s.balance -= debit;
            s.nonce += 1;
        }
        {
            let r = self.entry(&tx.to);
            r.balance = r.balance.saturating_add(tx.amount);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::compute_root;
    use crate::tx::build_signed;

    #[test]
    fn transfer_moves_balance() {
        let seed = [1u8; 32];
        let from = compute_root(&seed, 4);
        let to = [2u8; 32];
        let mut state = State::with_allocations(&[(from, 1000)]);
        let tx = build_signed(&seed, 4, from, to, 300, 10, 0);
        state.apply_tx(&tx).unwrap();
        assert_eq!(state.balance(&from), 690);
        assert_eq!(state.balance(&to), 300);
        assert_eq!(state.nonce(&from), 1);
    }

    #[test]
    fn overspend_rejected() {
        let seed = [4u8; 32];
        let from = compute_root(&seed, 4);
        let mut state = State::with_allocations(&[(from, 100)]);
        let tx = build_signed(&seed, 4, from, [5u8; 32], 200, 0, 0);
        assert!(matches!(
            state.apply_tx(&tx),
            Err(StateError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn replayed_nonce_rejected() {
        let seed = [6u8; 32];
        let from = compute_root(&seed, 4);
        let mut state = State::with_allocations(&[(from, 1000)]);
        let tx = build_signed(&seed, 4, from, [7u8; 32], 100, 0, 0);
        state.apply_tx(&tx).unwrap();
        // Replaying the same nonce-0 transaction fails.
        assert!(matches!(
            state.apply_tx(&tx),
            Err(StateError::WrongNonce { .. })
        ));
    }
}
