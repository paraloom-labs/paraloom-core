//! On-chain validator quorum for settlement (#260).
//!
//! Settlement (`withdraw` / `shielded_transfer`) is authorized by a
//! supermajority of registered, active validators **co-signing the transaction**
//! — not a single authority key. The Solana runtime verifies the signatures
//! natively; this module only confirms, for each counted member, that:
//!   - its wallet signed this transaction (`is_signer`),
//!   - it owns the canonical, program-owned [`ValidatorAccount`] PDA
//!     (`seeds = [b"validator", wallet]`) and that account is `is_active`,
//! and that each validator is counted at most once. Relying on the runtime for
//! signature verification keeps the on-chain attack surface minimal.
//!
//! `quorum_accounts` are `(validator_wallet, validator_pda)` pairs passed via
//! `remaining_accounts`. Called by `withdraw` and `shielded_transfer`. The
//! node-side co-signing round that produces a real multi-validator quorum is
//! tracked separately in #260 (this enforces it on-chain).

use crate::{BridgeError, ValidatorAccount, ValidatorRegistry};
use anchor_lang::prelude::*;

/// BFT supermajority threshold: strictly more than 2/3 of the active set,
/// i.e. `floor(2N/3) + 1`. With 0 active validators the threshold is 1, so no
/// settlement can be authorized by an empty set.
pub fn quorum_threshold(active_validators: u64) -> u64 {
    active_validators.saturating_mul(2) / 3 + 1
}

/// Verify that a supermajority of registered, active validators co-signed this
/// transaction. Returns [`BridgeError::QuorumNotMet`] if fewer than
/// [`quorum_threshold`] distinct active validators are present and signing.
pub fn verify_validator_quorum(
    program_id: &Pubkey,
    registry: &ValidatorRegistry,
    quorum_accounts: &[AccountInfo],
) -> Result<()> {
    let threshold = quorum_threshold(registry.active_validators);
    let mut counted: u64 = 0;
    let mut seen: Vec<Pubkey> = Vec::new();

    for pair in quorum_accounts.chunks(2) {
        if pair.len() != 2 {
            break;
        }
        let wallet = &pair[0];
        let pda = &pair[1];

        // The wallet must have signed this transaction.
        if !wallet.is_signer {
            continue;
        }
        // The PDA must be one of our program's accounts...
        if pda.owner != program_id {
            continue;
        }
        // ...and the canonical validator PDA for this exact wallet, so a fake
        // "active" account cannot be injected for a signer.
        let (expected, _) =
            Pubkey::find_program_address(&[b"validator", wallet.key.as_ref()], program_id);
        if expected != *pda.key {
            continue;
        }
        let data = pda.try_borrow_data()?;
        let validator = match ValidatorAccount::try_deserialize(&mut &data[..]) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !validator.is_active || validator.validator != *wallet.key {
            continue;
        }
        // Count each validator at most once.
        if seen.contains(wallet.key) {
            continue;
        }
        seen.push(*wallet.key);
        counted += 1;
    }

    require!(counted >= threshold, BridgeError::QuorumNotMet);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prog() -> Pubkey {
        crate::ID
    }

    fn registry(active: u64) -> ValidatorRegistry {
        ValidatorRegistry {
            authority: prog(),
            total_validators: active,
            active_validators: active,
            minimum_stake: 0,
        }
    }

    fn validator_data(wallet: Pubkey, is_active: bool) -> Vec<u8> {
        let v = ValidatorAccount {
            validator: wallet,
            stake_amount: 1_000_000_000,
            reputation_score: 0,
            total_tasks_verified: 0,
            successful_verifications: 0,
            registered_at: 0,
            last_active: 0,
            is_active,
            pending_rewards: 0,
            total_earnings: 0,
            times_slashed: 0,
        };
        let mut buf = Vec::new();
        v.try_serialize(&mut buf).unwrap();
        buf
    }

    #[test]
    fn threshold_is_bft_supermajority() {
        // floor(2N/3) + 1 — strictly more than two thirds.
        assert_eq!(quorum_threshold(0), 1);
        assert_eq!(quorum_threshold(1), 1);
        assert_eq!(quorum_threshold(2), 2);
        assert_eq!(quorum_threshold(3), 3);
        assert_eq!(quorum_threshold(4), 3);
        assert_eq!(quorum_threshold(5), 4);
        assert_eq!(quorum_threshold(7), 5);
        assert_eq!(quorum_threshold(10), 7);
    }

    #[test]
    fn empty_quorum_is_rejected() {
        assert!(verify_validator_quorum(&prog(), &registry(3), &[]).is_err());
    }

    #[test]
    fn supermajority_accepts() {
        let p = prog();
        let sys = anchor_lang::solana_program::system_program::ID;
        // 2 active validators, both sign → threshold 2 met.
        let w0 = Pubkey::new_unique();
        let w1 = Pubkey::new_unique();
        let (pda0, _) = Pubkey::find_program_address(&[b"validator", w0.as_ref()], &p);
        let (pda1, _) = Pubkey::find_program_address(&[b"validator", w1.as_ref()], &p);
        let mut d0 = validator_data(w0, true);
        let mut d1 = validator_data(w1, true);
        let (mut l0, mut l1, mut lp0, mut lp1) = (0u64, 0u64, 0u64, 0u64);
        let (mut e0, mut e1) = ([0u8; 0], [0u8; 0]);
        let s0 = AccountInfo::new(&w0, true, false, &mut l0, &mut e0, &sys, false, 0);
        let a0 = AccountInfo::new(&pda0, false, false, &mut lp0, &mut d0, &p, false, 0);
        let s1 = AccountInfo::new(&w1, true, false, &mut l1, &mut e1, &sys, false, 0);
        let a1 = AccountInfo::new(&pda1, false, false, &mut lp1, &mut d1, &p, false, 0);
        let accts = [s0, a0, s1, a1];
        assert!(verify_validator_quorum(&p, &registry(2), &accts).is_ok());
    }

    #[test]
    fn sub_threshold_is_rejected() {
        let p = prog();
        let sys = anchor_lang::solana_program::system_program::ID;
        // 3 active validators but only 1 signs → threshold 3 not met.
        let w0 = Pubkey::new_unique();
        let (pda0, _) = Pubkey::find_program_address(&[b"validator", w0.as_ref()], &p);
        let mut d0 = validator_data(w0, true);
        let (mut l0, mut lp0) = (0u64, 0u64);
        let mut e0 = [0u8; 0];
        let s0 = AccountInfo::new(&w0, true, false, &mut l0, &mut e0, &sys, false, 0);
        let a0 = AccountInfo::new(&pda0, false, false, &mut lp0, &mut d0, &p, false, 0);
        let accts = [s0, a0];
        assert!(verify_validator_quorum(&p, &registry(3), &accts).is_err());
    }

    #[test]
    fn non_signer_is_not_counted() {
        let p = prog();
        let sys = anchor_lang::solana_program::system_program::ID;
        let w0 = Pubkey::new_unique();
        let (pda0, _) = Pubkey::find_program_address(&[b"validator", w0.as_ref()], &p);
        let mut d0 = validator_data(w0, true);
        let (mut l0, mut lp0) = (0u64, 0u64);
        let mut e0 = [0u8; 0];
        // is_signer = false → must not count, registry needs 1.
        let s0 = AccountInfo::new(&w0, false, false, &mut l0, &mut e0, &sys, false, 0);
        let a0 = AccountInfo::new(&pda0, false, false, &mut lp0, &mut d0, &p, false, 0);
        let accts = [s0, a0];
        assert!(verify_validator_quorum(&p, &registry(1), &accts).is_err());
    }

    #[test]
    fn inactive_validator_is_not_counted() {
        let p = prog();
        let sys = anchor_lang::solana_program::system_program::ID;
        let w0 = Pubkey::new_unique();
        let (pda0, _) = Pubkey::find_program_address(&[b"validator", w0.as_ref()], &p);
        let mut d0 = validator_data(w0, false); // inactive
        let (mut l0, mut lp0) = (0u64, 0u64);
        let mut e0 = [0u8; 0];
        let s0 = AccountInfo::new(&w0, true, false, &mut l0, &mut e0, &sys, false, 0);
        let a0 = AccountInfo::new(&pda0, false, false, &mut lp0, &mut d0, &p, false, 0);
        let accts = [s0, a0];
        assert!(verify_validator_quorum(&p, &registry(1), &accts).is_err());
    }

    #[test]
    fn wrong_pda_is_not_counted() {
        let p = prog();
        let sys = anchor_lang::solana_program::system_program::ID;
        let w0 = Pubkey::new_unique();
        // PDA derived for a DIFFERENT wallet → injected fake account.
        let other = Pubkey::new_unique();
        let (bad_pda, _) = Pubkey::find_program_address(&[b"validator", other.as_ref()], &p);
        let mut d0 = validator_data(w0, true);
        let (mut l0, mut lp0) = (0u64, 0u64);
        let mut e0 = [0u8; 0];
        let s0 = AccountInfo::new(&w0, true, false, &mut l0, &mut e0, &sys, false, 0);
        let a0 = AccountInfo::new(&bad_pda, false, false, &mut lp0, &mut d0, &p, false, 0);
        let accts = [s0, a0];
        assert!(verify_validator_quorum(&p, &registry(1), &accts).is_err());
    }

    #[test]
    fn duplicate_validator_counts_once() {
        let p = prog();
        let sys = anchor_lang::solana_program::system_program::ID;
        // Same validator passed twice; registry needs 2 → one distinct counted < 2.
        let w0 = Pubkey::new_unique();
        let (pda0, _) = Pubkey::find_program_address(&[b"validator", w0.as_ref()], &p);
        let mut d0 = validator_data(w0, true);
        let mut d0b = validator_data(w0, true);
        let (mut l0, mut l0b, mut lp0, mut lp0b) = (0u64, 0u64, 0u64, 0u64);
        let (mut e0, mut e0b) = ([0u8; 0], [0u8; 0]);
        let s0 = AccountInfo::new(&w0, true, false, &mut l0, &mut e0, &sys, false, 0);
        let a0 = AccountInfo::new(&pda0, false, false, &mut lp0, &mut d0, &p, false, 0);
        let s0b = AccountInfo::new(&w0, true, false, &mut l0b, &mut e0b, &sys, false, 0);
        let a0b = AccountInfo::new(&pda0, false, false, &mut lp0b, &mut d0b, &p, false, 0);
        let accts = [s0, a0, s0b, a0b];
        assert!(verify_validator_quorum(&p, &registry(2), &accts).is_err());
    }
}
