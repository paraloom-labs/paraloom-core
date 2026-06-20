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

/// BFT supermajority threshold: strictly more than 2/3 of the active validator
/// STAKE, i.e. `floor(2·stake/3) + 1`. With 0 active stake the threshold is 1,
/// so no settlement can be authorized by an empty (or zero-stake) set. Weighting
/// by stake rather than head count is what stops a permissionless registry from
/// being Sybil-forged with many tiny validators.
pub fn quorum_threshold(total_active_stake: u64) -> u64 {
    total_active_stake.saturating_mul(2) / 3 + 1
}

/// Verify that a stake-weighted supermajority of registered, active validators
/// co-signed this transaction. Returns [`BridgeError::QuorumNotMet`] if the
/// summed stake of the distinct active validators present and signing is below
/// [`quorum_threshold`] of the registry's total active stake.
pub fn verify_validator_quorum(
    program_id: &Pubkey,
    registry: &ValidatorRegistry,
    quorum_accounts: &[AccountInfo],
) -> Result<()> {
    let threshold = quorum_threshold(registry.total_active_stake);
    let mut counted_stake: u64 = 0;
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
        // Weight by the validator's staked amount, not a head count.
        counted_stake = counted_stake.saturating_add(validator.stake_amount);
    }

    require!(counted_stake >= threshold, BridgeError::QuorumNotMet);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prog() -> Pubkey {
        crate::ID
    }

    fn registry(active: u64) -> ValidatorRegistry {
        // Each test validator stakes 1 SOL, so N active validators carry N SOL
        // of active stake.
        registry_with_stake(active, active.saturating_mul(1_000_000_000))
    }

    fn registry_with_stake(active: u64, total_active_stake: u64) -> ValidatorRegistry {
        ValidatorRegistry {
            authority: prog(),
            total_validators: active,
            active_validators: active,
            minimum_stake: 0,
            total_active_stake,
        }
    }

    fn validator_data(wallet: Pubkey, is_active: bool) -> Vec<u8> {
        validator_data_staked(wallet, is_active, 1_000_000_000)
    }

    fn validator_data_staked(wallet: Pubkey, is_active: bool, stake_amount: u64) -> Vec<u8> {
        let v = ValidatorAccount {
            validator: wallet,
            stake_amount,
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

    #[test]
    fn quorum_is_weighted_by_stake_not_head_count() {
        let p = prog();
        let sys = anchor_lang::solana_program::system_program::ID;

        // Total active stake is 9 SOL, so the 2/3 threshold is 6 SOL. One 7-SOL
        // validator alone clears it — a head-count scheme would have rejected a
        // single signer.
        let big = Pubkey::new_unique();
        let (pda_big, _) = Pubkey::find_program_address(&[b"validator", big.as_ref()], &p);
        let mut d_big = validator_data_staked(big, true, 7_000_000_000);
        let (mut lb, mut lpb) = (0u64, 0u64);
        let mut eb = [0u8; 0];
        let s_big = AccountInfo::new(&big, true, false, &mut lb, &mut eb, &sys, false, 0);
        let a_big = AccountInfo::new(&pda_big, false, false, &mut lpb, &mut d_big, &p, false, 0);
        assert!(
            verify_validator_quorum(&p, &registry_with_stake(3, 9_000_000_000), &[s_big, a_big])
                .is_ok()
        );

        // A lone 1-SOL validator against the same 9-SOL total is below 2/3, so
        // many tiny Sybil validators cannot forge the quorum one signature at a
        // time.
        let small = Pubkey::new_unique();
        let (pda_small, _) = Pubkey::find_program_address(&[b"validator", small.as_ref()], &p);
        let mut d_small = validator_data_staked(small, true, 1_000_000_000);
        let (mut ls, mut lps) = (0u64, 0u64);
        let mut es = [0u8; 0];
        let s_small = AccountInfo::new(&small, true, false, &mut ls, &mut es, &sys, false, 0);
        let a_small =
            AccountInfo::new(&pda_small, false, false, &mut lps, &mut d_small, &p, false, 0);
        assert!(verify_validator_quorum(
            &p,
            &registry_with_stake(3, 9_000_000_000),
            &[s_small, a_small]
        )
        .is_err());
    }
}
