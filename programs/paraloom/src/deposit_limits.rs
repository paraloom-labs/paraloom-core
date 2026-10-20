//! What one append has to be worth: the deposit floor (#1132).
//!
//! `deposit_note` and `deposit_note_spl` are permissionless, and every call
//! appends exactly one leaf — which pushes one root into the 64-entry history
//! ring in [`crate::merkle_tree`] and evicts the oldest. With no minimum amount,
//! 64 one-unit deposits evict every root an honest prover could have built
//! against, and every in-flight `transact` fails with `UnknownMerkleRoot`: a
//! griefing halt of all shielded settlement, paid for in dust (the notes stay
//! the attacker's own, so even that principal is nominally recoverable).
//!
//! The missing control is a price per append, not a wider window — the window
//! is counted in appends and the attacker is the one producing appends. This
//! module holds that price:
//!
//! - **native**: [`BridgeState::min_deposit_amount`] is the price, initialised
//!   to [`RECOMMENDED_MIN_DEPOSIT_LAMPORTS`] and adjustable by the cold
//!   authority through `set_min_deposit_amount`. Config, not a constant, for
//!   `set_min_token_stake`'s reason: the gate's real cost is a fiat amount, and
//!   a compile-time lamport number drifts out of calibration as SOL moves.
//! - **SPL**: base units are not comparable across mints, so the floor there is
//!   a FRACTION of one whole token ([`min_deposit_base_units`]), which needs
//!   only the mint's decimals. It stays a constant because `AssetConfig` has no
//!   spare layout — see the function's note.
//!
//! [`BridgeState::min_deposit_amount`]: crate::BridgeState::min_deposit_amount

/// Recommended native price of one `deposit_note`, in lamports: 0.01 SOL.
///
/// The ENFORCED value is [`crate::BridgeState::min_deposit_amount`]
/// (`set_min_deposit_amount`); `initialize` and `migrate_bridge_state` start
/// that field here, so a fresh or newly grown pool is priced from the first
/// deposit instead of opening the griefing window by default. Sized as the cost
/// of a *sustained* halt — evicting the 64-root window costs 64 of these (0.64
/// SOL) and the attacker has to keep paying to keep the window clear — while
/// 0.01 SOL sits far below any honest shield.
///
/// Lowering the field below this (down to 0) is allowed on purpose: the proof
/// fixtures replay a 1000-lamport note to pin the circuit root, so the fixture
/// tests price their pool at 0 explicitly.
pub const RECOMMENDED_MIN_DEPOSIT_LAMPORTS: u64 = 10_000_000;

/// SPL floor as 1/100 of one whole token (see [`min_deposit_base_units`]).
pub const SPL_MIN_DEPOSIT_DIVISOR: u64 = 100;

/// Minimum `deposit_note_spl` amount in the mint's base units: 1 % of one whole
/// token, i.e. `10^decimals / 100`.
///
/// `decimals < 2` collapses to a single base unit — at that granularity one
/// base unit already is a tenth (or the whole) of a token, so it is the
/// strictest floor expressible. For an absurd `decimals` whose `10^(decimals-2)`
/// does not fit a `u64` the floor saturates at `u64::MAX`: no deposit can meet
/// it, so that mint is effectively closed rather than silently unpriced.
///
/// A constant rather than an `AssetConfig` field on purpose: adding a field
/// would change that account's size, and every `AssetConfig` already created on
/// devnet would stop deserialising until it was migrated. Mints are curated —
/// `init_asset_vault` is upgrade-authority gated and each config starts closed
/// at cap 0 — so an asset whose 1 % unit is worthless is never opened for
/// shielding in the first place.
pub fn min_deposit_base_units(decimals: u8) -> u64 {
    match decimals.checked_sub(2) {
        None => 1,
        Some(exp) => 10u64.checked_pow(exp as u32).unwrap_or(u64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spl_floor_is_one_percent_of_a_whole_token() {
        // 1 % of 1.0 = 0.01, in base units of each precision.
        assert_eq!(min_deposit_base_units(2), 1); // 0.01 of a 2-decimal token
        assert_eq!(min_deposit_base_units(6), 10_000); // 0.01 USDC
        assert_eq!(min_deposit_base_units(9), 10_000_000); // 0.01 SOL-token
    }

    #[test]
    fn spl_floor_never_sinks_below_one_base_unit() {
        // Fewer than two decimals: one base unit is already >= 1 % of a token.
        assert_eq!(min_deposit_base_units(0), 1);
        assert_eq!(min_deposit_base_units(1), 1);
    }

    #[test]
    fn spl_floor_grows_with_precision_and_saturates() {
        let mut previous = 0;
        for decimals in 0u8..=18 {
            let floor = min_deposit_base_units(decimals);
            assert!(
                floor >= previous,
                "floor must not shrink as decimals grow ({} < {})",
                floor,
                previous
            );
            previous = floor;
        }
        // 10^(decimals-2) does not fit a u64 past 21 decimals: saturate, never wrap.
        assert_eq!(min_deposit_base_units(30), u64::MAX);
    }

    #[test]
    fn recommended_native_price_is_a_hundredth_of_a_sol() {
        assert_eq!(RECOMMENDED_MIN_DEPOSIT_LAMPORTS, 10_000_000); // 0.01 SOL
        assert_eq!(
            RECOMMENDED_MIN_DEPOSIT_LAMPORTS * crate::merkle_tree::ROOT_HISTORY_SIZE as u64,
            640_000_000, // 0.64 SOL to evict the whole window once
        );
    }
}
