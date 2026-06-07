//! Property-based tests for #71. The existing proptest block in
//! `src/privacy/types.rs` already pins commitment determinism, the
//! hiding/binding pair, and `Nullifier::derive` over a varying
//! spending key. This file fills the three gaps the audit asked us
//! to lock down: pool-level value conservation across a deposit /
//! withdraw round-trip, nullifier injectivity in the *commitment*
//! argument (the symmetric direction), and the insert-then-lookup
//! contract on the pool's Merkle tree that withdrawals rely on.

use paraloom::privacy::{Commitment, Note, Nullifier, ShieldedAddress, ShieldedPool};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use tokio::runtime::Builder;

fn rt() -> tokio::runtime::Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

proptest! {
    /// `deposit(amount)` followed by `withdraw(amount)` returns the
    /// pool's `total_supply` to zero for arbitrary amounts. Pool fees
    /// are metadata and supply tracking is independent of them, so
    /// the invariant must hold over the full positive range.
    #[test]
    fn deposit_withdraw_zeroes_supply(
        amount in 1u64..1_000_000_000,
        recipient in any::<[u8; 32]>(),
        randomness in any::<[u8; 32]>(),
    ) {
        let result: Result<(), TestCaseError> = rt().block_on(async {
            let pool = ShieldedPool::new();
            let note = Note::new_native(ShieldedAddress(recipient), amount, randomness);
            pool.deposit(note.clone(), amount).await.unwrap();
            prop_assert_eq!(pool.total_supply().await, amount);

            let nullifier = Nullifier::derive(&note.commitment(), &randomness);
            pool.withdraw(nullifier, amount, &[0u8; 32]).await.unwrap();
            prop_assert_eq!(pool.total_supply().await, 0u64);
            Ok(())
        });
        result?;
    }

    /// Distinct commitments under the same spending key must produce
    /// distinct nullifiers. Symmetric to the existing
    /// `nullifier_differs_with_spending_key` — together they pin
    /// injectivity of `Nullifier::derive` in both arguments and rule
    /// out the mirrored form of the v0.2.0 commitment/nullifier mix-up.
    #[test]
    fn nullifier_differs_with_commitment(
        sk in any::<[u8; 32]>(),
        c_a in any::<[u8; 32]>(),
        c_b in any::<[u8; 32]>(),
    ) {
        prop_assume!(c_a != c_b);
        let n_a = Nullifier::derive(&Commitment(c_a), &sk);
        let n_b = Nullifier::derive(&Commitment(c_b), &sk);
        prop_assert_ne!(n_a, n_b);
    }

    /// After `pool.deposit`, the pool's stored Merkle path for the
    /// freshly inserted commitment verifies against the post-deposit
    /// root. Withdrawals reconstruct exactly this path from witness
    /// data, so a regression here would silently break every withdraw.
    #[test]
    fn merkle_insert_then_lookup_verifies(
        amount in 1u64..1_000_000_000,
        recipient in any::<[u8; 32]>(),
        randomness in any::<[u8; 32]>(),
    ) {
        let result: Result<(), TestCaseError> = rt().block_on(async {
            let pool = ShieldedPool::new();
            let note = Note::new_native(ShieldedAddress(recipient), amount, randomness);
            let commitment = pool.deposit(note, amount).await.unwrap();
            let root = pool.root().await;
            let path = pool.path(&commitment).await.unwrap();
            prop_assert!(path.verify(commitment.as_bytes(), &root));
            Ok(())
        });
        result?;
    }
}
