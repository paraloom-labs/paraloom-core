//! Privacy layer integration tests
//!
//! End-to-end tests for the complete privacy flow

#[cfg(test)]
mod tests {
    use crate::privacy::{pedersen, DepositTx, ShieldedAddress, ShieldedPool};

    /// Test full deposit flow: User deposits → Commitment added to pool
    #[tokio::test]
    async fn test_full_deposit_flow() {
        println!("\n=== Testing Full Deposit Flow ===");

        let pool = ShieldedPool::new();

        // User wants to deposit 1000 tokens (10 fee)
        let recipient = ShieldedAddress([1u8; 32]);
        let amount = 1000u64;
        let fee = 10u64;
        let randomness = pedersen::generate_randomness();
        let from_public = vec![0x42u8; 32]; // Solana pubkey

        // Create deposit transaction
        let deposit_tx = DepositTx::new(from_public, amount, recipient.clone(), randomness, fee);

        println!(
            "Deposit: {} tokens (fee: {}) to {:?}",
            amount,
            fee,
            &recipient.as_bytes()[..4]
        );

        // Verify transaction is valid
        assert!(deposit_tx.verify(), "Deposit transaction should be valid");

        // Process deposit
        let note = deposit_tx.output_note.clone();
        let net_amount = amount - fee;

        let result = pool.deposit(note, net_amount).await;
        assert!(result.is_ok(), "Deposit should succeed");

        let commitment = result.unwrap();
        assert_eq!(commitment, deposit_tx.output_commitment);

        // Verify pool state
        let commitment_count = pool.commitment_count().await;
        assert_eq!(commitment_count, 1, "Pool should have 1 commitment");

        let total_supply = pool.total_supply().await;
        assert_eq!(
            total_supply, net_amount,
            "Total supply should be {} (amount - fee)",
            net_amount
        );

        println!("Deposit successful");
        println!("Commitment: {:?}", &commitment.as_bytes()[..8]);
        println!("Net amount: {}", net_amount);
        println!("Total supply: {}", total_supply);
    }

    /// Test privacy guarantees: single-field commitment binding and pool state updates
    #[tokio::test]
    async fn test_privacy_guarantees() {
        let pool = ShieldedPool::new();

        let alice_addr = ShieldedAddress([0xA1u8; 32]);
        let bob_addr = ShieldedAddress([0xB0u8; 32]);

        let rand_1 = [0x11u8; 32];
        let rand_2 = [0x22u8; 32];

        // 1. Determinism: identical (recipient, amount, randomness) produces identical commitment
        let alice_tx_a = DepositTx::new(vec![0x42; 32], 1000, alice_addr.clone(), rand_1, 10);
        let alice_tx_b = DepositTx::new(vec![0x42; 32], 1000, alice_addr.clone(), rand_1, 10);
        assert_eq!(
            alice_tx_a.output_commitment, alice_tx_b.output_commitment,
            "Identical note inputs must yield the same commitment"
        );

        // 2. Randomness binding (hiding): same recipient and amount, different randomness -> different commitment
        let alice_diff_rand = DepositTx::new(vec![0x42; 32], 1000, alice_addr.clone(), rand_2, 10);
        assert_ne!(
            alice_tx_a.output_commitment, alice_diff_rand.output_commitment,
            "Commitment must bind randomness so repeated deposits by the same user are unlinkable"
        );

        // 3. Recipient binding: same amount and randomness, different recipient -> different commitment
        let bob_same_rand = DepositTx::new(vec![0x43; 32], 1000, bob_addr.clone(), rand_1, 10);
        assert_ne!(
            alice_tx_a.output_commitment, bob_same_rand.output_commitment,
            "Commitment must bind recipient address"
        );

        // 4. Value binding: same recipient and randomness, different net amount -> different commitment
        let alice_diff_amount =
            DepositTx::new(vec![0x42; 32], 2000, alice_addr.clone(), rand_1, 10);
        assert_ne!(
            alice_tx_a.output_commitment, alice_diff_amount.output_commitment,
            "Commitment must bind note value"
        );

        // 5. Deposit both notes into the pool and verify returned commitments and pool state
        let alice_deposit = alice_tx_a;
        let bob_deposit = DepositTx::new(vec![0x43; 32], 1000, bob_addr.clone(), rand_2, 10);

        let alice_commitment = alice_deposit.output_commitment.clone();
        let bob_commitment = bob_deposit.output_commitment.clone();

        let credited_alice = pool
            .deposit(alice_deposit.output_note.clone(), 990)
            .await
            .expect("Alice deposit should succeed");
        let credited_bob = pool
            .deposit(bob_deposit.output_note.clone(), 990)
            .await
            .expect("Bob deposit should succeed");

        assert_eq!(credited_alice, alice_commitment);
        assert_eq!(credited_bob, bob_commitment);
        assert_eq!(pool.commitment_count().await, 2);
        assert_eq!(pool.total_supply().await, 1980);

        let stored_alice = pool
            .get_note(&alice_commitment)
            .await
            .expect("Alice note must be stored in pool");
        let stored_bob = pool
            .get_note(&bob_commitment)
            .await
            .expect("Bob note must be stored in pool");
        assert_eq!(stored_alice.recipient, alice_addr);
        assert_eq!(stored_alice.amount, 990);
        assert_eq!(stored_bob.recipient, bob_addr);
        assert_eq!(stored_bob.amount, 990);
        assert!(pool.verify_consistency().await.is_ok());
    }
}
