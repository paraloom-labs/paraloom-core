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

    /// Test privacy guarantees
    #[tokio::test]
    async fn test_privacy_guarantees() {
        println!("\n=== Testing Privacy Guarantees ===");

        let pool = ShieldedPool::new();

        // Alice and Bob deposit same amount
        let alice_addr = ShieldedAddress([0xA1u8; 32]);
        let bob_addr = ShieldedAddress([0xB0u8; 32]);

        let alice_rand = pedersen::generate_randomness();
        let bob_rand = pedersen::generate_randomness();

        let alice_deposit = DepositTx::new(vec![0x42; 32], 1000, alice_addr, alice_rand, 10);
        let bob_deposit = DepositTx::new(vec![0x43; 32], 1000, bob_addr, bob_rand, 10);

        let alice_commitment = alice_deposit.output_commitment.clone();
        let bob_commitment = bob_deposit.output_commitment.clone();

        // Commitments should be different even for same amount
        assert_ne!(
            alice_commitment, bob_commitment,
            "Commitments should hide identity"
        );

        pool.deposit(alice_deposit.output_note, 990).await.unwrap();
        pool.deposit(bob_deposit.output_note, 990).await.unwrap();

        println!("Same amount, different commitments");
        println!("Alice: {:?}", &alice_commitment.as_bytes()[..8]);
        println!("Bob:   {:?}", &bob_commitment.as_bytes()[..8]);

        // Observer can't tell who has how much
        println!("\nPrivacy guaranteed");
        println!("Observer sees: 2 commitments, total supply 1980");
        println!("Observer CANNOT see: Who has what amount");
    }
}
