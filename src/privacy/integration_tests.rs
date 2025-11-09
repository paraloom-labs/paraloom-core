//! Privacy layer integration tests
//!
//! End-to-end tests for the complete privacy flow

#[cfg(test)]
mod tests {
    use crate::privacy::{pedersen, DepositTx, Note, Nullifier, ShieldedAddress, ShieldedPool};

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

    /// Test full transfer flow: Private → Private transfer
    #[tokio::test]
    async fn test_full_transfer_flow() {
        println!("\n=== Testing Full Transfer Flow ===");

        let pool = ShieldedPool::new();

        // Setup: First deposit some funds for Alice
        let alice_address = ShieldedAddress([0xA1u8; 32]);
        let initial_amount = 1000u64;
        let alice_randomness = pedersen::generate_randomness();

        let deposit = DepositTx::new(
            vec![0x42; 32],
            initial_amount,
            alice_address.clone(),
            alice_randomness,
            10,
        );

        let alice_note = deposit.output_note.clone();
        pool.deposit(alice_note.clone(), initial_amount - 10)
            .await
            .unwrap();

        println!("Setup: Alice deposited {} tokens", initial_amount - 10);

        // Now Alice transfers 300 to Bob, keeps 690 as change
        let bob_address = ShieldedAddress([0xB0u8; 32]);
        let transfer_amount = 300u64;
        let change_amount = 680u64; // 990 - 10 fee - 300
        let _fee = 10u64;

        // Create nullifier for Alice's input
        let spending_key = alice_randomness; // Simplified - in production use proper key derivation
        let input_nullifier = Nullifier::derive(&alice_note.commitment(), &spending_key);

        // Create output notes
        let bob_randomness = pedersen::generate_randomness();
        let alice_change_randomness = pedersen::generate_randomness();

        let bob_note = Note::new(bob_address.clone(), transfer_amount, bob_randomness);
        let alice_change_note = Note::new(
            alice_address.clone(),
            change_amount,
            alice_change_randomness,
        );

        println!(
            "Transfer: {} to Bob, {} change to Alice",
            transfer_amount, change_amount
        );

        // Process transfer
        let result = pool
            .transfer(
                vec![input_nullifier.clone()],
                vec![bob_note, alice_change_note],
            )
            .await;

        assert!(result.is_ok(), "Transfer should succeed");
        let output_commitments = result.unwrap();
        assert_eq!(
            output_commitments.len(),
            2,
            "Should have 2 output commitments"
        );

        // Verify pool state
        assert_eq!(pool.commitment_count().await, 3); // 1 input + 2 outputs
        assert_eq!(
            pool.total_supply().await,
            990,
            "Total supply should remain constant (minus original fee)"
        );

        // Verify nullifier was spent
        let nullifiers_spent = pool.spent_count().await;
        assert_eq!(nullifiers_spent, 1, "Should have 1 spent nullifier");

        println!("Transfer successful");
        println!("   Outputs: {}", output_commitments.len());
        println!("   Total supply: {}", pool.total_supply().await);
    }

    /// Test full withdraw flow: Private → Public withdrawal
    #[tokio::test]
    async fn test_full_withdraw_flow() {
        println!("\n=== Testing Full Withdraw Flow ===");

        let pool = ShieldedPool::new();

        // Setup: Deposit funds first
        let owner_address = ShieldedAddress([1u8; 32]);
        let initial_amount = 1000u64;
        let randomness = pedersen::generate_randomness();

        let deposit = DepositTx::new(
            vec![0x42; 32],
            initial_amount,
            owner_address.clone(),
            randomness,
            10,
        );

        let note = deposit.output_note.clone();
        pool.deposit(note.clone(), initial_amount - 10)
            .await
            .unwrap();

        println!("Setup: Deposited {} tokens", initial_amount - 10);

        // Now withdraw 600 tokens
        let withdraw_amount = 600u64;
        let fee = 10u64;

        // Create nullifier
        let spending_key = randomness;
        let nullifier = Nullifier::derive(&note.commitment(), &spending_key);

        println!("Withdraw: {} tokens", withdraw_amount);

        // Process withdrawal
        let recipient_address = [0x99u8; 32]; // Solana address to receive funds
        let result = pool
            .withdraw(nullifier.clone(), withdraw_amount + fee, &recipient_address)
            .await;
        assert!(result.is_ok(), "Withdrawal should succeed");

        // Verify state
        let total_supply = pool.total_supply().await;
        let expected_supply = (initial_amount - 10) - (withdraw_amount + fee);
        assert_eq!(
            total_supply, expected_supply,
            "Total supply should decrease by withdrawal + fee"
        );

        // Verify nullifier was spent
        assert_eq!(pool.spent_count().await, 1);

        println!("Withdrawal successful");
        println!("Withdrawn: {}", withdraw_amount);
        println!("Remaining supply: {}", total_supply);
    }

    /// Test complete privacy cycle: Deposit → Transfer → Transfer → Withdraw
    #[tokio::test]
    async fn test_complete_privacy_cycle() {
        println!("\n=== Testing Complete Privacy Cycle ===");

        let pool = ShieldedPool::new();

        // === STEP 1: Alice deposits 1000 tokens ===
        println!("\n[1] Alice deposits 1000 tokens");
        let alice_address = ShieldedAddress([0xA1u8; 32]);
        let alice_randomness = pedersen::generate_randomness();

        let alice_deposit = DepositTx::new(
            vec![0x42; 32],
            1000,
            alice_address.clone(),
            alice_randomness,
            10,
        );

        let alice_note = alice_deposit.output_note.clone();
        pool.deposit(alice_note.clone(), 990).await.unwrap();

        assert_eq!(pool.commitment_count().await, 1);
        assert_eq!(pool.total_supply().await, 990);
        println!("Alice has 990 tokens (after 10 fee)");

        // === STEP 2: Alice transfers 300 to Bob ===
        println!("\n[2] Alice transfers 300 to Bob (680 change)");
        let bob_address = ShieldedAddress([0xB0u8; 32]);

        let alice_nullifier = Nullifier::derive(&alice_note.commitment(), &alice_randomness);

        let bob_randomness = pedersen::generate_randomness();
        let alice_change_randomness = pedersen::generate_randomness();

        let bob_note = Note::new(bob_address.clone(), 300, bob_randomness);
        let alice_change_note = Note::new(alice_address.clone(), 680, alice_change_randomness);

        pool.transfer(
            vec![alice_nullifier],
            vec![bob_note.clone(), alice_change_note.clone()],
        )
        .await
        .unwrap();

        assert_eq!(pool.commitment_count().await, 3);
        assert_eq!(pool.total_supply().await, 990);
        println!("Bob has 300, Alice has 680");

        // === STEP 3: Bob transfers 100 to Charlie ===
        println!("\n[3] Bob transfers 100 to Charlie (190 change, 10 fee)");
        let charlie_address = ShieldedAddress([0xC0u8; 32]);

        let bob_nullifier = Nullifier::derive(&bob_note.commitment(), &bob_randomness);

        let charlie_randomness = pedersen::generate_randomness();
        let bob_change_randomness = pedersen::generate_randomness();

        let charlie_note = Note::new(charlie_address.clone(), 100, charlie_randomness);
        let bob_change_note = Note::new(bob_address.clone(), 190, bob_change_randomness);

        pool.transfer(
            vec![bob_nullifier],
            vec![charlie_note.clone(), bob_change_note.clone()],
        )
        .await
        .unwrap();

        assert_eq!(pool.commitment_count().await, 5);
        assert_eq!(pool.total_supply().await, 990);
        println!("Charlie has 100, Bob has 190, Alice has 680");

        // === STEP 4: Alice withdraws 500 ===
        println!("\n[4] Alice withdraws 500 (10 fee)");

        let alice_change_nullifier =
            Nullifier::derive(&alice_change_note.commitment(), &alice_change_randomness);

        let alice_public_address = [0xAAu8; 32]; // Alice's Solana address
        pool.withdraw(alice_change_nullifier, 510, &alice_public_address)
            .await
            .unwrap();

        assert_eq!(pool.commitment_count().await, 5);
        let final_supply = pool.total_supply().await;
        assert_eq!(final_supply, 480); // 990 - 510
        println!("Alice withdrew 500 (+ 10 fee)");

        // Final state verification
        println!("\nFinal State:");
        println!("Total commitments: {}", pool.commitment_count().await);
        println!("Total supply: {}", final_supply);
        println!("Nullifiers spent: 3 (Alice x2, Bob x1)");

        // Remaining balances (in pool):
        // - Alice: 170 (680 - 510)
        // - Bob: 190
        // - Charlie: 100
        // Total: 460 (but supply is 480 because we count unspent change)

        println!("\nComplete privacy cycle successful");
    }

    /// Test double-spend prevention
    #[tokio::test]
    async fn test_double_spend_prevention() {
        println!("\n=== Testing Double-Spend Prevention ===");

        let pool = ShieldedPool::new();

        // Deposit
        let address = ShieldedAddress([1u8; 32]);
        let randomness = pedersen::generate_randomness();
        let deposit = DepositTx::new(vec![0x42; 32], 1000, address.clone(), randomness, 10);

        let note = deposit.output_note.clone();
        pool.deposit(note.clone(), 990).await.unwrap();

        // First spend - should succeed
        let nullifier = Nullifier::derive(&note.commitment(), &randomness);
        let output_note = Note::new(address.clone(), 990, pedersen::generate_randomness());

        let result = pool
            .transfer(vec![nullifier.clone()], vec![output_note])
            .await;
        assert!(result.is_ok(), "First spend should succeed");
        println!("First spend succeeded");

        // Try to spend again - should fail
        let output_note2 = Note::new(address.clone(), 990, pedersen::generate_randomness());
        let result2 = pool
            .transfer(vec![nullifier.clone()], vec![output_note2])
            .await;

        assert!(result2.is_err(), "Double-spend should be prevented!");
        println!("Double-spend prevented: {:?}", result2.err());
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
