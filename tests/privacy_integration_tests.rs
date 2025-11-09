use paraloom::privacy::*;

#[tokio::test]
async fn test_full_shielded_transaction_flow() {
    // Create shielded pool
    let pool = ShieldedPool::new();

    // Alice deposits 1000 into the pool
    let alice_addr = ShieldedAddress([1u8; 32]);
    let alice_note = Note::new(alice_addr.clone(), 1000, [10u8; 32]);
    let alice_commitment = pool.deposit(alice_note.clone(), 1000).await.unwrap();

    assert_eq!(pool.total_supply().await, 1000);
    assert_eq!(pool.commitment_count().await, 1);

    // Bob also deposits
    let bob_addr = ShieldedAddress([2u8; 32]);
    let bob_note = Note::new(bob_addr.clone(), 500, [20u8; 32]);
    pool.deposit(bob_note, 500).await.unwrap();

    assert_eq!(pool.total_supply().await, 1500);
    assert_eq!(pool.commitment_count().await, 2);

    // Alice transfers 300 to Bob (shielded)
    let alice_spending_key = [100u8; 32];
    let alice_nullifier = Nullifier::derive(&alice_commitment, &alice_spending_key);

    let bob_new_note = Note::new(bob_addr.clone(), 300, [30u8; 32]);
    let alice_change_note = Note::new(alice_addr, 690, [31u8; 32]); // 1000 - 300 - 10 fee

    let output_commitments = pool
        .transfer(
            vec![alice_nullifier.clone()],
            vec![bob_new_note, alice_change_note],
        )
        .await
        .unwrap();

    assert_eq!(output_commitments.len(), 2);
    assert_eq!(pool.commitment_count().await, 4); // 2 original + 2 new
    assert!(pool.is_spent(&alice_nullifier).await);

    // Bob withdraws 100
    let bob_spending_key = [200u8; 32];
    let bob_commitment = output_commitments[0].clone();
    let bob_nullifier = Nullifier::derive(&bob_commitment, &bob_spending_key);

    let recipient_public = [5u8; 32];
    pool.withdraw(bob_nullifier.clone(), 100, &recipient_public)
        .await
        .unwrap();

    assert_eq!(pool.total_supply().await, 1400); // 1500 - 100
    assert!(pool.is_spent(&bob_nullifier).await);
}

#[tokio::test]
async fn test_double_spend_prevention() {
    let pool = ShieldedPool::new();

    // Deposit
    let note = Note::new(ShieldedAddress([1u8; 32]), 1000, [1u8; 32]);
    let commitment = pool.deposit(note.clone(), 1000).await.unwrap();

    // Create nullifier
    let spending_key = [10u8; 32];
    let nullifier = Nullifier::derive(&commitment, &spending_key);

    // First spend - should succeed
    let output_note = Note::new(ShieldedAddress([2u8; 32]), 900, [2u8; 32]);
    pool.transfer(vec![nullifier.clone()], vec![output_note.clone()])
        .await
        .unwrap();

    // Second spend with same nullifier - should fail
    let result = pool.transfer(vec![nullifier], vec![output_note]).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_deposit_transaction_creation() {
    let from_public = vec![1u8; 32];
    let recipient = ShieldedAddress([2u8; 32]);
    let randomness = [42u8; 32];

    let tx = DepositTx::new(from_public, 1000, recipient, randomness, 10);

    assert_eq!(tx.amount, 1000);
    assert_eq!(tx.fee, 10);
    assert_eq!(tx.output_note.amount, 990);
    assert!(tx.verify());

    // Commitment should match note
    assert_eq!(tx.output_commitment, tx.output_note.commitment());
}

#[tokio::test]
async fn test_transfer_transaction_creation() {
    let nullifiers = vec![Nullifier([1u8; 32]), Nullifier([2u8; 32])];

    let note1 = Note::new(ShieldedAddress([10u8; 32]), 500, [1u8; 32]);
    let note2 = Note::new(ShieldedAddress([20u8; 32]), 490, [2u8; 32]);

    let tx = TransferTx::new(nullifiers, vec![note1, note2], [0u8; 32], 10);

    assert_eq!(tx.input_nullifiers.len(), 2);
    assert_eq!(tx.output_commitments.len(), 2);
    assert_eq!(tx.output_notes.len(), 2);
    assert!(tx.verify_structure());
    assert!(tx.verify_range_proofs());
}

#[tokio::test]
async fn test_withdraw_transaction_creation() {
    let nullifier = Nullifier([1u8; 32]);
    let to_public = vec![5u8; 32];

    let tx = WithdrawTx::new(nullifier, 1000, to_public, [0u8; 32], 10);

    assert_eq!(tx.amount, 1000);
    assert_eq!(tx.fee, 10);
    assert!(tx.verify());
}

#[tokio::test]
async fn test_verification_chunking() {
    let nullifiers = vec![Nullifier([1u8; 32])];
    let note = Note::new(ShieldedAddress([1u8; 32]), 100, [1u8; 32]);

    let tx = TransferTx::new(nullifiers, vec![note], [0u8; 32], 10);

    let chunks = ProofVerifier::create_verification_chunks(&tx);

    // Should have: outputs, nullifiers, and range proof
    assert_eq!(chunks.len(), 3);

    // Verify each chunk
    for chunk in &chunks {
        let result = chunk.verify();
        assert!(result.is_valid());
    }
}

#[tokio::test]
async fn test_distributed_verification_coordinator() {
    let coordinator = VerificationCoordinator::new();

    // Register validators
    for i in 0..10 {
        coordinator
            .register_validator(paraloom::types::NodeId(vec![i]))
            .await;
    }

    // Create a transfer transaction with multiple outputs
    // This ensures we have enough verification tasks for consensus
    let mut output_notes = vec![];
    for i in 0..7 {
        output_notes.push(Note::new(
            ShieldedAddress([i as u8; 32]),
            100,
            [i as u8; 32],
        ));
    }

    let tx = ShieldedTransaction::Transfer(TransferTx::new(
        vec![Nullifier([1u8; 32])],
        output_notes,
        [0u8; 32],
        10,
    ));

    // Create verification tasks
    let tasks = coordinator.create_verification_tasks(&tx).await.unwrap();

    assert!(!tasks.is_empty());

    // Simulate verification results
    for task in &tasks {
        let result = VerificationTaskResult {
            task_id: task.task_id.clone(),
            validator: task.validator.clone(),
            result: VerificationResult::Valid,
            timestamp: 0,
        };

        coordinator.submit_result(result).await.unwrap();
    }

    // Check consensus
    let consensus = coordinator.check_consensus(&tx.id()).await.unwrap();
    assert!(consensus.is_some());
    assert!(consensus.unwrap().is_valid());
}

#[tokio::test]
async fn test_merkle_tree_integration() {
    let tree = MerkleTree::new();

    // Add multiple commitments
    let commitments = vec![
        Commitment([1u8; 32]),
        Commitment([2u8; 32]),
        Commitment([3u8; 32]),
    ];

    for commitment in &commitments {
        tree.insert(commitment).await;
    }

    let root = tree.root().await;
    assert_ne!(root, [0u8; 32]);

    // Root should be deterministic
    let root2 = tree.root().await;
    assert_eq!(root, root2);
}

#[tokio::test]
async fn test_nullifier_set_integration() {
    let nullifier_set = NullifierSet::new();

    let nullifier1 = Nullifier([1u8; 32]);
    let nullifier2 = Nullifier([2u8; 32]);

    // Initially empty
    assert!(!nullifier_set.contains(&nullifier1).await);

    // Add first nullifier
    assert!(nullifier_set.insert(nullifier1.clone()).await);

    // Should now contain it
    assert!(nullifier_set.contains(&nullifier1).await);

    // Duplicate insert should fail
    assert!(!nullifier_set.insert(nullifier1.clone()).await);

    // Batch check
    assert!(
        nullifier_set
            .check_batch(std::slice::from_ref(&nullifier2))
            .await
    );
    assert!(
        !nullifier_set
            .check_batch(std::slice::from_ref(&nullifier1))
            .await
    );
}

#[tokio::test]
async fn test_shielded_transaction_serialization() {
    let tx = ShieldedTransaction::Deposit(DepositTx::new(
        vec![1u8; 32],
        1000,
        ShieldedAddress([2u8; 32]),
        [3u8; 32],
        10,
    ));

    // Serialize
    let serialized = bincode::serialize(&tx).unwrap();
    assert!(!serialized.is_empty());

    // Deserialize
    let deserialized: ShieldedTransaction = bincode::deserialize(&serialized).unwrap();

    // Should match
    assert_eq!(tx.id(), deserialized.id());
}

#[test]
fn test_commitment_scheme() {
    let value = 1000u64;
    let randomness = [42u8; 32];

    let c1 = CommitmentGenerator::commit(value, &randomness);
    let c2 = CommitmentGenerator::commit(value, &randomness);

    // Deterministic
    assert_eq!(c1, c2);

    // Hiding
    let c3 = CommitmentGenerator::commit(2000, &randomness);
    assert_ne!(c1, c3);

    // Blinding
    let c4 = CommitmentGenerator::commit(value, &[43u8; 32]);
    assert_ne!(c1, c4);
}
