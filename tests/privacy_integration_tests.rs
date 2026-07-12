use paraloom::privacy::*;

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

    let note1 = Note::new_native(ShieldedAddress([10u8; 32]), 500, [1u8; 32]);
    let note2 = Note::new_native(ShieldedAddress([20u8; 32]), 490, [2u8; 32]);

    let tx = TransferTx::new(nullifiers, vec![note1, note2], [0u8; 32], 10);

    assert_eq!(tx.input_nullifiers.len(), 2);
    assert_eq!(tx.output_commitments.len(), 2);
    assert_eq!(tx.output_notes.len(), 2);
    assert!(tx.verify_structure());
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
    let note = Note::new_native(ShieldedAddress([1u8; 32]), 100, [1u8; 32]);

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
        output_notes.push(Note::new_native(
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
        tree.insert(commitment).await.expect("in-memory insert");
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
    assert!(nullifier_set
        .insert(nullifier1.clone())
        .await
        .expect("in-memory insert"));

    // Should now contain it
    assert!(nullifier_set.contains(&nullifier1).await);

    // Duplicate insert should fail
    assert!(!nullifier_set
        .insert(nullifier1.clone())
        .await
        .expect("in-memory insert"));

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
