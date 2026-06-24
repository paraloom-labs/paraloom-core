//! Network partition test for #71. Models a partition where a
//! subset of validators temporarily cannot reach the coordinator:
//! quorum stalls during the split, the partition heals, late votes
//! arrive and consensus resolves to `Valid`. The pool then enforces
//! single execution against the freshly committed nullifier — a
//! stale duplicate dispatch (modelling a delayed message that
//! arrives after the heal) must be rejected rather than
//! double-spend.

use paraloom::consensus::withdrawal::{
    VerificationVote, WithdrawalVerificationRequest, WithdrawalVerificationResult,
};
use paraloom::consensus::WithdrawalVerificationCoordinator;
use paraloom::privacy::{pedersen, DepositTx, Nullifier, ShieldedAddress, ShieldedPool};
use paraloom::types::NodeId;
use std::sync::Arc;

#[tokio::test]
async fn partition_heals_and_pool_blocks_double_execution() {
    let pool = Arc::new(ShieldedPool::new());
    let coordinator = WithdrawalVerificationCoordinator::new();
    let validators: Vec<NodeId> = (0..10).map(|i| NodeId(vec![i as u8])).collect();
    for v in &validators {
        coordinator.register_validator(v.clone()).await;
    }

    let randomness = pedersen::generate_randomness();
    let deposit = DepositTx::new(
        vec![0u8; 32],
        1_000_000,
        ShieldedAddress([1u8; 32]),
        randomness,
        1_000,
    );
    let alice_note = deposit.output_note.clone();
    pool.deposit(alice_note.clone(), 999_000).await.unwrap();

    let nullifier = Nullifier::derive(&alice_note.commitment(), &randomness);
    let recipient = [9u8; 32];
    let request = WithdrawalVerificationRequest {
        request_id: "partition-001".to_string(),
        nullifier: nullifier.0,
        amount: 999_000,
        recipient,
        proof: vec![0u8; 192],
        fee: 1_000,
        timestamp: 0,
        prover_root: [0u8; 32],
    };
    coordinator
        .start_verification(request.clone())
        .await
        .unwrap();

    let req_id = request.request_id.as_str();
    let result_for = |v: &NodeId, vote| WithdrawalVerificationResult {
        request_id: req_id.to_string(),
        validator: v.clone(),
        vote,
        timestamp: 0,
    };

    // Partition: 6/10 validators submit. 6 < default 7-of-10 quorum,
    // so consensus must NOT yet be reached.
    for v in &validators[0..6] {
        coordinator
            .submit_result(result_for(v, VerificationVote::Valid))
            .await
            .unwrap();
    }
    assert!(coordinator.check_consensus(req_id).await.unwrap().is_none());

    // Heal: remaining 4 validators reconnect and vote. 10 Valid votes
    // now exceed quorum and consensus resolves to Valid.
    for v in &validators[6..10] {
        coordinator
            .submit_result(result_for(v, VerificationVote::Valid))
            .await
            .unwrap();
    }
    let post = coordinator.check_consensus(req_id).await.unwrap();
    assert_eq!(post, Some(VerificationVote::Valid));

    // Execute once. The pool burns the nullifier in its spent-set.
    pool.withdraw(nullifier.clone(), 999_000, &recipient)
        .await
        .unwrap();
    assert!(pool.is_spent(&nullifier).await);

    // A stale duplicate dispatch arriving after the heal must be
    // rejected — the partition window cannot become a double-spend
    // window.
    assert!(pool
        .withdraw(nullifier.clone(), 999_000, &recipient)
        .await
        .is_err());
}
