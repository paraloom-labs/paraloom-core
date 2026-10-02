use std::collections::HashMap;

use paraloom::consensus::transact::{
    TransactVerificationCoordinator, TransactVerificationRequest, TransactVerificationResult,
};
use paraloom::consensus::vote_tally::VerificationVote;
use paraloom::types::NodeId;

fn canonical_request() -> TransactVerificationRequest {
    let mut request = TransactVerificationRequest {
        request_id: String::new(),
        recipient: [1u8; 32],
        mint: None,
        nullifiers: [[2u8; 32], [3u8; 32]],
        output_commitments: [[4u8; 32], [5u8; 32]],
        root: [6u8; 32],
        ext_amount: -100,
        proof: vec![7, 8, 9],
        ciphertexts: ["aa".to_string(), "bb".to_string()],
        timestamp: 123,
    };
    request.request_id = request.canonical_id();
    request
}

fn vote(request_id: &str, idx: u8, valid: bool) -> TransactVerificationResult {
    TransactVerificationResult {
        request_id: request_id.to_string(),
        validator: NodeId(vec![idx]),
        vote: if valid {
            VerificationVote::Valid
        } else {
            VerificationVote::Invalid {
                reason: "one dissenting validator".to_string(),
            }
        },
        timestamp: 1,
        wallet_pubkey: format!("W{idx}"),
        signature: vec![1],
    }
}

#[tokio::test]
async fn mixed_votes_at_response_quorum_remain_pending_until_outcome_quorum() {
    let mut coordinator = TransactVerificationCoordinator::new();
    coordinator.set_consensus_thresholds(7, 10);

    let mut stakes = HashMap::new();
    for i in 0..10u8 {
        coordinator
            .register_validator_with_wallet(NodeId(vec![i]), Some(format!("W{i}")))
            .await;
        stakes.insert(format!("W{i}"), 1_000_000_000);
    }
    coordinator.sync_onchain_stakes(stakes, 10_000_000_000).await;

    let request = canonical_request();
    let request_id = request.request_id.clone();
    coordinator.start_verification(request).await.unwrap();

    // 6 Valid votes and 1 Invalid vote (7 total responses).
    for i in 0..6u8 {
        coordinator
            .submit_result(vote(&request_id, i, true))
            .await
            .unwrap();
    }
    coordinator
        .submit_result(vote(&request_id, 6, false))
        .await
        .unwrap();

    let (_completion, valid, invalid) = coordinator.get_status(&request_id).await.unwrap();
    assert_eq!((valid, invalid), (6, 1));

    // Because 6 Valid < 7 and 1 Invalid < 7, consensus is not yet reached;
    // check_consensus must return None (pending) rather than premature Invalid (#801).
    assert!(
        coordinator.check_consensus(&request_id).await.unwrap().is_none(),
        "mixed split 6-valid/1-invalid must remain pending, not prematurely reject"
    );

    // Now a 7th Valid vote arrives from validator 7.
    coordinator
        .submit_result(vote(&request_id, 7, true))
        .await
        .unwrap();

    let (_completion, valid, invalid) = coordinator.get_status(&request_id).await.unwrap();
    assert_eq!((valid, invalid), (7, 1));

    // Valid quorum (7) is now achieved:
    match coordinator.check_consensus(&request_id).await.unwrap() {
        Some(VerificationVote::Valid) => {}
        other => panic!("expected Valid consensus after 7th valid vote, got {other:?}"),
    }
}

#[tokio::test]
async fn explicit_invalid_quorum_finalizes_as_invalid() {
    let mut coordinator = TransactVerificationCoordinator::new();
    coordinator.set_consensus_thresholds(7, 10);

    let mut stakes = HashMap::new();
    for i in 0..10u8 {
        coordinator
            .register_validator_with_wallet(NodeId(vec![i]), Some(format!("W{i}")))
            .await;
        stakes.insert(format!("W{i}"), 1_000_000_000);
    }
    coordinator.sync_onchain_stakes(stakes, 10_000_000_000).await;

    let request = canonical_request();
    let request_id = request.request_id.clone();
    coordinator.start_verification(request).await.unwrap();

    // 7 validators vote Invalid.
    for i in 0..7u8 {
        coordinator
            .submit_result(vote(&request_id, i, false))
            .await
            .unwrap();
    }

    match coordinator.check_consensus(&request_id).await.unwrap() {
        Some(VerificationVote::Invalid { reason }) => {
            assert!(
                reason.contains("7 invalid"),
                "expected invalid consensus reason to document 7 invalid votes, got: {reason}"
            );
        }
        other => panic!("expected Invalid consensus with 7 invalid votes, got {other:?}"),
    }
}
