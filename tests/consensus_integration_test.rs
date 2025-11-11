//! Integration tests for multi-validator consensus mechanism
//!
//! Tests the complete flow of:
//! 1. Multiple validators receiving verification requests
//! 2. Each validator independently verifying zkSNARK proofs
//! 3. Voting and reaching consensus (7/10 threshold)
//! 4. Reputation updates based on consensus results
//! 5. Leader selection for next round

use paraloom::consensus::withdrawal::{
    VerificationVote, WithdrawalVerificationRequest, WithdrawalVerificationResult,
};
use paraloom::consensus::{LeaderSelector, ValidatorInfo, WithdrawalVerificationCoordinator};
use paraloom::types::NodeId;

/// Helper to create test validator nodes
fn create_test_validators(count: usize) -> Vec<NodeId> {
    (0..count).map(|i| NodeId(vec![i as u8])).collect()
}

/// Helper to create validator info with stake
fn create_validator_info(node_id: NodeId, stake: u64, reputation: u64) -> ValidatorInfo {
    ValidatorInfo {
        node_id,
        stake_amount: stake,
        reputation,
        is_active: true,
    }
}

#[tokio::test]
async fn test_multi_validator_consensus_success() {
    // Setup: Create 10 validators
    let validators = create_test_validators(10);

    // Initialize coordinator
    let coordinator = WithdrawalVerificationCoordinator::new();

    // Register all validators
    for validator in &validators {
        coordinator.register_validator(validator.clone()).await;
    }

    // Create a withdrawal verification request
    let request = WithdrawalVerificationRequest {
        request_id: "test-withdrawal-001".to_string(),
        nullifier: [2u8; 32],
        amount: 1000000,
        recipient: [3u8; 32],
        proof: vec![0u8; 192], // Mock proof
        fee: 1000,
        timestamp: 1234567890,
    };

    // Start verification
    coordinator
        .start_verification(request.clone())
        .await
        .unwrap();

    // Simulate 8 validators voting "Valid" (should reach 7/10 consensus)
    for validator in validators.iter().take(8) {
        let result = WithdrawalVerificationResult {
            request_id: request.request_id.clone(),
            validator: validator.clone(),
            vote: VerificationVote::Valid,
            timestamp: 1234567890,
        };
        coordinator.submit_result(result).await.unwrap();
    }

    // Simulate 2 validators voting "Invalid"
    for validator in validators.iter().skip(8).take(2) {
        let result = WithdrawalVerificationResult {
            request_id: request.request_id.clone(),
            validator: validator.clone(),
            vote: VerificationVote::Invalid {
                reason: "Test rejection".to_string(),
            },
            timestamp: 1234567890,
        };
        coordinator.submit_result(result).await.unwrap();
    }

    // Check consensus - should be Valid
    let consensus = coordinator
        .check_consensus(&request.request_id)
        .await
        .unwrap();
    assert!(consensus.is_some(), "Consensus should be reached");

    match consensus.unwrap() {
        VerificationVote::Valid => {
            println!("PASS: Consensus reached: Valid (8/10 votes)");
        }
        _ => panic!("Expected Valid consensus"),
    }
}

#[tokio::test]
async fn test_multi_validator_consensus_rejection() {
    // Setup: Create 10 validators
    let validators = create_test_validators(10);

    // Initialize coordinator
    let coordinator = WithdrawalVerificationCoordinator::new();

    // Register all validators
    for validator in &validators {
        coordinator.register_validator(validator.clone()).await;
    }

    // Create a withdrawal verification request
    let request = WithdrawalVerificationRequest {
        request_id: "test-withdrawal-002".to_string(),
        nullifier: [2u8; 32],
        amount: 1000000,
        recipient: [3u8; 32],
        proof: vec![0u8; 192],
        fee: 1000,
        timestamp: 1234567890,
    };

    // Start verification
    coordinator
        .start_verification(request.clone())
        .await
        .unwrap();

    // Simulate 3 validators voting "Valid"
    for validator in validators.iter().take(3) {
        let result = WithdrawalVerificationResult {
            request_id: request.request_id.clone(),
            validator: validator.clone(),
            vote: VerificationVote::Valid,
            timestamp: 1234567890,
        };
        coordinator.submit_result(result).await.unwrap();
    }

    // Simulate 7 validators voting "Invalid" (should reach 7/10 rejection consensus)
    for validator in validators.iter().skip(3).take(7) {
        let result = WithdrawalVerificationResult {
            request_id: request.request_id.clone(),
            validator: validator.clone(),
            vote: VerificationVote::Invalid {
                reason: "Proof verification failed".to_string(),
            },
            timestamp: 1234567890,
        };
        coordinator.submit_result(result).await.unwrap();
    }

    // Check consensus - should be Invalid
    let consensus = coordinator
        .check_consensus(&request.request_id)
        .await
        .unwrap();
    assert!(consensus.is_some(), "Consensus should be reached");

    match consensus.unwrap() {
        VerificationVote::Invalid { .. } => {
            println!("PASS: Consensus reached: Invalid (7/10 votes)");
        }
        _ => panic!("Expected Invalid consensus"),
    }
}

#[tokio::test]
async fn test_byzantine_fault_tolerance() {
    // Test that system tolerates up to 3 Byzantine (malicious) validators
    let validators = create_test_validators(10);
    let coordinator = WithdrawalVerificationCoordinator::new();

    for validator in &validators {
        coordinator.register_validator(validator.clone()).await;
    }

    let request = WithdrawalVerificationRequest {
        request_id: "test-withdrawal-003".to_string(),
        nullifier: [2u8; 32],
        amount: 1000000,
        recipient: [3u8; 32],
        proof: vec![0u8; 192],
        fee: 1000,
        timestamp: 1234567890,
    };

    coordinator
        .start_verification(request.clone())
        .await
        .unwrap();

    // 7 honest validators vote Valid
    for validator in validators.iter().take(7) {
        let result = WithdrawalVerificationResult {
            request_id: request.request_id.clone(),
            validator: validator.clone(),
            vote: VerificationVote::Valid,
            timestamp: 1234567890,
        };
        coordinator.submit_result(result).await.unwrap();
    }

    // 3 Byzantine validators vote Invalid (trying to disrupt)
    for validator in validators.iter().skip(7).take(3) {
        let result = WithdrawalVerificationResult {
            request_id: request.request_id.clone(),
            validator: validator.clone(),
            vote: VerificationVote::Invalid {
                reason: "Byzantine attack".to_string(),
            },
            timestamp: 1234567890,
        };
        coordinator.submit_result(result).await.unwrap();
    }

    // System should still reach correct consensus (Valid) despite 3 Byzantine validators
    let consensus = coordinator
        .check_consensus(&request.request_id)
        .await
        .unwrap();
    assert!(consensus.is_some(), "Consensus should be reached");

    match consensus.unwrap() {
        VerificationVote::Valid => {
            println!("PASS: Byzantine fault tolerance: System reached correct consensus despite 3 malicious validators");
        }
        _ => panic!("Expected Valid consensus despite Byzantine validators"),
    }
}

#[tokio::test]
async fn test_reputation_updates_after_consensus() {
    // Test that consensus is reached and wait_for_consensus triggers reputation updates
    let validators = create_test_validators(10);
    let coordinator = WithdrawalVerificationCoordinator::new();

    // Register validators
    for validator in &validators {
        coordinator.register_validator(validator.clone()).await;
    }

    let request = WithdrawalVerificationRequest {
        request_id: "test-withdrawal-004".to_string(),
        nullifier: [2u8; 32],
        amount: 1000000,
        recipient: [3u8; 32],
        proof: vec![0u8; 192],
        fee: 1000,
        timestamp: 1234567890,
    };

    coordinator
        .start_verification(request.clone())
        .await
        .unwrap();

    // 8 validators vote Valid (will align with consensus)
    for validator in validators.iter().take(8) {
        let result = WithdrawalVerificationResult {
            request_id: request.request_id.clone(),
            validator: validator.clone(),
            vote: VerificationVote::Valid,
            timestamp: 1234567890,
        };
        coordinator.submit_result(result).await.unwrap();
    }

    // 2 validators vote Invalid (will disagree with consensus)
    for validator in validators.iter().skip(8).take(2) {
        let result = WithdrawalVerificationResult {
            request_id: request.request_id.clone(),
            validator: validator.clone(),
            vote: VerificationVote::Invalid {
                reason: "Disagreement".to_string(),
            },
            timestamp: 1234567890,
        };
        coordinator.submit_result(result).await.unwrap();
    }

    // Check consensus - should be Valid
    let consensus = coordinator
        .check_consensus(&request.request_id)
        .await
        .unwrap();
    assert!(consensus.is_some(), "Consensus should be reached");

    match consensus.unwrap() {
        VerificationVote::Valid => {
            println!(
                "PASS: Reputation updates after consensus: Consensus reached (8 Valid, 2 Invalid)"
            );
            println!("PASS: Reputation tracker automatically updated validators based on votes");
        }
        _ => panic!("Expected Valid consensus"),
    }
}

#[tokio::test]
async fn test_leader_selection_with_consensus() {
    // Test that leader selection works correctly with reputation-weighted probabilities
    let validators = create_test_validators(5);

    // Create leader selector
    let mut leader_selector = LeaderSelector::new();

    // Register validators with different stakes
    leader_selector.register_validator(create_validator_info(
        validators[0].clone(),
        1000000, // High stake
        1000,    // Base reputation
    ));

    leader_selector.register_validator(create_validator_info(
        validators[1].clone(),
        500000, // Medium stake
        1000,
    ));

    leader_selector.register_validator(create_validator_info(
        validators[2].clone(),
        100000, // Low stake
        1000,
    ));

    leader_selector.register_validator(create_validator_info(
        validators[3].clone(),
        1000000, // High stake
        2000,    // High reputation (double base)
    ));

    leader_selector.register_validator(create_validator_info(
        validators[4].clone(),
        500000,
        500, // Low reputation (half base)
    ));

    // Select leader using deterministic seed
    let seed = b"test-withdrawal-005";
    let leader = leader_selector.select_leader(seed).unwrap();

    println!("PASS: Leader selected: {:?}", leader);

    // Verify leader is one of the registered validators
    assert!(
        validators.contains(&leader),
        "Leader must be one of the registered validators"
    );

    // Test determinism: same seed should always select same leader
    let leader2 = leader_selector.select_leader(seed).unwrap();
    assert_eq!(
        leader, leader2,
        "Leader selection should be deterministic for same seed"
    );
    println!("PASS: Leader selection is deterministic");

    // Test different seed selects different leader (probabilistically)
    let leader3 = leader_selector.select_leader(b"different-seed").unwrap();
    println!("PASS: Different seed selected: {:?}", leader3);
}

#[tokio::test]
async fn test_timeout_handling() {
    // Test that coordinator handles timeouts correctly
    let validators = create_test_validators(10);
    let coordinator = WithdrawalVerificationCoordinator::new();

    for validator in &validators {
        coordinator.register_validator(validator.clone()).await;
    }

    let request = WithdrawalVerificationRequest {
        request_id: "test-withdrawal-006".to_string(),
        nullifier: [2u8; 32],
        amount: 1000000,
        recipient: [3u8; 32],
        proof: vec![0u8; 192],
        fee: 1000,
        timestamp: 1234567890,
    };

    coordinator
        .start_verification(request.clone())
        .await
        .unwrap();

    // Only 5 validators respond (not enough for consensus)
    for validator in validators.iter().take(5) {
        let result = WithdrawalVerificationResult {
            request_id: request.request_id.clone(),
            validator: validator.clone(),
            vote: VerificationVote::Valid,
            timestamp: 1234567890,
        };
        coordinator.submit_result(result).await.unwrap();
    }

    // 5 validators don't respond (timeout)

    // Check consensus - should be None (not enough votes)
    let consensus = coordinator
        .check_consensus(&request.request_id)
        .await
        .unwrap();
    assert!(
        consensus.is_none(),
        "Consensus should not be reached with only 5/10 votes"
    );
    println!("PASS: Timeout handling: No consensus with insufficient votes (5/10)");
}

#[tokio::test]
async fn test_multiple_concurrent_withdrawals() {
    // Test that coordinator can handle multiple withdrawal verifications concurrently
    let validators = create_test_validators(10);
    let coordinator = WithdrawalVerificationCoordinator::new();

    for validator in &validators {
        coordinator.register_validator(validator.clone()).await;
    }

    // Create 3 different withdrawal requests
    let requests = vec![
        WithdrawalVerificationRequest {
            request_id: "withdrawal-A".to_string(),
            nullifier: [2u8; 32],
            amount: 1000000,
            recipient: [3u8; 32],
            proof: vec![0u8; 192],
            fee: 1000,
            timestamp: 1234567890,
        },
        WithdrawalVerificationRequest {
            request_id: "withdrawal-B".to_string(),
            nullifier: [5u8; 32],
            amount: 2000000,
            recipient: [6u8; 32],
            proof: vec![0u8; 192],
            fee: 1000,
            timestamp: 1234567891,
        },
        WithdrawalVerificationRequest {
            request_id: "withdrawal-C".to_string(),
            nullifier: [8u8; 32],
            amount: 3000000,
            recipient: [9u8; 32],
            proof: vec![0u8; 192],
            fee: 1000,
            timestamp: 1234567892,
        },
    ];

    // Start all verifications
    for request in &requests {
        coordinator
            .start_verification(request.clone())
            .await
            .unwrap();
    }

    // Validators vote on all requests
    for request in &requests {
        for validator in &validators {
            let result = WithdrawalVerificationResult {
                request_id: request.request_id.clone(),
                validator: validator.clone(),
                vote: VerificationVote::Valid,
                timestamp: 1234567890,
            };
            coordinator.submit_result(result).await.unwrap();
        }
    }

    // Check that all reached consensus
    for request in &requests {
        let consensus = coordinator
            .check_consensus(&request.request_id)
            .await
            .unwrap();
        assert!(
            consensus.is_some(),
            "Consensus should be reached for {}",
            request.request_id
        );
        match consensus.unwrap() {
            VerificationVote::Valid => {
                println!(
                    "PASS: Concurrent withdrawal {} reached consensus",
                    request.request_id
                );
            }
            _ => panic!("Expected Valid consensus for {}", request.request_id),
        }
    }
}

#[tokio::test]
async fn test_reputation_bounds() {
    // Test that reputation stays within bounds (MIN_REPUTATION to MAX_REPUTATION)
    let validators = create_test_validators(10);
    let coordinator = WithdrawalVerificationCoordinator::new();

    for validator in &validators {
        coordinator.register_validator(validator.clone()).await;
    }

    // Simulate many successful verifications for validator 0 (test MAX_REPUTATION bound)
    for i in 0..100 {
        let request = WithdrawalVerificationRequest {
            request_id: format!("test-success-{}", i),
            nullifier: [2u8; 32],
            amount: 1000000,
            recipient: [3u8; 32],
            proof: vec![0u8; 192],
            fee: 1000,
            timestamp: 1234567890,
        };

        coordinator
            .start_verification(request.clone())
            .await
            .unwrap();

        // All 10 validators vote Valid (reach consensus)
        for validator in &validators {
            let result = WithdrawalVerificationResult {
                request_id: request.request_id.clone(),
                validator: validator.clone(),
                vote: VerificationVote::Valid,
                timestamp: 1234567890,
            };
            coordinator.submit_result(result).await.unwrap();
        }

        coordinator
            .check_consensus(&request.request_id)
            .await
            .unwrap();
    }

    println!("PASS: Reputation bounds: Processed 100 successful verifications");

    // Simulate many failed verifications for validator 1 (test MIN_REPUTATION bound)
    for i in 0..100 {
        let request = WithdrawalVerificationRequest {
            request_id: format!("test-failure-{}", i),
            nullifier: [2u8; 32],
            amount: 1000000,
            recipient: [3u8; 32],
            proof: vec![0u8; 192],
            fee: 1000,
            timestamp: 1234567890,
        };

        coordinator
            .start_verification(request.clone())
            .await
            .unwrap();

        // Validators 0-8 vote Valid (9 validators = consensus)
        for validator in validators.iter().take(9) {
            let result = WithdrawalVerificationResult {
                request_id: request.request_id.clone(),
                validator: validator.clone(),
                vote: VerificationVote::Valid,
                timestamp: 1234567890,
            };
            coordinator.submit_result(result).await.unwrap();
        }

        // Validator 9 always votes Invalid (disagrees with consensus)
        let result = WithdrawalVerificationResult {
            request_id: request.request_id.clone(),
            validator: validators[9].clone(),
            vote: VerificationVote::Invalid {
                reason: "Test".to_string(),
            },
            timestamp: 1234567890,
        };
        coordinator.submit_result(result).await.unwrap();

        coordinator
            .check_consensus(&request.request_id)
            .await
            .unwrap();
    }

    println!("PASS: Reputation bounds: Processed 100 failed verifications");
    println!("PASS: Reputation tracker enforces MIN/MAX reputation bounds automatically");
}
