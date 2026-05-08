//! Byzantine consensus test for #71. Ten validators with three
//! misbehavers — equivocator, dropper, malformed routing — must
//! still resolve via the honest 7-of-10 quorum to `Valid`, and the
//! slashing tracker must flag only the equivocator (one missed
//! round ≠ persistent unavailability; unknown request_id rejected).

use paraloom::consensus::slashing::SlashingEvidence;
use paraloom::consensus::withdrawal::{
    VerificationVote, WithdrawalVerificationRequest, WithdrawalVerificationResult,
};
use paraloom::consensus::WithdrawalVerificationCoordinator;
use paraloom::types::NodeId;

#[tokio::test]
async fn ten_validators_three_byzantine_consensus_holds_and_flags_equivocator() {
    let coordinator = WithdrawalVerificationCoordinator::new();
    let validators: Vec<NodeId> = (0..10).map(|i| NodeId(vec![i as u8])).collect();
    for v in &validators {
        coordinator.register_validator(v.clone()).await;
    }

    let request = WithdrawalVerificationRequest {
        request_id: "byz-001".to_string(),
        nullifier: [0u8; 32],
        amount: 1_000_000,
        recipient: [99u8; 32],
        proof: vec![0u8; 192],
        fee: 1_000,
        timestamp: 0,
    };
    coordinator
        .start_verification(request.clone())
        .await
        .unwrap();

    let result_for = |v: &NodeId, req_id: &str, vote| WithdrawalVerificationResult {
        request_id: req_id.to_string(),
        validator: v.clone(),
        vote,
        timestamp: 0,
    };
    let req_id = request.request_id.as_str();

    for v in &validators[0..7] {
        coordinator
            .submit_result(result_for(v, req_id, VerificationVote::Valid))
            .await
            .unwrap();
    }

    // Validator 7: equivocator. Valid is installed; the follow-up
    // Invalid is rejected and surfaces as Equivocation evidence.
    coordinator
        .submit_result(result_for(&validators[7], req_id, VerificationVote::Valid))
        .await
        .unwrap();
    coordinator
        .submit_result(result_for(
            &validators[7],
            req_id,
            VerificationVote::Invalid {
                reason: "byzantine flip".into(),
            },
        ))
        .await
        .unwrap();

    // Validator 8: dropper, never submits.
    // Validator 9: malformed routing — unknown request_id must error
    // out before touching consensus state.
    assert!(coordinator
        .submit_result(result_for(
            &validators[9],
            "no-such-request",
            VerificationVote::Valid
        ))
        .await
        .is_err());

    // 7 honest + the equivocator's installed Valid = 8 effective
    // Valid votes, exceeding the default 7-of-10 quorum.
    let consensus = coordinator
        .check_consensus(req_id)
        .await
        .unwrap()
        .expect("consensus must reach");
    assert_eq!(consensus, VerificationVote::Valid);

    let slashing = coordinator.slashing_tracker();
    let flagged = slashing.flagged_validators().await;
    assert!(flagged.contains(&validators[7]));
    assert!(!flagged.contains(&validators[8]));
    assert!(!flagged.contains(&validators[9]));

    let records = slashing.for_validator(&validators[7]).await;
    assert!(matches!(
        records.first().map(|r| &r.evidence),
        Some(SlashingEvidence::Equivocation { .. })
    ));
}
