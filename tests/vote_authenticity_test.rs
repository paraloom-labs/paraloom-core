//! Audit: a verification vote must come from the validator it claims to be.
//!
//! `WithdrawalVerificationResult` carries a self-declared `validator: NodeId`.
//! Before the fix the node routed that straight into the coordinator without
//! checking it against the authenticated gossip sender, so one peer could
//! submit votes under every validator's identity and fabricate a quorum. The
//! node now drops any vote whose claimed validator does not match the sender.
//! This drives `handle_message` directly (no mesh needed) and asserts a forged
//! vote is dropped while a genuine one is counted.

use paraloom::config::Settings;
use paraloom::consensus::withdrawal::{VerificationVote, WithdrawalVerificationRequest};
use paraloom::network::protocol::NetworkEventHandler;
use paraloom::network::Message;
use paraloom::node::Node;
use paraloom::types::NodeId;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

fn validator_settings(port: u16, data_dir: &str) -> Settings {
    let mut s = Settings::development();
    s.network.listen_address = format!("/ip4/127.0.0.1/tcp/{port}");
    s.network.enable_mdns = false;
    s.storage.data_dir = data_dir.to_string();
    s.bridge.enabled = true;
    s.bridge.program_id = "8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP".to_string();
    s.bridge.solana_rpc_url = "http://127.0.0.1:1".to_string();
    s.bridge.merkle_path_query_address = String::new();
    s.bridge.poll_interval_secs = 3600;
    s
}

fn request(id: &str) -> WithdrawalVerificationRequest {
    WithdrawalVerificationRequest {
        request_id: id.to_string(),
        nullifier: [3u8; 32],
        amount: 1_000_000,
        recipient: [7u8; 32],
        proof: vec![1u8; 192],
        fee: 0,
        timestamp: 0,
        prover_root: [0u8; 32],
    }
}

fn vote(request_id: &str, validator: NodeId, v: VerificationVote) -> Message {
    Message::WithdrawalVerificationResult {
        result: paraloom::consensus::withdrawal::WithdrawalVerificationResult {
            request_id: request_id.to_string(),
            validator,
            vote: v,
            timestamp: 0,
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_vote_must_come_from_the_validator_it_claims_to_be() {
    let dir = tempfile::tempdir().expect("tempdir");
    // 1-of-3 threshold so a single counted vote is observable.
    let node = Node::new(validator_settings(
        free_port(),
        dir.path().to_str().unwrap(),
    ))
    .expect("node")
    .with_consensus_thresholds(1, 3);

    let coordinator = node
        .withdrawal_coordinator()
        .expect("bridge-enabled node has a withdrawal coordinator");

    let victim = NodeId(vec![0xBB]);
    let attacker = NodeId(vec![0xAA]);
    coordinator.register_validator(victim.clone()).await;
    coordinator.register_validator(attacker.clone()).await;

    // Start a verification so the coordinator holds a pending tally.
    let rid = coordinator
        .start_verification(request("r1"))
        .await
        .expect("start verification");

    // The attacker publishes a vote impersonating the victim. `handle_message`
    // is called with the authenticated sender = attacker, so the claimed
    // validator (victim) does not match and the vote must be dropped.
    node.handle_message(
        attacker.clone(),
        vote(&rid, victim.clone(), VerificationVote::Valid),
    )
    .await
    .expect("handle_message");
    assert_eq!(
        node.withdrawal_vote_counts(&rid).await.unwrap(),
        Some((0, 0)),
        "a vote whose claimed validator is not the sender must not be counted"
    );

    // The victim casting its own vote (sender == claimed validator) is counted.
    node.handle_message(
        victim.clone(),
        vote(&rid, victim.clone(), VerificationVote::Valid),
    )
    .await
    .expect("handle_message");
    assert_eq!(
        node.withdrawal_vote_counts(&rid).await.unwrap(),
        Some((1, 0)),
        "a genuine vote from the validator itself must be counted"
    );
}
