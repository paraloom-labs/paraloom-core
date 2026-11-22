//! #1654: a bridge-enabled node without a settlement keypair must refuse
//! transact submissions at the ingress instead of returning `200 OK` for a
//! transact it can provably never settle.
//!
//! The node is built with bridge enabled and `authority_keypair_path = None`,
//! an accept-all proof verifier, and 1-of-1 thresholds, mirroring the
//! `transact_cosign_e2e.rs` harness. No chain interaction: the Solana RPC URL
//! points at a dead port on purpose, and the defect fires before any chain
//! call.
//!
//! Ignored by default: it builds a live node, like the other libp2p e2e tests.

use ark_ec::AffineRepr;
use ark_serialize::CanonicalSerialize;
use paraloom::config::Settings;
use paraloom::consensus::transact::TransactVerificationRequest;
use paraloom::consensus::ApprovedTransact;
use paraloom::node::Node;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A well-formed compressed BN254 Groth16 proof. It need not satisfy the
/// circuit — voting is stubbed by the accept verifier — but it must
/// deserialize, since the leader converts it to the on-chain wire form when
/// building the settlement message.
fn valid_tagged_proof() -> Vec<u8> {
    let proof = ark_groth16::Proof::<ark_bn254::Bn254> {
        a: ark_bn254::G1Affine::generator(),
        b: ark_bn254::G2Affine::generator(),
        c: ark_bn254::G1Affine::generator(),
    };
    let mut body = Vec::new();
    proof
        .serialize_compressed(&mut body)
        .expect("serialize proof");
    paraloom::privacy::tag_proof(paraloom::privacy::ProofSuite::Groth16Bn254TransactV3, &body)
}

/// Bridge-enabled validator settings with NO settlement keypair
/// (`authority_keypair_path = None`) — a configuration `Node::new`
/// explicitly supports.
fn keypairless_settings(port: u16, data_dir: &str) -> Settings {
    let mut s = Settings::development();
    s.network.listen_address = format!("/ip4/127.0.0.1/tcp/{port}");
    s.network.bootstrap_nodes = vec![];
    s.network.enable_mdns = false;
    s.storage.data_dir = data_dir.to_string();
    s.bridge.enabled = true;
    s.bridge.program_id = "8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP".to_string();
    s.bridge.solana_rpc_url = "http://127.0.0.1:1".to_string();
    s.bridge.merkle_path_query_address = String::new();
    s.bridge.poll_interval_secs = 3600;
    s.bridge.authority_keypair_path = None;
    s
}

fn accept_verifier() -> paraloom::node::TransactProofVerifier {
    Arc::new(|_req: &TransactVerificationRequest| true)
}

fn canonical_request() -> TransactVerificationRequest {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut nf0 = [0u8; 32];
    nf0[..16].copy_from_slice(&nanos.to_le_bytes());
    let mut nf1 = [0u8; 32];
    nf1[..16].copy_from_slice(&nanos.to_le_bytes());
    nf1[16] = 1;
    let mut request = TransactVerificationRequest {
        request_id: String::new(),
        recipient: [7u8; 32],
        mint: None,
        nullifiers: [nf0, nf1],
        output_commitments: [[11u8; 32], [12u8; 32]],
        root: [13u8; 32],
        ext_amount: -500,
        proof: valid_tagged_proof(),
        ciphertexts: [String::new(), String::new()],
        timestamp: now_secs(),
    };
    request.request_id = request.canonical_id();
    request
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "builds a live node; CI runs with --ignored"]
async fn keypairless_node_rejects_transact_submission() {
    let _ = env_logger::builder().is_test(true).try_init();
    let dir = tempfile::tempdir().expect("tempdir");
    let settings = keypairless_settings(free_port(), dir.path().to_str().unwrap());
    let node = Node::new(settings)
        .expect("node")
        .with_transact_proof_verifier(accept_verifier())
        .with_transact_consensus_thresholds(1, 1);

    // FAILS at HEAD (#1654): result is Ok(request_id) — HTTP 200 for a
    // doomed request. After the fix the ingress refuses it, and
    // `submit_handler` maps the error to 503.
    let result = node
        .initiate_transact_verification(canonical_request())
        .await;
    assert!(
        result.is_err(),
        "keypair-less node must refuse the submission, got {result:?}"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("no settlement keypair"),
        "refusal must name the missing settlement keypair"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "builds a live node; CI runs with --ignored"]
async fn keypairless_node_cannot_run_cosign_round() {
    let _ = env_logger::builder().is_test(true).try_init();
    let dir = tempfile::tempdir().expect("tempdir");
    let settings = keypairless_settings(free_port(), dir.path().to_str().unwrap());
    let node = Node::new(settings)
        .expect("node")
        .with_transact_proof_verifier(accept_verifier())
        .with_transact_consensus_thresholds(1, 1);

    // Control: documents the asymmetry #1654 fixes — the same node errors
    // with "no settlement keypair configured" the moment it tries to settle.
    let approved = ApprovedTransact {
        request: canonical_request(),
    };
    let err = node
        .cosign_settlement_transact_tx(&approved, [0u8; 32])
        .await
        .expect_err("settlement without a keypair must fail");
    assert!(
        err.to_string().contains("no settlement keypair"),
        "unexpected error: {err}"
    );
}
