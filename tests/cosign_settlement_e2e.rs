//! #260: the leader-side co-signing round assembles a real multi-signature
//! settlement transaction over a live libp2p mesh.
//!
//! Two bridge-enabled validator nodes form a gossip mesh. node0 initiates a
//! withdrawal verification; node1 verifies it (accept), votes `Valid` over the
//! network, and caches the request. Once node0 has a `Valid` quorum and has
//! learned node1's advertised settlement wallet, it runs the co-signing round:
//! it signs the rebuilt settlement message itself, asks node1 to co-sign the
//! same message over the `/paraloom/cosign` protocol, and assembles both
//! signatures into one transaction. The assertion is that the assembled
//! transaction verifies with both signatures present — proving the whole
//! distributed path (verify → cache → co-sign → assemble) end to end, exercising
//! the real `handle_cosign_request` handler over a real connection.
//!
//! Ignored by default: it binds loopback TCP and depends on gossip-mesh timing.
//! CI runs it with `--ignored`, like the other libp2p e2e tests.

use ark_ec::AffineRepr;
use ark_serialize::CanonicalSerialize;
use paraloom::config::Settings;
use paraloom::consensus::withdrawal::VerificationVote;
use paraloom::consensus::{ApprovedWithdrawal, WithdrawalVerificationRequest};
use paraloom::node::Node;
use solana_sdk::signature::Keypair;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A well-formed compressed BN254 Groth16 proof. It need not satisfy the
/// circuit — voting is stubbed by the accept verifier and co-signers match
/// parameters, not the proof — but it must deserialize, since the leader
/// converts it to the on-chain wire form when building the settlement message.
fn valid_compressed_proof() -> Vec<u8> {
    let proof = ark_groth16::Proof::<ark_bn254::Bn254> {
        a: ark_bn254::G1Affine::generator(),
        b: ark_bn254::G2Affine::generator(),
        c: ark_bn254::G1Affine::generator(),
    };
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .expect("serialize proof");
    bytes
}

/// Bridge-enabled validator settings with a generated settlement keypair, so the
/// node advertises a co-signing wallet (#260) and can sign settlement messages.
fn validator_settings(port: u16, bootstrap: Vec<String>, data_dir: &str) -> Settings {
    let mut s = Settings::development();
    s.network.listen_address = format!("/ip4/127.0.0.1/tcp/{port}");
    s.network.bootstrap_nodes = bootstrap;
    s.network.enable_mdns = false;
    s.storage.data_dir = data_dir.to_string();
    s.bridge.enabled = true;
    s.bridge.program_id = "8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP".to_string();
    s.bridge.solana_rpc_url = "http://127.0.0.1:1".to_string();
    s.bridge.merkle_path_query_address = String::new();
    s.bridge.poll_interval_secs = 3600;

    // Write a fresh settlement keypair into the data dir and point the bridge at
    // it. The solana keypair-file format is a JSON array of the 64 secret bytes,
    // which `format!("{:?}", ..)` produces directly.
    let keypair = Keypair::new();
    let path = format!("{data_dir}/validator.json");
    std::fs::write(&path, format!("{:?}", keypair.to_bytes().to_vec()))
        .expect("write keypair file");
    s.bridge.authority_keypair_path = Some(path);
    s
}

fn accept_verifier() -> paraloom::node::WithdrawalProofVerifier {
    Arc::new(|_req: &WithdrawalVerificationRequest| true)
}

async fn wait_until<F, Fut>(deadline: Duration, step: Duration, mut condition: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let until = Instant::now() + deadline;
    loop {
        if condition().await {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        tokio::time::sleep(step).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binds loopback TCP + depends on gossip-mesh timing; CI runs with --ignored"]
async fn leader_assembles_a_co_signed_settlement_transaction() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir0 = tempfile::tempdir().expect("tempdir0");
    let dir1 = tempfile::tempdir().expect("tempdir1");
    let (port0, port1) = (free_port(), free_port());

    let node0 = Node::new(validator_settings(
        port0,
        vec![],
        dir0.path().to_str().unwrap(),
    ))
    .expect("node0")
    .with_proof_verifier(accept_verifier())
    .with_consensus_thresholds(1, 2);
    let node1 = Node::new(validator_settings(
        port1,
        vec![format!("/ip4/127.0.0.1/tcp/{port0}")],
        dir1.path().to_str().unwrap(),
    ))
    .expect("node1")
    .with_proof_verifier(accept_verifier())
    .with_consensus_thresholds(1, 2);

    let n0 = node0.clone();
    let h0 = tokio::spawn(async move { n0.run().await });

    let listening = wait_until(
        Duration::from_secs(15),
        Duration::from_millis(100),
        || async {
            tokio::net::TcpStream::connect(("127.0.0.1", port0))
                .await
                .is_ok()
        },
    )
    .await;
    assert!(listening, "node0 did not listen on {port0} within 15s");

    let n1 = node1.clone();
    let h1 = tokio::spawn(async move { n1.run().await });

    let connected = wait_until(
        Duration::from_secs(30),
        Duration::from_millis(500),
        || async {
            node0.connected_peer_count().await >= 1 && node1.connected_peer_count().await >= 1
        },
    )
    .await;
    assert!(connected, "nodes did not form a gossip mesh within 30s");

    // Build the request once so we can reconstruct the approval from it. The
    // proof is a well-formed compressed BN254 proof so the leader's wire
    // conversion succeeds.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut nullifier = [0u8; 32];
    nullifier[..16].copy_from_slice(&nanos.to_le_bytes());
    let request = WithdrawalVerificationRequest {
        request_id: format!("req-{nanos}"),
        nullifier,
        amount: 1_000_000,
        recipient: [7u8; 32],
        proof: valid_compressed_proof(),
        fee: 0,
        timestamp: now_secs(),
        prover_root: [0u8; 32],
    };

    // Initiate, retrying until node0's validator set is populated by discovery.
    let until = Instant::now() + Duration::from_secs(30);
    let request_id = loop {
        match node0
            .initiate_withdrawal_verification(request.clone())
            .await
        {
            Ok(rid) => break rid,
            Err(e) if Instant::now() < until => {
                log::debug!("initiate not ready yet ({e}); retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("node0 could not start verification within 30s: {e}"),
        }
    };

    // node1 verifies (accept), votes Valid over the mesh, and caches the
    // request; node0 reaches a Valid quorum at the 1-of-2 threshold.
    let quorum = wait_until(Duration::from_secs(30), Duration::from_millis(500), || {
        let rid = request_id.clone();
        let probe = node0.clone();
        async move {
            matches!(
                probe.withdrawal_consensus_status(&rid).await,
                Ok(Some(VerificationVote::Valid))
            )
        }
    })
    .await;
    assert!(quorum, "withdrawal did not reach Valid quorum within 30s");

    let approved = ApprovedWithdrawal {
        request_id: request_id.clone(),
        nullifier: request.nullifier,
        amount: request.amount,
        recipient: request.recipient,
        proof: request.proof.clone(),
        fee: request.fee,
        prover_root: request.prover_root,
    };

    // Run the co-signing round, retrying while node1's advertised wallet
    // propagates and its cache settles. Success means an assembled transaction
    // carrying BOTH signatures. The leader's own self-vote satisfies the 1-of-2
    // off-chain threshold the instant it initiates, so consensus can flip Valid
    // before node1's vote propagates — an early round then assembles only the
    // leader's signature. Retry until node1 has co-signed (or time out and let
    // the assertion below report the final count).
    let until = Instant::now() + Duration::from_secs(30);
    let tx = loop {
        match node0
            .cosign_settlement_tx(&approved, [0u8; 32], u64::MAX)
            .await
        {
            Ok(tx) if tx.signatures.len() >= 2 => break tx,
            Ok(_) if Instant::now() < until => {
                log::debug!("cosign round assembled only the leader so far; retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Ok(tx) => break tx,
            Err(e) if Instant::now() < until => {
                log::debug!("cosign round not ready yet ({e}); retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("co-signing round did not complete within 30s: {e}"),
        }
    };

    assert!(
        tx.verify().is_ok(),
        "the assembled co-signed settlement transaction must verify"
    );
    assert_eq!(
        tx.signatures.len(),
        2,
        "both the leader and the co-signing validator must have signed"
    );

    let _ = node0.stop().await;
    let _ = node1.stop().await;
    h0.abort();
    h1.abort();
}
