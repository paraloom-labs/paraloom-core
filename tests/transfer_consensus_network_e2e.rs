//! #194 Transfer consensus over a real libp2p network — the transfer twin of
//! `consensus_network_e2e` (withdrawal). Wires real `Node` instances over real
//! libp2p (TCP loopback) and lets the actual gossip path carry the transfer
//! verification: `initiate_transfer_verification` → gossipsub broadcast → the
//! peer's `handle_message` votes → result gossiped back → quorum.
//!
//! Like the withdrawal test, this proves the *network wiring*. Each node runs
//! with an injected accept/reject transfer verifier (`with_transfer_proof_verifier`)
//! so the votes are real votes over the real mesh while the Groth16 step is
//! stubbed (the proof path is covered by the privacy circuit tests and the
//! `verify_transfer_parts` round-trip). The quorum threshold is lowered with
//! `with_transfer_consensus_thresholds` (a test-only seam) for a small set.
//!
//! Ignored by default; binds loopback TCP and depends on gossipsub mesh timing.
//! CI runs it with `--ignored`.

use paraloom::config::Settings;
use paraloom::consensus::vote_tally::VerificationVote;
use paraloom::consensus::TransferVerificationRequest;
use paraloom::node::Node;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    s
}

/// Injected verifier that accepts every transfer. The mesh, votes and quorum
/// tally are real; only the Groth16 check is stubbed.
fn accept_verifier() -> paraloom::node::TransferProofVerifier {
    Arc::new(|_req: &TransferVerificationRequest| true)
}

/// Injected verifier that rejects every transfer — a byzantine validator
/// voting Invalid on a transfer the honest majority accepts.
fn reject_verifier() -> paraloom::node::TransferProofVerifier {
    Arc::new(|_req: &TransferVerificationRequest| false)
}

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

/// A distinct transfer request per call (nanosecond-keyed id + nullifiers) so
/// retried `initiate` calls never collide on the same pending entry.
fn sample_request() -> TransferVerificationRequest {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut n0 = [0u8; 32];
    n0[..16].copy_from_slice(&nanos.to_le_bytes());
    let mut n1 = [1u8; 32];
    n1[..16].copy_from_slice(&nanos.to_le_bytes());
    TransferVerificationRequest {
        request_id: format!("xfer-{nanos}"),
        nullifiers: [n0, n1],
        output_commitments: [[3u8; 32], [4u8; 32]],
        new_merkle_root: [7u8; 32],
        proof: vec![1u8; 192],
        ciphertexts: ["ab".repeat(88), "cd".repeat(88)],
        timestamp: now_secs(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binds loopback TCP + depends on gossipsub mesh timing; CI runs with --ignored"]
async fn two_node_transfer_reaches_quorum_over_libp2p() {
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
    .with_transfer_proof_verifier(accept_verifier())
    .with_transfer_consensus_thresholds(1, 2);
    let node1 = Node::new(validator_settings(
        port1,
        vec![format!("/ip4/127.0.0.1/tcp/{port0}")],
        dir1.path().to_str().unwrap(),
    ))
    .expect("node1")
    .with_transfer_proof_verifier(accept_verifier())
    .with_transfer_consensus_thresholds(1, 2);

    let n0 = node0.clone();
    let n1 = node1.clone();
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
    assert!(
        listening,
        "node0 did not start listening on {port0} within 15s"
    );

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

    let until = Instant::now() + Duration::from_secs(30);
    let request_id = loop {
        match node0.initiate_transfer_verification(sample_request()).await {
            Ok(rid) => break rid,
            Err(e) if Instant::now() < until => {
                log::debug!("initiate not ready yet ({e}); retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("node0 could not start transfer verification within 30s: {e}"),
        }
    };

    let quorum = wait_until(Duration::from_secs(30), Duration::from_millis(500), || {
        let rid = request_id.clone();
        let probe = node0.clone();
        async move {
            matches!(
                probe.transfer_consensus_status(&rid).await,
                Ok(Some(VerificationVote::Valid))
            )
        }
    })
    .await;
    assert!(
        quorum,
        "transfer did not reach Valid quorum over the mesh within 30s"
    );

    // Recipient discovery (#196): node1 received the request over gossip and
    // recorded the encrypted output notes, so its scan surface exposes them.
    let delivered = wait_until(Duration::from_secs(10), Duration::from_millis(200), || {
        let n1 = node1.clone();
        async move { n1.delivered_transfer_notes().await.len() == 2 }
    })
    .await;
    assert!(
        delivered,
        "node1 did not record the 2 delivered ciphertexts for scanning"
    );

    let _ = node0.stop().await;
    let _ = node1.stop().await;
    h0.abort();
    h1.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "binds loopback TCP + depends on gossipsub mesh timing; CI runs with --ignored"]
async fn five_node_byzantine_transfer_quorum_holds() {
    let _ = env_logger::builder().is_test(true).try_init();

    const N: usize = 5;
    let dirs: Vec<_> = (0..N)
        .map(|_| tempfile::tempdir().expect("tempdir"))
        .collect();
    let ports: Vec<u16> = (0..N).map(|_| free_port()).collect();
    let port0 = ports[0];

    let mut nodes = Vec::with_capacity(N);
    for i in 0..N {
        let bootstrap = if i == 0 {
            vec![]
        } else {
            vec![format!("/ip4/127.0.0.1/tcp/{port0}")]
        };
        let verifier = if i == N - 1 {
            reject_verifier() // byzantine
        } else {
            accept_verifier()
        };
        let node = Node::new(validator_settings(
            ports[i],
            bootstrap,
            dirs[i].path().to_str().unwrap(),
        ))
        .expect("node")
        .with_transfer_proof_verifier(verifier)
        .with_transfer_consensus_thresholds(3, 5);
        nodes.push(node);
    }

    let mut handles = Vec::with_capacity(N);
    let n0 = nodes[0].clone();
    handles.push(tokio::spawn(async move { n0.run().await }));
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
    assert!(
        listening,
        "node0 did not start listening on {port0} within 15s"
    );
    for node in nodes.iter().skip(1) {
        let n = node.clone();
        handles.push(tokio::spawn(async move { n.run().await }));
    }

    let node0 = nodes[0].clone();
    let connected = wait_until(Duration::from_secs(40), Duration::from_millis(500), || {
        let n0 = node0.clone();
        async move { n0.connected_peer_count().await >= N - 1 }
    })
    .await;
    assert!(
        connected,
        "node0 did not connect to all {} voters within 40s",
        N - 1
    );

    let until = Instant::now() + Duration::from_secs(30);
    let request_id = loop {
        match node0.initiate_transfer_verification(sample_request()).await {
            Ok(rid) => break rid,
            Err(e) if Instant::now() < until => {
                log::debug!("initiate not ready yet ({e}); retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("node0 could not start transfer verification within 30s: {e}"),
        }
    };

    let quorum = wait_until(Duration::from_secs(40), Duration::from_millis(500), || {
        let n0 = node0.clone();
        let rid = request_id.clone();
        async move {
            matches!(
                n0.transfer_consensus_status(&rid).await,
                Ok(Some(VerificationVote::Valid))
            )
        }
    })
    .await;
    assert!(
        quorum,
        "did not reach Valid transfer quorum despite a byzantine voter within 40s"
    );

    // Confirm the byzantine dissent landed and was outvoted, not that we got
    // lucky with three honest votes: >= 3 Valid and >= 1 Invalid.
    let counted = wait_until(Duration::from_secs(15), Duration::from_millis(500), || {
        let n0 = node0.clone();
        let rid = request_id.clone();
        async move {
            matches!(
                n0.transfer_vote_counts(&rid).await,
                Ok(Some((valid, invalid))) if valid >= 3 && invalid >= 1
            )
        }
    })
    .await;
    assert!(
        counted,
        "expected >=3 Valid and >=1 Invalid (byzantine) transfer vote recorded"
    );

    for node in &nodes {
        let _ = node.stop().await;
    }
    for h in handles {
        h.abort();
    }
}
