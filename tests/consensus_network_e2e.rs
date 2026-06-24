//! #181 Layer 2: withdrawal-consensus over a real libp2p network.
//!
//! Every other consensus test (`byzantine_consensus`, `consensus_integration_test`,
//! `network_partition`, `validator_privacy_e2e`) drives a bare
//! `WithdrawalVerificationCoordinator` in-process and submits votes in a loop.
//! This is the first test that wires real `Node` instances over real libp2p
//! (TCP loopback) and lets the actual gossip path carry the verification:
//! `initiate_withdrawal_verification` → gossipsub broadcast → the peer's
//! `handle_message` votes → result gossiped back → quorum.
//!
//! What this proves is the *network wiring*. The cryptographic proof path is
//! covered by the privacy circuit tests and the on-chain settlement test
//! (#180), so here each node runs with an injected accept-verifier
//! (`with_proof_verifier`) — the votes are real votes traversing the real
//! mesh, but the Groth16 step is stubbed so the test is about transport and
//! consensus, not the SNARK. The quorum threshold is lowered with
//! `with_consensus_thresholds` (a test-only seam, never wired to config) so a
//! small validator set reaches consensus.
//!
//! Ignored by default; it binds loopback TCP ports and depends on gossipsub
//! mesh timing. CI runs it with `--ignored`.

use paraloom::config::Settings;
use paraloom::consensus::withdrawal::VerificationVote;
use paraloom::consensus::WithdrawalVerificationRequest;
use paraloom::node::Node;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Settings for a bridge-enabled validator node on a fixed loopback port.
/// Starts from `Settings::development()` and overrides the fields that
/// matter: the bridge is enabled so the node owns a shielded pool and a
/// withdrawal coordinator, but `solana_rpc_url` points nowhere — the deposit
/// poll loop logs and retries without failing the node, and no settlement is
/// attempted before the test has already observed quorum. The Merkle path
/// server is disabled with an empty bind address. (The sub-settings structs
/// are not re-exported, so we mutate the public fields rather than build the
/// struct literally.)
fn validator_settings(port: u16, bootstrap: Vec<String>, data_dir: &str) -> Settings {
    let mut s = Settings::development();
    s.network.listen_address = format!("/ip4/127.0.0.1/tcp/{port}");
    s.network.bootstrap_nodes = bootstrap;
    s.network.enable_mdns = false;
    // A per-node data dir; sharing the default `./data` makes the two nodes
    // contend on the same RocksDB LOCK.
    s.storage.data_dir = data_dir.to_string();
    s.bridge.enabled = true;
    // Any valid base58 pubkey parses; the listener never reaches a live
    // cluster, so the value only needs to be well-formed.
    s.bridge.program_id = "8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP".to_string();
    s.bridge.solana_rpc_url = "http://127.0.0.1:1".to_string();
    s.bridge.merkle_path_query_address = String::new();
    s.bridge.poll_interval_secs = 3600;
    s
}

/// An injected verifier that accepts every request. The mesh, the votes and
/// the quorum tally are all real; only the Groth16 check is stubbed.
fn accept_verifier() -> paraloom::node::WithdrawalProofVerifier {
    Arc::new(|_req: &WithdrawalVerificationRequest| true)
}

/// An injected verifier that rejects every request — a byzantine validator
/// that votes Invalid on a withdrawal the honest majority accepts.
fn reject_verifier() -> paraloom::node::WithdrawalProofVerifier {
    Arc::new(|_req: &WithdrawalVerificationRequest| false)
}

/// An OS-assigned free loopback port. Binding to port 0 and reading back the
/// assignment avoids both the lack of a bound-address API (we need the port
/// to build node1's bootstrap address) and the cross-run flakiness of fixed
/// ports: a port left in TIME_WAIT by a previous run is not handed out as
/// free, so successive runs never collide.
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

/// Poll `condition` until it returns true or `deadline` elapses, sleeping
/// `step` between checks. Returns whether the condition held in time — no
/// fixed sleeps, so a fast machine proceeds immediately and a slow CI runner
/// still gets the full budget.
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
#[ignore = "binds loopback TCP + depends on gossipsub mesh timing; CI runs with --ignored"]
async fn two_node_withdrawal_reaches_quorum_over_libp2p() {
    let _ = env_logger::builder().is_test(true).try_init();

    // Per-node temp data dirs, kept alive for the test so RocksDB does not
    // see a contended LOCK and is cleaned up on drop.
    let dir0 = tempfile::tempdir().expect("tempdir0");
    let dir1 = tempfile::tempdir().expect("tempdir1");

    let (port0, port1) = (free_port(), free_port());

    // node0 is the initiator/observer; node1 dials it and votes. A 1-of-2
    // quorum: in a two-node mesh the initiator does not receive its own
    // broadcast, so exactly one remote vote (node1's) reaches it.
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

    // run() loops forever; drive it on a clone and keep the originals to
    // issue calls. Node is cheap to clone (every field is Arc-backed).
    let n0 = node0.clone();
    let n1 = node1.clone();
    let h0 = tokio::spawn(async move { n0.run().await });

    // node1's bootstrap dial fires once at startup and is not retried, so
    // node0 must already be listening when node1 starts. Probe the port
    // directly (a deterministic readiness signal, not a blind sleep) before
    // launching node1.
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

    // Wait for the gossip mesh: node0 must see node1 connected before we
    // broadcast, or the request is dropped for want of a mesh peer.
    let connected = wait_until(
        Duration::from_secs(30),
        Duration::from_millis(500),
        || async {
            node0.connected_peer_count().await >= 1 && node1.connected_peer_count().await >= 1
        },
    )
    .await;
    assert!(connected, "nodes did not form a gossip mesh within 30s");

    // Start the verification, retrying until node0's validator set is
    // populated by the Discovery handshake. `start_verification` errors on an
    // empty set *before* broadcasting and without creating a pending entry,
    // so a failed attempt leaves no residue — retry until one succeeds and
    // keep that request_id. Each attempt uses a fresh request, so ids never
    // collide.
    let until = Instant::now() + Duration::from_secs(60);
    let request_id = loop {
        match node0
            .initiate_withdrawal_verification(sample_request())
            .await
        {
            Ok(rid) => break rid,
            Err(e) if Instant::now() < until => {
                log::debug!("initiate not ready yet ({e}); retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("node0 could not start verification within 60s: {e}"),
        }
    };

    // node1 verifies (accept) and gossips its vote back; node0's coordinator
    // tallies it and, at the 1-of-2 threshold, reaches a Valid quorum.
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
    assert!(
        quorum,
        "withdrawal did not reach Valid quorum over the mesh within 30s"
    );

    // Shut down so the swarms and bridge pollers do not outlive the test.
    let _ = node0.stop().await;
    let _ = node1.stop().await;
    h0.abort();
    h1.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "binds loopback TCP + depends on gossipsub mesh timing; CI runs with --ignored"]
async fn five_node_byzantine_quorum_holds() {
    let _ = env_logger::builder().is_test(true).try_init();

    // node0 initiates and observes; nodes 1..=4 vote. Honest nodes accept;
    // the last node is byzantine and votes Invalid. A 3-of-5 threshold: the
    // three honest Valid votes reach quorum despite the one Invalid.
    const N: usize = 5;
    let dirs: Vec<_> = (0..N)
        .map(|_| tempfile::tempdir().expect("tempdir"))
        .collect();
    let ports: Vec<u16> = (0..N).map(|_| free_port()).collect();
    let port0 = ports[0];

    let mut nodes = Vec::with_capacity(N);
    for i in 0..N {
        // Star topology: every voter dials node0, so node0 broadcasts to and
        // collects votes from all of them.
        let bootstrap = if i == 0 {
            vec![]
        } else {
            vec![format!("/ip4/127.0.0.1/tcp/{port0}")]
        };
        let verifier = if i == N - 1 {
            reject_verifier() // the byzantine node
        } else {
            accept_verifier()
        };
        let node = Node::new(validator_settings(
            ports[i],
            bootstrap,
            dirs[i].path().to_str().unwrap(),
        ))
        .expect("node")
        .with_proof_verifier(verifier)
        .with_consensus_thresholds(3, 5);
        nodes.push(node);
    }

    // Launch node0 first and wait until it is listening — each voter's
    // bootstrap dial fires once and is not retried, so the hub must be up.
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

    // node0 must connect to all four voters before it broadcasts. The window is
    // generous because five in-process libp2p nodes share a contended CI runner;
    // under normal load they connect within seconds, so a genuine connectivity
    // failure still trips this — just with headroom against runner starvation.
    let connected = wait_until(Duration::from_secs(120), Duration::from_millis(500), || {
        let n0 = node0.clone();
        async move { n0.connected_peer_count().await >= N - 1 }
    })
    .await;
    assert!(
        connected,
        "node0 did not connect to all {} voters within 120s",
        N - 1
    );

    // Start the verification, retrying until the Discovery handshake has
    // registered enough validators (the 3-of-5 threshold needs >= 3).
    let until = Instant::now() + Duration::from_secs(60);
    let request_id = loop {
        match node0
            .initiate_withdrawal_verification(sample_request())
            .await
        {
            Ok(rid) => break rid,
            Err(e) if Instant::now() < until => {
                log::debug!("initiate not ready yet ({e}); retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("node0 could not start verification within 60s: {e}"),
        }
    };

    // Three honest Valid votes reach the 3-of-5 quorum despite the byzantine
    // node's Invalid vote.
    let quorum = wait_until(Duration::from_secs(90), Duration::from_millis(500), || {
        let n0 = node0.clone();
        let rid = request_id.clone();
        async move {
            matches!(
                n0.withdrawal_consensus_status(&rid).await,
                Ok(Some(VerificationVote::Valid))
            )
        }
    })
    .await;
    assert!(
        quorum,
        "did not reach Valid quorum despite a byzantine voter within 90s"
    );

    // Confirm the byzantine dissent actually landed and was outvoted, not that
    // we merely got lucky with three honest votes: >= 3 Valid and >= 1 Invalid.
    let counted = wait_until(Duration::from_secs(15), Duration::from_millis(500), || {
        let n0 = node0.clone();
        let rid = request_id.clone();
        async move {
            matches!(
                n0.withdrawal_vote_counts(&rid).await,
                Ok(Some((valid, invalid))) if valid >= 3 && invalid >= 1
            )
        }
    })
    .await;
    assert!(
        counted,
        "expected >=3 Valid and >=1 Invalid (byzantine) vote to be recorded"
    );

    for node in &nodes {
        let _ = node.stop().await;
    }
    for h in handles {
        h.abort();
    }
}

/// A distinct request per call (nanosecond-keyed id + nullifier) so retried
/// `initiate` calls never collide on the same pending entry.
fn sample_request() -> WithdrawalVerificationRequest {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut nullifier = [0u8; 32];
    nullifier[..16].copy_from_slice(&nanos.to_le_bytes());
    WithdrawalVerificationRequest {
        request_id: format!("req-{nanos}"),
        nullifier,
        amount: 1_000_000,
        recipient: [7u8; 32],
        proof: vec![1u8; 192],
        fee: 0,
        timestamp: now_secs(),
        prover_root: [0u8; 32],
    }
}
