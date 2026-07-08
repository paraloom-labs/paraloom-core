//! #260: the settlement co-signing request-response protocol carries a request
//! to a peer and a response back over a real libp2p network (TCP loopback).
//!
//! The unit tests in `network::cosign` prove the codec round-trips. This test
//! proves the *end-to-end wire path* wired up in the swarm: a node sends a
//! `CoSignRequest` to a connected peer, the peer's event loop dispatches it to
//! its `handle_cosign_request` handler, and the response is routed back and
//! matched to the awaiting `send_cosign_request` call via the outbound-request
//! correlation map. That round-trip — send, dispatch, reply, correlate — is the
//! new machinery; nothing else exercises it.
//!
//! No co-signing handler is installed on the responder, so it takes the trait
//! default and *declines* (`signature: None`). The decline is the point: it
//! confirms the request reached the handler and a well-formed response came
//! back, independent of the verify-then-sign logic that lands on the node.
//!
//! Ignored by default: it binds loopback TCP and depends on connection timing.
//! CI runs it with `--ignored`, like the other libp2p e2e tests.

use paraloom::config::Settings;
use paraloom::network::cosign::{CoSignRequest, SettlementKind};
use paraloom::network::NetworkManager;
use std::time::{Duration, Instant};

/// An OS-assigned free loopback port (bind to 0, read back the assignment) so
/// successive runs never collide on a port left in TIME_WAIT.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// Network-only settings on a fixed loopback port, mDNS off.
fn net_settings(port: u16) -> Settings {
    let mut s = Settings::development();
    s.network.listen_address = format!("/ip4/127.0.0.1/tcp/{port}");
    s.network.enable_mdns = false;
    s
}

/// Poll `condition` until it returns true or `deadline` elapses.
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
#[ignore = "binds loopback TCP + depends on connection timing; CI runs with --ignored"]
async fn cosign_request_round_trips_to_a_peer() {
    let _ = env_logger::builder().is_test(true).try_init();

    let (port_a, port_b) = (free_port(), free_port());

    // Node A: the round leader that sends the co-sign request.
    let mgr_a = NetworkManager::new(&net_settings(port_a)).expect("manager A");
    mgr_a
        .start(
            format!("/ip4/127.0.0.1/tcp/{port_a}")
                .parse()
                .expect("listen addr A"),
        )
        .await
        .expect("start node A");

    // Node B: the validator that receives the request and replies.
    let mgr_b = NetworkManager::new(&net_settings(port_b)).expect("manager B");
    mgr_b
        .start(
            format!("/ip4/127.0.0.1/tcp/{port_b}")
                .parse()
                .expect("listen addr B"),
        )
        .await
        .expect("start node B");

    // A must already be accepting connections before B dials it. Probe the port
    // directly — a deterministic readiness signal, not a blind sleep.
    let a_listening = wait_until(
        Duration::from_secs(15),
        Duration::from_millis(100),
        || async {
            tokio::net::TcpStream::connect(("127.0.0.1", port_a))
                .await
                .is_ok()
        },
    )
    .await;
    assert!(a_listening, "node A did not listen on {port_a} within 15s");

    // B dials A so the two are connected; the co-sign request then travels over
    // that established connection.
    let a_addr = format!("/ip4/127.0.0.1/tcp/{port_a}/p2p/{}", mgr_a.peer_id_base58());
    mgr_b
        .connect_to_bootstrap(vec![a_addr])
        .await
        .expect("B dials A");

    // Wait until A sees B as a connected peer, so `send_cosign_request` has a
    // live route to it.
    let b_node_id = mgr_b.local_peer_id();
    let connected = wait_until(Duration::from_secs(20), Duration::from_millis(200), || {
        let mgr_a = &mgr_a;
        let b_node_id = b_node_id.clone();
        async move { mgr_a.connected_peers().await.contains(&b_node_id) }
    })
    .await;
    assert!(connected, "A did not connect to B within 20s");

    // A sends B a co-sign request and awaits the reply.
    let request = CoSignRequest {
        request_id: "e2e-round-1".to_string(),
        kind: SettlementKind::Transact,
        message: vec![0xA1, 0xB2, 0xC3, 0xD4],
    };
    let response = mgr_a
        .send_cosign_request(b_node_id, request)
        .await
        .expect("A receives a co-sign response from B");

    // B installed no co-sign handler, so it declined — but the request reached
    // the handler and a well-formed, correlated reply came back.
    assert_eq!(
        response.request_id, "e2e-round-1",
        "the response must echo the request id so the leader can correlate it"
    );
    assert_eq!(
        response.signature, None,
        "with no handler installed the responder declines (signature: None)"
    );
}
