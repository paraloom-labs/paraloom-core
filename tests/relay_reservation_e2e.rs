//! #226 PR-B: a NATed node reserves a circuit on a relay server over a real
//! libp2p network (TCP loopback).
//!
//! The unit tests in `network::protocol` prove the relay-server `Toggle`
//! flips with config and that the swarm builds with the relay-client transport
//! woven in. This test proves the *end-to-end reservation path*: a second node
//! dials a relay-server node, requests a circuit-relay v2 reservation, and —
//! once the relay grants it — starts listening on the resulting
//! `/<relay>/p2p-circuit` address. That `/p2p-circuit` listener is the
//! observable signal that a peer behind a NAT has become reachable through the
//! relay; nothing else in the swarm produces it.
//!
//! No NAT is simulated (both nodes are on loopback): the test exercises the
//! reservation protocol itself, not the kernel-level traversal. DCUtR's
//! hole-punch upgrade is not asserted here — on loopback there is nothing to
//! punch through; it is logged and left to live devnet validation.
//!
//! Ignored by default: it binds loopback TCP and depends on reservation timing.
//! CI runs it with `--ignored`, like the other libp2p e2e tests.

use paraloom::config::Settings;
use paraloom::network::NetworkManager;
use std::time::{Duration, Instant};

/// An OS-assigned free loopback port. Binding to port 0 and reading back the
/// assignment avoids fixed-port cross-run flakiness (a port left in TIME_WAIT
/// is not handed out as free, so successive runs never collide).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// Network-only settings on a fixed loopback port. Starts from
/// `Settings::development()` and overrides just the network fields; the relay
/// server is opt-in via `enable_relay_server`. (The sub-settings structs are
/// not re-exported, so we mutate the public fields rather than build literally.)
fn net_settings(port: u16, enable_relay_server: bool) -> Settings {
    let mut s = Settings::development();
    s.network.listen_address = format!("/ip4/127.0.0.1/tcp/{port}");
    s.network.enable_mdns = false;
    s.network.enable_relay_server = enable_relay_server;
    s
}

/// Poll `condition` until it returns true or `deadline` elapses, sleeping
/// `step` between checks. No fixed sleeps: a fast machine proceeds immediately
/// and a slow CI runner still gets the full budget.
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
#[ignore = "binds loopback TCP + depends on relay reservation timing; CI runs with --ignored"]
async fn nated_node_reserves_circuit_on_relay_server() {
    let _ = env_logger::builder().is_test(true).try_init();

    let (port_a, port_b) = (free_port(), free_port());

    // Node A: a public, dialable relay server.
    let mgr_a = NetworkManager::new(&net_settings(port_a, true)).expect("relay-server manager");
    mgr_a
        .start(
            format!("/ip4/127.0.0.1/tcp/{port_a}")
                .parse()
                .expect("listen addr A"),
        )
        .await
        .expect("start node A");
    assert!(
        mgr_a.relay_server_enabled().await,
        "node A must be running a relay server"
    );
    // A relay grants reservations that carry only its own external
    // addresses; on loopback there is no AutoNAT server to confirm one,
    // so declare it explicitly or the client gets an empty reservation
    // (NoAddressesInReservation) and never obtains a circuit address.
    mgr_a
        .add_external_address(&format!("/ip4/127.0.0.1/tcp/{port_a}"))
        .await
        .expect("declare A's external address");

    // Node B: the "NATed" client (loopback stands in for a NATed peer).
    let mgr_b = NetworkManager::new(&net_settings(port_b, false)).expect("client manager");
    mgr_b
        .start(
            format!("/ip4/127.0.0.1/tcp/{port_b}")
                .parse()
                .expect("listen addr B"),
        )
        .await
        .expect("start node B");

    // B's reservation dial fires as soon as it listens on the circuit, so A
    // must already be accepting connections. Probe the port directly — a
    // deterministic readiness signal, not a blind sleep.
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
    assert!(
        a_listening,
        "relay server A did not start listening on {port_a} within 15s"
    );

    // B reserves a slot on A's relay and starts listening via the circuit.
    // The address must carry A's /p2p/<peer_id> suffix for the relay client to
    // identify the reservation target.
    let relay_addr = format!("/ip4/127.0.0.1/tcp/{port_a}/p2p/{}", mgr_a.peer_id_base58());
    mgr_b
        .listen_via_relay(&relay_addr)
        .await
        .expect("node B requests a relay reservation");

    // The reservation is confirmed asynchronously. Once A grants it, B's
    // listener set gains the `/p2p-circuit` address — the proof that B is now
    // reachable through the relay. Poll for it rather than sleeping a fixed
    // amount so a fast run finishes quickly.
    let until = Instant::now() + Duration::from_secs(30);
    let mut reserved = false;
    while Instant::now() < until {
        if mgr_b
            .listen_addresses()
            .await
            .iter()
            .any(|a| a.contains("p2p-circuit"))
        {
            reserved = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        reserved,
        "node B did not obtain a /p2p-circuit reservation on the relay within 30s"
    );
}
