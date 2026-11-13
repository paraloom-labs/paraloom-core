//! Regression tests verifying that `NetworkManager::run_event_loop` owns
//! `Swarm` directly without holding `Arc<Mutex<Swarm>>` across `swarm.next().await`.
//!
//! Covers the three starvation/deadlock modes fixed for #1599:
//! 1. Idle `NetworkManager` commands completing immediately without waiting on a `SwarmEvent`.
//! 2. Sequential `send_cosign_request` round-trips completing without ~15s ping-interval stalls.
//! 3. `Node::run()` bootstrap retry loop recovering once a delayed bootstrap node comes online.

use paraloom::config::Settings;
use paraloom::coordinator::CoordinatorSnapshot;
use paraloom::network::cosign::{CoSignRequest, SettlementKind};
use paraloom::network::{HeartbeatRequest, NetworkManager, ResultRequest};
use paraloom::node::Node;
use paraloom::task::{ResultData, TaskResult};
use std::net::TcpListener;
use std::time::{Duration, Instant};

fn free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

fn network_settings(listen_port: u16, data_dir: &str) -> Settings {
    let mut settings = Settings::development();
    settings.network.listen_address = format!("/ip4/127.0.0.1/tcp/{listen_port}");
    settings.network.bootstrap_nodes = Vec::new();
    settings.network.enable_mdns = false;
    settings.storage.data_dir = data_dir.to_string();
    settings
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

#[tokio::test]
async fn idle_network_manager_commands_complete_without_starvation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let settings = network_settings(0, dir.path().to_str().expect("utf8 path"));
    let mgr = NetworkManager::new(&settings).expect("NetworkManager::new");
    let listen_addr = settings.network.listen_address.parse().expect("multiaddr");
    mgr.start(listen_addr).await.expect("start");

    // Let initial NewListenAddr drain so the event loop is parked idle in select!.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let dummy_peer_id = mgr.local_peer_id();
    let dummy_addr = format!("/ip4/127.0.0.1/tcp/1/p2p/{}", mgr.peer_id_base58());

    let t0 = Instant::now();
    let listen_addrs = tokio::time::timeout(Duration::from_secs(2), mgr.listen_addresses())
        .await
        .expect("listen_addresses should not starve");
    assert!(
        !listen_addrs.is_empty(),
        "started manager should report at least one listen address"
    );

    let relay_enabled = tokio::time::timeout(Duration::from_secs(2), mgr.relay_server_enabled())
        .await
        .expect("relay_server_enabled should not starve");
    assert!(!relay_enabled);

    tokio::time::timeout(
        Duration::from_secs(2),
        mgr.add_external_address("/ip4/127.0.0.1/tcp/12345"),
    )
    .await
    .expect("add_external_address should not starve")
    .expect("valid external multiaddr");

    tokio::time::timeout(
        Duration::from_secs(2),
        mgr.redial_disconnected_co_validators(std::slice::from_ref(&dummy_addr)),
    )
    .await
    .expect("redial_disconnected_co_validators should not starve");

    tokio::time::timeout(
        Duration::from_secs(2),
        mgr.connect_to_bootstrap(vec![dummy_addr]),
    )
    .await
    .expect("connect_to_bootstrap should not starve")
    .expect("connect_to_bootstrap returns Ok");

    tokio::time::timeout(
        Duration::from_secs(2),
        mgr.send_heartbeat_request(
            dummy_peer_id.clone(),
            HeartbeatRequest {
                primary: dummy_peer_id.clone(),
                sequence: 1,
                snapshot: CoordinatorSnapshot::default(),
            },
        ),
    )
    .await
    .expect("send_heartbeat_request should not starve")
    .expect("send_heartbeat_request enqueues");

    tokio::time::timeout(
        Duration::from_secs(2),
        mgr.send_result_request(
            dummy_peer_id,
            ResultRequest {
                result: TaskResult {
                    task_id: "idle-regression".to_string(),
                    execution_time_ms: 1,
                    data: ResultData::Hashes {
                        hashes: Vec::new(),
                        count: 0,
                    },
                },
            },
        ),
    )
    .await
    .expect("send_result_request should not starve")
    .expect("send_result_request enqueues");

    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "all idle swarm commands must complete promptly, elapsed={:?}",
        t0.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connected_peers_sequential_cosign_requests_complete_without_ping_stall() {
    let dir_a = tempfile::tempdir().expect("tempdir A");
    let dir_b = tempfile::tempdir().expect("tempdir B");
    let port_a = free_tcp_port();

    let mgr_a = NetworkManager::new(&network_settings(port_a, dir_a.path().to_str().unwrap()))
        .expect("mgr_a");
    let mgr_b =
        NetworkManager::new(&network_settings(0, dir_b.path().to_str().unwrap())).expect("mgr_b");

    mgr_a
        .start(format!("/ip4/127.0.0.1/tcp/{port_a}").parse().unwrap())
        .await
        .expect("start A");
    mgr_b
        .start("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .await
        .expect("start B");

    let addr_a = format!("/ip4/127.0.0.1/tcp/{port_a}/p2p/{}", mgr_a.peer_id_base58());
    mgr_b
        .connect_to_bootstrap(vec![addr_a])
        .await
        .expect("dial A");

    let connected = wait_until(
        Duration::from_secs(5),
        Duration::from_millis(20),
        || async {
            !mgr_a.connected_peers().await.is_empty() && !mgr_b.connected_peers().await.is_empty()
        },
    )
    .await;
    assert!(connected, "peers failed to connect within 5s");

    // Let handshake events drain so both event loops sit idle between 15s pings.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let t_query = Instant::now();
    let addrs = tokio::time::timeout(Duration::from_secs(3), mgr_a.listen_addresses())
        .await
        .expect("listen_addresses on idle connected swarm must not stall for 15s ping");
    assert!(!addrs.is_empty());
    assert!(
        t_query.elapsed() < Duration::from_secs(3),
        "listen_addresses took {:?}",
        t_query.elapsed()
    );

    let peer_b = mgr_b.local_peer_id();
    for idx in 1..=2 {
        let req = CoSignRequest {
            request_id: format!("reg-cosign-{idx}"),
            kind: SettlementKind::Transact,
            message: vec![1, 2, 3, 4],
        };
        let t_req = Instant::now();
        let resp = tokio::time::timeout(
            Duration::from_secs(3),
            mgr_a.send_cosign_request(peer_b.clone(), req),
        )
        .await
        .unwrap_or_else(|_| panic!("sequential cosign #{idx} stalled past 3s"))
        .unwrap_or_else(|e| panic!("sequential cosign #{idx} failed: {e}"));
        assert_eq!(resp.request_id, format!("reg-cosign-{idx}"));
        assert!(
            t_req.elapsed() < Duration::from_secs(3),
            "sequential cosign #{idx} took {:?}",
            t_req.elapsed()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_run_bootstrap_retry_recovers_after_delayed_bootstrap_start() {
    let dir_boot = tempfile::tempdir().expect("tempdir boot");
    let dir_node = tempfile::tempdir().expect("tempdir node");
    let boot_port = free_tcp_port();

    let boot_mgr = NetworkManager::new(&network_settings(
        boot_port,
        dir_boot.path().to_str().expect("utf8 path"),
    ))
    .expect("boot_mgr");
    let boot_addr = format!(
        "/ip4/127.0.0.1/tcp/{boot_port}/p2p/{}",
        boot_mgr.peer_id_base58()
    );

    let mut settings = network_settings(0, dir_node.path().to_str().expect("utf8 path"));
    settings.network.bootstrap_nodes = vec![boot_addr];
    let node = Node::new(settings).expect("Node::new");
    let node_ref = node.clone();
    let node_handle = tokio::spawn(async move { node_ref.run().await });

    // Wait past attempt 1 (1000ms cadence) so attempt 2+ has already executed.
    tokio::time::sleep(Duration::from_millis(1600)).await;

    // Now start the bootstrap node; subsequent retry attempts must connect promptly.
    boot_mgr
        .start(format!("/ip4/127.0.0.1/tcp/{boot_port}").parse().unwrap())
        .await
        .expect("start bootstrap");

    let connected = wait_until(
        Duration::from_secs(6),
        Duration::from_millis(50),
        || async { !boot_mgr.connected_peers().await.is_empty() },
    )
    .await;
    assert!(
        connected,
        "Node::run bootstrap retry loop must recover once bootstrap comes online"
    );
    assert!(!node_handle.is_finished());

    let _ = node.stop().await;
    node_handle.abort();
}
