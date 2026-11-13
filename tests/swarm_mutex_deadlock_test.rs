use paraloom::config::Settings;
use paraloom::network::cosign::{CoSignRequest, SettlementKind};
use paraloom::network::NetworkManager;
use paraloom::node::Node;
use std::net::TcpListener;
use std::time::{Duration, Instant};

fn free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

fn network_settings(listen_port: u16) -> Settings {
    let toml_text = format!(
        r#"
        [network]
        listen_address = "/ip4/127.0.0.1/tcp/{listen_port}"
        bootstrap_nodes = []
        enable_mdns = false

        [node]
        node_type = "Coordinator"
        max_cpu_usage = 80
        max_memory_usage = 70
        max_storage_usage = 1024

        [storage]
        data_dir = "/tmp/paraloom_test_unused"
        "#
    );
    toml::from_str(&toml_text).expect("valid test settings")
}

#[tokio::test]
async fn idle_network_manager_does_not_deadlock_on_commands() {
    let settings = network_settings(0);
    let mgr = NetworkManager::new(&settings).expect("NetworkManager::new");
    let listen_addr = settings.network.listen_address.parse().expect("multiaddr");
    mgr.start(listen_addr).await.expect("start");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let dummy_peer = mgr.peer_id_base58();
    let dummy_addr = format!("/ip4/127.0.0.1/tcp/1/p2p/{dummy_peer}");

    let t0 = Instant::now();
    let listen_res = tokio::time::timeout(Duration::from_millis(500), mgr.listen_addresses()).await;
    let relay_res =
        tokio::time::timeout(Duration::from_millis(500), mgr.relay_server_enabled()).await;
    let redial_res = tokio::time::timeout(
        Duration::from_millis(500),
        mgr.redial_disconnected_co_validators(&[dummy_addr.clone()]),
    )
    .await;
    let bootstrap_res = tokio::time::timeout(
        Duration::from_millis(500),
        mgr.connect_to_bootstrap(vec![dummy_addr]),
    )
    .await;
    let elapsed = t0.elapsed();

    assert!(listen_res.is_ok(), "listen_addresses must not deadlock");
    assert!(relay_res.is_ok(), "relay_server_enabled must not deadlock");
    assert!(redial_res.is_ok(), "redial_disconnected_co_validators must not deadlock");
    assert!(bootstrap_res.is_ok(), "connect_to_bootstrap must not deadlock");
    assert!(elapsed < Duration::from_millis(500), "all idle commands must complete in <500ms");
}

#[tokio::test]
async fn sequential_cosign_requests_do_not_stall_for_ping_interval() {
    let port_a = free_tcp_port();
    let mgr_a = NetworkManager::new(&network_settings(port_a)).expect("mgr_a");
    let mgr_b = NetworkManager::new(&network_settings(0)).expect("mgr_b");

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

    let wait_conn = Instant::now();
    while mgr_a.connected_peers().await.is_empty() || mgr_b.connected_peers().await.is_empty() {
        assert!(wait_conn.elapsed() < Duration::from_secs(5), "peers failed to connect in 5s");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let peer_b = mgr_b.local_peer_id();
    let req1 = CoSignRequest {
        request_id: "test-cosign-1".to_string(),
        kind: SettlementKind::Transact,
        message: vec![1, 2, 3, 4],
    };

    let t_cosign_1 = Instant::now();
    let cosign_res_1 = tokio::time::timeout(
        Duration::from_secs(3),
        mgr_a.send_cosign_request(peer_b.clone(), req1),
    )
    .await;
    let cosign_elapsed_1 = t_cosign_1.elapsed();

    assert!(cosign_res_1.is_ok(), "1st cosign request must succeed without timeout");
    assert!(
        cosign_elapsed_1 < Duration::from_secs(2),
        "1st cosign request took too long ({:?})",
        cosign_elapsed_1
    );

    let req2 = CoSignRequest {
        request_id: "test-cosign-2".to_string(),
        kind: SettlementKind::Transact,
        message: vec![5, 6, 7, 8],
    };

    let t_cosign_2 = Instant::now();
    let cosign_res_2 = tokio::time::timeout(
        Duration::from_secs(3),
        mgr_a.send_cosign_request(peer_b, req2),
    )
    .await;
    let cosign_elapsed_2 = t_cosign_2.elapsed();

    assert!(cosign_res_2.is_ok(), "2nd sequential cosign request must succeed without timeout");
    assert!(
        cosign_elapsed_2 < Duration::from_secs(2),
        "2nd sequential cosign request took too long ({:?})",
        cosign_elapsed_2
    );
}

#[tokio::test]
async fn bootstrap_retry_loop_connects_when_bootstrap_starts_late() {
    let dir = tempfile::tempdir().expect("tempdir");
    let boot_port = free_tcp_port();

    let boot_mgr = NetworkManager::new(&network_settings(boot_port)).expect("boot_mgr");
    let boot_addr = format!(
        "/ip4/127.0.0.1/tcp/{boot_port}/p2p/{}",
        boot_mgr.peer_id_base58()
    );

    let data_dir_str = dir.path().to_str().expect("utf8 path");
    let node_toml = format!(
        r#"
        [network]
        listen_address = "/ip4/127.0.0.1/tcp/0"
        bootstrap_nodes = ["{boot_addr}"]
        enable_mdns = false

        [node]
        node_type = "Coordinator"
        max_cpu_usage = 80
        max_memory_usage = 70
        max_storage_usage = 1024

        [storage]
        data_dir = "{data_dir_str}"
        "#
    );
    let settings: Settings = toml::from_str(&node_toml).expect("valid node settings");
    let node = Node::new(settings).expect("Node::new");

    let node_handle = tokio::spawn(async move { node.run().await });

    // Wait 2s for attempt 1 to fail and enter retry sleep
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Now start the bootstrap node
    boot_mgr
        .start(format!("/ip4/127.0.0.1/tcp/{boot_port}").parse().unwrap())
        .await
        .expect("start bootstrap");

    // Wait up to 6s for the node to connect on a subsequent retry attempt
    let start_wait = Instant::now();
    let mut connected = false;
    while start_wait.elapsed() < Duration::from_secs(6) {
        if !boot_mgr.connected_peers().await.is_empty() {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(connected, "Node must connect to bootstrap on retry attempt without deadlocking");
    node_handle.abort();
}
