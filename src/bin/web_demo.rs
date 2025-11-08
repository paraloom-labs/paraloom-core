//! Web dashboard demo with task execution
//!
//! This demo starts:
//! - 1 Coordinator node (port 9001) with web dashboard (port 8080)
//! - 2 Validator nodes (ports 9002, 9003)
//!
//! Open http://localhost:8080 in your browser to submit tasks

use paraloom::{
    node::Node,
    web::{server::start_dashboard_with_coordinator, DashboardState},
    Settings,
};
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("\n=== Paraloom Web Dashboard Demo ===\n");
    println!("Starting distributed task execution system...\n");

    // Start Coordinator with Dashboard
    let coordinator_task = tokio::spawn(async move {
        let mut settings = Settings::development();
        settings.node.node_type = "Coordinator".to_string();
        settings.network.listen_address = "/ip4/0.0.0.0/tcp/9001".to_string();
        settings.network.bootstrap_nodes = vec![];

        let node = Node::new(settings).expect("Failed to create coordinator node");
        let coordinator = node.coordinator().expect("Coordinator not initialized");

        // Create dashboard state
        let dashboard_state = DashboardState::new();

        // Add coordinator node info to dashboard
        dashboard_state.add_node(&node.node_info());

        // Periodically update dashboard with connected peers
        let dashboard_clone = dashboard_state.clone();
        let coordinator_clone = coordinator.clone();
        let node_clone = node.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(5)).await;

                // Clear old nodes and refresh
                dashboard_clone.clear_nodes();

                // Add coordinator node
                dashboard_clone.add_node(&node_clone.node_info());

                // Get connected peers from coordinator
                let peers = coordinator_clone.get_connected_peers().await;
                log::info!("Dashboard update: {} connected peers", peers.len());

                // For each peer, create a node info for dashboard
                for peer in peers {
                    use paraloom::types::{NodeInfo, NodeType, ResourceContribution};
                    let peer_info = NodeInfo {
                        id: peer.clone(),
                        node_type: NodeType::ResourceProvider,
                        resources: ResourceContribution {
                            cpu_cores: 12, // Will be updated when we receive actual info
                            memory_mb: 16000,
                            storage_mb: 10240,
                            bandwidth_kbps: 10000,
                        },
                        address: "remote".to_string(),
                    };
                    dashboard_clone.add_node(&peer_info);
                }
            }
        });

        println!("Coordinator started on port 9001");
        println!("Dashboard starting on http://localhost:8080\n");

        // Manually register validator nodes (workaround for p2p messaging issue)
        let coordinator_clone = coordinator.clone();
        tokio::spawn(async move {
            // Wait longer for validators to connect and gossipsub mesh to form
            sleep(Duration::from_secs(8)).await;
            println!("Registering connected validators...");
            coordinator_clone.register_connected_validators().await;
            println!("Validators registered. You can now submit tasks!");
        });

        // Start node in background
        let node_handle = tokio::spawn(async move {
            if let Err(e) = node.run().await {
                eprintln!("Coordinator node error: {}", e);
            }
        });

        // Start dashboard with coordinator integration
        if let Err(e) = start_dashboard_with_coordinator(dashboard_state, coordinator, 8080).await {
            eprintln!("Dashboard server error: {}", e);
        }

        node_handle.await.expect("Node task failed");
    });

    // Wait for coordinator to initialize
    sleep(Duration::from_secs(3)).await;

    // Start Validator 1
    let validator1_task = tokio::spawn(async move {
        let mut settings = Settings::development();
        settings.node.node_type = "ResourceProvider".to_string();
        settings.network.listen_address = "/ip4/127.0.0.1/tcp/9002".to_string();
        settings.network.bootstrap_nodes = vec!["/ip4/127.0.0.1/tcp/9001".to_string()];

        let node = Node::new(settings).expect("Failed to create validator 1");
        println!("Validator 1 started on port 9002");

        if let Err(e) = node.run().await {
            eprintln!("Validator 1 error: {}", e);
        }
    });

    // Wait before starting next validator
    sleep(Duration::from_secs(2)).await;

    // Start Validator 2
    let validator2_task = tokio::spawn(async move {
        let mut settings = Settings::development();
        settings.node.node_type = "ResourceProvider".to_string();
        settings.network.listen_address = "/ip4/127.0.0.1/tcp/9003".to_string();
        settings.network.bootstrap_nodes = vec!["/ip4/127.0.0.1/tcp/9001".to_string()];

        let node = Node::new(settings).expect("Failed to create validator 2");
        println!("Validator 2 started on port 9003\n");

        if let Err(e) = node.run().await {
            eprintln!("Validator 2 error: {}", e);
        }
    });

    println!("=== System Ready ===");
    println!("Open your browser to: http://localhost:8080");
    println!("Submit a task and watch it get distributed and executed!\n");

    // Wait for all tasks
    tokio::try_join!(coordinator_task, validator1_task, validator2_task)?;

    Ok(())
}
