//! Demo: Run coordinator and validator, then submit task

use anyhow::Result;
use log::info;
use paraloom::config::Settings;
use paraloom::node::Node;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("=================================");
    info!("Paraloom Task Demo");
    info!("=================================");

    // Create coordinator
    let mut coord_settings = Settings::development();
    coord_settings.node.node_type = "Coordinator".to_string();
    coord_settings.network.listen_address = "/ip4/127.0.0.1/tcp/9001".to_string();

    let coordinator = Node::new(coord_settings)?;

    // Start coordinator in background
    let coord_handle = tokio::spawn(async move {
        if let Err(e) = coordinator.run().await {
            log::error!("Coordinator error: {}", e);
        }
    });

    // Wait for coordinator to start
    sleep(Duration::from_secs(2)).await;

    info!("Coordinator started");

    // Create validator 1
    let mut val1_settings = Settings::development();
    val1_settings.node.node_type = "ResourceProvider".to_string();
    val1_settings.network.listen_address = "/ip4/127.0.0.1/tcp/9002".to_string();
    val1_settings.network.bootstrap_nodes = vec!["/ip4/127.0.0.1/tcp/9001".to_string()];

    let validator1 = Node::new(val1_settings)?;

    let val1_handle = tokio::spawn(async move {
        if let Err(e) = validator1.run().await {
            log::error!("Validator 1 error: {}", e);
        }
    });

    sleep(Duration::from_secs(2)).await;
    info!("Validator 1 started");

    // Create validator 2
    let mut val2_settings = Settings::development();
    val2_settings.node.node_type = "ResourceProvider".to_string();
    val2_settings.network.listen_address = "/ip4/127.0.0.1/tcp/9003".to_string();
    val2_settings.network.bootstrap_nodes = vec!["/ip4/127.0.0.1/tcp/9001".to_string()];

    let validator2 = Node::new(val2_settings)?;

    let val2_handle = tokio::spawn(async move {
        if let Err(e) = validator2.run().await {
            log::error!("Validator 2 error: {}", e);
        }
    });

    sleep(Duration::from_secs(2)).await;
    info!("Validator 2 started");

    // Wait for validators to connect and register
    info!("Waiting for validators to register...");
    sleep(Duration::from_secs(5)).await;

    info!("=================================");
    info!("Submitting test task...");
    info!("Task: Calculate SHA256 hashes of numbers 0 to 1000");
    info!("=================================");

    // Note: We need to get the coordinator reference to submit the task
    // For now, this demo just shows the infrastructure working
    // Task submission would be done via the coordinator.submit_task() method

    info!("Infrastructure is running. Task submission requires coordinator access.");
    info!("In a real scenario, you would:");
    info!("  1. Get coordinator reference");
    info!("  2. Call coordinator.submit_task(TaskType::HashCalculation {{...}})");
    info!("  3. Task would be split and distributed to validators");
    info!("  4. Results would be aggregated");

    info!("=================================");
    info!("Demo will run for 30 seconds...");
    info!("Observe logs for connection events");
    info!("=================================");

    // Keep running for a while
    sleep(Duration::from_secs(30)).await;

    info!("Demo complete");

    // Clean shutdown
    coord_handle.abort();
    val1_handle.abort();
    val2_handle.abort();

    Ok(())
}
