//! CLI tool to submit tasks to coordinator

use anyhow::Result;
use clap::Parser;
use log::info;
use paraloom::config::Settings;
use paraloom::network::NetworkManager;
use paraloom::task::{Task, TaskType};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Parser)]
#[command(author, version, about = "Submit task to Paraloom coordinator")]
struct Cli {
    /// Start number for hash calculation
    #[arg(long, default_value = "0")]
    start: u64,

    /// End number for hash calculation
    #[arg(long, default_value = "1000")]
    end: u64,

    /// Hash algorithm
    #[arg(long, default_value = "sha256")]
    algorithm: String,

    /// Coordinator peer ID (e.g., 12D3KooW...)
    #[arg(long)]
    coordinator: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    info!("Submitting task to coordinator: {}", cli.coordinator);
    info!("Hash calculation: {} to {}", cli.start, cli.end);

    // Create network manager
    let mut settings = Settings::development();
    settings.network.listen_address = "/ip4/127.0.0.1/tcp/0".to_string();

    let network = NetworkManager::new(&settings)?;
    let network_arc = Arc::new(network);

    // Parse coordinator address
    let coordinator_addr = format!("/ip4/127.0.0.1/tcp/9001/p2p/{}", cli.coordinator);

    info!("Connecting to coordinator: {}", coordinator_addr);

    // Start network
    let listen_addr = settings.network.listen_address.parse()?;
    network_arc.start(listen_addr).await?;

    // Connect to coordinator
    network_arc
        .connect_to_bootstrap(vec![coordinator_addr])
        .await?;

    // Wait for connection
    sleep(Duration::from_secs(2)).await;

    // Create and send task
    let task = Task::new(TaskType::HashCalculation {
        start: cli.start,
        end: cli.end,
        algorithm: cli.algorithm,
    });

    info!("Task created: {}", task.id);
    info!("Sending TaskRequest...");

    // Note: This is simplified. In production, we need to get coordinator's NodeId
    // For now, we'll log the task but can't directly submit without proper coordinator discovery

    info!(
        "Task would be submitted: {} (range: {} to {})",
        task.id, cli.start, cli.end
    );
    info!("Note: Full task submission requires coordinator discovery implementation");

    Ok(())
}
