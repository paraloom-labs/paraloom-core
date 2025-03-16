//! Resource monitoring test

use anyhow::Result;
use log::info;
use paraloom::{config::Settings, resource::ResourceMonitor};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    info!("Starting resource monitoring test");

    // Create a resource monitor with some limits
    let monitor = ResourceMonitor::new(
        80,    // max CPU usage %
        70,    // max memory usage %
        10240, // max storage usage (10GB)
    );

    // Check for GPU information
    if let Some(gpu_info) = monitor.check_gpu() {
        info!("Detected GPU: {}", gpu_info);
    } else {
        info!("No GPU detected or information not available");
    }

    // Start resource monitoring
    monitor.start().await?;

    // Initial resource contribution
    let initial = monitor.get_contribution();
    info!("Initial contribution: {:?}", initial);

    // Keep the program running to collect resource information
    info!("Resource monitor running. Press Ctrl+C to stop...");

    // Run for a minute, reporting resources every 10 seconds
    for _ in 0..6 {
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        let current = monitor.get_contribution();
        info!("Current resource contribution: {:?}", current);
    }

    info!("Resource monitoring test completed");

    Ok(())
}
