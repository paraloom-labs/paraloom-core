//! Node test with resource monitoring

use anyhow::Result;
use log::info;
use paraloom::{config::Settings, node::Node};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info")
    );
    
    info!("Starting Paraloom node test");
    
    // Create development settings
    let settings = Settings::development();
    
    // Create and run the node
    let node = Node::new(settings)?;
    
    // Run the node (this will start resource monitoring and networking)
    node.run().await?;
    
    Ok(())
}