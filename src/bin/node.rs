//! Paraloom node binary

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::{error, info};
use paraloom::config::Settings;
use paraloom::node::Node;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a node
    Start {
        /// Path to config file
        #[arg(short, long, default_value = "config.toml")]
        config: String,

        /// Run in development mode
        #[arg(long)]
        dev: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Start { config, dev } => {
            info!("Starting Paraloom node...");

            let settings = if dev {
                info!("Using development settings");
                Settings::development()
            } else {
                info!("Loading settings from {}", config);
                match Settings::from_file(&config) {
                    Ok(settings) => settings,
                    Err(e) => {
                        error!("Failed to load settings: {}", e);
                        return Err(anyhow::anyhow!("Failed to load settings"));
                    }
                }
            };

            let node = Node::new(settings)?;
            node.run().await?;

            Ok(())
        }
    }
}
