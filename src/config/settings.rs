//! Settings for the Paraloom node

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Node settings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    /// Network settings
    pub network: NetworkSettings,
    /// Node settings
    pub node: NodeSettings,
    /// Storage settings
    pub storage: StorageSettings,
}

/// Network settings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// Listening address
    pub listen_address: String,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
    /// Enable mDNS discovery
    pub enable_mdns: bool,
}

/// Node settings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeSettings {
    /// Node type
    pub node_type: String,
    /// Maximum CPU usage in percentage
    pub max_cpu_usage: u8,
    /// Maximum memory usage in percentage
    pub max_memory_usage: u8,
    /// Maximum storage usage in MB
    pub max_storage_usage: u64,
}

/// Storage settings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageSettings {
    /// Path to data directory
    pub data_dir: String,
}

impl Settings {
    /// Load settings from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let settings = toml::from_str(&content)?;
        Ok(settings)
    }
    
    /// Create development settings
    pub fn development() -> Self {
        Settings {
            network: NetworkSettings {
                listen_address: "/ip4/127.0.0.1/tcp/0".to_string(),
                bootstrap_nodes: vec![],
                enable_mdns: true,
            },
            node: NodeSettings {
                node_type: "ResourceProvider".to_string(),
                max_cpu_usage: 80,
                max_memory_usage: 70,
                max_storage_usage: 10240, // 10 GB
            },
            storage: StorageSettings {
                data_dir: "./data".to_string(),
            },
        }
    }
}