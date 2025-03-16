//! Basic data structures for the Paraloom network

use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a node
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub Vec<u8>);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Resources a node is contributing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceContribution {
    /// CPU cores
    pub cpu_cores: u8,
    /// Memory in megabytes
    pub memory_mb: u64,
    /// Storage in megabytes
    pub storage_mb: u64,
    /// Bandwidth in kbps
    pub bandwidth_kbps: u64,
}

/// Node type in the network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeType {
    /// Standard node providing resources
    ResourceProvider,
    /// Coordinator for task distribution
    Coordinator,
    /// Bridge to Solana network
    Bridge,
}

/// Node information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Unique identifier
    pub id: NodeId,
    /// Type of node
    pub node_type: NodeType,
    /// Resources contributed
    pub resources: ResourceContribution,
    /// Network address
    pub address: String,
}

/// Status of a node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Node is starting up
    Starting,
    /// Node is fully operational
    Running,
    /// Node is shutting down
    ShuttingDown,
    /// Node has encountered an error
    Error(String),
}