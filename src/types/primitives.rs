//! Basic data structures for the Paraloom network

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

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

/// Round-trip with `Display`: the hex form an operator pastes into
/// a config file decodes back to the same byte vector. Used by the
/// HA settings (#66) to lift `String` config values into `NodeId`
/// at node startup.
impl FromStr for NodeId {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(s).map(NodeId)
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nodeid_display_and_fromstr_round_trip() {
        let id = NodeId(vec![0x12, 0x34, 0xab, 0xcd, 0xef]);
        let rendered = format!("{}", id);
        assert_eq!(rendered, "1234abcdef");
        let parsed: NodeId = rendered.parse().expect("decode");
        assert_eq!(parsed, id);
    }

    #[test]
    fn nodeid_fromstr_rejects_odd_length_hex() {
        // hex::decode requires even-length input; an operator who
        // pastes a truncated id should get a clear error rather
        // than a silently-truncated NodeId.
        let result: Result<NodeId, _> = "abc".parse();
        assert!(result.is_err());
    }

    #[test]
    fn nodeid_fromstr_rejects_non_hex_characters() {
        let result: Result<NodeId, _> = "zz".parse();
        assert!(result.is_err());
    }
}
