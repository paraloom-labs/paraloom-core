//! Network message types

use serde::{Deserialize, Serialize};

/// Network message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    /// Ping message
    Ping,
    /// Pong response
    Pong,
    /// Node discovery
    Discovery {
        /// Node information
        node_info: crate::types::NodeInfo,
    },
    /// Resource update
    ResourceUpdate {
        /// Resources being contributed
        resources: crate::types::ResourceContribution,
    },
}
