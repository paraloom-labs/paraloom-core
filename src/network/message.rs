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

    // Task-related messages

    /// Coordinator -> Validator: Execute this task
    TaskRequest {
        task: crate::task::Task,
    },

    /// Validator -> Coordinator: Task completed
    TaskResponse {
        result: crate::task::TaskResult,
    },

    /// Validator -> Coordinator: Task failed
    TaskError {
        task_id: String,
        error: String,
    },
}
