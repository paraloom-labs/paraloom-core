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
        coordinator_id: crate::types::NodeId,
    },

    /// Validator -> Coordinator: Task completed
    TaskResponse { result: crate::task::TaskResult },

    /// Validator -> Coordinator: Task failed
    TaskError { task_id: String, error: String },

    // Privacy-related messages
    /// Submit a shielded transaction
    ShieldedTransaction {
        transaction: crate::privacy::transaction::ShieldedTransaction,
    },

    /// Request verification of a transaction chunk
    VerificationRequest {
        task_id: String,
        transaction_id: String,
        chunk: crate::privacy::proof::VerificationChunk,
    },

    /// Submit verification result
    VerificationResult {
        task_id: String,
        validator_id: crate::types::NodeId,
        result: crate::privacy::proof::VerificationResult,
    },

    /// Query shielded pool state
    PoolStateQuery,

    /// Response with pool state
    PoolStateResponse {
        merkle_root: [u8; 32],
        total_supply: u64,
        commitment_count: usize,
    },

    /// Query if a nullifier has been spent
    NullifierQuery {
        nullifier: crate::privacy::types::Nullifier,
    },

    /// Response to nullifier query
    NullifierResponse {
        nullifier: crate::privacy::types::Nullifier,
        is_spent: bool,
    },
}
