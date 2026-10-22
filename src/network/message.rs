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

    // Consensus-related messages. The legacy off-chain-root
    // `Withdrawal`/`Transfer` verification messages were removed; the surviving
    // consensus flow is the unified `Transact` (appended at the end of the enum
    // to keep the bincode variant indices of the other messages stable).
    /// Validator registration announcement
    ValidatorRegistration {
        validator_id: crate::types::NodeId,
        stake_amount: u64,
        pubkey: Option<String>,
    },

    /// Validator unregistration announcement
    ValidatorUnregistration { validator_id: crate::types::NodeId },

    /// Validator heartbeat (liveness check)
    ValidatorHeartbeat {
        validator_id: crate::types::NodeId,
        timestamp: u64,
    },

    // Compute-related messages
    /// Submit a compute job for execution
    ComputeJobRequest {
        job_id: String,
        wasm_code: Vec<u8>,
        input_data: Vec<u8>,
        max_memory_bytes: u64,
        max_instructions: u64,
        timeout_secs: u64,
    },

    /// Response to compute job submission
    ComputeJobResponse {
        job_id: String,
        accepted: bool,
        message: String,
    },

    /// Query compute job status
    ComputeJobQuery { job_id: String },

    /// Response with compute job result
    ComputeJobResult {
        job_id: String,
        status: crate::compute::JobStatus,
        output_data: Option<Vec<u8>>,
        execution_time_ms: u64,
        memory_used_bytes: u64,
        instructions_executed: u64,
    },

    // v3 unified-transact consensus messages (#350). Appended at the very end
    // of the enum, NOT next to the transfer twins: this enum travels gossip
    // bincode-encoded, and bincode encodes the variant index, so inserting
    // mid-enum would shift every later variant and break rolling upgrades.
    /// Transact verification request (broadcast to all validators, #350)
    TransactVerificationRequest {
        request: crate::consensus::transact::TransactVerificationRequest,
    },

    /// Transact verification result (validator -> coordinator, #350)
    TransactVerificationResult {
        result: crate::consensus::transact::TransactVerificationResult,
    },

    /// Wallet-ownership-attested node discovery (#1145).
    ///
    /// Same payload as [`Message::Discovery`], plus an ed25519 signature by the
    /// advertised wallet's key over
    /// [`crate::consensus::transact::discovery_wallet_signing_bytes`] (domain,
    /// NodeId, wallet, timestamp). A peer admits the `NodeId -> wallet` binding
    /// only after verifying this proof, so an unprivileged mesh peer can no
    /// longer claim a registered validator's wallet and inherit its co-sign
    /// authority (the residual gap of #627).
    ///
    /// Appended at the end of the enum, like the transact messages above, so
    /// the bincode discriminant of every existing variant stays stable. The
    /// legacy `Discovery` variant is still emitted for pre-#1145 peers, whose
    /// wallet claim new peers deliberately ignore.
    SignedDiscovery {
        /// Node information; `wallet_pubkey` is the claimed settlement wallet.
        node_info: crate::types::NodeInfo,
        /// Unix seconds at signing time; bounds how long a copy can be replayed.
        timestamp: u64,
        /// ed25519 signature by `node_info.wallet_pubkey` over the canonical
        /// discovery-wallet preimage.
        wallet_signature: Vec<u8>,
    },
}
