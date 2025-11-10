//! Bridge type definitions

use serde::{Deserialize, Serialize};

/// Solana address (32 bytes)
pub type SolanaAddress = [u8; 32];

/// Deposit event from Solana
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositEvent {
    /// Transaction signature on Solana
    pub signature: String,

    /// Depositor's Solana address
    pub from: SolanaAddress,

    /// Amount deposited (in lamports)
    pub amount: u64,

    /// Shielded address to receive private funds
    pub recipient: [u8; 32],

    /// Randomness for commitment
    pub randomness: [u8; 32],

    /// Fee paid
    pub fee: u64,

    /// Block number
    pub block: u64,

    /// Timestamp
    pub timestamp: i64,
}

/// Withdrawal request to Solana
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    /// Nullifier proving ownership
    pub nullifier: [u8; 32],

    /// Amount to withdraw
    pub amount: u64,

    /// Recipient Solana address
    pub recipient: SolanaAddress,

    /// Fee
    pub fee: u64,

    /// zkSNARK proof
    pub proof: Vec<u8>,
}

/// Bridge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Solana RPC endpoint
    pub solana_rpc_url: String,

    /// Solana program ID
    pub program_id: String,

    /// Poll interval for events (seconds)
    pub poll_interval_secs: u64,

    /// Starting block for event listener
    pub start_block: Option<u64>,

    /// Enable bridge (can be disabled for testing)
    pub enabled: bool,

    /// Bridge authority keypair path (for signing withdrawals)
    pub authority_keypair_path: Option<String>,

    /// Bridge vault address (PDA for holding funds)
    pub bridge_vault: Option<String>,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            solana_rpc_url: std::env::var("SOLANA_RPC_URL")
                .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string()),
            program_id: std::env::var("SOLANA_PROGRAM_ID").unwrap_or_default(),
            poll_interval_secs: std::env::var("BRIDGE_POLL_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5),
            start_block: std::env::var("BRIDGE_START_BLOCK")
                .ok()
                .and_then(|s| s.parse().ok()),
            enabled: std::env::var("BRIDGE_ENABLED")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(false),
            authority_keypair_path: std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH").ok(),
            bridge_vault: std::env::var("BRIDGE_VAULT_ADDRESS").ok(),
        }
    }
}

/// Bridge statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BridgeStats {
    /// Total deposits processed
    pub total_deposits: u64,

    /// Total withdrawals processed
    pub total_withdrawals: u64,

    /// Total volume deposited
    pub volume_deposited: u64,

    /// Total volume withdrawn
    pub volume_withdrawn: u64,

    /// Last processed block
    pub last_block: u64,
}
