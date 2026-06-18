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

    /// Asset id of the deposit (#237): the SPL mint's 32 bytes, or all-zero
    /// `NATIVE_SOL_ASSET` for native SOL. The note is indexed under this asset.
    pub asset_id: [u8; 32],

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

    /// Solana slot past which the on-chain program will reject this
    /// request. Bound at construction time to give every withdrawal a
    /// finite window — see #61 and the on-chain `WithdrawalExpired`
    /// error variant.
    pub expiration_slot: u64,

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

    /// Slot lag (current Solana slot − most recently processed slot) at
    /// which the deposit listener will start logging a warning each
    /// poll. ~1500 slots is roughly 10 minutes on Solana mainnet at
    /// 400ms slot times — high enough to ignore brief network blips,
    /// low enough that a stuck listener is visible within a few polls.
    pub event_lag_warn_threshold_slots: u64,

    /// Slots past `getSlot` at which a freshly built `WithdrawalRequest`
    /// will expire. ~150 slots ≈ 60 seconds on Solana mainnet at
    /// ~400ms slots — long enough to absorb the round trip through L2
    /// consensus and the RPC submit, short enough that a leaked
    /// request becomes useless within ~1 minute. See #61.
    pub withdrawal_expiration_window_slots: u64,

    /// Address the Merkle path-query HTTP server binds to on a
    /// bridge-enabled node (#163). Withdrawing clients query it for the
    /// `(root, path)` of the note they spend. The data is public, so the
    /// endpoint is unauthenticated — it defaults to a loopback address
    /// and should stay on a loopback or management interface. Set to an
    /// empty string to disable the server while keeping the bridge on.
    pub merkle_path_query_address: String,

    /// Address the withdrawal-verification ingress HTTP server binds to on a
    /// bridge-enabled node (#184). A client (wallet/CLI) POSTs a withdrawal
    /// request here and the node broadcasts it into the consensus mesh. Unlike
    /// the Merkle path server this *triggers consensus*, so it defaults to an
    /// empty string (disabled) and should stay on a loopback/management
    /// interface when enabled.
    pub withdrawal_ingress_address: String,

    /// Address the transfer-verification ingress HTTP server binds to on a
    /// bridge-enabled node (#194), the transfer twin of
    /// `withdrawal_ingress_address`. A client POSTs a shielded transfer here
    /// and the node broadcasts it into the consensus mesh. Triggers consensus,
    /// so it defaults to an empty string (disabled).
    pub transfer_ingress_address: String,

    /// Shared bearer token the write-surface ingress endpoints
    /// (`withdrawal_ingress_address` / `transfer_ingress_address`) require. When
    /// non-empty, a request must present `Authorization: Bearer <token>` or it is
    /// refused with 401 — so an ingress exposed beyond loopback cannot be driven
    /// by an unauthenticated caller. Empty (the default) keeps the historical
    /// no-auth behaviour, which is only safe on a loopback/management interface.
    pub ingress_token: String,
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
            event_lag_warn_threshold_slots: std::env::var("BRIDGE_EVENT_LAG_WARN_THRESHOLD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1500),
            withdrawal_expiration_window_slots: std::env::var(
                "BRIDGE_WITHDRAWAL_EXPIRATION_WINDOW",
            )
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(150),
            merkle_path_query_address: std::env::var("BRIDGE_MERKLE_PATH_ADDRESS")
                .unwrap_or_else(|_| "127.0.0.1:9090".to_string()),
            withdrawal_ingress_address: std::env::var("BRIDGE_WITHDRAWAL_INGRESS_ADDRESS")
                .unwrap_or_default(),
            transfer_ingress_address: std::env::var("BRIDGE_TRANSFER_INGRESS_ADDRESS")
                .unwrap_or_default(),
            ingress_token: std::env::var("BRIDGE_INGRESS_TOKEN").unwrap_or_default(),
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

    /// Listener event lag in Solana slots, computed each poll as
    /// `current_slot − last_processed_slot`. Useful as a metric to
    /// drive operator dashboards or pageable alerts.
    pub event_lag_slots: u64,
}
