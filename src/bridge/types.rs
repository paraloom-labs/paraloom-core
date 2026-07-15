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

impl WithdrawalRequest {
    /// Returns true if this withdrawal request has expired relative to the
    /// current slot. A request with `expiration_slot == 0` is treated as
    /// having no expiry (backward compatibility) and never expires.
    ///
    /// Callers should reject requests where `is_expired(current_slot)` returns
    /// `true` before forwarding them to the consensus or on-chain settlement
    /// path (#532).
    pub fn is_expired(&self, current_slot: u64) -> bool {
        self.expiration_slot != 0 && current_slot > self.expiration_slot
    }
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

    /// Address the transact-verification ingress HTTP server binds to on a
    /// bridge-enabled node (#350), the v3 unified-transact twin of
    /// `transfer_ingress_address`. A client POSTs a 2-in/2-out transact (pure
    /// shielded transfer or withdrawal) here and the node broadcasts it into
    /// the consensus mesh. Triggers consensus, so it defaults to an empty
    /// string (disabled). `#[serde(default)]` so a config predating this
    /// field still parses (and stays disabled) instead of failing to load.
    #[serde(default)]
    pub transact_ingress_address: String,

    /// Shared bearer token the write-surface ingress endpoints
    /// (`withdrawal_ingress_address` / `transfer_ingress_address` /
    /// `transact_ingress_address`) require. When non-empty, a request must
    /// present `Authorization: Bearer <token>` or it is refused with 401 — so an
    /// ingress exposed beyond loopback cannot be driven by an unauthenticated
    /// caller. Empty (the default) keeps the historical
    /// no-auth behaviour, which is only safe on a loopback/management interface.
    /// `#[serde(default)]` so a config predating this field still parses (and
    /// gets the empty, no-auth default) instead of failing to load.
    #[serde(default)]
    pub ingress_token: String,

    /// When true (the default) the node settles consensus-approved withdrawals
    /// by gathering a #260 validator co-signing quorum
    /// (`Node::cosign_settlement_tx`) and submitting the multi-sig transaction,
    /// rather than signing single-key. The single-key path is still used when no
    /// `cosign_keypair` is configured (a solo operator with no peers to
    /// co-sign), so this flag only takes effect on a node set up to co-sign.
    #[serde(default = "default_use_cosign_settlement")]
    pub use_cosign_settlement: bool,

    /// Off-chain consensus thresholds — optional override of the BFT defaults
    /// (`DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS` / `_TOTAL_VALIDATORS_` /
    /// `_MIN_REPUTATION_FOR_CONSENSUS`, i.e. 7-of-10 / rep 200). Left unset on
    /// mainnet so the coordinator keeps the secure defaults; devnet operators
    /// lower them in `validator.toml` to settle with a small live cohort. This
    /// is an off-chain availability knob only — it cannot release funds.
    ///
    /// HONEST TRUST NOTE (pre-mainnet): the on-chain validator quorum is
    /// enforced on every settlement, but it is NOT yet Sybil-resistant —
    /// `register_validator` is permissionless (a refundable 1-SOL bond) and the
    /// threshold is counted over the active set, so an attacker holding the
    /// single bridge authority key could register their own validators to meet
    /// it. So the BINDING fund gate on this build is still the single bridge
    /// authority key (`has_one = authority` on every fund instruction), with the
    /// quorum as defence-in-depth on top — NOT a trustless multi-validator gate.
    /// A Sybil-resistant quorum (permissioned set and/or meaningful
    /// stake-weighting) is a tracked mainnet-hardening gate.
    #[serde(default)]
    pub consensus_min_validators: Option<usize>,
    /// See [`Self::consensus_min_validators`] — the percentage divisor.
    #[serde(default)]
    pub consensus_total_validators: Option<usize>,
    /// See [`Self::consensus_min_validators`] — the reputation floor.
    #[serde(default)]
    pub consensus_min_reputation: Option<u64>,

    /// File the deposit listener persists its scan cursor (the last processed
    /// signature) to, so a restart resumes from that point instead of
    /// re-scanning from the chain tip and losing deposits that landed while the
    /// node was down. Injected by the node from its data directory, not a user
    /// config knob — `#[serde(skip)]` keeps it out of config files. `None`
    /// (the default, and what tests use) keeps the cursor in memory only.
    #[serde(skip)]
    pub cursor_path: Option<std::path::PathBuf>,
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
            transact_ingress_address: std::env::var("BRIDGE_TRANSACT_INGRESS_ADDRESS")
                .unwrap_or_default(),
            ingress_token: std::env::var("BRIDGE_INGRESS_TOKEN").unwrap_or_default(),
            use_cosign_settlement: default_use_cosign_settlement(),
            consensus_min_validators: None,
            consensus_total_validators: None,
            consensus_min_reputation: None,
            cursor_path: None,
        }
    }
}

/// Default for [`BridgeConfig::use_cosign_settlement`] — co-signing is the
/// intended settlement path (#260); the single-key fallback is automatic when
/// no co-signing keypair is configured.
fn default_use_cosign_settlement() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_thresholds_default_to_none() {
        // No override by default → the node keeps the coordinator's mainnet BFT
        // thresholds (7/10/rep200). A devnet config opts into lower values; a
        // mainnet config MUST leave them unset.
        let cfg = BridgeConfig::default();
        assert_eq!(cfg.consensus_min_validators, None);
        assert_eq!(cfg.consensus_total_validators, None);
        assert_eq!(cfg.consensus_min_reputation, None);
    }

    #[test]
    fn consensus_thresholds_parse_from_toml() {
        // A devnet validator.toml lowering the cohort round-trips into the
        // optional fields (absent fields stay None via #[serde(default)]).
        let cfg: BridgeConfig = toml::from_str(
            r#"
            solana_rpc_url = "http://localhost:8899"
            program_id = ""
            poll_interval_secs = 5
            enabled = true
            event_lag_warn_threshold_slots = 1500
            withdrawal_expiration_window_slots = 150
            merkle_path_query_address = "127.0.0.1:9090"
            withdrawal_ingress_address = ""
            transfer_ingress_address = ""
            consensus_min_validators = 2
            consensus_total_validators = 3
            "#,
        )
        .expect("config parses");
        assert_eq!(cfg.consensus_min_validators, Some(2));
        assert_eq!(cfg.consensus_total_validators, Some(3));
        assert_eq!(cfg.consensus_min_reputation, None);
    }
}

/// Bridge statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BridgeStats {
    /// Total deposits processed
    pub total_deposits: u64,

    /// Total withdrawals processed
    /// DEPRECATED / not maintained: withdrawals settle on-chain; this
    /// off-chain counter is never written.
    pub total_withdrawals: u64,

    /// Total volume deposited
    pub volume_deposited: u64,

    /// Total volume withdrawn
    /// DEPRECATED / not maintained: withdrawals settle on-chain; this
    /// off-chain counter is never written.
    pub volume_withdrawn: u64,

    /// Last processed block
    pub last_block: u64,

    /// Listener event lag in Solana slots, computed each poll as
    /// `current_slot − last_processed_slot`. Useful as a metric to
    /// drive operator dashboards or pageable alerts.
    pub event_lag_slots: u64,
}
