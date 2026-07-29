//! Bridge error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum BridgeError {
    #[error("Solana RPC error: {0}")]
    SolanaRpc(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// The settlement this node tried to submit is already on chain: its
    /// nullifier PDA exists. Expected whenever two nodes reach quorum on the
    /// same request and both submit (#164), so callers skip it quietly rather
    /// than retrying a transaction that can never succeed.
    ///
    /// Deliberately a variant rather than a string match on the submit error.
    /// The previous check looked for "already spent", which nothing in the
    /// program or the bridge ever produces — the real failure comes from
    /// Anchor's `init` on an existing account, whose text is not ours to
    /// predict, and only the test constructed a matching error (#703).
    #[error("already settled on chain (nullifier spent)")]
    AlreadySettled,

    #[error("Deposit failed: {0}")]
    DepositFailed(String),

    #[error("Withdrawal failed: {0}")]
    WithdrawalFailed(String),

    #[error("Event parsing failed: {0}")]
    EventParsing(String),

    #[error("Signature verification failed")]
    SignatureVerification,

    #[error("Insufficient funds: required {required}, available {available}")]
    InsufficientFunds { required: u64, available: u64 },

    #[error("Privacy layer error: {0}")]
    PrivacyLayer(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, BridgeError>;
