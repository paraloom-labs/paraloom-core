//! Bridge error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum BridgeError {
    #[error("Solana RPC error: {0}")]
    SolanaRpc(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

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
