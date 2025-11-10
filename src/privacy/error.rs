//! Privacy layer error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PrivacyError {
    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Proof verification failed: {0}")]
    InvalidProof(String),

    #[error("Nullifier already used")]
    NullifierAlreadyUsed,

    #[error("Invalid Merkle root")]
    InvalidMerkleRoot,

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Circuit synthesis error: {0}")]
    SynthesisError(String),
}

pub type Result<T> = std::result::Result<T, PrivacyError>;
