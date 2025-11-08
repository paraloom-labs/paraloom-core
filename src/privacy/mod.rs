//! Privacy layer for shielded transactions
//!
//! This module implements ZCash-inspired privacy features including:
//! - Shielded pool with commitments and nullifiers
//! - Zero-knowledge proofs (placeholder interface)
//! - Distributed verification across validators
//! - Merkle tree for commitment tracking

pub mod commitment;
pub mod merkle;
pub mod nullifier;
pub mod pool;
pub mod proof;
pub mod transaction;
pub mod types;
pub mod verification;

pub use commitment::{CommitmentBuilder, CommitmentGenerator};
pub use merkle::MerkleTree;
pub use nullifier::NullifierSet;
pub use pool::ShieldedPool;
pub use proof::{ProofVerifier, VerificationChunk, VerificationResult};
pub use transaction::{DepositTx, ShieldedTransaction, TrackedTransaction, TransferTx, WithdrawTx};
pub use types::{Commitment, MerklePath, Note, Nullifier, ShieldedAddress, ViewingKey};
pub use verification::{
    VerificationAggregator, VerificationCoordinator, VerificationTask, VerificationTaskResult,
    MIN_VALIDATORS_FOR_CONSENSUS, TOTAL_VALIDATORS,
};
