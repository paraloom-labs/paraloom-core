//! Privacy layer for shielded transactions
//!
//! This module implements ZCash-inspired privacy features including:
//! - Shielded pool with commitments and nullifiers
//! - Zero-knowledge proofs using Groth16 on BN254
//! - Distributed verification across validators
//! - Merkle tree for commitment tracking

// Regression guard for #59. The original bug was that storage writes
// in this module silently discarded their `Result` via patterns like
// `let _ = storage.insert_*()`. Denying `let_underscore_must_use` at
// the privacy-module root catches the same shape of regression at
// compile time. Scoped here so it does not disturb intentional
// fire-and-forget patterns elsewhere in the codebase.
#![deny(clippy::let_underscore_must_use)]

pub mod batch;
pub mod circuit_benchmark;
pub mod circuits;

pub mod commitment;
pub mod error;
#[cfg(test)]
mod integration_tests;
pub mod merkle;
pub mod note_crypto;
pub mod nullifier;
pub mod onchain_verifier;
pub mod pedersen;
pub mod pool;
pub mod poseidon;
pub mod poseidon_circom;
pub mod proof;
pub mod proof_codec;
pub mod sparse_merkle;
pub mod transaction;
pub mod types;
pub mod verification;

pub use batch::{AdaptiveBatchVerifier, BatchVerificationResult, BatchVerifier};
pub use circuits::{
    DepositCircuit, Groth16ProofSystem, TransferCircuit, WithdrawCircuit, MAX_INPUTS, MAX_OUTPUTS,
};
pub use commitment::{CommitmentBuilder, CommitmentGenerator};
pub use error::{PrivacyError, Result};
pub use merkle::MerkleTree;
pub use note_crypto::{decrypt_note, encrypt_note, EncryptedNote, NotePlaintext};
pub use nullifier::NullifierSet;
pub use pool::ShieldedPool;
pub use proof::{ProofVerifier, VerificationChunk, VerificationResult};
pub use proof_codec::{
    bytes_to_field, deserialize_proof, field_to_bytes, serialize_proof, Groth16Proof,
    Groth16VerifyingKey,
};
pub use sparse_merkle::{MemoryStats, SparseMerkleTree, SPARSE_TREE_DEPTH};
pub use transaction::{DepositTx, ShieldedTransaction, TrackedTransaction, TransferTx, WithdrawTx};
pub use types::{Commitment, MerklePath, Note, Nullifier, ShieldedAddress, ViewingKey};
pub use verification::{
    VerificationAggregator, VerificationCoordinator, VerificationTask, VerificationTaskResult,
    MIN_VALIDATORS_FOR_CONSENSUS, TOTAL_VALIDATORS,
};
