//! Consensus mechanism for distributed validator network
//!
//! Handles withdrawal verification consensus, leader selection,
//! reputation tracking, and validator coordination.

pub mod leader;
pub mod reputation;
pub mod slashing;
pub mod transact;
pub mod transfer;
pub mod vote_tally;
pub mod withdrawal;

pub use leader::{LeaderSelector, ValidatorInfo};
pub use reputation::{ReputationTracker, ValidatorMetrics};
pub use slashing::{SlashingEvidence, SlashingRecord, SlashingTracker};
pub use transact::{
    ApprovedTransact, TransactVerificationCoordinator, TransactVerificationRequest,
    TransactVerificationResult,
};
pub use transfer::{
    ApprovedTransfer, TransferVerificationCoordinator, TransferVerificationRequest,
    TransferVerificationResult,
};
pub use vote_tally::{VerificationVote, VoteTally};
pub use withdrawal::{
    ApprovedWithdrawal, WithdrawalVerificationCoordinator, WithdrawalVerificationRequest,
};
