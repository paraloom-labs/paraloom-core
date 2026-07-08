//! Consensus mechanism for distributed validator network
//!
//! Handles withdrawal verification consensus, leader selection,
//! reputation tracking, and validator coordination.

pub mod leader;
pub mod reputation;
pub mod slashing;
pub mod transact;
pub mod vote_tally;

pub use leader::{LeaderSelector, ValidatorInfo};
pub use reputation::{ReputationTracker, ValidatorMetrics};
pub use slashing::{SlashingEvidence, SlashingRecord, SlashingTracker};
pub use transact::{
    ApprovedTransact, TransactVerificationCoordinator, TransactVerificationRequest,
    TransactVerificationResult,
};
pub use vote_tally::{VerificationVote, VoteTally};
