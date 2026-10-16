// Unified-transact verification consensus (#350).
//!
//! Circuit-v3 settlement consensus. A client submits a
//! unified transact (two input nullifiers, two output commitments, the
//! membership root, a signed external flow, and a `TransactCircuitV3` proof);
//! validators verify the proof and vote, and once a BFT quorum of eligible
//! voters agrees the coordinator emits an [`ApprovedTransact`] that a
//! submitter task settles on-chain via the unified `transact` instruction.
//!
//! The vote/quorum machinery is shared with withdrawals through
//! [`VoteTally`]; this module only adds the transact-specific request,
//! approval, and the thin coordinator shell. The reputation/slashing/leader
//! trackers are reused as-is, so a validator's standing is consistent across
//! all verification paths.

use crate::consensus::leader::{LeaderSelector, ValidatorInfo};
use crate::consensus::reputation::ReputationTracker;
use crate::consensus::slashing::SlashingTracker;
use crate::consensus::vote_tally::{VerificationVote, VoteTally};
use crate::types::NodeId;

/// Default minimum registered validators that must approve before a transact
/// settles (7-of-10 BFT). The actual threshold is configurable per
/// coordinator; this is the fallback when no override is supplied. (Relocated
/// here from the retired off-chain-root withdrawal consensus module.)
pub const DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS: usize = 7;

/// Default validator-set size for the 7-of-10 BFT consensus, used as the
/// completion-percentage divisor when no override is supplied.
pub const DEFAULT_TOTAL_VALIDATORS: usize = 10;

/// Default reputation floor for consensus participation. A validator below this
/// may still submit a vote, but the result is computed as if it had not.
pub const DEFAULT_MIN_REPUTATION_FOR_CONSENSUS: u64 = 200;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// A unified-transact verification request broadcast to validators (#350).
///
/// Fixed 2-in/2-out, matching the on-chain `transact` instruction and
/// `TransactCircuitV3`. One request covers both a pure shielded transfer
/// (`ext_amount == 0`) and a withdrawal (`ext_amount < 0`); the signed
/// external flow and the recipient are proof public inputs, so validators
/// verify exactly what settles.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactVerificationRequest {
    /// Unique request ID
    pub request_id: String,

    /// Withdrawal destination (`ext_amount < 0`); all-zero for a pure
    /// shielded transfer (`ext_amount == 0`). For an SPL settlement (`mint`
    /// set) this is the recipient **token account**, not a system address.
    pub recipient: [u8; 32],

    /// The SPL mint being spent (#779), or `None` for a native-SOL settlement.
    /// When set, the settlement takes the `transact_spl` path: the proof's
    /// asset id is `mint_to_asset(mint)` and the pay
