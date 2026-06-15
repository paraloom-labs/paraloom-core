//! Payload-independent BFT vote tally (#194).
//!
//! The vote-collection and reputation-gated quorum logic shared by
//! withdrawal and transfer verification. It tracks votes keyed by validator
//! for a single request id and computes the quorum without knowing anything
//! about the payload being verified, so both
//! [`crate::consensus::withdrawal::WithdrawalConsensus`] and
//! [`crate::consensus::transfer::TransferConsensus`] embed one and delegate
//! to it. Keeping the audit-sensitive counting logic (the reputation gating
//! from #62) in one place means a fix applies to both paths at once.

use crate::consensus::reputation::ReputationTracker;
use crate::consensus::slashing::SlashingEvidence;
use crate::types::NodeId;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Verification result from a validator
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum VerificationVote {
    /// Proof is valid
    Valid,

    /// Proof is invalid
    Invalid { reason: String },
}

impl VerificationVote {
    /// Check if vote is valid
    pub fn is_valid(&self) -> bool {
        matches!(self, VerificationVote::Valid)
    }
}

/// Payload-independent vote tally and quorum state for one verification
/// request. Owns the validator votes plus the BFT thresholds and deadline;
/// the consensus-specific wrapper adds the request payload alongside.
#[derive(Clone, Debug)]
pub struct VoteTally {
    /// Request ID
    pub request_id: String,

    /// Validators who voted
    pub votes: Arc<RwLock<HashMap<NodeId, VerificationVote>>>,

    /// When consensus started
    pub started_at: u64,

    /// Deadline for consensus (30 seconds)
    pub deadline: u64,

    /// Minimum eligible-vote count required for this consensus to be
    /// considered reached. Configurable so different validator-set
    /// sizes can use different BFT thresholds (e.g. 5-of-7 on a small
    /// devnet, 14-of-20 on a larger network) without recompiling.
    pub min_validators_for_consensus: usize,

    /// Total validator-set size used as the divisor in
    /// [`completion_percentage`](Self::completion_percentage). Must agree
    /// with the actual size of the validator pool the coordinator drew
    /// from; mismatch only affects the reported percentage, not consensus
    /// correctness.
    pub total_validators: usize,
}

impl VoteTally {
    /// Create a new tally for `request_id` with explicit BFT thresholds.
    pub fn new(
        request_id: String,
        min_validators_for_consensus: usize,
        total_validators: usize,
    ) -> Self {
        let now = crate::utils::now_unix_seconds();

        Self {
            request_id,
            votes: Arc::new(RwLock::new(HashMap::new())),
            started_at: now,
            deadline: now + 30, // 30 second deadline
            min_validators_for_consensus,
            total_validators,
        }
    }

    /// Submit a vote.
    ///
    /// Returns `Ok(None)` for the normal case (first vote, or a
    /// repeated identical vote which we treat as idempotent). Returns
    /// `Ok(Some(SlashingEvidence::Equivocation { .. }))` if the
    /// validator has previously submitted a vote on this request and
    /// the new vote disagrees — this is provable misbehavior and is
    /// surfaced to the caller for recording in the
    /// [`crate::consensus::SlashingTracker`]. The new vote is **not**
    /// installed in that case; the original stands.
    pub async fn submit_vote(
        &self,
        validator: NodeId,
        vote: VerificationVote,
    ) -> Result<Option<SlashingEvidence>> {
        let mut votes = self.votes.write().await;
        if let Some(previous) = votes.get(&validator) {
            if previous == &vote {
                // Idempotent re-send. Common when a validator retries
                // over a flaky transport.
                return Ok(None);
            }
            let evidence = SlashingEvidence::Equivocation {
                request_id: self.request_id.clone(),
                previous_vote: previous.clone(),
                new_vote: vote,
            };
            return Ok(Some(evidence));
        }
        votes.insert(validator, vote);
        Ok(None)
    }

    /// Check whether consensus has been reached among the eligible
    /// validators — those whose reputation is at or above
    /// `min_reputation`. A validator below the threshold is silently
    /// excluded from the count; their vote may still be in `votes`
    /// (the network cannot prevent the bytes from arriving) but it
    /// does not contribute to the quorum.
    pub async fn has_consensus(
        &self,
        reputation_tracker: &ReputationTracker,
        min_reputation: u64,
    ) -> bool {
        let eligible = self
            .count_eligible_votes(reputation_tracker, min_reputation)
            .await;
        eligible >= self.min_validators_for_consensus
    }

    /// Check if consensus deadline has passed
    pub fn is_timed_out(&self) -> bool {
        let now = crate::utils::now_unix_seconds();
        now > self.deadline
    }

    /// Number of submitted votes whose validators currently sit at or
    /// above `min_reputation`. Helper for [`has_consensus`](Self::has_consensus)
    /// and [`consensus_result`](Self::consensus_result) so they share a
    /// single eligibility view.
    async fn count_eligible_votes(
        &self,
        reputation_tracker: &ReputationTracker,
        min_reputation: u64,
    ) -> usize {
        let votes = self.votes.read().await;
        let mut count = 0;
        for validator in votes.keys() {
            let reputation = reputation_tracker
                .get_reputation(validator)
                .await
                .unwrap_or(0);
            if reputation >= min_reputation {
                count += 1;
            }
        }
        count
    }

    /// Compute consensus result, filtering out votes from validators
    /// whose reputation has dropped below `min_reputation`.
    ///
    /// The audit (#62) flagged that the previous version aggregated
    /// every submitted vote regardless of the voter's standing, so a
    /// validator whose reputation had bottomed out from repeated
    /// dishonest votes still got to influence the quorum. This version
    /// snapshots reputation at result-time and counts only votes from
    /// validators currently in good standing.
    pub async fn consensus_result(
        &self,
        reputation_tracker: &ReputationTracker,
        min_reputation: u64,
    ) -> Result<VerificationVote> {
        let votes = self.votes.read().await;

        // Collect (validator, vote) pairs whose reputation is currently
        // at or above the threshold.
        let mut eligible: Vec<&VerificationVote> = Vec::with_capacity(votes.len());
        let mut excluded = 0usize;
        for (validator, vote) in votes.iter() {
            let reputation = reputation_tracker
                .get_reputation(validator)
                .await
                .unwrap_or(0);
            if reputation >= min_reputation {
                eligible.push(vote);
            } else {
                excluded += 1;
                log::warn!(
                    target: "paraloom::consensus",
                    "vote from low-reputation validator {:?} (rep {}, threshold {}) excluded from consensus on {}",
                    validator,
                    reputation,
                    min_reputation,
                    self.request_id
                );
            }
        }

        if eligible.len() < self.min_validators_for_consensus {
            return Err(anyhow!(
                "Not enough eligible votes: {} < {} (excluded {} below reputation {})",
                eligible.len(),
                self.min_validators_for_consensus,
                excluded,
                min_reputation
            ));
        }

        let valid_count = eligible.iter().filter(|v| v.is_valid()).count();
        let invalid_count = eligible.len() - valid_count;

        if valid_count >= self.min_validators_for_consensus {
            Ok(VerificationVote::Valid)
        } else {
            Ok(VerificationVote::Invalid {
                reason: format!(
                    "Consensus rejected: {} valid, {} invalid (need {})",
                    valid_count, invalid_count, self.min_validators_for_consensus
                ),
            })
        }
    }

    /// Get completion percentage
    pub async fn completion_percentage(&self) -> f64 {
        let votes = self.votes.read().await;
        (votes.len() as f64 / self.total_validators as f64) * 100.0
    }

    /// Get vote counts
    pub async fn vote_counts(&self) -> (usize, usize) {
        let votes = self.votes.read().await;
        let valid = votes.values().filter(|v| v.is_valid()).count();
        let invalid = votes.len() - valid;
        (valid, invalid)
    }

    /// The validators that voted `Valid` (#260) — the eligible co-signers the
    /// round leader collects settlement signatures from.
    pub async fn valid_voters(&self) -> Vec<NodeId> {
        let votes = self.votes.read().await;
        votes
            .iter()
            .filter(|(_, vote)| vote.is_valid())
            .map(|(node, _)| node.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn valid_voters_lists_only_the_valid_votes() {
        let tally = VoteTally::new("req-1".to_string(), 2, 3);
        tally
            .submit_vote(NodeId(vec![1]), VerificationVote::Valid)
            .await
            .unwrap();
        tally
            .submit_vote(
                NodeId(vec![2]),
                VerificationVote::Invalid {
                    reason: "bad proof".to_string(),
                },
            )
            .await
            .unwrap();
        tally
            .submit_vote(NodeId(vec![3]), VerificationVote::Valid)
            .await
            .unwrap();

        let mut voters = tally.valid_voters().await;
        voters.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(voters, vec![NodeId(vec![1]), NodeId(vec![3])]);
    }
}
