//! Slashing-evidence catalog and in-memory tracker.
//!
//! The audit (#62) called for the consensus layer to record actionable
//! evidence whenever a validator misbehaves, so a separate slashing
//! pipeline (today: the on-chain `slash_validator` instruction in
//! `programs/paraloom`) can act on it. This module defines the
//! evidence shape, a small in-memory store, and the helpers that the
//! consensus path uses to record the two conditions in scope:
//!
//!  1. **Equivocation** — a validator submits two distinct votes on
//!     the same settlement request. The on-chain decision was
//!     deterministic per `(request_id, validator)`, so any pair of
//!     differing votes is provable misbehavior.
//!  2. **Persistent unavailability** — a validator misses a
//!     configured streak of consecutive verification rounds. A single
//!     timeout is a network blip; a streak of timeouts is a validator
//!     that is offline or otherwise failing to do its job.
//!
//! Persisting the evidence to RocksDB is out of scope for this PR —
//! the in-memory store is enough to drive the integration test and the
//! eventual on-chain slashing call. The store is `Send + Sync` so a
//! caller can park it inside an `Arc` and share it across coordinator
//! threads.

use crate::consensus::vote_tally::VerificationVote;
use crate::types::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// A piece of evidence that a validator deserves slashing.
///
/// Stored together with a `recorded_at` timestamp so a downstream
/// pipeline can prioritise recent misbehavior or expire stale entries
/// before sending them on-chain.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SlashingEvidence {
    /// Validator submitted two votes that disagree on the same request.
    /// `previous_vote` was already recorded when `new_vote` arrived.
    Equivocation {
        request_id: String,
        previous_vote: VerificationVote,
        new_vote: VerificationVote,
    },

    /// Validator missed `streak_length` consecutive verification rounds.
    /// The threshold that triggered the entry is captured for forensic
    /// clarity: a future raise of the threshold should not retroactively
    /// invalidate previously recorded evidence.
    PersistentUnavailability { streak_length: u64, threshold: u64 },
}

/// One entry in the slashing log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub validator: NodeId,
    pub evidence: SlashingEvidence,
    /// Unix-seconds timestamp at which the evidence was recorded.
    pub recorded_at: u64,
}

impl SlashingRecord {
    pub fn new(validator: NodeId, evidence: SlashingEvidence) -> Self {
        let recorded_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            validator,
            evidence,
            recorded_at,
        }
    }
}

/// In-memory log of slashing evidence.
///
/// Keyed by validator so a downstream slashing pipeline can iterate
/// per-validator without re-grouping. Each validator's entries are
/// kept in insertion order (vec).
#[derive(Default)]
pub struct SlashingTracker {
    records: RwLock<HashMap<NodeId, Vec<SlashingRecord>>>,
}

impl SlashingTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a record for `validator`. Logs at `warn` so the entry is
    /// discoverable even before a metrics endpoint is wired up (#67).
    pub async fn record(&self, validator: NodeId, evidence: SlashingEvidence) {
        log::warn!(
            target: "paraloom::consensus::slashing",
            "slashing evidence recorded for {:?}: {:?}",
            validator,
            evidence
        );
        let record = SlashingRecord::new(validator.clone(), evidence);
        self.records
            .write()
            .await
            .entry(validator)
            .or_default()
            .push(record);
    }

    /// All records for a single validator, in insertion order.
    pub async fn for_validator(&self, validator: &NodeId) -> Vec<SlashingRecord> {
        self.records
            .read()
            .await
            .get(validator)
            .cloned()
            .unwrap_or_default()
    }

    /// Total number of evidence entries across all validators.
    pub async fn total_count(&self) -> usize {
        self.records.read().await.values().map(|v| v.len()).sum()
    }

    /// Set of validators with at least one record. Useful for the
    /// downstream slasher to pick a worklist.
    pub async fn flagged_validators(&self) -> Vec<NodeId> {
        self.records.read().await.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tracker_records_and_groups_per_validator() {
        let tracker = SlashingTracker::new();
        let alice = NodeId(vec![1]);
        let bob = NodeId(vec![2]);

        tracker
            .record(
                alice.clone(),
                SlashingEvidence::Equivocation {
                    request_id: "r1".to_string(),
                    previous_vote: VerificationVote::Valid,
                    new_vote: VerificationVote::Invalid {
                        reason: "test".to_string(),
                    },
                },
            )
            .await;
        tracker
            .record(
                alice.clone(),
                SlashingEvidence::PersistentUnavailability {
                    streak_length: 5,
                    threshold: 3,
                },
            )
            .await;
        tracker
            .record(
                bob.clone(),
                SlashingEvidence::PersistentUnavailability {
                    streak_length: 3,
                    threshold: 3,
                },
            )
            .await;

        assert_eq!(tracker.total_count().await, 3);
        assert_eq!(tracker.for_validator(&alice).await.len(), 2);
        assert_eq!(tracker.for_validator(&bob).await.len(), 1);

        let mut flagged = tracker.flagged_validators().await;
        flagged.sort_by_key(|n| n.0.clone());
        assert_eq!(flagged, vec![alice, bob]);
    }

    #[tokio::test]
    async fn tracker_returns_empty_for_unknown_validator() {
        let tracker = SlashingTracker::new();
        let unknown = NodeId(vec![99]);
        assert!(tracker.for_validator(&unknown).await.is_empty());
        assert_eq!(tracker.total_count().await, 0);
    }
}
