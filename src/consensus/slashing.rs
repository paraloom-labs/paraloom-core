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
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tokio::sync::RwLock;

/// Maximum number of slashing records retained per validator `NodeId`.
pub const MAX_RECORDS_PER_VALIDATOR: usize = 256;

/// Maximum number of distinct validator `NodeId` entries retained in memory.
pub const MAX_TRACKED_VALIDATORS: usize = 4_096;

/// A piece of evidence that a validator deserves slashing.
///
/// Stored together with a `recorded_at` timestamp so a downstream
/// pipeline can prioritise recent misbehavior or expire stale entries
/// before sending them on-chain.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SlashingEvidence {
    /// Validator submitted two votes that disagree on the same request.
    /// `previous_vote` was already recorded when `new_vote` arrived. Attributed
    /// to the stable co-sign `wallet_pubkey` (undodgeable by rotating NodeId),
    /// and non-repudiable: the two conflicting ed25519 vote signatures ARE the
    /// proof.
    Equivocation {
        request_id: String,
        wallet_pubkey: String,
        previous_vote: VerificationVote,
        new_vote: VerificationVote,
        previous_signature: Vec<u8>,
        new_signature: Vec<u8>,
    },

    /// Validator missed `streak_length` consecutive verification rounds.
    /// The threshold that triggered the entry is captured for forensic
    /// clarity: a future raise of the threshold should not retroactively
    /// invalidate previously recorded evidence.
    PersistentUnavailability { streak_length: u64, threshold: u64 },
}

impl SlashingEvidence {
    /// Return the stable on-chain co-sign wallet associated with this evidence,
    /// if present.
    pub fn wallet_pubkey(&self) -> Option<&str> {
        match self {
            SlashingEvidence::Equivocation { wallet_pubkey, .. } => Some(wallet_pubkey.as_str()),
            SlashingEvidence::PersistentUnavailability { .. } => None,
        }
    }

    /// Structural validity check on the evidence before it enters the log.
    ///
    /// - `Equivocation` requires non-empty `request_id`, `wallet_pubkey`, and
    ///   signatures, and the two votes must actually disagree in validity
    ///   (`previous_vote.is_valid() != new_vote.is_valid()`).
    /// - `PersistentUnavailability` requires a non-zero `threshold` and
    ///   `streak_length >= threshold`.
    pub fn is_well_formed(&self) -> bool {
        match self {
            SlashingEvidence::Equivocation {
                request_id,
                wallet_pubkey,
                previous_vote,
                new_vote,
                previous_signature,
                new_signature,
            } => {
                !request_id.trim().is_empty()
                    && !wallet_pubkey.trim().is_empty()
                    && !previous_signature.is_empty()
                    && !new_signature.is_empty()
                    && previous_vote.is_valid() != new_vote.is_valid()
            }
            SlashingEvidence::PersistentUnavailability {
                streak_length,
                threshold,
            } => *threshold > 0 && *streak_length >= *threshold,
        }
    }

    /// Whether two evidence payloads represent the same underlying slashable
    /// offense (used to deduplicate replayed conflicting votes on the same
    /// request or duplicate unavailability records at the same streak length).
    pub fn same_offense(&self, other: &Self) -> bool {
        match (self, other) {
            (
                SlashingEvidence::Equivocation {
                    request_id: r1,
                    wallet_pubkey: w1,
                    ..
                },
                SlashingEvidence::Equivocation {
                    request_id: r2,
                    wallet_pubkey: w2,
                    ..
                },
            ) => r1 == r2 && w1 == w2,
            (
                SlashingEvidence::PersistentUnavailability {
                    streak_length: s1,
                    threshold: t1,
                },
                SlashingEvidence::PersistentUnavailability {
                    streak_length: s2,
                    threshold: t2,
                },
            ) => s1 == s2 && t1 == t2,
            _ => false,
        }
    }
}

/// One entry in the slashing log.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
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

/// In-memory (and optionally file-backed) log of slashing evidence.
///
/// Keyed by validator so a downstream slashing pipeline can iterate
/// per-validator without re-grouping, with cross-`NodeId` wallet lookup and
/// deduplication so a validator that rotates its libp2p `NodeId` cannot split or
/// duplicate its equivocation record.
#[derive(Default)]
pub struct SlashingTracker {
    records: RwLock<HashMap<NodeId, Vec<SlashingRecord>>>,
    persist_path: Option<PathBuf>,
}

impl SlashingTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a slashing tracker backed by `path`. Loads any existing snapshot
    /// at construction and atomically rewrites it on every mutation so
    /// non-repudiable slashing proofs survive node restarts.
    pub fn with_persistence(path: PathBuf) -> Self {
        let records = Self::load_snapshot(&path).unwrap_or_default();
        Self {
            records: RwLock::new(records),
            persist_path: Some(path),
        }
    }

    fn load_snapshot(path: &Path) -> Option<HashMap<NodeId, Vec<SlashingRecord>>> {
        let bytes = std::fs::read(path).ok()?;
        let list: Vec<SlashingRecord> = serde_json::from_slice(&bytes).ok()?;
        let mut map: HashMap<NodeId, Vec<SlashingRecord>> = HashMap::new();
        for rec in list {
            if !rec.evidence.is_well_formed() {
                continue;
            }
            let is_dup = match &rec.evidence {
                SlashingEvidence::Equivocation { .. } => map
                    .values()
                    .flatten()
                    .any(|existing| existing.evidence.same_offense(&rec.evidence)),
                SlashingEvidence::PersistentUnavailability { .. } => map
                    .get(&rec.validator)
                    .map(|entries| {
                        entries
                            .iter()
                            .any(|existing| existing.evidence.same_offense(&rec.evidence))
                    })
                    .unwrap_or(false),
            };
            if is_dup {
                continue;
            }
            if !map.contains_key(&rec.validator) && map.len() >= MAX_TRACKED_VALIDATORS {
                continue;
            }
            let entries = map.entry(rec.validator.clone()).or_default();
            if entries.len() >= MAX_RECORDS_PER_VALIDATOR {
                entries.remove(0);
            }
            entries.push(rec);
        }
        Some(map)
    }

    fn persist_locked(&self, map: &HashMap<NodeId, Vec<SlashingRecord>>) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let list: Vec<&SlashingRecord> = map.values().flatten().collect();
        match serde_json::to_vec(&list) {
            Ok(bytes) => {
                let tmp = path.with_extension("tmp");
                if let Err(e) = std::fs::write(&tmp, &bytes)
                    .and_then(|()| std::fs::rename(&tmp, path))
                {
                    log::warn!(
                        target: "paraloom::consensus::slashing",
                        "failed to persist slashing evidence to {}: {}",
                        path.display(),
                        e
                    );
                }
            }
            Err(e) => log::warn!(
                target: "paraloom::consensus::slashing",
                "failed to serialize slashing snapshot: {}",
                e
            ),
        }
    }

    /// Append a record for `validator`. Rejects malformed evidence, deduplicates
    /// repeated reports of the same offense (including across `NodeId` rotations
    /// for wallet-attributed equivocations), enforces capacity bounds, and
    /// persists to disk when configured.
    pub async fn record(&self, validator: NodeId, evidence: SlashingEvidence) {
        if !evidence.is_well_formed() {
            log::warn!(
                target: "paraloom::consensus::slashing",
                "ignoring malformed slashing evidence for {:?}: {:?}",
                validator,
                evidence
            );
            return;
        }

        let mut guard = self.records.write().await;

        let already_recorded = match &evidence {
            SlashingEvidence::Equivocation { .. } => guard
                .values()
                .flatten()
                .any(|existing| existing.evidence.same_offense(&evidence)),
            SlashingEvidence::PersistentUnavailability { .. } => guard
                .get(&validator)
                .map(|entries| {
                    entries
                        .iter()
                        .any(|existing| existing.evidence.same_offense(&evidence))
                })
                .unwrap_or(false),
        };
        if already_recorded {
            log::debug!(
                target: "paraloom::consensus::slashing",
                "skipping duplicate slashing evidence for {:?}: {:?}",
                validator,
                evidence
            );
            return;
        }

        log::warn!(
            target: "paraloom::consensus::slashing",
            "slashing evidence recorded for {:?}: {:?}",
            validator,
            evidence
        );

        if !guard.contains_key(&validator) && guard.len() >= MAX_TRACKED_VALIDATORS {
            if let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, entries)| {
                    entries.last().map(|r| r.recorded_at).unwrap_or(0)
                })
                .map(|(k, _)| k.clone())
            {
                guard.remove(&oldest_key);
            }
        }

        let record = SlashingRecord::new(validator.clone(), evidence);
        let entries = guard.entry(validator).or_default();
        if entries.len() >= MAX_RECORDS_PER_VALIDATOR {
            entries.remove(0);
        }
        entries.push(record);
        self.persist_locked(&guard);
    }

    /// All records for a single validator `NodeId`, in insertion order.
    pub async fn for_validator(&self, validator: &NodeId) -> Vec<SlashingRecord> {
        self.records
            .read()
            .await
            .get(validator)
            .cloned()
            .unwrap_or_default()
    }

    /// All records attributed to `wallet_pubkey` across any `NodeId`, so a
    /// validator that rotates its libp2p `NodeId` cannot split its slashing
    /// history away from its on-chain stake identity.
    pub async fn for_wallet(&self, wallet_pubkey: &str) -> Vec<SlashingRecord> {
        let guard = self.records.read().await;
        let mut out: Vec<SlashingRecord> = guard
            .values()
            .flatten()
            .filter(|r| r.evidence.wallet_pubkey() == Some(wallet_pubkey))
            .cloned()
            .collect();
        out.sort_by_key(|r| r.recorded_at);
        out
    }

    /// Drain and return all slashing records for `validator`, removing it from
    /// the pending worklist once the downstream slasher has acted on them.
    pub async fn take_for_validator(&self, validator: &NodeId) -> Vec<SlashingRecord> {
        let mut guard = self.records.write().await;
        let taken = guard.remove(validator).unwrap_or_default();
        if !taken.is_empty() {
            self.persist_locked(&guard);
        }
        taken
    }

    /// Drain and return all slashing records attributed to `wallet_pubkey`
    /// across all `NodeId` entries, pruning any validator buckets that become
    /// empty.
    pub async fn take_for_wallet(&self, wallet_pubkey: &str) -> Vec<SlashingRecord> {
        let mut guard = self.records.write().await;
        let mut taken = Vec::new();
        guard.retain(|_, entries| {
            let mut i = 0;
            while i < entries.len() {
                if entries[i].evidence.wallet_pubkey() == Some(wallet_pubkey) {
                    taken.push(entries.remove(i));
                } else {
                    i += 1;
                }
            }
            !entries.is_empty()
        });
        if !taken.is_empty() {
            self.persist_locked(&guard);
        }
        taken.sort_by_key(|r| r.recorded_at);
        taken
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

    /// Distinct on-chain validator wallets (`wallet_pubkey`) that have recorded
    /// equivocation evidence.
    pub async fn flagged_wallets(&self) -> Vec<String> {
        let guard = self.records.read().await;
        let mut wallets: HashSet<String> = HashSet::new();
        for rec in guard.values().flatten() {
            if let Some(w) = rec.evidence.wallet_pubkey() {
                wallets.insert(w.to_string());
            }
        }
        let mut out: Vec<String> = wallets.into_iter().collect();
        out.sort();
        out
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
                    wallet_pubkey: "W1".to_string(),
                    previous_vote: VerificationVote::Valid,
                    new_vote: VerificationVote::Invalid {
                        reason: "test".to_string(),
                    },
                    previous_signature: vec![1],
                    new_signature: vec![2],
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

    #[tokio::test]
    async fn tracker_deduplicates_repeated_offenses_across_node_id_rotations_and_rejects_malformed() {
        let tracker = SlashingTracker::new();
        let node_a = NodeId(vec![1]);
        let node_b = NodeId(vec![2]);

        // Malformed evidence (non-conflicting votes, empty signature, streak < threshold) must be rejected.
        tracker
            .record(
                node_a.clone(),
                SlashingEvidence::Equivocation {
                    request_id: "r1".to_string(),
                    wallet_pubkey: "W1".to_string(),
                    previous_vote: VerificationVote::Valid,
                    new_vote: VerificationVote::Valid,
                    previous_signature: vec![1],
                    new_signature: vec![2],
                },
            )
            .await;
        tracker
            .record(
                node_a.clone(),
                SlashingEvidence::Equivocation {
                    request_id: "r1".to_string(),
                    wallet_pubkey: "W1".to_string(),
                    previous_vote: VerificationVote::Valid,
                    new_vote: VerificationVote::Invalid {
                        reason: "bad".into(),
                    },
                    previous_signature: vec![],
                    new_signature: vec![2],
                },
            )
            .await;
        tracker
            .record(
                node_a.clone(),
                SlashingEvidence::PersistentUnavailability {
                    streak_length: 2,
                    threshold: 3,
                },
            )
            .await;
        assert_eq!(tracker.total_count().await, 0);

        // First valid equivocation on (r1, W1) under node_a is recorded.
        let eq = SlashingEvidence::Equivocation {
            request_id: "r1".to_string(),
            wallet_pubkey: "W1".to_string(),
            previous_vote: VerificationVote::Valid,
            new_vote: VerificationVote::Invalid {
                reason: "flip".into(),
            },
            previous_signature: vec![1, 2],
            new_signature: vec![3, 4],
        };
        tracker.record(node_a.clone(), eq.clone()).await;
        // Replaying the same (r1, W1) offense under the same or a rotated NodeId must be deduplicated.
        tracker.record(node_a.clone(), eq.clone()).await;
        tracker.record(node_b.clone(), eq).await;
        assert_eq!(tracker.total_count().await, 1);

        // A distinct request r2 for the same wallet under rotated node_b is recorded and queryable by wallet.
        tracker
            .record(
                node_b.clone(),
                SlashingEvidence::Equivocation {
                    request_id: "r2".to_string(),
                    wallet_pubkey: "W1".to_string(),
                    previous_vote: VerificationVote::Invalid {
                        reason: "first".into(),
                    },
                    new_vote: VerificationVote::Valid,
                    previous_signature: vec![5],
                    new_signature: vec![6],
                },
            )
            .await;
        assert_eq!(tracker.for_wallet("W1").await.len(), 2);
        assert_eq!(tracker.flagged_wallets().await, vec!["W1".to_string()]);
    }

    #[tokio::test]
    async fn tracker_persists_across_restarts_and_drains_by_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        let node_a = NodeId(vec![10]);
        let node_b = NodeId(vec![20]);

        {
            let tracker = SlashingTracker::with_persistence(path.clone());
            tracker
                .record(
                    node_a.clone(),
                    SlashingEvidence::Equivocation {
                        request_id: "req-a".to_string(),
                        wallet_pubkey: "WalletX".to_string(),
                        previous_vote: VerificationVote::Valid,
                        new_vote: VerificationVote::Invalid {
                            reason: "flip".into(),
                        },
                        previous_signature: vec![9],
                        new_signature: vec![8],
                    },
                )
                .await;
            tracker
                .record(
                    node_b.clone(),
                    SlashingEvidence::PersistentUnavailability {
                        streak_length: 4,
                        threshold: 3,
                    },
                )
                .await;
        }

        let reloaded = SlashingTracker::with_persistence(path.clone());
        assert_eq!(reloaded.total_count().await, 2);
        let drained = reloaded.take_for_wallet("WalletX").await;
        assert_eq!(drained.len(), 1);
        assert_eq!(reloaded.total_count().await, 1);
        assert!(reloaded.for_validator(&node_a).await.is_empty());

        let reloaded_after_drain = SlashingTracker::with_persistence(path);
        assert_eq!(reloaded_after_drain.total_count().await, 1);
    }
}

