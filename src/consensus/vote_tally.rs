//! Payload-independent BFT vote tally (#194).
//!
//! The vote-collection and quorum logic shared by withdrawal and transact
//! verification. It tracks votes keyed by the voter's on-chain **co-sign
//! wallet** — the stable, stake-bearing identity — for a single request id and
//! computes the quorum without knowing anything about the payload being
//! verified, so [`crate::consensus::transact::TransactConsensus`] embeds one
//! and delegates to it.
//!
//! Wallet-keying (not libp2p NodeId) is the fix for the intermittent quorum
//! failure: a co-signer that flaps/reconnects keeps a stable wallet identity,
//! so its vote is always counted as long as the wallet is a staked on-chain
//! validator — eligibility no longer depends on a flap-prone `active` NodeId
//! set. The authenticated transport `node_id` is retained inside each record
//! for co-sign routing, and the ed25519 `signature` for non-repudiable
//! equivocation evidence.

use crate::consensus::slashing::SlashingEvidence;
use crate::types::NodeId;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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

    /// Check if an invalid vote was caused by an operational/transient error
    /// (e.g. verifying key unavailable, pool unavailable, IO error) rather than
    /// an evaluated proof verification failure (#812).
    pub fn is_transient_error(&self) -> bool {
        match self {
            VerificationVote::Invalid { reason } => {
                let r = reason.to_lowercase();
                r.contains("verifying key unavailable")
                    || r.contains("pool not available")
                    || r.contains("verification error")
                    || r.contains("transient")
                    || r.contains("temporar")
                    || r.contains("unavailable")
                    || r.contains("self-verify error")
                    || r.contains("io error")
            }
            VerificationVote::Valid => false,
        }
    }
}

/// One validator's recorded vote, keyed in the tally by its co-sign wallet.
/// `node_id` is the authenticated libp2p identity the signed vote arrived under
/// (retained for co-sign routing so the co-sign quorum equals the counted
/// quorum); `signature` is the ed25519 vote signature (retained so an
/// equivocation flip can be surfaced as non-repudiable evidence carrying both
/// conflicting signatures).
#[derive(Clone, Debug)]
pub struct VoteRecord {
    pub vote: VerificationVote,
    pub node_id: NodeId,
    pub signature: Vec<u8>,
}

/// Payload-independent vote tally and quorum state for one verification
/// request. Owns the validator votes (keyed by wallet) plus the BFT thresholds
/// and deadline; the consensus-specific wrapper adds the request payload
/// alongside.
#[derive(Clone, Debug)]
pub struct VoteTally {
    /// Request ID
    pub request_id: String,

    /// Votes, keyed by the voter's on-chain co-sign wallet (base58).
    pub votes: Arc<RwLock<HashMap<String, VoteRecord>>>,

    /// When consensus started
    pub started_at: u64,

    /// Deadline for consensus (30 seconds)
    pub deadline: u64,

    /// Minimum eligible-vote count required for this consensus to be
    /// considered reached.
    pub min_validators_for_consensus: usize,

    /// Total validator-set size used as the divisor in
    /// [`completion_percentage`](Self::completion_percentage).
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

    /// Submit a vote, keyed by the voter's co-sign `wallet`.
    ///
    /// Returns `Ok(None)` for the normal case (first vote, or a repeated
    /// identical vote which we treat as idempotent). Returns
    /// `Ok(Some(SlashingEvidence::Equivocation { .. }))` if the wallet has
    /// previously submitted a vote on this request and the new vote disagrees —
    /// provable misbehaviour surfaced for recording. The new vote is **not**
    /// installed in that case; the original stands. On the idempotent path the
    /// stored `node_id`/`signature` are deliberately NOT overwritten (both are
    /// signature-bound, so the first authenticated record is authoritative).
    pub async fn submit_vote(
        &self,
        wallet: String,
        node_id: NodeId,
        vote: VerificationVote,
        signature: Vec<u8>,
    ) -> Result<Option<SlashingEvidence>> {
        let mut votes = self.votes.write().await;
        if let Some(previous) = votes.get(&wallet) {
            if previous.vote.is_valid() == vote.is_valid() {
                // Same decision — idempotent. Equivocation is a *flip* between
                // Valid and Invalid, not two Invalid votes whose free-text
                // `reason` differs.
                return Ok(None);
            }

            // Distinguish operational/transient errors from Byzantine flips (#812).
            // An honest validator encountering a temporary failure (e.g. verifying
            // key temporarily unavailable from disk, pool unready) should not be flagged as an
            // equivocator when it subsequently recovers and votes Valid.
            if previous.vote.is_transient_error() || vote.is_transient_error() {
                if vote.is_valid() {
                    // Recovered to Valid: update the stored vote so quorum can form.
                    votes.insert(
                        wallet,
                        VoteRecord {
                            vote,
                            node_id,
                            signature,
                        },
                    );
                }
                return Ok(None);
            }

            let evidence = SlashingEvidence::Equivocation {
                request_id: self.request_id.clone(),
                wallet_pubkey: wallet.clone(),
                previous_vote: previous.vote.clone(),
                new_vote: vote,
                previous_signature: previous.signature.clone(),
                new_signature: signature,
            };
            return Ok(Some(evidence));
        }
        votes.insert(
            wallet,
            VoteRecord {
                vote,
                node_id,
                signature,
            },
        );
        Ok(None)
    }

    /// Whether consensus has been reached among the eligible wallets — those in
    /// `eligible_wallets` (the staked on-chain co-sign set minus equivocators).
    pub async fn has_consensus(&self, eligible_wallets: &HashSet<String>) -> bool {
        self.count_eligible_votes(eligible_wallets).await >= self.min_validators_for_consensus
    }

    /// Check if consensus deadline has passed
    pub fn is_timed_out(&self) -> bool {
        let now = crate::utils::now_unix_seconds();
        now > self.deadline
    }

    /// Number of submitted votes whose wallet is in `eligible_wallets`.
    async fn count_eligible_votes(&self, eligible_wallets: &HashSet<String>) -> usize {
        let votes = self.votes.read().await;
        votes
            .keys()
            .filter(|wallet| eligible_wallets.contains(*wallet))
            .count()
    }

    /// Compute the consensus result, counting only votes whose wallet is in
    /// `eligible_wallets`. A wallet absent from the on-chain staked set (or
    /// banned for equivocation) does not contribute — this replaces the old
    /// reputation-floor + active-NodeId-set gating, which made counting depend
    /// on the flap-prone registration state.
    pub async fn consensus_result(
        &self,
        eligible_wallets: &HashSet<String>,
    ) -> Result<VerificationVote> {
        let votes = self.votes.read().await;

        let mut eligible: Vec<&VerificationVote> = Vec::with_capacity(votes.len());
        let mut excluded = 0usize;
        for (wallet, rec) in votes.iter() {
            if eligible_wallets.contains(wallet) {
                eligible.push(&rec.vote);
            } else {
                excluded += 1;
            }
        }

        if eligible.len() < self.min_validators_for_consensus {
            return Err(anyhow!(
                "Not enough eligible votes: {} < {} (excluded {} not in the staked set)",
                eligible.len(),
                self.min_validators_for_consensus,
                excluded
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
        let valid = votes.values().filter(|r| r.vote.is_valid()).count();
        let invalid = votes.len() - valid;
        (valid, invalid)
    }

    /// The NodeIds of the wallets that voted `Valid` **and** are in
    /// `eligible_wallets` — the co-signers the round leader collects settlement
    /// signatures from. Returning the record's authenticated `node_id` keeps the
    /// co-sign set equal to the counted set: a wallet that was counted is dialed
    /// under exactly the NodeId its signed vote arrived on.
    pub async fn valid_voters(&self, eligible_wallets: &HashSet<String>) -> Vec<NodeId> {
        let votes = self.votes.read().await;
        let mut out = Vec::new();
        for (wallet, rec) in votes.iter() {
            if rec.vote.is_valid() && eligible_wallets.contains(wallet) {
                out.push(rec.node_id.clone());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallets(ws: &[&str]) -> HashSet<String> {
        ws.iter().map(|w| w.to_string()).collect()
    }

    #[tokio::test]
    async fn valid_voters_lists_only_eligible_valid_votes() {
        let tally = VoteTally::new("req-1".to_string(), 2, 3);
        tally
            .submit_vote(
                "W1".into(),
                NodeId(vec![1]),
                VerificationVote::Valid,
                vec![1],
            )
            .await
            .unwrap();
        tally
            .submit_vote(
                "W2".into(),
                NodeId(vec![2]),
                VerificationVote::Invalid {
                    reason: "bad proof".to_string(),
                },
                vec![2],
            )
            .await
            .unwrap();
        tally
            .submit_vote(
                "W3".into(),
                NodeId(vec![3]),
                VerificationVote::Valid,
                vec![3],
            )
            .await
            .unwrap();

        let eligible = wallets(&["W1", "W2", "W3"]);
        let mut voters = tally.valid_voters(&eligible).await;
        voters.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(voters, vec![NodeId(vec![1]), NodeId(vec![3])]);
    }

    #[tokio::test]
    async fn valid_voters_excludes_wallets_not_in_eligible_set() {
        let tally = VoteTally::new("req-1".to_string(), 1, 3);
        tally
            .submit_vote(
                "W1".into(),
                NodeId(vec![1]),
                VerificationVote::Valid,
                vec![1],
            )
            .await
            .unwrap();
        tally
            .submit_vote(
                "W3".into(),
                NodeId(vec![3]),
                VerificationVote::Valid,
                vec![3],
            )
            .await
            .unwrap();

        // Only W1 is in the staked set; W3's Valid vote must not make it a
        // co-signer even though it voted Valid.
        let eligible = wallets(&["W1"]);
        let voters = tally.valid_voters(&eligible).await;
        assert_eq!(voters, vec![NodeId(vec![1])]);
    }

    #[tokio::test]
    async fn equivocation_is_wallet_keyed_and_carries_both_signatures() {
        let tally = VoteTally::new("req-1".to_string(), 1, 2);
        // Same wallet, two different NodeIds, Valid then Invalid -> equivocation
        // attributed to the wallet, undodgeable by rotating NodeId.
        assert!(tally
            .submit_vote(
                "W1".into(),
                NodeId(vec![1]),
                VerificationVote::Valid,
                vec![9, 9]
            )
            .await
            .unwrap()
            .is_none());
        let evidence = tally
            .submit_vote(
                "W1".into(),
                NodeId(vec![2]),
                VerificationVote::Invalid {
                    reason: "flip".into(),
                },
                vec![8, 8],
            )
            .await
            .unwrap();
        match evidence {
            Some(SlashingEvidence::Equivocation {
                wallet_pubkey,
                previous_signature,
                new_signature,
                ..
            }) => {
                assert_eq!(wallet_pubkey, "W1");
                assert_eq!(previous_signature, vec![9, 9]);
                assert_eq!(new_signature, vec![8, 8]);
            }
            _ => panic!("expected wallet-keyed equivocation evidence"),
        }
    }

    #[tokio::test]
    async fn transient_invalid_then_valid_does_not_equivocate_and_updates_vote() {
        let tally = VoteTally::new("req-transient-1".to_string(), 1, 2);
        // Honest validator had temporary key read issue -> Invalid with key unavailable
        let first = tally
            .submit_vote(
                "W1".into(),
                NodeId(vec![1]),
                VerificationVote::Invalid {
                    reason: "transact verifying key unavailable: file not found".into(),
                },
                vec![1, 1],
            )
            .await
            .unwrap();
        assert!(first.is_none());

        // Validator recovers and votes Valid -> NOT treated as equivocation
        let recovered = tally
            .submit_vote(
                "W1".into(),
                NodeId(vec![1]),
                VerificationVote::Valid,
                vec![2, 2],
            )
            .await
            .unwrap();
        assert!(
            recovered.is_none(),
            "transient error recovery must not produce equivocation evidence"
        );

        // The Valid vote must now be counted
        let eligible = wallets(&["W1"]);
        assert!(tally.has_consensus(&eligible).await);
        assert_eq!(tally.valid_voters(&eligible).await, vec![NodeId(vec![1])]);
    }

    #[tokio::test]
    async fn definitive_invalid_then_valid_still_equivocates() {
        let tally = VoteTally::new("req-definitive-1".to_string(), 1, 2);
        let first = tally
            .submit_vote(
                "W1".into(),
                NodeId(vec![1]),
                VerificationVote::Invalid {
                    reason: "proof verification failed: pairing mismatch".into(),
                },
                vec![1, 1],
            )
            .await
            .unwrap();
        assert!(first.is_none());

        // A flip on a non-transient, definitive verification outcome MUST equivocate
        let flip = tally
            .submit_vote(
                "W1".into(),
                NodeId(vec![1]),
                VerificationVote::Valid,
                vec![2, 2],
            )
            .await
            .unwrap();
        assert!(matches!(flip, Some(SlashingEvidence::Equivocation { .. })));
    }
}
