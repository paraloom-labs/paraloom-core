//! Shielded → shielded transfer verification consensus (#194).
//!
//! The transfer twin of [`crate::consensus::withdrawal`]. A client submits a
//! transfer (two input nullifiers, two output commitments, the post-state
//! Merkle root, and a `TransferCircuit` proof); validators verify the proof
//! and vote, and once a BFT quorum of eligible voters agrees the coordinator
//! emits an [`ApprovedTransfer`] that a submitter task settles on-chain via
//! the `shielded_transfer` instruction.
//!
//! The vote/quorum machinery is shared with withdrawals through
//! [`VoteTally`]; this module only adds the transfer-specific request,
//! approval, and the thin coordinator shell. The reputation/slashing/leader
//! trackers are reused as-is, so a validator's standing is consistent across
//! both verification paths.

use crate::consensus::leader::{LeaderSelector, ValidatorInfo};
use crate::consensus::reputation::ReputationTracker;
use crate::consensus::slashing::SlashingTracker;
use crate::consensus::vote_tally::{VerificationVote, VoteTally};
use crate::consensus::withdrawal::{
    DEFAULT_MIN_REPUTATION_FOR_CONSENSUS, DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS,
    DEFAULT_TOTAL_VALIDATORS,
};
use crate::types::NodeId;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// A shielded-transfer verification request broadcast to validators.
///
/// Fixed 2-in/2-out, matching the on-chain `shielded_transfer` instruction
/// and `TransferCircuit`. `new_merkle_root` is the leader-computed root
/// *after* the two output commitments are appended; it is carried for
/// settlement only and is **not** a proof public input (the proof is checked
/// against the inputs' membership root, the pool's current root).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferVerificationRequest {
    /// Unique request ID
    pub request_id: String,

    /// Input note nullifiers (one may be a random dummy for a 1-real-input spend)
    pub nullifiers: [[u8; 32]; 2],

    /// New output note commitments
    pub output_commitments: [[u8; 32]; 2],

    /// Merkle root after appending the output commitments (settlement only)
    pub new_merkle_root: [u8; 32],

    /// zkSNARK proof (serialized `TransferCircuit` Groth16 proof)
    pub proof: Vec<u8>,

    /// Encrypted output notes (#196), one per output commitment, hex-encoded
    /// `EncryptedNote`. Opaque to validators — carried so recipients can scan
    /// and trial-decrypt; never verified or settled on-chain.
    pub ciphertexts: [String; 2],

    /// Timestamp when the request was created
    pub timestamp: u64,
}

/// Verification result from a validator for a transfer request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferVerificationResult {
    /// Request ID
    pub request_id: String,

    /// Validator who performed verification
    pub validator: NodeId,

    /// Verification vote
    pub vote: VerificationVote,

    /// Timestamp when verified
    pub timestamp: u64,
}

/// A transfer the validator quorum has approved (#194). Emitted on the
/// approval channel the moment a `Valid` quorum is first reached, carrying
/// exactly the fields needed to build the on-chain `shielded_transfer`
/// instruction.
#[derive(Clone, Debug)]
pub struct ApprovedTransfer {
    pub request_id: String,
    pub nullifiers: [[u8; 32]; 2],
    pub output_commitments: [[u8; 32]; 2],
    pub new_merkle_root: [u8; 32],
    pub proof: Vec<u8>,
}

/// Consensus state for one transfer verification: the request plus the
/// shared [`VoteTally`].
#[derive(Clone, Debug)]
pub struct TransferConsensus {
    pub request: TransferVerificationRequest,
    pub tally: VoteTally,
}

impl TransferConsensus {
    /// Create new consensus state with explicit BFT thresholds.
    pub fn new_with_thresholds(
        request: TransferVerificationRequest,
        min_validators_for_consensus: usize,
        total_validators: usize,
    ) -> Self {
        let tally = VoteTally::new(
            request.request_id.clone(),
            min_validators_for_consensus,
            total_validators,
        );
        Self { request, tally }
    }
}

/// Coordinates transfer verification across validators. Mirrors
/// [`crate::consensus::withdrawal::WithdrawalVerificationCoordinator`]; the
/// quorum logic is delegated to the embedded [`VoteTally`] of each
/// [`TransferConsensus`].
pub struct TransferVerificationCoordinator {
    /// Active consensus states (request_id -> consensus)
    pending: Arc<RwLock<HashMap<String, TransferConsensus>>>,

    /// Registered validators
    validators: Arc<RwLock<Vec<NodeId>>>,

    /// Leader selector (shared selection model with withdrawals)
    leader_selector: Arc<RwLock<LeaderSelector>>,

    /// Reputation tracker for eligibility gating
    reputation_tracker: Arc<ReputationTracker>,

    /// Slashing-evidence log (equivocation detection)
    slashing_tracker: Arc<SlashingTracker>,

    /// Per-validator timeout streaks
    timeout_streaks: Arc<RwLock<HashMap<NodeId, u64>>>,

    /// Reputation floor for consensus participation
    min_reputation_for_consensus: u64,

    /// Minimum eligible-vote count for the BFT quorum
    min_validators_for_consensus: usize,

    /// Total validator-set size (percentage divisor)
    total_validators: usize,

    /// Approval-event sender; `Some` only when built with
    /// [`new_with_approvals`](Self::new_with_approvals).
    approval_tx: Option<mpsc::UnboundedSender<ApprovedTransfer>>,

    /// Request IDs already emitted, so a transfer is settled at most once.
    emitted: Arc<RwLock<HashSet<String>>>,
}

impl TransferVerificationCoordinator {
    /// Create a new coordinator with the default 7-of-10 thresholds.
    pub fn new() -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            validators: Arc::new(RwLock::new(Vec::new())),
            leader_selector: Arc::new(RwLock::new(LeaderSelector::new())),
            reputation_tracker: Arc::new(ReputationTracker::new()),
            slashing_tracker: Arc::new(SlashingTracker::new()),
            timeout_streaks: Arc::new(RwLock::new(HashMap::new())),
            min_reputation_for_consensus: DEFAULT_MIN_REPUTATION_FOR_CONSENSUS,
            min_validators_for_consensus: DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS,
            total_validators: DEFAULT_TOTAL_VALIDATORS,
            approval_tx: None,
            emitted: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Create a coordinator that emits approved transfers on a channel.
    /// Returned as a pair so the receiver (not `Clone`) is owned by exactly
    /// one submitter consumer.
    pub fn new_with_approvals() -> (Self, mpsc::UnboundedReceiver<ApprovedTransfer>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut coordinator = Self::new();
        coordinator.approval_tx = Some(tx);
        (coordinator, rx)
    }

    /// Override the BFT thresholds. Falls back to defaults on an invalid
    /// pair (`min == 0`, `total == 0`, or `min > total`).
    pub fn set_consensus_thresholds(
        &mut self,
        min_validators_for_consensus: usize,
        total_validators: usize,
    ) {
        if min_validators_for_consensus == 0
            || total_validators == 0
            || min_validators_for_consensus > total_validators
        {
            log::warn!(
                target: "paraloom::consensus",
                "ignoring invalid transfer consensus thresholds (min={} total={}); falling back to {}/{}",
                min_validators_for_consensus,
                total_validators,
                DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS,
                DEFAULT_TOTAL_VALIDATORS
            );
            self.min_validators_for_consensus = DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS;
            self.total_validators = DEFAULT_TOTAL_VALIDATORS;
            return;
        }
        self.min_validators_for_consensus = min_validators_for_consensus;
        self.total_validators = total_validators;
    }

    /// Reference to the slashing-evidence log (tests/pipelines read it).
    pub fn slashing_tracker(&self) -> &Arc<SlashingTracker> {
        &self.slashing_tracker
    }

    /// Register a validator into the transfer consensus, mirroring the
    /// withdrawal coordinator (reputation tracker + leader selector).
    pub async fn register_validator(&self, validator: NodeId) {
        self.register_validator_with_wallet(validator, None).await;
    }

    /// Register a validator, recording the Solana wallet pubkey it co-signs
    /// settlement with (#260) — the leader maps a voting `NodeId` to the
    /// on-chain `(wallet, pda)` pair the settlement quorum requires.
    pub async fn register_validator_with_wallet(
        &self,
        validator: NodeId,
        wallet_pubkey: Option<String>,
    ) {
        let mut validators = self.validators.write().await;
        if !validators.contains(&validator) {
            log::info!(
                "Validator registered for transfer consensus: {:?} (wallet: {:?})",
                validator,
                wallet_pubkey
            );
            validators.push(validator.clone());
        }

        self.reputation_tracker
            .register_validator(validator.clone())
            .await;

        let validator_info =
            ValidatorInfo::new(validator, 10_000_000_000, 1000).with_wallet(wallet_pubkey);
        let mut leader_selector = self.leader_selector.write().await;
        leader_selector.register_validator(validator_info);
    }

    /// Remove a validator from the transfer-consensus set — e.g. when it
    /// disconnects. Mirrors [`Self::register_validator_with_wallet`] so the
    /// validator-set reconciler can drop peers that are no longer connected.
    pub async fn unregister_validator(&self, validator: &NodeId) {
        let mut validators = self.validators.write().await;
        validators.retain(|v| v != validator);

        self.reputation_tracker
            .unregister_validator(validator)
            .await;

        let mut leader_selector = self.leader_selector.write().await;
        leader_selector.unregister_validator(validator);

        log::info!(
            "Validator unregistered from transfer consensus: {:?}",
            validator
        );
    }

    /// Look up the Solana wallet pubkey a registered validator co-signs
    /// settlement with (#260), or `None` if unknown / not advertised.
    pub async fn validator_wallet(&self, node_id: &NodeId) -> Option<String> {
        let leader_selector = self.leader_selector.read().await;
        leader_selector
            .get_validator(node_id)
            .and_then(|v| v.wallet_pubkey.clone())
    }

    /// The validators that voted `Valid` on a transfer (#260) — the eligible
    /// co-signers for its settlement. Empty if the request is unknown here.
    pub async fn valid_voters(&self, request_id: &str) -> Vec<NodeId> {
        let pending = self.pending.read().await;
        match pending.get(request_id) {
            Some(consensus) => consensus.tally.valid_voters().await,
            None => Vec::new(),
        }
    }

    /// Number of registered validators
    pub async fn validator_count(&self) -> usize {
        self.validators.read().await.len()
    }

    /// Clear the timeout streak after a validator is observed alive.
    async fn reset_timeout_streak(&self, validator: &NodeId) {
        self.timeout_streaks
            .write()
            .await
            .insert(validator.clone(), 0);
    }

    /// Start verification for a transfer request. Errors if there are not
    /// enough registered validators to reach the configured quorum.
    pub async fn start_verification(&self, request: TransferVerificationRequest) -> Result<String> {
        let validators = self.validators.read().await;

        if validators.is_empty() {
            return Err(anyhow!("No validators available"));
        }
        if validators.len() < self.min_validators_for_consensus {
            return Err(anyhow!(
                "Not enough validators: {} < {}",
                validators.len(),
                self.min_validators_for_consensus
            ));
        }

        let request_id = request.request_id.clone();
        let consensus = TransferConsensus::new_with_thresholds(
            request,
            self.min_validators_for_consensus,
            self.total_validators,
        );

        self.pending
            .write()
            .await
            .insert(request_id.clone(), consensus);

        log::info!("Started transfer verification: {}", request_id);
        Ok(request_id)
    }

    /// Submit a verification result from a validator. On the node that
    /// started the request, the vote that first completes a `Valid` quorum
    /// makes the coordinator emit an [`ApprovedTransfer`] exactly once.
    pub async fn submit_result(&self, result: TransferVerificationResult) -> Result<()> {
        let pending = self.pending.read().await;

        let consensus = pending
            .get(&result.request_id)
            .ok_or_else(|| anyhow!("Request not found: {}", result.request_id))?;

        log::debug!(
            "Transfer vote submitted for {}: {:?}",
            result.request_id,
            result.validator
        );

        let validator = result.validator.clone();
        self.reset_timeout_streak(&validator).await;

        if let Some(evidence) = consensus
            .tally
            .submit_vote(validator.clone(), result.vote)
            .await?
        {
            // Equivocation: record the evidence; the original vote stands. Also
            // penalise the equivocator's reputation (audit) so the misbehaviour
            // costs it standing and gates it out of future quorums, mirroring
            // the withdrawal path.
            if let Err(e) = self.reputation_tracker.record_failure(&validator).await {
                log::warn!("could not penalise equivocator {:?}: {}", validator, e);
            }
            self.slashing_tracker.record(validator, evidence).await;
        }

        // Emit the approval the first time this vote completes a `Valid`
        // quorum. Computed from the borrowed `consensus` directly, guarded by
        // the `emitted` set against later votes re-triggering it.
        if let Some(tx) = &self.approval_tx {
            let mut emitted = self.emitted.write().await;
            if !emitted.contains(&result.request_id)
                && consensus
                    .tally
                    .has_consensus(&self.reputation_tracker, self.min_reputation_for_consensus)
                    .await
                && matches!(
                    consensus
                        .tally
                        .consensus_result(
                            &self.reputation_tracker,
                            self.min_reputation_for_consensus,
                        )
                        .await,
                    Ok(VerificationVote::Valid)
                )
            {
                let req = &consensus.request;
                let approved = ApprovedTransfer {
                    request_id: result.request_id.clone(),
                    nullifiers: req.nullifiers,
                    output_commitments: req.output_commitments,
                    new_merkle_root: req.new_merkle_root,
                    proof: req.proof.clone(),
                };
                if tx.send(approved).is_ok() {
                    emitted.insert(result.request_id.clone());
                }
            }
        }

        Ok(())
    }

    /// Non-blocking quorum check.
    pub async fn check_consensus(&self, request_id: &str) -> Result<Option<VerificationVote>> {
        let pending = self.pending.read().await;
        let consensus = pending
            .get(request_id)
            .ok_or_else(|| anyhow!("Request not found: {}", request_id))?;

        if consensus.tally.is_timed_out() {
            return Err(anyhow!("Verification timed out"));
        }

        if consensus
            .tally
            .has_consensus(&self.reputation_tracker, self.min_reputation_for_consensus)
            .await
        {
            let result = consensus
                .tally
                .consensus_result(&self.reputation_tracker, self.min_reputation_for_consensus)
                .await?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// `(completion_percentage, valid, invalid)` vote tally for a request.
    pub async fn get_status(&self, request_id: &str) -> Result<(f64, usize, usize)> {
        let pending = self.pending.read().await;
        let consensus = pending
            .get(request_id)
            .ok_or_else(|| anyhow!("Request not found: {}", request_id))?;
        let percentage = consensus.tally.completion_percentage().await;
        let (valid, invalid) = consensus.tally.vote_counts().await;
        Ok((percentage, valid, invalid))
    }

    /// Remove a completed verification's state.
    pub async fn cleanup(&self, request_id: &str) -> Result<()> {
        self.pending.write().await.remove(request_id);
        log::debug!("Cleaned up transfer verification: {}", request_id);
        Ok(())
    }

    /// Remove timed-out pending verifications so the map cannot grow unbounded.
    /// The ingress write-surface inserts a request before any vote arrives, so
    /// requests that never reach quorum must be reclaimed by a periodic sweep.
    pub async fn cleanup_timeouts(&self) -> Result<usize> {
        let mut pending = self.pending.write().await;
        let timed_out: Vec<String> = pending
            .iter()
            .filter(|(_, consensus)| consensus.tally.is_timed_out())
            .map(|(id, _)| id.clone())
            .collect();
        let count = timed_out.len();
        for id in timed_out {
            pending.remove(&id);
            log::warn!("Cleaned up timed out transfer verification: {}", id);
        }
        Ok(count)
    }
}

impl Default for TransferVerificationCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The validator-set reconciler registers currently-connected peers and
    /// drops those that disconnect. `unregister_validator` is the removal half;
    /// it must shrink the transfer-consensus set so a stale peer stops counting
    /// toward (and being selected for) transfer settlement.
    #[tokio::test]
    async fn register_then_unregister_tracks_the_validator_set() {
        let coordinator = TransferVerificationCoordinator::new();

        coordinator.register_validator(NodeId(vec![1])).await;
        coordinator.register_validator(NodeId(vec![2])).await;
        assert_eq!(coordinator.validator_count().await, 2);

        coordinator.unregister_validator(&NodeId(vec![1])).await;
        assert_eq!(coordinator.validator_count().await, 1);

        // Unregistering an absent validator is a no-op, not an error.
        coordinator.unregister_validator(&NodeId(vec![9])).await;
        assert_eq!(coordinator.validator_count().await, 1);
    }
}
