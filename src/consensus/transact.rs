//! Unified-transact verification consensus (#350).
//!
//! The circuit-v3 twin of [`crate::consensus::transfer`]. A client submits a
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
    /// shielded transfer (`ext_amount == 0`).
    pub recipient: [u8; 32],

    /// Input note nullifiers (one may be a random dummy for a 1-real-input spend)
    pub nullifiers: [[u8; 32]; 2],

    /// New output note commitments
    pub output_commitments: [[u8; 32]; 2],

    /// The on-chain tree root the proof proves membership against; must be
    /// in the program's root history at settlement (`is_known_root`).
    pub root: [u8; 32],

    /// Signed external flow: `< 0` withdraws `|ext_amount|`, `== 0` moves
    /// nothing externally. `> 0` is invalid (deposits go through
    /// `deposit_note`).
    pub ext_amount: i64,

    /// zkSNARK proof (arkworks-compressed `TransactCircuitV3` Groth16 proof).
    pub proof: Vec<u8>,

    /// Encrypted output notes (#196), one per output commitment, hex-encoded
    /// `EncryptedNote`. Opaque to validators — carried so recipients can scan
    /// and trial-decrypt; never verified or settled on-chain.
    pub ciphertexts: [String; 2],

    /// Timestamp when the request was created
    pub timestamp: u64,
}

impl TransactVerificationRequest {
    /// Canonical, content-bound request id: a domain-separated SHA-256 over the
    /// proof/settlement-defining fields (#383). Keying consensus state by this,
    /// rather than by a caller-chosen string, means a peer cannot pick an id to
    /// overwrite or poison a cache entry; an exact replay is idempotent (same
    /// id); and any mutated field yields a different id — so two distinct
    /// transacts can never collide on one verification round (which previously
    /// let an honest validator's Valid-then-Invalid votes read as equivocation).
    /// Excludes `ciphertexts`, `timestamp`, and `request_id`, which are not
    /// settlement-bound.
    pub fn canonical_id(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"paraloom:transact-request:v1");
        h.update(self.root);
        h.update(self.recipient);
        h.update(self.ext_amount.to_le_bytes());
        h.update(self.nullifiers[0]);
        h.update(self.nullifiers[1]);
        h.update(self.output_commitments[0]);
        h.update(self.output_commitments[1]);
        h.update((self.proof.len() as u64).to_le_bytes());
        h.update(&self.proof);
        format!("transact-{}", hex::encode(h.finalize()))
    }
}

/// Verification result from a validator for a transact request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactVerificationResult {
    /// Request ID
    pub request_id: String,

    /// Validator who performed verification
    pub validator: NodeId,

    /// Verification vote
    pub vote: VerificationVote,

    /// Timestamp when verified
    pub timestamp: u64,
}

/// A transact the validator quorum has approved (#350). Emitted on the
/// approval channel the moment a `Valid` quorum is first reached, carrying
/// the full request — everything needed to build the on-chain `transact`
/// instruction.
#[derive(Clone, Debug)]
pub struct ApprovedTransact {
    pub request: TransactVerificationRequest,
}

/// Consensus state for one transact verification: the request plus the
/// shared [`VoteTally`].
#[derive(Clone, Debug)]
pub struct TransactConsensus {
    pub request: TransactVerificationRequest,
    pub tally: VoteTally,
}

impl TransactConsensus {
    /// Create new consensus state with explicit BFT thresholds.
    pub fn new_with_thresholds(
        request: TransactVerificationRequest,
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

/// Coordinates transact verification across validators. Mirrors
/// [`crate::consensus::withdrawal::WithdrawalVerificationCoordinator`]; the
/// quorum logic is delegated to the embedded [`VoteTally`] of each
/// [`TransactConsensus`].
pub struct TransactVerificationCoordinator {
    /// Active consensus states (request_id -> consensus)
    pending: Arc<RwLock<HashMap<String, TransactConsensus>>>,

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
    approval_tx: Option<mpsc::UnboundedSender<ApprovedTransact>>,

    /// Request IDs already emitted, so a transact is settled at most once.
    emitted: Arc<RwLock<HashSet<String>>>,
}

impl TransactVerificationCoordinator {
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

    /// Create a coordinator that emits approved transacts on a channel.
    /// Returned as a pair so the receiver (not `Clone`) is owned by exactly
    /// one submitter consumer.
    pub fn new_with_approvals() -> (Self, mpsc::UnboundedReceiver<ApprovedTransact>) {
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
                "ignoring invalid transact consensus thresholds (min={} total={}); falling back to {}/{}",
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

    /// Register a validator into the transact consensus, mirroring the
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
                "Validator registered for transact consensus: {:?} (wallet: {:?})",
                validator,
                wallet_pubkey
            );
            validators.push(validator.clone());
        }

        self.reputation_tracker
            .register_validator(validator.clone())
            .await;

        // Preserve an existing leader-selector entry's stake/reputation; only a
        // new validator is added with defaults, and an existing one only adopts a
        // freshly advertised co-sign wallet (#260). Mirrors the withdrawal
        // coordinator so a wallet-less reconciler pass / periodic Discovery never
        // clobbers a known wallet or resets accumulated state.
        let mut leader_selector = self.leader_selector.write().await;
        match leader_selector.get_validator(&validator).cloned() {
            Some(existing) => {
                if wallet_pubkey.is_some() && wallet_pubkey != existing.wallet_pubkey {
                    leader_selector.update_validator(existing.with_wallet(wallet_pubkey));
                }
            }
            None => {
                leader_selector.register_validator(
                    ValidatorInfo::new(validator, 10_000_000_000, 1000).with_wallet(wallet_pubkey),
                );
            }
        }
    }

    /// Remove a validator from the *active* transact-consensus set — e.g. when
    /// it disconnects. Drops it from the live voter set and leader selection so
    /// a stale peer stops counting toward (and being selected for) settlement,
    /// but deliberately PRESERVES its `ReputationTracker` metrics.
    ///
    /// Connectivity and security history are separate lifecycle state. Deleting
    /// the reputation entry on disconnect let a validator penalized below the
    /// consensus-eligibility floor reset itself to `BASE_REPUTATION` simply by
    /// reconnecting — for any offline duration — erasing its Byzantine history
    /// and regaining eligibility. Preserving the entry keeps a penalized
    /// validator penalized across reconnects: reputation only decays with
    /// inactivity, it never rises back over the floor. A preserved entry for a
    /// disconnected peer is inert (tallies only iterate over validators who
    /// actually voted this round).
    pub async fn unregister_validator(&self, validator: &NodeId) {
        let mut validators = self.validators.write().await;
        validators.retain(|v| v != validator);

        let mut leader_selector = self.leader_selector.write().await;
        leader_selector.unregister_validator(validator);

        log::info!(
            "Validator unregistered from active transact consensus set (reputation preserved): {:?}",
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

    /// The validators that voted `Valid` on a transact (#260) — the eligible
    /// co-signers for its settlement. Empty if the request is unknown here.
    pub async fn valid_voters(&self, request_id: &str) -> Vec<NodeId> {
        let pending = self.pending.read().await;
        match pending.get(request_id) {
            Some(consensus) => {
                consensus
                    .tally
                    .valid_voters(&self.reputation_tracker, self.min_reputation_for_consensus)
                    .await
            }
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

    /// Start verification for a transact request. Errors if there are not
    /// enough registered validators to reach the configured quorum.
    pub async fn start_verification(&self, request: TransactVerificationRequest) -> Result<String> {
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
        let consensus = TransactConsensus::new_with_thresholds(
            request,
            self.min_validators_for_consensus,
            self.total_validators,
        );

        // Insert-if-absent: a duplicate start for an already in-flight canonical
        // id (a client retry or a re-broadcast) must not discard the votes
        // already collected for this round. The id is content-bound
        // (`canonical_id`), so an existing entry is the same settlement — keep
        // collecting on it rather than resetting the tally.
        self.pending
            .write()
            .await
            .entry(request_id.clone())
            .or_insert(consensus);

        log::info!("Started transact verification: {}", request_id);
        Ok(request_id)
    }

    /// Submit a verification result from a validator. On the node that
    /// started the request, the vote that first completes a `Valid` quorum
    /// makes the coordinator emit an [`ApprovedTransact`] exactly once.
    pub async fn submit_result(&self, result: TransactVerificationResult) -> Result<()> {
        let pending = self.pending.read().await;

        let consensus = pending
            .get(&result.request_id)
            .ok_or_else(|| anyhow!("Request not found: {}", result.request_id))?;

        log::debug!(
            "Transact vote submitted for {}: {:?}",
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
                let approved = ApprovedTransact {
                    request: consensus.request.clone(),
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
        log::debug!("Cleaned up transact verification: {}", request_id);
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
            log::warn!("Cleaned up timed out transact verification: {}", id);
        }
        Ok(count)
    }
}

impl Default for TransactVerificationCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The validator-set reconciler (#333) registers currently-connected peers
    /// and drops those that disconnect. `unregister_validator` is the removal
    /// half; it must shrink the transact-consensus set so a stale peer stops
    /// counting toward (and being selected for) transact settlement.
    #[tokio::test]
    async fn register_then_unregister_tracks_the_validator_set() {
        let coordinator = TransactVerificationCoordinator::new();

        coordinator.register_validator(NodeId(vec![1])).await;
        coordinator.register_validator(NodeId(vec![2])).await;
        assert_eq!(coordinator.validator_count().await, 2);

        coordinator.unregister_validator(&NodeId(vec![1])).await;
        assert_eq!(coordinator.validator_count().await, 1);

        // Unregistering an absent validator is a no-op, not an error.
        coordinator.unregister_validator(&NodeId(vec![9])).await;
        assert_eq!(coordinator.validator_count().await, 1);
    }

    #[tokio::test]
    async fn reconciler_reregister_preserves_the_advertised_wallet() {
        // Same #260 wallet-preservation guarantee as the withdrawal coordinator:
        // a wallet-less reconciler re-register must not clobber a wallet learned
        // via Discovery.
        let coordinator = TransactVerificationCoordinator::new();
        coordinator
            .register_validator_with_wallet(NodeId(vec![1]), Some("WaLLet1111".to_string()))
            .await;
        coordinator
            .register_validator_with_wallet(NodeId(vec![1]), None)
            .await;
        assert_eq!(
            coordinator.validator_wallet(&NodeId(vec![1])).await,
            Some("WaLLet1111".to_string()),
            "a wallet-less re-register must not clobber the advertised wallet"
        );
    }

    /// A validator penalized below the consensus-eligibility floor must not be
    /// able to wipe that history by disconnecting and reconnecting. The
    /// reconciler's `unregister_validator` drops the peer from the active set
    /// but preserves its reputation, so a re-registration cannot reset it to
    /// `BASE_REPUTATION` and make a previously-excluded vote count (#394).
    #[tokio::test]
    async fn reconnect_preserves_reputation_and_keeps_excluded_vote_excluded() {
        let (mut coordinator, mut approvals) =
            TransactVerificationCoordinator::new_with_approvals();
        coordinator.set_consensus_thresholds(1, 1);
        let validator = NodeId(vec![0x44]);
        coordinator.register_validator(validator.clone()).await;

        // Drive the validator below the eligibility floor (17 * 50 penalty).
        for _ in 0..17 {
            coordinator
                .reputation_tracker
                .record_failure(&validator)
                .await
                .unwrap();
        }
        let penalized = coordinator
            .reputation_tracker
            .get_reputation(&validator)
            .await
            .unwrap();
        assert!(
            penalized < DEFAULT_MIN_REPUTATION_FOR_CONSENSUS,
            "precondition: validator must be below the consensus floor"
        );

        // A below-floor vote must not reach quorum.
        let mut request = sample_request();
        request.request_id = request.canonical_id();
        coordinator
            .start_verification(request.clone())
            .await
            .unwrap();
        let vote = TransactVerificationResult {
            request_id: request.request_id.clone(),
            validator: validator.clone(),
            vote: VerificationVote::Valid,
            timestamp: 1,
        };
        coordinator.submit_result(vote.clone()).await.unwrap();
        assert!(
            approvals.try_recv().is_err(),
            "a below-floor validator's vote must not reach quorum"
        );

        // Simulate a disconnect/reconnect across a reconciler tick.
        coordinator.unregister_validator(&validator).await;
        coordinator.register_validator(validator.clone()).await;

        // Reputation must survive the round-trip, NOT reset to BASE_REPUTATION.
        let after = coordinator
            .reputation_tracker
            .get_reputation(&validator)
            .await
            .unwrap();
        assert_eq!(
            after, penalized,
            "disconnect/reconnect must preserve reputation, not reset it to BASE"
        );
        assert!(after < DEFAULT_MIN_REPUTATION_FOR_CONSENSUS);

        // The same vote must still be excluded after the reconnect.
        coordinator.submit_result(vote).await.unwrap();
        assert!(
            approvals.try_recv().is_err(),
            "disconnect/reconnect must not make a previously-excluded vote quorum-eligible"
        );
    }

    /// A duplicate `start_verification` for an in-flight canonical id must not
    /// reset the vote tally — the first vote must survive so the quorum can
    /// still complete (insert-if-absent).
    #[tokio::test]
    async fn restarting_an_in_flight_verification_preserves_collected_votes() {
        let (mut coordinator, mut approvals) =
            TransactVerificationCoordinator::new_with_approvals();
        coordinator.set_consensus_thresholds(2, 2);
        let v1 = NodeId(vec![1]);
        let v2 = NodeId(vec![2]);
        coordinator.register_validator(v1.clone()).await;
        coordinator.register_validator(v2.clone()).await;

        let mut request = sample_request();
        request.request_id = request.canonical_id();
        let id = request.request_id.clone();
        coordinator
            .start_verification(request.clone())
            .await
            .unwrap();

        coordinator
            .submit_result(TransactVerificationResult {
                request_id: id.clone(),
                validator: v1.clone(),
                vote: VerificationVote::Valid,
                timestamp: 1,
            })
            .await
            .unwrap();
        assert!(
            approvals.try_recv().is_err(),
            "one of two votes must not reach quorum yet"
        );

        // Duplicate start for the same in-flight id — must be a no-op, not a reset.
        coordinator.start_verification(request).await.unwrap();

        coordinator
            .submit_result(TransactVerificationResult {
                request_id: id.clone(),
                validator: v2.clone(),
                vote: VerificationVote::Valid,
                timestamp: 2,
            })
            .await
            .unwrap();
        assert!(
            approvals.try_recv().is_ok(),
            "re-starting an in-flight verification must preserve the first vote so the quorum completes"
        );
    }

    fn sample_request() -> TransactVerificationRequest {
        TransactVerificationRequest {
            request_id: "attacker-chosen".to_string(),
            recipient: [1u8; 32],
            nullifiers: [[2u8; 32], [3u8; 32]],
            output_commitments: [[4u8; 32], [5u8; 32]],
            root: [6u8; 32],
            ext_amount: -100,
            proof: vec![7, 8, 9],
            ciphertexts: ["a".to_string(), "b".to_string()],
            timestamp: 123,
        }
    }

    #[test]
    fn canonical_id_binds_only_settlement_fields() {
        // The caller-chosen id, the ciphertexts, and the timestamp must not
        // change the canonical id (#383/#382): an exact settlement replay is
        // idempotent regardless of those non-bound fields.
        let base = sample_request().canonical_id();
        let mut r = sample_request();
        r.request_id = "different".to_string();
        r.ciphertexts = ["x".to_string(), "y".to_string()];
        r.timestamp = 999;
        assert_eq!(
            r.canonical_id(),
            base,
            "id must bind only settlement fields"
        );
    }

    #[test]
    fn canonical_id_changes_when_a_settlement_field_changes() {
        let base = sample_request().canonical_id();
        for mutate in [
            (|r: &mut TransactVerificationRequest| r.ext_amount = -101) as fn(&mut _),
            |r| r.nullifiers[0] = [9u8; 32],
            |r| r.output_commitments[1] = [9u8; 32],
            |r| r.root = [9u8; 32],
            |r| r.recipient = [9u8; 32],
            |r| r.proof = vec![7, 8, 10],
        ] {
            let mut r = sample_request();
            mutate(&mut r);
            assert_ne!(
                r.canonical_id(),
                base,
                "mutating a settlement field must change the canonical id"
            );
        }
    }
}
