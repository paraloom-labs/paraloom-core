//! Withdrawal verification consensus
//!
//! Coordinates distributed verification of withdrawal zkSNARK proofs
//! across multiple validators.

use crate::bridge::WithdrawalRequest;
use crate::consensus::leader::{LeaderSelector, ValidatorInfo};
use crate::consensus::reputation::ReputationTracker;
use crate::consensus::slashing::{SlashingEvidence, SlashingTracker};
use crate::types::NodeId;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Default minimum validator count for the 7-of-10 BFT consensus.
/// The actual threshold is configurable per [`WithdrawalConsensus`]
/// instance and per [`WithdrawalVerificationCoordinator`]; this is
/// the fallback used when no override is supplied.
pub const DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS: usize = 7;

/// Default validator-set size for the 7-of-10 BFT consensus. Used
/// only as the divisor in [`WithdrawalConsensus::completion_percentage`]
/// when no override is supplied.
pub const DEFAULT_TOTAL_VALIDATORS: usize = 10;

/// Backwards-compatible alias for [`DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS`].
/// Pre-#69 callers imported `MIN_VALIDATORS_FOR_CONSENSUS` directly;
/// keeping the alias avoids a wire break for external consumers while
/// the rename ripples through the workspace.
pub const MIN_VALIDATORS_FOR_CONSENSUS: usize = DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS;

/// Backwards-compatible alias for [`DEFAULT_TOTAL_VALIDATORS`].
pub const TOTAL_VALIDATORS: usize = DEFAULT_TOTAL_VALIDATORS;

/// Default reputation floor for consensus participation. A validator
/// whose reputation drops below this is excluded from vote aggregation
/// — they may still submit a vote (the network has no way to stop the
/// bytes from arriving), but the consensus result is computed as if
/// they had not. The default sits one notch above
/// [`reputation::MIN_REPUTATION`] so a validator that bottoms out is
/// already gated out before any further punishment.
pub const DEFAULT_MIN_REPUTATION_FOR_CONSENSUS: u64 = 200;

/// Number of consecutive timeouts after which a validator is considered
/// persistently unavailable and a `PersistentUnavailability` slashing
/// event is recorded. Three is small enough to react quickly to a
/// genuinely offline validator and large enough to absorb a transient
/// network blip.
pub const PERSISTENT_UNAVAILABILITY_TIMEOUT_STREAK: u64 = 3;

/// Withdrawal verification request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawalVerificationRequest {
    /// Unique request ID
    pub request_id: String,

    /// Withdrawal nullifier
    pub nullifier: [u8; 32],

    /// Withdrawal amount
    pub amount: u64,

    /// Recipient address
    pub recipient: [u8; 32],

    /// zkSNARK proof (serialized)
    pub proof: Vec<u8>,

    /// Fee amount
    pub fee: u64,

    /// Timestamp when request was created
    pub timestamp: u64,

    /// The Merkle root the prover built this proof against — i.e. the root the
    /// path server served when the wallet fetched its note's path. A verifier
    /// checks the proof against THIS root (not its own current tip) and
    /// separately confirms the root is one its pool computed recently
    /// ([`crate::privacy::ShieldedPool::knows_root`]), so validators whose trees
    /// have advanced by different amounts still accept the same proof.
    /// `#[serde(default)]` (all-zero) keeps wire-compatibility with senders that
    /// predate this field; the initiating node fills its own current root in
    /// that case (see `Node::initiate_withdrawal_verification`).
    #[serde(default)]
    pub prover_root: [u8; 32],
}

impl WithdrawalVerificationRequest {
    /// Create new verification request from withdrawal
    pub fn from_withdrawal(request: &WithdrawalRequest) -> Self {
        let timestamp = crate::utils::now_unix_seconds();

        Self {
            request_id: format!("withdrawal_{}", timestamp),
            nullifier: request.nullifier,
            amount: request.amount,
            recipient: request.recipient,
            proof: request.proof.clone(),
            fee: request.fee,
            timestamp,
            // The bridge-side request carries no prover root; the initiating
            // node fills its own current root before broadcasting/verifying.
            prover_root: [0u8; 32],
        }
    }
}

// The vote type now lives with the payload-independent tally (#194) so the
// transfer path can share it; re-exported here to keep the existing
// `crate::consensus::withdrawal::VerificationVote` path stable.
pub use crate::consensus::vote_tally::{VerificationVote, VoteTally};

/// Verification result from a validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawalVerificationResult {
    /// Request ID
    pub request_id: String,

    /// Validator who performed verification
    pub validator: NodeId,

    /// Verification vote
    pub vote: VerificationVote,

    /// Timestamp when verified
    pub timestamp: u64,
}

/// A withdrawal the validator quorum has approved (#164). Emitted by the
/// coordinator on the approval channel the moment a `Valid` quorum is
/// first reached for a request, so a submitter task can settle it
/// on-chain without polling. Carries exactly the fields needed to build
/// a [`WithdrawalRequest`]; the expiration slot is computed at submit
/// time against the live chain, so it is intentionally not included.
#[derive(Clone, Debug)]
pub struct ApprovedWithdrawal {
    pub request_id: String,
    pub nullifier: [u8; 32],
    pub amount: u64,
    pub recipient: [u8; 32],
    pub proof: Vec<u8>,
    pub fee: u64,
    /// The Merkle root the proof was built against (from the request). The settle
    /// path publishes THIS root on-chain (via the co-signed update_merkle_root
    /// round) before the withdraw, so the on-chain verify runs against the same
    /// root — not whatever the pool's tip happens to be at settle time.
    pub prover_root: [u8; 32],
}

/// Consensus state for a withdrawal verification.
///
/// The vote/quorum machinery now lives in the payload-independent
/// [`VoteTally`] (#194) so the transfer path can share it; this struct adds
/// the withdrawal request alongside and delegates the consensus methods to
/// the tally, keeping the public API unchanged.
#[derive(Clone, Debug)]
pub struct WithdrawalConsensus {
    /// Original request
    pub request: WithdrawalVerificationRequest,

    /// Vote collection + BFT quorum state
    pub tally: VoteTally,
}

impl WithdrawalConsensus {
    /// Create new consensus state with the default 7-of-10 thresholds.
    /// Use [`Self::new_with_thresholds`] when the coordinator is
    /// configured for a different validator-set size.
    pub fn new(request: WithdrawalVerificationRequest) -> Self {
        Self::new_with_thresholds(
            request,
            DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS,
            DEFAULT_TOTAL_VALIDATORS,
        )
    }

    /// Create new consensus state with explicit BFT thresholds.
    pub fn new_with_thresholds(
        request: WithdrawalVerificationRequest,
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

    /// Submit a vote — delegates to the [`VoteTally`].
    pub async fn submit_vote(
        &self,
        validator: NodeId,
        vote: VerificationVote,
    ) -> Result<Option<SlashingEvidence>> {
        self.tally.submit_vote(validator, vote).await
    }

    /// Whether the BFT quorum of eligible voters has been reached.
    pub async fn has_consensus(
        &self,
        reputation_tracker: &ReputationTracker,
        min_reputation: u64,
    ) -> bool {
        self.tally
            .has_consensus(reputation_tracker, min_reputation)
            .await
    }

    /// Check if consensus deadline has passed
    pub fn is_timed_out(&self) -> bool {
        self.tally.is_timed_out()
    }

    /// Compute the reputation-gated consensus result.
    pub async fn consensus_result(
        &self,
        reputation_tracker: &ReputationTracker,
        min_reputation: u64,
    ) -> Result<VerificationVote> {
        self.tally
            .consensus_result(reputation_tracker, min_reputation)
            .await
    }

    /// Get completion percentage
    pub async fn completion_percentage(&self) -> f64 {
        self.tally.completion_percentage().await
    }

    /// Get vote counts
    pub async fn vote_counts(&self) -> (usize, usize) {
        self.tally.vote_counts().await
    }
}

/// Coordinates withdrawal verification across validators
pub struct WithdrawalVerificationCoordinator {
    /// Active consensus states (request_id -> consensus)
    pending: Arc<RwLock<HashMap<String, WithdrawalConsensus>>>,

    /// Available validators (for backward compatibility)
    validators: Arc<RwLock<Vec<NodeId>>>,

    /// Leader selector for weighted random selection
    leader_selector: Arc<RwLock<LeaderSelector>>,

    /// Reputation tracker for automatic reputation updates
    reputation_tracker: Arc<ReputationTracker>,

    /// Slashing-evidence log. Equivocation and persistent-unavailability
    /// detections are appended here. A separate slashing pipeline (the
    /// on-chain `slash_validator` instruction) will consume the log.
    slashing_tracker: Arc<SlashingTracker>,

    /// Per-validator timeout streak counter, used to detect persistent
    /// unavailability. Reset to 0 whenever the validator is observed
    /// active in a verification round.
    timeout_streaks: Arc<RwLock<HashMap<NodeId, u64>>>,

    /// Reputation floor for consensus participation. Configurable so an
    /// operator can tighten or loosen the gate without recompiling.
    min_reputation_for_consensus: u64,

    /// Minimum eligible-vote count for the BFT quorum. Coordinator-
    /// scoped so a single coordinator can run different validator-set
    /// sizes (e.g. 5-of-7 on devnet, 14-of-20 on mainnet) without a
    /// recompile.
    min_validators_for_consensus: usize,

    /// Total validator-set size used as the divisor in
    /// completion-percentage reporting.
    total_validators: usize,

    /// Approval-event sender (#164). `Some` only when the coordinator was
    /// built with [`WithdrawalVerificationCoordinator::new_with_approvals`];
    /// a quorum-`Valid` result is pushed here so a submitter task settles
    /// it on-chain. `None` for the plain `new()` coordinator, which keeps
    /// every existing caller and test unchanged.
    approval_tx: Option<mpsc::UnboundedSender<ApprovedWithdrawal>>,

    /// Request IDs already emitted on `approval_tx`, so a request is
    /// settled at most once even though more validator votes may keep
    /// arriving after the quorum is first reached.
    emitted: Arc<RwLock<HashSet<String>>>,
}

impl WithdrawalVerificationCoordinator {
    /// Create new coordinator
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

    /// Create a coordinator that emits approved withdrawals on a channel
    /// (#164). Identical to [`new`](Self::new) except a `Valid` quorum
    /// result is pushed to the returned receiver, which a submitter task
    /// drains to settle the withdrawal on-chain. Returned as a pair so
    /// the receiver — not `Clone` — is owned by exactly one consumer.
    pub fn new_with_approvals() -> (Self, mpsc::UnboundedReceiver<ApprovedWithdrawal>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut coordinator = Self::new();
        coordinator.approval_tx = Some(tx);
        (coordinator, rx)
    }

    /// Override the BFT thresholds for this coordinator. The two
    /// values must satisfy `min_validators_for_consensus <= total_validators`;
    /// the setter logs a warning and silently swaps to defaults if
    /// that invariant is violated to avoid an unrecoverable
    /// misconfiguration at runtime.
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
                "ignoring invalid consensus thresholds (min={} total={}); falling back to {}/{}",
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

    /// Read the configured BFT thresholds as `(min_validators, total_validators)`.
    pub fn consensus_thresholds(&self) -> (usize, usize) {
        (self.min_validators_for_consensus, self.total_validators)
    }

    /// Reference to the slashing-evidence log. Tests and downstream
    /// pipelines read this directly; the coordinator never mutates it
    /// outside its own write paths.
    pub fn slashing_tracker(&self) -> &Arc<SlashingTracker> {
        &self.slashing_tracker
    }

    /// Record a verification timeout against `validator` and append a
    /// `PersistentUnavailability` slashing record once the streak hits
    /// [`PERSISTENT_UNAVAILABILITY_TIMEOUT_STREAK`]. Resetting the
    /// streak after a successful round happens in
    /// [`Self::reset_timeout_streak`].
    pub async fn record_timeout(&self, validator: &NodeId) {
        let mut streaks = self.timeout_streaks.write().await;
        let streak = streaks.entry(validator.clone()).or_insert(0);
        *streak += 1;
        let current = *streak;
        drop(streaks);

        if current >= PERSISTENT_UNAVAILABILITY_TIMEOUT_STREAK {
            self.slashing_tracker
                .record(
                    validator.clone(),
                    SlashingEvidence::PersistentUnavailability {
                        streak_length: current,
                        threshold: PERSISTENT_UNAVAILABILITY_TIMEOUT_STREAK,
                    },
                )
                .await;
        }

        if let Err(e) = self.reputation_tracker.record_timeout(validator).await {
            log::debug!(
                target: "paraloom::consensus",
                "skipping reputation timeout for {:?}: {}",
                validator,
                e
            );
        }
    }

    /// Clear the timeout streak after a validator is observed alive.
    pub async fn reset_timeout_streak(&self, validator: &NodeId) {
        self.timeout_streaks
            .write()
            .await
            .insert(validator.clone(), 0);
    }

    /// Override the reputation floor for consensus participation. Useful
    /// in tests and for operator-driven retuning at runtime.
    pub fn set_min_reputation_for_consensus(&mut self, threshold: u64) {
        self.min_reputation_for_consensus = threshold;
    }

    /// Read the current reputation floor.
    pub fn min_reputation_for_consensus(&self) -> u64 {
        self.min_reputation_for_consensus
    }

    /// Register a validator (simple version for backward compatibility)
    pub async fn register_validator(&self, validator: NodeId) {
        self.register_validator_with_wallet(validator, None).await;
    }

    /// Register a validator, recording the Solana wallet pubkey it co-signs
    /// settlement with (#260). The wallet is advertised via discovery and lets
    /// the leader map a voting `NodeId` to the on-chain `(wallet, pda)` pair the
    /// settlement quorum requires.
    pub async fn register_validator_with_wallet(
        &self,
        validator: NodeId,
        wallet_pubkey: Option<String>,
    ) {
        let mut validators = self.validators.write().await;
        if !validators.contains(&validator) {
            log::info!(
                "Validator registered for consensus: {:?} (wallet: {:?})",
                validator,
                wallet_pubkey
            );
            validators.push(validator.clone());
        }

        // Register with reputation tracker (idempotent — preserves reputation).
        self.reputation_tracker
            .register_validator(validator.clone())
            .await;

        // Register with the leader selector, preserving any entry that already
        // exists: a new validator is added with default stake/reputation and
        // whatever wallet it advertised; an existing one only adopts a freshly
        // advertised co-sign wallet (#260). A wallet-less re-register (the #333
        // reconciler) or a periodic Discovery re-announce therefore neither
        // clobbers a known wallet with None nor resets accumulated
        // stake/reputation back to the defaults.
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

    /// Look up the Solana wallet pubkey a registered validator co-signs
    /// settlement with (#260), or `None` if unknown / not advertised.
    pub async fn validator_wallet(&self, node_id: &NodeId) -> Option<String> {
        let leader_selector = self.leader_selector.read().await;
        leader_selector
            .get_validator(node_id)
            .and_then(|v| v.wallet_pubkey.clone())
    }

    /// The validators that voted `Valid` on a request (#260) — the eligible
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

    /// Register a validator with full information
    pub async fn register_validator_with_info(&self, validator_info: ValidatorInfo) {
        let node_id = validator_info.node_id.clone();

        let mut validators = self.validators.write().await;
        if !validators.contains(&node_id) {
            log::info!(
                "Validator registered for consensus: {:?} (stake: {}, reputation: {})",
                node_id,
                validator_info.stake_amount,
                validator_info.reputation
            );
            validators.push(node_id.clone());
        }

        // Register with reputation tracker
        self.reputation_tracker.register_validator(node_id).await;

        // Register with leader selector
        let mut leader_selector = self.leader_selector.write().await;
        leader_selector.register_validator(validator_info);
    }

    /// Update validator reputation
    pub async fn update_validator_reputation(&self, node_id: &NodeId, new_reputation: u64) {
        let leader_selector = self.leader_selector.read().await;
        if let Some(mut validator) = leader_selector.get_validator(node_id).cloned() {
            drop(leader_selector);

            validator.reputation = new_reputation;
            let mut leader_selector = self.leader_selector.write().await;
            leader_selector.update_validator(validator);

            log::info!(
                "Updated validator reputation: {:?} -> {}",
                node_id,
                new_reputation
            );
        }
    }

    /// Unregister a validator
    pub async fn unregister_validator(&self, validator: &NodeId) {
        let mut validators = self.validators.write().await;
        validators.retain(|v| v != validator);

        // Unregister from reputation tracker
        self.reputation_tracker
            .unregister_validator(validator)
            .await;

        // Unregister from leader selector
        let mut leader_selector = self.leader_selector.write().await;
        leader_selector.unregister_validator(validator);

        log::info!("Validator unregistered from consensus: {:?}", validator);
    }

    /// Get number of registered validators
    pub async fn validator_count(&self) -> usize {
        let validators = self.validators.read().await;
        validators.len()
    }

    /// Start verification for a withdrawal request
    pub async fn start_verification(
        &self,
        request: WithdrawalVerificationRequest,
    ) -> Result<String> {
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
        let consensus = WithdrawalConsensus::new_with_thresholds(
            request,
            self.min_validators_for_consensus,
            self.total_validators,
        );

        let mut pending = self.pending.write().await;
        pending.insert(request_id.clone(), consensus);

        log::info!("Started withdrawal verification: {}", request_id);

        Ok(request_id)
    }

    /// Submit a verification result from a validator
    pub async fn submit_result(&self, result: WithdrawalVerificationResult) -> Result<()> {
        let pending = self.pending.read().await;

        let consensus = pending
            .get(&result.request_id)
            .ok_or_else(|| anyhow!("Request not found: {}", result.request_id))?;

        log::debug!(
            "Vote submitted for {}: {:?}",
            result.request_id,
            result.validator
        );

        let validator = result.validator.clone();
        // Once a validator submitted any vote, they are alive — clear
        // any outstanding timeout streak before classifying the vote.
        self.reset_timeout_streak(&validator).await;

        if let Some(evidence) = consensus
            .submit_vote(validator.clone(), result.vote)
            .await?
        {
            // Equivocation: a previous vote on this request from the
            // same validator disagreed with the new one. Record the
            // evidence and *do not* install the new vote — the
            // original stands. Also penalise the equivocator's reputation
            // (audit): provable misbehaviour must cost it standing and gate it
            // out of future quorums, not just produce an in-memory log entry.
            if let Err(e) = self.reputation_tracker.record_failure(&validator).await {
                log::warn!("could not penalise equivocator {:?}: {}", validator, e);
            }
            self.slashing_tracker.record(validator, evidence).await;
        }

        // Emit the approval the first time this vote completes a `Valid`
        // quorum (#164). Computed from the borrowed `consensus` directly
        // — the same eligibility view check_consensus uses — to avoid
        // re-locking `pending`. The `emitted` set guards against emitting
        // twice as later votes keep arriving.
        if let Some(tx) = &self.approval_tx {
            let mut emitted = self.emitted.write().await;
            if !emitted.contains(&result.request_id)
                && consensus
                    .has_consensus(&self.reputation_tracker, self.min_reputation_for_consensus)
                    .await
                && matches!(
                    consensus
                        .consensus_result(
                            &self.reputation_tracker,
                            self.min_reputation_for_consensus,
                        )
                        .await,
                    Ok(VerificationVote::Valid)
                )
            {
                let req = &consensus.request;
                let approved = ApprovedWithdrawal {
                    request_id: result.request_id.clone(),
                    nullifier: req.nullifier,
                    amount: req.amount,
                    recipient: req.recipient,
                    proof: req.proof.clone(),
                    fee: req.fee,
                    prover_root: req.prover_root,
                };
                // A closed receiver just means no submitter is listening
                // (e.g. a non-bridge node); that is not an error here.
                if tx.send(approved).is_ok() {
                    emitted.insert(result.request_id.clone());
                }
            }
        }

        Ok(())
    }

    /// Check if consensus has been reached
    pub async fn check_consensus(&self, request_id: &str) -> Result<Option<VerificationVote>> {
        let pending = self.pending.read().await;

        let consensus = pending
            .get(request_id)
            .ok_or_else(|| anyhow!("Request not found: {}", request_id))?;

        // Check timeout
        if consensus.is_timed_out() {
            return Err(anyhow!("Verification timed out"));
        }

        // Check if we have consensus among reputation-eligible voters.
        // Both checks share the coordinator's tracker so the eligibility
        // view is consistent within a single tick.
        if consensus
            .has_consensus(&self.reputation_tracker, self.min_reputation_for_consensus)
            .await
        {
            let result = consensus
                .consensus_result(&self.reputation_tracker, self.min_reputation_for_consensus)
                .await?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Wait for consensus to be reached (with timeout)
    pub async fn wait_for_consensus(&self, request_id: &str) -> Result<VerificationVote> {
        let timeout = tokio::time::Duration::from_secs(30);
        let start = tokio::time::Instant::now();

        loop {
            // Check for consensus
            match self.check_consensus(request_id).await {
                Ok(Some(result)) => {
                    log::info!("Consensus reached for {}: {:?}", request_id, result);

                    // Update reputations based on consensus result
                    if let Err(e) = self
                        .update_reputations_after_consensus(request_id, &result)
                        .await
                    {
                        log::warn!("Failed to update reputations for {}: {}", request_id, e);
                    }

                    return Ok(result);
                }
                Ok(None) => {
                    // Not ready yet, keep waiting
                }
                Err(e) => {
                    return Err(e);
                }
            }

            // Check timeout
            if start.elapsed() > timeout {
                return Err(anyhow!("Consensus timeout"));
            }

            // Sleep briefly before checking again
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    /// Get consensus status
    pub async fn get_status(&self, request_id: &str) -> Result<(f64, usize, usize)> {
        let pending = self.pending.read().await;

        let consensus = pending
            .get(request_id)
            .ok_or_else(|| anyhow!("Request not found: {}", request_id))?;

        let percentage = consensus.completion_percentage().await;
        let (valid, invalid) = consensus.vote_counts().await;

        Ok((percentage, valid, invalid))
    }

    /// Clean up completed verification
    pub async fn cleanup(&self, request_id: &str) -> Result<()> {
        let mut pending = self.pending.write().await;
        pending.remove(request_id);
        log::debug!("Cleaned up verification: {}", request_id);
        Ok(())
    }

    /// Select leader for a withdrawal request using deterministic weighted random selection
    ///
    /// All validators will select the same leader for the same request_id,
    /// because the selection is deterministic based on the request_id.
    pub async fn select_leader(&self, request_id: &str) -> Result<NodeId> {
        let leader_selector = self.leader_selector.read().await;

        // Use request_id as seed for deterministic selection
        let seed = request_id.as_bytes();
        let leader = leader_selector.select_leader(seed)?;

        log::info!("Selected leader for {}: {:?}", request_id, leader);
        Ok(leader)
    }

    /// Get leader selection probability for a validator
    pub async fn leader_probability(&self, node_id: &NodeId) -> f64 {
        let leader_selector = self.leader_selector.read().await;
        leader_selector.leader_probability(node_id)
    }

    /// Get all validators sorted by selection weight
    pub async fn get_validators_by_weight(&self) -> Vec<ValidatorInfo> {
        let leader_selector = self.leader_selector.read().await;
        leader_selector.get_validators_by_weight()
    }

    /// Update reputations after consensus is reached
    ///
    /// Rewards validators who voted with consensus,
    /// penalizes those who voted against it
    async fn update_reputations_after_consensus(
        &self,
        request_id: &str,
        consensus_vote: &VerificationVote,
    ) -> Result<()> {
        let pending = self.pending.read().await;
        let consensus = pending
            .get(request_id)
            .ok_or_else(|| anyhow!("Request not found: {}", request_id))?;

        let votes = consensus.tally.votes.read().await;

        for (validator_id, vote) in votes.iter() {
            // Check if vote aligns with consensus
            if vote.is_valid() == consensus_vote.is_valid() {
                // Vote aligned with consensus -> reward
                if let Err(e) = self.reputation_tracker.record_success(validator_id).await {
                    log::warn!("Failed to record success for {:?}: {}", validator_id, e);
                }
            } else {
                // Vote disagreed with consensus -> penalize
                if let Err(e) = self.reputation_tracker.record_failure(validator_id).await {
                    log::warn!("Failed to record failure for {:?}: {}", validator_id, e);
                }
            }
        }

        // Check for validators who didn't vote (timeout)
        let all_validators = self.validators.read().await;
        for validator_id in all_validators.iter() {
            if !votes.contains_key(validator_id) {
                // Validator didn't respond -> timeout penalty
                if let Err(e) = self.reputation_tracker.record_timeout(validator_id).await {
                    log::warn!("Failed to record timeout for {:?}: {}", validator_id, e);
                }
            }
        }

        // Update leader selector with new reputations
        for validator_id in all_validators.iter() {
            if let Some(reputation) = self.reputation_tracker.get_reputation(validator_id).await {
                self.update_validator_reputation(validator_id, reputation)
                    .await;
            }
        }

        Ok(())
    }

    /// Get reputation tracker reference
    pub fn reputation_tracker(&self) -> Arc<ReputationTracker> {
        self.reputation_tracker.clone()
    }

    /// Apply decay to all inactive validators
    pub async fn apply_reputation_decay(&self) -> usize {
        self.reputation_tracker.apply_decay_all().await
    }

    /// Clean up timed out verifications
    pub async fn cleanup_timeouts(&self) -> Result<usize> {
        let mut pending = self.pending.write().await;

        let timed_out: Vec<String> = pending
            .iter()
            .filter(|(_, consensus)| consensus.is_timed_out())
            .map(|(id, _)| id.clone())
            .collect();

        let count = timed_out.len();
        for id in timed_out {
            pending.remove(&id);
            log::warn!("Cleaned up timed out verification: {}", id);
        }

        Ok(count)
    }
}

impl Default for WithdrawalVerificationCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_consensus_creation() {
        let request = WithdrawalVerificationRequest {
            request_id: "test123".to_string(),
            nullifier: [1u8; 32],
            amount: 1000,
            recipient: [2u8; 32],
            proof: vec![0u8; 128],
            fee: 10,
            timestamp: 0,
            prover_root: [0u8; 32],
        };

        let consensus = WithdrawalConsensus::new(request);
        assert_eq!(consensus.tally.request_id, "test123");
        let tracker = ReputationTracker::new();
        assert!(
            !consensus
                .has_consensus(&tracker, DEFAULT_MIN_REPUTATION_FOR_CONSENSUS)
                .await
        );
    }

    #[tokio::test]
    async fn cleanup_timeouts_removes_only_timed_out_verifications() {
        let coordinator = WithdrawalVerificationCoordinator::new();
        let req = |id: &str| WithdrawalVerificationRequest {
            request_id: id.to_string(),
            nullifier: [1u8; 32],
            amount: 1000,
            recipient: [2u8; 32],
            proof: vec![0u8; 128],
            fee: 10,
            timestamp: 0,
            prover_root: [0u8; 32],
        };
        {
            let mut pending = coordinator.pending.write().await;
            let fresh = WithdrawalConsensus::new(req("fresh"));
            let mut stale = WithdrawalConsensus::new(req("stale"));
            stale.tally.deadline = 0; // already past => is_timed_out()
            pending.insert("fresh".to_string(), fresh);
            pending.insert("stale".to_string(), stale);
        }
        let removed = coordinator.cleanup_timeouts().await.unwrap();
        assert_eq!(removed, 1);
        let pending = coordinator.pending.read().await;
        assert!(pending.contains_key("fresh"));
        assert!(!pending.contains_key("stale"));
    }

    #[tokio::test]
    async fn test_consensus_voting() {
        let request = WithdrawalVerificationRequest {
            request_id: "test123".to_string(),
            nullifier: [1u8; 32],
            amount: 1000,
            recipient: [2u8; 32],
            proof: vec![0u8; 128],
            fee: 10,
            timestamp: 0,
            prover_root: [0u8; 32],
        };

        let consensus = WithdrawalConsensus::new(request);
        let tracker = ReputationTracker::new();

        // Submit 7 valid votes from registered validators so they pass
        // the reputation gate.
        for i in 0..7 {
            let validator = NodeId(vec![i]);
            tracker.register_validator(validator.clone()).await;
            consensus
                .submit_vote(validator, VerificationVote::Valid)
                .await
                .unwrap();
        }

        // Should have consensus
        assert!(
            consensus
                .has_consensus(&tracker, DEFAULT_MIN_REPUTATION_FOR_CONSENSUS)
                .await
        );

        // Result should be valid
        let result = consensus
            .consensus_result(&tracker, DEFAULT_MIN_REPUTATION_FOR_CONSENSUS)
            .await
            .unwrap();
        assert!(result.is_valid());
    }

    #[tokio::test]
    async fn test_consensus_rejection() {
        let request = WithdrawalVerificationRequest {
            request_id: "test123".to_string(),
            nullifier: [1u8; 32],
            amount: 1000,
            recipient: [2u8; 32],
            proof: vec![0u8; 128],
            fee: 10,
            timestamp: 0,
            prover_root: [0u8; 32],
        };

        let consensus = WithdrawalConsensus::new(request);
        let tracker = ReputationTracker::new();

        // Submit 7 invalid votes from registered validators.
        for i in 0..7 {
            let validator = NodeId(vec![i]);
            tracker.register_validator(validator.clone()).await;
            consensus
                .submit_vote(
                    validator,
                    VerificationVote::Invalid {
                        reason: "Test".to_string(),
                    },
                )
                .await
                .unwrap();
        }

        // Should have consensus
        assert!(
            consensus
                .has_consensus(&tracker, DEFAULT_MIN_REPUTATION_FOR_CONSENSUS)
                .await
        );

        // Result should be invalid
        let result = consensus
            .consensus_result(&tracker, DEFAULT_MIN_REPUTATION_FOR_CONSENSUS)
            .await
            .unwrap();
        assert!(!result.is_valid());
    }

    #[tokio::test]
    async fn test_coordinator_register_validators() {
        let coordinator = WithdrawalVerificationCoordinator::new();

        coordinator.register_validator(NodeId(vec![1])).await;
        coordinator.register_validator(NodeId(vec![2])).await;

        assert_eq!(coordinator.validator_count().await, 2);
    }

    #[tokio::test]
    async fn test_coordinator_records_validator_wallet() {
        let coordinator = WithdrawalVerificationCoordinator::new();

        // A validator that advertised its settlement wallet (#260) and one that
        // did not.
        coordinator
            .register_validator_with_wallet(NodeId(vec![1]), Some("WaLLet1111".to_string()))
            .await;
        coordinator.register_validator(NodeId(vec![2])).await;

        assert_eq!(
            coordinator.validator_wallet(&NodeId(vec![1])).await,
            Some("WaLLet1111".to_string()),
            "the advertised co-signing wallet must be looked up by NodeId"
        );
        assert_eq!(coordinator.validator_wallet(&NodeId(vec![2])).await, None);
        assert_eq!(coordinator.validator_wallet(&NodeId(vec![9])).await, None);
    }

    #[tokio::test]
    async fn reconciler_reregister_preserves_the_advertised_wallet() {
        // A validator advertises its co-sign wallet via Discovery, then the
        // wallet-less reconciler (#333) re-registers the same connected peer.
        // The wallet must survive — a clobber to None would silently drop the
        // validator from the #260 co-signing set.
        let coordinator = WithdrawalVerificationCoordinator::new();
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

        // A later Discovery can still upgrade an unknown wallet to a known one.
        coordinator
            .register_validator_with_wallet(NodeId(vec![2]), None)
            .await;
        coordinator
            .register_validator_with_wallet(NodeId(vec![2]), Some("WaLLet2222".to_string()))
            .await;
        assert_eq!(
            coordinator.validator_wallet(&NodeId(vec![2])).await,
            Some("WaLLet2222".to_string()),
        );
    }

    #[tokio::test]
    async fn test_coordinator_start_verification() {
        let coordinator = WithdrawalVerificationCoordinator::new();

        // Register enough validators
        for i in 0..10 {
            coordinator.register_validator(NodeId(vec![i])).await;
        }

        let request = WithdrawalVerificationRequest {
            request_id: "test123".to_string(),
            nullifier: [1u8; 32],
            amount: 1000,
            recipient: [2u8; 32],
            proof: vec![0u8; 128],
            fee: 10,
            timestamp: 0,
            prover_root: [0u8; 32],
        };

        let request_id = coordinator.start_verification(request).await.unwrap();
        assert_eq!(request_id, "test123");
    }

    #[tokio::test]
    async fn approval_channel_emits_once_on_valid_quorum() {
        let (coordinator, mut rx) = WithdrawalVerificationCoordinator::new_with_approvals();
        let validators: Vec<NodeId> = (0..10).map(|i| NodeId(vec![i as u8])).collect();
        for v in &validators {
            coordinator.register_validator(v.clone()).await;
        }

        let request = WithdrawalVerificationRequest {
            request_id: "approve-1".to_string(),
            nullifier: [5u8; 32],
            amount: 4_200,
            recipient: [6u8; 32],
            proof: vec![7u8; 64],
            fee: 9,
            timestamp: 0,
            prover_root: [0u8; 32],
        };
        coordinator
            .start_verification(request.clone())
            .await
            .unwrap();

        // No approval before the 7-vote quorum is reached.
        for v in validators.iter().take(6) {
            coordinator
                .submit_result(WithdrawalVerificationResult {
                    request_id: request.request_id.clone(),
                    validator: v.clone(),
                    vote: VerificationVote::Valid,
                    timestamp: 0,
                })
                .await
                .unwrap();
        }
        assert!(rx.try_recv().is_err(), "no approval before quorum");

        // The 7th valid vote crosses the quorum and emits one approval
        // carrying the original request's fields.
        coordinator
            .submit_result(WithdrawalVerificationResult {
                request_id: request.request_id.clone(),
                validator: validators[6].clone(),
                vote: VerificationVote::Valid,
                timestamp: 0,
            })
            .await
            .unwrap();

        let approved = rx.try_recv().expect("approval emitted at quorum");
        assert_eq!(approved.request_id, "approve-1");
        assert_eq!(approved.nullifier, [5u8; 32]);
        assert_eq!(approved.amount, 4_200);
        assert_eq!(approved.recipient, [6u8; 32]);
        assert_eq!(approved.fee, 9);

        // Later votes must not emit a second approval for the same request.
        coordinator
            .submit_result(WithdrawalVerificationResult {
                request_id: request.request_id.clone(),
                validator: validators[7].clone(),
                vote: VerificationVote::Valid,
                timestamp: 0,
            })
            .await
            .unwrap();
        assert!(rx.try_recv().is_err(), "approval emitted at most once");
    }

    #[tokio::test]
    async fn test_completion_percentage() {
        let request = WithdrawalVerificationRequest {
            request_id: "test123".to_string(),
            nullifier: [1u8; 32],
            amount: 1000,
            recipient: [2u8; 32],
            proof: vec![0u8; 128],
            fee: 10,
            timestamp: 0,
            prover_root: [0u8; 32],
        };

        let consensus = WithdrawalConsensus::new(request);

        assert_eq!(consensus.completion_percentage().await, 0.0);

        // Add 5 votes
        for i in 0..5 {
            consensus
                .submit_vote(NodeId(vec![i]), VerificationVote::Valid)
                .await
                .unwrap();
        }

        // 5/10 = 50%
        assert_eq!(consensus.completion_percentage().await, 50.0);
    }

    /// Submitting a second, *disagreeing* vote on the same request
    /// from the same validator must not silently overwrite the first
    /// — it must surface as `Equivocation` evidence and the original
    /// vote must remain authoritative.
    #[tokio::test]
    async fn test_submit_vote_detects_equivocation() {
        let request = WithdrawalVerificationRequest {
            request_id: "eq-1".to_string(),
            nullifier: [1u8; 32],
            amount: 1000,
            recipient: [2u8; 32],
            proof: vec![0u8; 32],
            fee: 0,
            timestamp: 0,
            prover_root: [0u8; 32],
        };
        let consensus = WithdrawalConsensus::new(request);
        let validator = NodeId(vec![1]);

        // First vote: clean.
        let evidence = consensus
            .submit_vote(validator.clone(), VerificationVote::Valid)
            .await
            .unwrap();
        assert!(evidence.is_none());

        // Second vote, disagreeing.
        let evidence = consensus
            .submit_vote(
                validator.clone(),
                VerificationVote::Invalid {
                    reason: "flipped".to_string(),
                },
            )
            .await
            .unwrap();
        match evidence {
            Some(SlashingEvidence::Equivocation {
                request_id,
                previous_vote,
                new_vote,
            }) => {
                assert_eq!(request_id, "eq-1");
                assert_eq!(previous_vote, VerificationVote::Valid);
                assert!(matches!(new_vote, VerificationVote::Invalid { .. }));
            }
            other => panic!("expected Equivocation, got {:?}", other),
        }

        // Idempotent re-send of the original vote: no evidence.
        let evidence = consensus
            .submit_vote(validator, VerificationVote::Valid)
            .await
            .unwrap();
        assert!(evidence.is_none());
    }

    /// Equivocation costs the validator reputation (audit), not just an
    /// in-memory log entry — so provable misbehaviour gates it out of quorums.
    #[tokio::test]
    async fn equivocation_penalises_the_validator_reputation() {
        let mut coordinator = WithdrawalVerificationCoordinator::new();
        coordinator.set_consensus_thresholds(1, 1);
        let v = NodeId(vec![7]);
        coordinator.register_validator(v.clone()).await;
        let before = coordinator
            .reputation_tracker()
            .get_reputation(&v)
            .await
            .unwrap();

        let rid = coordinator
            .start_verification(WithdrawalVerificationRequest {
                request_id: "eq-rep".to_string(),
                nullifier: [1u8; 32],
                amount: 1000,
                recipient: [2u8; 32],
                proof: vec![0u8; 32],
                fee: 0,
                timestamp: 0,
                prover_root: [0u8; 32],
            })
            .await
            .unwrap();

        coordinator
            .submit_result(WithdrawalVerificationResult {
                request_id: rid.clone(),
                validator: v.clone(),
                vote: VerificationVote::Valid,
                timestamp: 0,
            })
            .await
            .unwrap();
        // The same validator flips its vote — equivocation.
        coordinator
            .submit_result(WithdrawalVerificationResult {
                request_id: rid,
                validator: v.clone(),
                vote: VerificationVote::Invalid {
                    reason: "flipped".to_string(),
                },
                timestamp: 0,
            })
            .await
            .unwrap();

        let after = coordinator
            .reputation_tracker()
            .get_reputation(&v)
            .await
            .unwrap();
        assert!(
            after < before,
            "equivocation must lower the validator's reputation (was {before}, now {after})"
        );
    }

    /// A low-reputation validator's vote must not contribute to the
    /// quorum, even if they otherwise hit `submit_vote` cleanly.
    /// Builds a 10-validator pool, knocks one of them below the
    /// reputation floor, and verifies that the remaining 9 votes are
    /// what consensus_result counts.
    #[tokio::test]
    async fn test_low_reputation_vote_excluded_from_consensus() {
        // Hand-roll a tracker so we can drive reputations precisely.
        let tracker = ReputationTracker::new();
        let validators: Vec<NodeId> = (0..10).map(|i| NodeId(vec![i as u8])).collect();
        for v in &validators {
            tracker.register_validator(v.clone()).await;
        }

        // Drive validator[0] far below the gate. Each failure subtracts
        // REPUTATION_DECREASE_FAILURE; loop until below the threshold.
        for _ in 0..100 {
            tracker.record_failure(&validators[0]).await.unwrap();
        }
        let rep = tracker.get_reputation(&validators[0]).await.unwrap();
        assert!(
            rep < DEFAULT_MIN_REPUTATION_FOR_CONSENSUS,
            "test setup: validator[0] should be below the gate, got {}",
            rep
        );

        let request = WithdrawalVerificationRequest {
            request_id: "rep-gate".to_string(),
            nullifier: [1u8; 32],
            amount: 1,
            recipient: [0u8; 32],
            proof: vec![0u8; 32],
            fee: 0,
            timestamp: 0,
            prover_root: [0u8; 32],
        };
        let consensus = WithdrawalConsensus::new(request);

        // All 10 vote Valid, including the gated one.
        for v in &validators {
            consensus
                .submit_vote(v.clone(), VerificationVote::Valid)
                .await
                .unwrap();
        }

        // The gated validator's vote is excluded — 9 eligible votes
        // remain, all Valid, well above the 7/10 threshold.
        assert!(
            consensus
                .has_consensus(&tracker, DEFAULT_MIN_REPUTATION_FOR_CONSENSUS)
                .await
        );
        let result = consensus
            .consensus_result(&tracker, DEFAULT_MIN_REPUTATION_FOR_CONSENSUS)
            .await
            .unwrap();
        assert!(result.is_valid());

        // Now push a second validator below the gate as well — only 8
        // eligible votes remain, still above the 7/10 threshold.
        for _ in 0..100 {
            tracker.record_failure(&validators[1]).await.unwrap();
        }
        assert!(
            consensus
                .has_consensus(&tracker, DEFAULT_MIN_REPUTATION_FOR_CONSENSUS)
                .await
        );

        // Push two more (total 4 gated). Only 6 eligible votes remain
        // — below the 7/10 threshold, so consensus_result errors
        // rather than returning a result.
        for _ in 0..100 {
            tracker.record_failure(&validators[2]).await.unwrap();
            tracker.record_failure(&validators[3]).await.unwrap();
        }
        assert!(
            !consensus
                .has_consensus(&tracker, DEFAULT_MIN_REPUTATION_FOR_CONSENSUS)
                .await
        );
        assert!(consensus
            .consensus_result(&tracker, DEFAULT_MIN_REPUTATION_FOR_CONSENSUS)
            .await
            .is_err());
    }

    /// Three consecutive timeouts against the same validator must
    /// produce a `PersistentUnavailability` record on the coordinator's
    /// slashing tracker.
    #[tokio::test]
    async fn test_persistent_unavailability_after_streak() {
        let coordinator = WithdrawalVerificationCoordinator::new();
        let v = NodeId(vec![7]);
        coordinator.register_validator(v.clone()).await;

        for _ in 0..PERSISTENT_UNAVAILABILITY_TIMEOUT_STREAK {
            coordinator.record_timeout(&v).await;
        }

        let records = coordinator.slashing_tracker().for_validator(&v).await;
        assert_eq!(records.len(), 1);
        assert!(matches!(
            records[0].evidence,
            SlashingEvidence::PersistentUnavailability { .. }
        ));

        // A successful vote submission resets the streak; subsequent
        // single timeouts then must not produce a new record on their
        // own.
        coordinator.reset_timeout_streak(&v).await;
        coordinator.record_timeout(&v).await;
        let records = coordinator.slashing_tracker().for_validator(&v).await;
        assert_eq!(records.len(), 1, "streak reset must prevent fresh record");
    }

    /// Byzantine integration test: 10 validators, 3 of whom
    /// (a) try to equivocate by flipping their vote, and
    /// (b) bottom out their reputation through repeated failures.
    /// The honest 7 must still produce a Valid consensus result, and
    /// the slashing tracker must record evidence for each of the 3
    /// misbehaving validators.
    #[tokio::test]
    async fn test_byzantine_consensus_3_of_10() {
        let coordinator = WithdrawalVerificationCoordinator::new();
        let validators: Vec<NodeId> = (0..10).map(|i| NodeId(vec![i as u8])).collect();
        for v in &validators {
            coordinator.register_validator(v.clone()).await;
        }

        let request = WithdrawalVerificationRequest {
            request_id: "byz-1".to_string(),
            nullifier: [9u8; 32],
            amount: 1_000,
            recipient: [3u8; 32],
            proof: vec![0u8; 32],
            fee: 0,
            timestamp: 0,
            prover_root: [0u8; 32],
        };
        coordinator
            .start_verification(request.clone())
            .await
            .unwrap();

        // The 7 honest validators vote valid.
        for v in validators.iter().take(7) {
            coordinator
                .submit_result(WithdrawalVerificationResult {
                    request_id: request.request_id.clone(),
                    validator: v.clone(),
                    vote: VerificationVote::Valid,
                    timestamp: 0,
                })
                .await
                .unwrap();
        }

        // The 3 Byzantine validators each submit a Valid vote first
        // (so they enter the quorum), then immediately flip — the
        // flipped vote is rejected as equivocation and the original
        // stands. This shape is more realistic than a single
        // disagreeing vote: a Byzantine validator that wanted to
        // poison the quorum without leaving evidence would just send
        // one vote, but the round-tripping check above
        // (`test_submit_vote_detects_equivocation`) covers that path.
        for v in validators.iter().skip(7) {
            coordinator
                .submit_result(WithdrawalVerificationResult {
                    request_id: request.request_id.clone(),
                    validator: v.clone(),
                    vote: VerificationVote::Valid,
                    timestamp: 0,
                })
                .await
                .unwrap();
            coordinator
                .submit_result(WithdrawalVerificationResult {
                    request_id: request.request_id.clone(),
                    validator: v.clone(),
                    vote: VerificationVote::Invalid {
                        reason: "byzantine flip".to_string(),
                    },
                    timestamp: 0,
                })
                .await
                .unwrap();
        }

        // Consensus must converge to Valid: the 10 votes that were
        // counted (the equivocation flips were dropped) are all Valid.
        let result = coordinator
            .check_consensus(&request.request_id)
            .await
            .unwrap()
            .expect("quorum reached");
        assert!(result.is_valid(), "honest majority must produce Valid");

        // Slashing tracker must hold one Equivocation record per
        // Byzantine validator, and only those validators.
        let flagged = coordinator.slashing_tracker().flagged_validators().await;
        assert_eq!(
            flagged.len(),
            3,
            "exactly the 3 Byzantine validators flagged"
        );
        for v in validators.iter().skip(7) {
            let records = coordinator.slashing_tracker().for_validator(v).await;
            assert_eq!(records.len(), 1);
            assert!(matches!(
                records[0].evidence,
                SlashingEvidence::Equivocation { .. }
            ));
        }
    }

    /// Defaults pin the well-known 7-of-10 BFT thresholds; a regression
    /// that silently changes either default would shift every downstream
    /// quorum calculation.
    #[test]
    fn test_default_consensus_thresholds() {
        let coordinator = WithdrawalVerificationCoordinator::new();
        assert_eq!(
            coordinator.consensus_thresholds(),
            (
                DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS,
                DEFAULT_TOTAL_VALIDATORS
            )
        );
    }

    /// Setter installs a valid 5-of-7 configuration and the
    /// coordinator stamps the new thresholds onto every subsequently
    /// created \`WithdrawalConsensus\`. The completion percentage uses
    /// the new total validator count as its divisor.
    #[tokio::test]
    async fn test_set_consensus_thresholds_propagates_to_consensus() {
        let mut coordinator = WithdrawalVerificationCoordinator::new();
        coordinator.set_consensus_thresholds(5, 7);
        assert_eq!(coordinator.consensus_thresholds(), (5, 7));

        for i in 0..7 {
            coordinator.register_validator(NodeId(vec![i])).await;
        }

        let request = WithdrawalVerificationRequest {
            request_id: "thresh-cfg".to_string(),
            nullifier: [1u8; 32],
            amount: 1,
            recipient: [0u8; 32],
            proof: vec![0u8; 32],
            fee: 0,
            timestamp: 0,
            prover_root: [0u8; 32],
        };
        coordinator
            .start_verification(request.clone())
            .await
            .unwrap();

        // Five Valid votes is a quorum at 5-of-7. Confirm via the
        // pending consensus state directly.
        for i in 0..5 {
            coordinator
                .submit_result(WithdrawalVerificationResult {
                    request_id: request.request_id.clone(),
                    validator: NodeId(vec![i]),
                    vote: VerificationVote::Valid,
                    timestamp: 0,
                })
                .await
                .unwrap();
        }
        let result = coordinator
            .check_consensus(&request.request_id)
            .await
            .unwrap()
            .expect("quorum at 5-of-7 must be reached");
        assert!(result.is_valid());

        // Completion percentage uses the new total of 7 in its
        // divisor: 5 votes / 7 total ≈ 71%, never the old 50%.
        let pending = coordinator.pending.read().await;
        let consensus = pending.get(&request.request_id).unwrap();
        let pct = consensus.completion_percentage().await;
        assert!(
            (pct - (5.0 / 7.0 * 100.0)).abs() < 0.01,
            "expected ~71%, got {}",
            pct
        );
    }

    /// Invalid threshold combinations (zero, or min > total) must be
    /// rejected and fall back to the defaults rather than installing
    /// an unrecoverable configuration.
    #[test]
    fn test_set_consensus_thresholds_rejects_invalid() {
        let mut coordinator = WithdrawalVerificationCoordinator::new();

        coordinator.set_consensus_thresholds(0, 5);
        assert_eq!(
            coordinator.consensus_thresholds(),
            (
                DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS,
                DEFAULT_TOTAL_VALIDATORS
            ),
            "zero min must fall back to defaults"
        );

        coordinator.set_consensus_thresholds(8, 5);
        assert_eq!(
            coordinator.consensus_thresholds(),
            (
                DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS,
                DEFAULT_TOTAL_VALIDATORS
            ),
            "min > total must fall back to defaults"
        );
    }
}
