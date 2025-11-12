//! Withdrawal verification consensus
//!
//! Coordinates distributed verification of withdrawal zkSNARK proofs
//! across multiple validators.

use crate::bridge::WithdrawalRequest;
use crate::consensus::leader::{LeaderSelector, ValidatorInfo};
use crate::consensus::reputation::ReputationTracker;
use crate::types::NodeId;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Minimum validators required for consensus (7 out of 10)
pub const MIN_VALIDATORS_FOR_CONSENSUS: usize = 7;

/// Total validators selected for verification
pub const TOTAL_VALIDATORS: usize = 10;

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
}

impl WithdrawalVerificationRequest {
    /// Create new verification request from withdrawal
    pub fn from_withdrawal(request: &WithdrawalRequest) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            request_id: format!("withdrawal_{}", timestamp),
            nullifier: request.nullifier,
            amount: request.amount,
            recipient: request.recipient,
            proof: request.proof.clone(),
            fee: request.fee,
            timestamp,
        }
    }
}

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

/// Consensus state for a withdrawal verification
#[derive(Clone, Debug)]
pub struct WithdrawalConsensus {
    /// Request ID
    pub request_id: String,

    /// Original request
    pub request: WithdrawalVerificationRequest,

    /// Validators who voted
    pub votes: Arc<RwLock<HashMap<NodeId, VerificationVote>>>,

    /// When consensus started
    pub started_at: u64,

    /// Deadline for consensus (30 seconds)
    pub deadline: u64,
}

impl WithdrawalConsensus {
    /// Create new consensus state
    pub fn new(request: WithdrawalVerificationRequest) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            request_id: request.request_id.clone(),
            request,
            votes: Arc::new(RwLock::new(HashMap::new())),
            started_at: now,
            deadline: now + 30, // 30 second deadline
        }
    }

    /// Submit a vote
    pub async fn submit_vote(&self, validator: NodeId, vote: VerificationVote) -> Result<()> {
        let mut votes = self.votes.write().await;
        votes.insert(validator, vote);
        Ok(())
    }

    /// Check if consensus has been reached
    pub async fn has_consensus(&self) -> bool {
        let votes = self.votes.read().await;
        votes.len() >= MIN_VALIDATORS_FOR_CONSENSUS
    }

    /// Check if consensus deadline has passed
    pub fn is_timed_out(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now > self.deadline
    }

    /// Compute consensus result
    pub async fn consensus_result(&self) -> Result<VerificationVote> {
        let votes = self.votes.read().await;

        if votes.len() < MIN_VALIDATORS_FOR_CONSENSUS {
            return Err(anyhow!(
                "Not enough votes: {} < {}",
                votes.len(),
                MIN_VALIDATORS_FOR_CONSENSUS
            ));
        }

        // Count valid vs invalid votes
        let valid_count = votes.values().filter(|v| v.is_valid()).count();
        let invalid_count = votes.len() - valid_count;

        // Require 7/10 majority to accept
        if valid_count >= MIN_VALIDATORS_FOR_CONSENSUS {
            Ok(VerificationVote::Valid)
        } else {
            Ok(VerificationVote::Invalid {
                reason: format!(
                    "Consensus rejected: {} valid, {} invalid (need {})",
                    valid_count, invalid_count, MIN_VALIDATORS_FOR_CONSENSUS
                ),
            })
        }
    }

    /// Get completion percentage
    pub async fn completion_percentage(&self) -> f64 {
        let votes = self.votes.read().await;
        (votes.len() as f64 / TOTAL_VALIDATORS as f64) * 100.0
    }

    /// Get vote counts
    pub async fn vote_counts(&self) -> (usize, usize) {
        let votes = self.votes.read().await;
        let valid = votes.values().filter(|v| v.is_valid()).count();
        let invalid = votes.len() - valid;
        (valid, invalid)
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
}

impl WithdrawalVerificationCoordinator {
    /// Create new coordinator
    pub fn new() -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            validators: Arc::new(RwLock::new(Vec::new())),
            leader_selector: Arc::new(RwLock::new(LeaderSelector::new())),
            reputation_tracker: Arc::new(ReputationTracker::new()),
        }
    }

    /// Register a validator (simple version for backward compatibility)
    pub async fn register_validator(&self, validator: NodeId) {
        let mut validators = self.validators.write().await;
        if !validators.contains(&validator) {
            log::info!("Validator registered for consensus: {:?}", validator);
            validators.push(validator.clone());
        }

        // Register with reputation tracker
        self.reputation_tracker
            .register_validator(validator.clone())
            .await;

        // Also register with leader selector (default stake/reputation)
        let validator_info = ValidatorInfo::new(validator, 10_000_000_000, 1000);
        let mut leader_selector = self.leader_selector.write().await;
        leader_selector.register_validator(validator_info);
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

        if validators.len() < MIN_VALIDATORS_FOR_CONSENSUS {
            return Err(anyhow!(
                "Not enough validators: {} < {}",
                validators.len(),
                MIN_VALIDATORS_FOR_CONSENSUS
            ));
        }

        let request_id = request.request_id.clone();
        let consensus = WithdrawalConsensus::new(request);

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

        consensus.submit_vote(result.validator, result.vote).await?;

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

        // Check if we have consensus
        if consensus.has_consensus().await {
            let result = consensus.consensus_result().await?;
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

        let votes = consensus.votes.read().await;

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
        };

        let consensus = WithdrawalConsensus::new(request);
        assert_eq!(consensus.request_id, "test123");
        assert!(!consensus.has_consensus().await);
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
        };

        let consensus = WithdrawalConsensus::new(request);

        // Submit 7 valid votes
        for i in 0..7 {
            consensus
                .submit_vote(NodeId(vec![i]), VerificationVote::Valid)
                .await
                .unwrap();
        }

        // Should have consensus
        assert!(consensus.has_consensus().await);

        // Result should be valid
        let result = consensus.consensus_result().await.unwrap();
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
        };

        let consensus = WithdrawalConsensus::new(request);

        // Submit 7 invalid votes
        for i in 0..7 {
            consensus
                .submit_vote(
                    NodeId(vec![i]),
                    VerificationVote::Invalid {
                        reason: "Test".to_string(),
                    },
                )
                .await
                .unwrap();
        }

        // Should have consensus
        assert!(consensus.has_consensus().await);

        // Result should be invalid
        let result = consensus.consensus_result().await.unwrap();
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
        };

        let request_id = coordinator.start_verification(request).await.unwrap();
        assert_eq!(request_id, "test123");
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
}
