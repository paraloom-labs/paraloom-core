//! Distributed verification coordinator
//!
//! Handles distributing verification tasks across multiple validators
//! and aggregating their results for consensus.

use crate::privacy::proof::{ProofVerifier, VerificationChunk, VerificationResult};
use crate::privacy::transaction::ShieldedTransaction;
use crate::types::NodeId;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Default minimum validator count for distributed proof verification.
/// The actual threshold is configurable per [`VerificationAggregator`]
/// instance and per [`VerificationCoordinator`]; this is the fallback
/// used when no override is supplied.
pub const DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS: usize = 7;

/// Default validator-set size for distributed proof verification.
/// Used as the divisor in [`VerificationAggregator::completion_percentage`]
/// when no override is supplied.
pub const DEFAULT_TOTAL_VALIDATORS: usize = 10;

/// Backwards-compatible alias for [`DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS`].
/// Pre-#69 callers imported this name directly; keeping the alias
/// avoids a wire break for external consumers while the rename
/// ripples through the workspace.
pub const MIN_VALIDATORS_FOR_CONSENSUS: usize = DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS;

/// Backwards-compatible alias for [`DEFAULT_TOTAL_VALIDATORS`].
pub const TOTAL_VALIDATORS: usize = DEFAULT_TOTAL_VALIDATORS;

/// Verification task assigned to a validator
#[derive(Clone, Debug)]
pub struct VerificationTask {
    /// Task ID
    pub task_id: String,

    /// Transaction being verified
    pub transaction_id: String,

    /// Verification chunk
    pub chunk: VerificationChunk,

    /// Assigned validator
    pub validator: NodeId,

    /// Deadline for completion
    pub deadline: u64,
}

/// Verification task result from a validator
#[derive(Clone, Debug)]
pub struct VerificationTaskResult {
    /// Task ID
    pub task_id: String,

    /// Validator who performed verification
    pub validator: NodeId,

    /// Verification result
    pub result: VerificationResult,

    /// Timestamp when verified
    pub timestamp: u64,
}

/// Aggregates verification results for consensus
#[derive(Clone, Debug)]
pub struct VerificationAggregator {
    /// Transaction ID
    pub transaction_id: String,

    /// Total chunks to verify
    pub total_chunks: usize,

    /// Results collected so far
    pub results: Arc<RwLock<Vec<VerificationTaskResult>>>,

    /// Validators who voted
    pub voters: Arc<RwLock<HashMap<NodeId, VerificationResult>>>,

    /// Minimum eligible-vote count required for this aggregator to
    /// declare consensus. Configurable so different validator-set
    /// sizes can use different BFT thresholds without recompiling.
    pub min_validators_for_consensus: usize,

    /// Total validator-set size used as the divisor in
    /// [`completion_percentage`]. Must agree with the actual size of
    /// the validator pool the coordinator drew from.
    pub total_validators: usize,
}

impl VerificationAggregator {
    /// Create a new aggregator with the default 7-of-10 thresholds.
    pub fn new(transaction_id: String, total_chunks: usize) -> Self {
        Self::new_with_thresholds(
            transaction_id,
            total_chunks,
            DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS,
            DEFAULT_TOTAL_VALIDATORS,
        )
    }

    /// Create a new aggregator with explicit BFT thresholds.
    pub fn new_with_thresholds(
        transaction_id: String,
        total_chunks: usize,
        min_validators_for_consensus: usize,
        total_validators: usize,
    ) -> Self {
        VerificationAggregator {
            transaction_id,
            total_chunks,
            results: Arc::new(RwLock::new(Vec::new())),
            voters: Arc::new(RwLock::new(HashMap::new())),
            min_validators_for_consensus,
            total_validators,
        }
    }

    /// Submit a verification result
    pub async fn submit_result(&self, result: VerificationTaskResult) -> Result<()> {
        let mut results = self.results.write().await;
        let mut voters = self.voters.write().await;

        // Record vote
        voters.insert(result.validator.clone(), result.result.clone());

        // Store result
        results.push(result);

        Ok(())
    }

    /// Check if we have enough results for consensus
    pub async fn has_consensus(&self) -> bool {
        let voters = self.voters.read().await;
        voters.len() >= self.min_validators_for_consensus
    }

    /// Compute consensus result
    pub async fn consensus(&self) -> Result<VerificationResult> {
        let voters = self.voters.read().await;

        if voters.len() < self.min_validators_for_consensus {
            return Err(anyhow!(
                "Not enough validators: {} < {}",
                voters.len(),
                self.min_validators_for_consensus
            ));
        }

        // Count valid vs invalid votes
        let valid_count = voters.values().filter(|r| r.is_valid()).count();
        let invalid_count = voters.len() - valid_count;

        // Require majority to accept
        if valid_count >= self.min_validators_for_consensus {
            Ok(VerificationResult::Valid)
        } else {
            Ok(VerificationResult::Invalid {
                reason: format!(
                    "Consensus failed: {} valid, {} invalid (need {})",
                    valid_count, invalid_count, self.min_validators_for_consensus
                ),
            })
        }
    }

    /// Get completion percentage
    pub async fn completion_percentage(&self) -> f64 {
        let voters = self.voters.read().await;
        (voters.len() as f64 / self.total_validators as f64) * 100.0
    }
}

/// Distributed verification coordinator
pub struct VerificationCoordinator {
    /// Active verification tasks
    tasks: Arc<RwLock<HashMap<String, VerificationTask>>>,

    /// Aggregators for each transaction
    aggregators: Arc<RwLock<HashMap<String, VerificationAggregator>>>,

    /// Available validators
    validators: Arc<RwLock<Vec<NodeId>>>,

    /// Minimum eligible-vote count for the BFT quorum. Mirrors the
    /// configurable threshold on `WithdrawalVerificationCoordinator`
    /// so both consensus surfaces share the same operator-tunable
    /// shape.
    min_validators_for_consensus: usize,

    /// Total validator-set size used as the divisor in
    /// completion-percentage reporting on aggregators created by
    /// this coordinator.
    total_validators: usize,
}

impl VerificationCoordinator {
    /// Create a new coordinator with the default 7-of-10 thresholds.
    pub fn new() -> Self {
        VerificationCoordinator {
            tasks: Arc::new(RwLock::new(HashMap::new())),
            aggregators: Arc::new(RwLock::new(HashMap::new())),
            validators: Arc::new(RwLock::new(Vec::new())),
            min_validators_for_consensus: DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS,
            total_validators: DEFAULT_TOTAL_VALIDATORS,
        }
    }

    /// Override the BFT thresholds for this coordinator. Invariants:
    /// `min_validators_for_consensus` must be non-zero, `total_validators`
    /// must be non-zero, and `min <= total`. A violation is logged at
    /// `warn` and the coordinator falls back to the defaults — the
    /// alternative would be installing an unrecoverable misconfiguration
    /// at runtime.
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
                target: "paraloom::privacy::verification",
                "ignoring invalid verification thresholds (min={} total={}); falling back to {}/{}",
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

    /// Register a validator
    pub async fn register_validator(&self, validator: NodeId) {
        let mut validators = self.validators.write().await;
        if !validators.contains(&validator) {
            validators.push(validator);
        }
    }

    /// Create verification tasks for a shielded transaction
    pub async fn create_verification_tasks(
        &self,
        transaction: &ShieldedTransaction,
    ) -> Result<Vec<VerificationTask>> {
        let tx_id = transaction.id();

        // Get verification chunks based on transaction type
        let chunks = match transaction {
            ShieldedTransaction::Deposit(_) => {
                // Deposits are simple, no chunks needed
                vec![]
            }
            ShieldedTransaction::Transfer(tx) => ProofVerifier::create_verification_chunks(tx),
            ShieldedTransaction::Withdraw(_) => {
                // Withdraws need minimal verification
                vec![]
            }
        };

        if chunks.is_empty() {
            // No distributed verification needed
            return Ok(vec![]);
        }

        // Select validators
        let validators = self.select_validators(chunks.len()).await?;

        // Create tasks
        let mut tasks = Vec::new();
        // 60 second deadline; `now_unix_seconds()` saturates rather
        // than panicking on a pre-epoch clock (see #69).
        let deadline = crate::utils::now_unix_seconds() + 60;

        for (chunk, validator) in chunks.into_iter().zip(validators) {
            let task_id = uuid::Uuid::new_v4().to_string();
            let task = VerificationTask {
                task_id: task_id.clone(),
                transaction_id: tx_id.clone(),
                chunk,
                validator,
                deadline,
            };

            tasks.push(task.clone());

            // Store task
            let mut task_map = self.tasks.write().await;
            task_map.insert(task_id, task);
        }

        // Create aggregator stamped with this coordinator's
        // configured BFT thresholds so per-transaction quorum logic
        // matches the operator's intent.
        let aggregator = VerificationAggregator::new_with_thresholds(
            tx_id.clone(),
            tasks.len(),
            self.min_validators_for_consensus,
            self.total_validators,
        );
        let mut aggregators = self.aggregators.write().await;
        aggregators.insert(tx_id, aggregator);

        Ok(tasks)
    }

    /// Submit a verification result
    pub async fn submit_result(&self, result: VerificationTaskResult) -> Result<()> {
        // Find the task
        let tasks = self.tasks.read().await;
        let task = tasks
            .get(&result.task_id)
            .ok_or_else(|| anyhow!("Task not found: {}", result.task_id))?;

        let tx_id = task.transaction_id.clone();
        drop(tasks);

        // Submit to aggregator
        let aggregators = self.aggregators.read().await;
        let aggregator = aggregators
            .get(&tx_id)
            .ok_or_else(|| anyhow!("Aggregator not found for tx: {}", tx_id))?;

        aggregator.submit_result(result).await?;

        Ok(())
    }

    /// Check if transaction has reached consensus
    pub async fn check_consensus(
        &self,
        transaction_id: &str,
    ) -> Result<Option<VerificationResult>> {
        let aggregators = self.aggregators.read().await;
        let aggregator = aggregators
            .get(transaction_id)
            .ok_or_else(|| anyhow!("Transaction not found: {}", transaction_id))?;

        if aggregator.has_consensus().await {
            Ok(Some(aggregator.consensus().await?))
        } else {
            Ok(None)
        }
    }

    /// Get verification status
    pub async fn get_status(&self, transaction_id: &str) -> Result<f64> {
        let aggregators = self.aggregators.read().await;
        let aggregator = aggregators
            .get(transaction_id)
            .ok_or_else(|| anyhow!("Transaction not found: {}", transaction_id))?;

        Ok(aggregator.completion_percentage().await)
    }

    /// Select validators for verification (round-robin for now)
    async fn select_validators(&self, count: usize) -> Result<Vec<NodeId>> {
        let validators = self.validators.read().await;

        if validators.is_empty() {
            return Err(anyhow!("No validators available"));
        }

        // Simple selection: take first N validators (cycling if needed)
        let mut selected = Vec::new();
        for i in 0..count {
            let idx = i % validators.len();
            selected.push(validators[idx].clone());
        }

        Ok(selected)
    }

    /// Clean up completed verification tasks
    pub async fn cleanup(&self, transaction_id: &str) -> Result<()> {
        let mut aggregators = self.aggregators.write().await;
        aggregators.remove(transaction_id);

        // Clean up tasks
        let mut tasks = self.tasks.write().await;
        tasks.retain(|_, task| task.transaction_id != transaction_id);

        Ok(())
    }
}

impl Default for VerificationCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::transaction::TransferTx;
    use crate::privacy::types::{Note, Nullifier, ShieldedAddress};

    #[tokio::test]
    async fn test_aggregator_consensus() {
        let aggregator = VerificationAggregator::new("tx123".to_string(), 3);

        // Not enough votes yet
        assert!(!aggregator.has_consensus().await);

        // Add 7 valid votes
        for i in 0..7 {
            let result = VerificationTaskResult {
                task_id: format!("task{}", i),
                validator: NodeId(vec![i as u8]),
                result: VerificationResult::Valid,
                timestamp: 0,
            };
            aggregator.submit_result(result).await.unwrap();
        }

        // Should have consensus now
        assert!(aggregator.has_consensus().await);

        // Consensus should be valid
        let consensus = aggregator.consensus().await.unwrap();
        assert!(consensus.is_valid());
    }

    #[tokio::test]
    async fn test_aggregator_reject() {
        let aggregator = VerificationAggregator::new("tx123".to_string(), 3);

        // Add 7 invalid votes
        for i in 0..7 {
            let result = VerificationTaskResult {
                task_id: format!("task{}", i),
                validator: NodeId(vec![i as u8]),
                result: VerificationResult::Invalid {
                    reason: "Test".to_string(),
                },
                timestamp: 0,
            };
            aggregator.submit_result(result).await.unwrap();
        }

        // Consensus should be invalid
        let consensus = aggregator.consensus().await.unwrap();
        assert!(!consensus.is_valid());
    }

    #[tokio::test]
    async fn test_coordinator_register_validators() {
        let coordinator = VerificationCoordinator::new();

        coordinator.register_validator(NodeId(vec![1])).await;
        coordinator.register_validator(NodeId(vec![2])).await;

        let validators = coordinator.validators.read().await;
        assert_eq!(validators.len(), 2);
    }

    #[tokio::test]
    async fn test_coordinator_create_tasks() {
        let coordinator = VerificationCoordinator::new();

        // Register validators
        for i in 0..10 {
            coordinator.register_validator(NodeId(vec![i])).await;
        }

        // Create transfer transaction
        let tx = ShieldedTransaction::Transfer(TransferTx::new(
            vec![Nullifier([1u8; 32])],
            vec![Note::new(ShieldedAddress([1u8; 32]), 100, [1u8; 32])],
            [0u8; 32],
            10,
        ));

        let tasks = coordinator.create_verification_tasks(&tx).await.unwrap();

        // Should have created tasks
        assert!(!tasks.is_empty());
    }

    #[tokio::test]
    async fn test_completion_percentage() {
        let aggregator = VerificationAggregator::new("tx123".to_string(), 3);

        assert_eq!(aggregator.completion_percentage().await, 0.0);

        // Add 3 results
        for i in 0..3 {
            let result = VerificationTaskResult {
                task_id: format!("task{}", i),
                validator: NodeId(vec![i as u8]),
                result: VerificationResult::Valid,
                timestamp: 0,
            };
            aggregator.submit_result(result).await.unwrap();
        }

        // 3/10 = 30%
        assert_eq!(aggregator.completion_percentage().await, 30.0);
    }

    /// Defaults pin 7-of-10; a regression that silently changes them
    /// would shift every downstream quorum calculation.
    #[test]
    fn test_default_consensus_thresholds() {
        let coordinator = VerificationCoordinator::new();
        assert_eq!(
            coordinator.consensus_thresholds(),
            (
                DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS,
                DEFAULT_TOTAL_VALIDATORS
            )
        );
    }

    /// A coordinator configured for 5-of-7 stamps every aggregator it
    /// creates with the new thresholds, so quorum reaches at 5 votes
    /// and completion percentage uses 7 as its divisor.
    #[tokio::test]
    async fn test_aggregator_threshold_5_of_7() {
        let aggregator =
            VerificationAggregator::new_with_thresholds("tx-5-of-7".to_string(), 1, 5, 7);

        // 4 votes — below quorum.
        for i in 0..4 {
            aggregator
                .submit_result(VerificationTaskResult {
                    task_id: format!("task{}", i),
                    validator: NodeId(vec![i as u8]),
                    result: VerificationResult::Valid,
                    timestamp: 0,
                })
                .await
                .unwrap();
        }
        assert!(!aggregator.has_consensus().await);
        assert!(aggregator.consensus().await.is_err());

        // 5th vote — quorum reaches.
        aggregator
            .submit_result(VerificationTaskResult {
                task_id: "task4".to_string(),
                validator: NodeId(vec![4]),
                result: VerificationResult::Valid,
                timestamp: 0,
            })
            .await
            .unwrap();
        assert!(aggregator.has_consensus().await);
        assert!(aggregator.consensus().await.unwrap().is_valid());

        // 5/7 ≈ 71%, never the old 50% that 5-of-10 would report.
        let pct = aggregator.completion_percentage().await;
        assert!(
            (pct - (5.0 / 7.0 * 100.0)).abs() < 0.01,
            "expected ~71.4%, got {}",
            pct
        );
    }

    /// Setter rejects invalid combinations and falls back to defaults.
    #[test]
    fn test_set_consensus_thresholds_rejects_invalid() {
        let mut coordinator = VerificationCoordinator::new();

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
