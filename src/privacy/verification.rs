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

/// Minimum validators required for consensus (7 out of 10)
pub const MIN_VALIDATORS_FOR_CONSENSUS: usize = 7;

/// Total validators selected for verification
pub const TOTAL_VALIDATORS: usize = 10;

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
}

impl VerificationAggregator {
    /// Create a new aggregator
    pub fn new(transaction_id: String, total_chunks: usize) -> Self {
        VerificationAggregator {
            transaction_id,
            total_chunks,
            results: Arc::new(RwLock::new(Vec::new())),
            voters: Arc::new(RwLock::new(HashMap::new())),
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
        voters.len() >= MIN_VALIDATORS_FOR_CONSENSUS
    }

    /// Compute consensus result
    pub async fn consensus(&self) -> Result<VerificationResult> {
        let voters = self.voters.read().await;

        if voters.len() < MIN_VALIDATORS_FOR_CONSENSUS {
            return Err(anyhow!(
                "Not enough validators: {} < {}",
                voters.len(),
                MIN_VALIDATORS_FOR_CONSENSUS
            ));
        }

        // Count valid vs invalid votes
        let valid_count = voters.values().filter(|r| r.is_valid()).count();
        let invalid_count = voters.len() - valid_count;

        // Require majority to accept
        if valid_count >= MIN_VALIDATORS_FOR_CONSENSUS {
            Ok(VerificationResult::Valid)
        } else {
            Ok(VerificationResult::Invalid {
                reason: format!(
                    "Consensus failed: {} valid, {} invalid (need {})",
                    valid_count, invalid_count, MIN_VALIDATORS_FOR_CONSENSUS
                ),
            })
        }
    }

    /// Get completion percentage
    pub async fn completion_percentage(&self) -> f64 {
        let voters = self.voters.read().await;
        (voters.len() as f64 / TOTAL_VALIDATORS as f64) * 100.0
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
}

impl VerificationCoordinator {
    /// Create a new coordinator
    pub fn new() -> Self {
        VerificationCoordinator {
            tasks: Arc::new(RwLock::new(HashMap::new())),
            aggregators: Arc::new(RwLock::new(HashMap::new())),
            validators: Arc::new(RwLock::new(Vec::new())),
        }
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
        let deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60; // 60 second deadline

        for (chunk, validator) in chunks.into_iter().zip(validators.into_iter()) {
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

        // Create aggregator
        let aggregator = VerificationAggregator::new(tx_id.clone(), tasks.len());
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
}
