//! Reputation tracking system for validators
//!
//! Tracks validator performance and automatically adjusts reputation based on:
//! - Verification success/failure
//! - Response time
//! - Consensus alignment
//! - Activity/inactivity

use crate::types::NodeId;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Base reputation score for new validators
pub const BASE_REPUTATION: u64 = 1000;

/// Maximum reputation score
pub const MAX_REPUTATION: u64 = 10000;

/// Minimum reputation score (validators below this may be slashed)
pub const MIN_REPUTATION: u64 = 100;

/// Reputation increase per successful verification
pub const REPUTATION_INCREASE_SUCCESS: u64 = 10;

/// Reputation decrease per failed verification
pub const REPUTATION_DECREASE_FAILURE: u64 = 50;

/// Reputation decrease for timeout/no response
pub const REPUTATION_DECREASE_TIMEOUT: u64 = 30;

/// Reputation bonus for aligning with consensus
pub const REPUTATION_BONUS_CONSENSUS: u64 = 5;

/// Reputation decay per day of inactivity (in basis points: 1 = 0.01%)
pub const REPUTATION_DECAY_PER_DAY: u64 = 10; // 0.1% per day

/// Seconds in a day
const SECONDS_PER_DAY: u64 = 86400;

/// Validator performance metrics
#[derive(Clone, Debug)]
pub struct ValidatorMetrics {
    /// Node ID
    pub node_id: NodeId,

    /// Current reputation score (100-10000)
    pub reputation: u64,

    /// Total verifications participated in
    pub total_verifications: u64,

    /// Successful verifications (aligned with consensus)
    pub successful_verifications: u64,

    /// Failed verifications (disagreed with consensus)
    pub failed_verifications: u64,

    /// Timeouts (didn't respond in time)
    pub timeouts: u64,

    /// Last active timestamp (unix seconds)
    pub last_active: u64,

    /// Registration timestamp
    pub registered_at: u64,
}

impl ValidatorMetrics {
    /// Create new metrics for a validator
    pub fn new(node_id: NodeId) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            node_id,
            reputation: BASE_REPUTATION,
            total_verifications: 0,
            successful_verifications: 0,
            failed_verifications: 0,
            timeouts: 0,
            last_active: now,
            registered_at: now,
        }
    }

    /// Calculate success rate (0.0 - 1.0)
    pub fn success_rate(&self) -> f64 {
        if self.total_verifications == 0 {
            return 1.0; // New validators start with perfect rate
        }
        (self.successful_verifications as f64) / (self.total_verifications as f64)
    }

    /// Calculate days since last active
    pub fn days_inactive(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        (now.saturating_sub(self.last_active)) / SECONDS_PER_DAY
    }

    /// Apply reputation decay based on inactivity
    pub fn apply_decay(&mut self) {
        let days_inactive = self.days_inactive();
        if days_inactive == 0 {
            return;
        }

        // Decay formula: reputation * (1 - decay_rate)^days
        // decay_rate = REPUTATION_DECAY_PER_DAY / 10000 (basis points to percentage)
        let decay_rate = REPUTATION_DECAY_PER_DAY as f64 / 10000.0;
        let multiplier = (1.0 - decay_rate).powi(days_inactive as i32);

        let new_reputation = (self.reputation as f64 * multiplier) as u64;
        self.reputation = new_reputation.max(MIN_REPUTATION);

        log::debug!(
            "Applied {} days decay to {:?}: {} -> {}",
            days_inactive,
            self.node_id,
            self.reputation,
            new_reputation
        );
    }

    /// Update last active timestamp
    pub fn mark_active(&mut self) {
        self.last_active = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

/// Reputation tracker for all validators
pub struct ReputationTracker {
    /// Validator metrics (node_id -> metrics)
    metrics: Arc<RwLock<HashMap<NodeId, ValidatorMetrics>>>,
}

impl ReputationTracker {
    /// Create new reputation tracker
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new validator
    pub async fn register_validator(&self, node_id: NodeId) {
        let mut metrics = self.metrics.write().await;
        metrics.entry(node_id.clone()).or_insert_with(|| {
            let validator_metrics = ValidatorMetrics::new(node_id.clone());
            log::info!(
                "Registered validator for reputation tracking: {:?} (reputation: {})",
                node_id,
                validator_metrics.reputation
            );
            validator_metrics
        });
    }

    /// Unregister a validator
    pub async fn unregister_validator(&self, node_id: &NodeId) {
        let mut metrics = self.metrics.write().await;
        metrics.remove(node_id);
        log::info!(
            "Unregistered validator from reputation tracking: {:?}",
            node_id
        );
    }

    /// Record successful verification (aligned with consensus)
    pub async fn record_success(&self, node_id: &NodeId) -> Result<u64> {
        let mut metrics = self.metrics.write().await;
        let validator = metrics
            .get_mut(node_id)
            .ok_or_else(|| anyhow::anyhow!("Validator not found: {:?}", node_id))?;

        validator.total_verifications += 1;
        validator.successful_verifications += 1;
        validator.mark_active();

        // Increase reputation
        let old_reputation = validator.reputation;
        validator.reputation =
            (validator.reputation + REPUTATION_INCREASE_SUCCESS + REPUTATION_BONUS_CONSENSUS)
                .min(MAX_REPUTATION);

        log::info!(
            "Success recorded for {:?}: reputation {} -> {} (success rate: {:.2}%)",
            node_id,
            old_reputation,
            validator.reputation,
            validator.success_rate() * 100.0
        );

        Ok(validator.reputation)
    }

    /// Record failed verification (disagreed with consensus)
    pub async fn record_failure(&self, node_id: &NodeId) -> Result<u64> {
        let mut metrics = self.metrics.write().await;
        let validator = metrics
            .get_mut(node_id)
            .ok_or_else(|| anyhow::anyhow!("Validator not found: {:?}", node_id))?;

        validator.total_verifications += 1;
        validator.failed_verifications += 1;
        validator.mark_active();

        // Decrease reputation
        let old_reputation = validator.reputation;
        validator.reputation = validator
            .reputation
            .saturating_sub(REPUTATION_DECREASE_FAILURE)
            .max(MIN_REPUTATION);

        log::warn!(
            "Failure recorded for {:?}: reputation {} -> {} (success rate: {:.2}%)",
            node_id,
            old_reputation,
            validator.reputation,
            validator.success_rate() * 100.0
        );

        Ok(validator.reputation)
    }

    /// Record timeout (validator didn't respond)
    pub async fn record_timeout(&self, node_id: &NodeId) -> Result<u64> {
        let mut metrics = self.metrics.write().await;
        let validator = metrics
            .get_mut(node_id)
            .ok_or_else(|| anyhow::anyhow!("Validator not found: {:?}", node_id))?;

        validator.total_verifications += 1;
        validator.timeouts += 1;

        // Decrease reputation (less penalty than failure)
        let old_reputation = validator.reputation;
        validator.reputation = validator
            .reputation
            .saturating_sub(REPUTATION_DECREASE_TIMEOUT)
            .max(MIN_REPUTATION);

        log::warn!(
            "Timeout recorded for {:?}: reputation {} -> {}",
            node_id,
            old_reputation,
            validator.reputation
        );

        Ok(validator.reputation)
    }

    /// Apply decay to all validators based on inactivity
    pub async fn apply_decay_all(&self) -> usize {
        let mut metrics = self.metrics.write().await;
        let mut count = 0;

        for validator in metrics.values_mut() {
            let old_reputation = validator.reputation;
            validator.apply_decay();

            if validator.reputation != old_reputation {
                count += 1;
            }
        }

        log::debug!("Applied decay to {} validators", count);
        count
    }

    /// Get validator metrics
    pub async fn get_metrics(&self, node_id: &NodeId) -> Option<ValidatorMetrics> {
        let metrics = self.metrics.read().await;
        metrics.get(node_id).cloned()
    }

    /// Get current reputation for a validator
    pub async fn get_reputation(&self, node_id: &NodeId) -> Option<u64> {
        let metrics = self.metrics.read().await;
        metrics.get(node_id).map(|m| m.reputation)
    }

    /// Get all validators sorted by reputation (descending)
    pub async fn get_top_validators(&self, limit: usize) -> Vec<ValidatorMetrics> {
        let metrics = self.metrics.read().await;
        let mut validators: Vec<_> = metrics.values().cloned().collect();

        validators.sort_by(|a, b| b.reputation.cmp(&a.reputation));
        validators.truncate(limit);
        validators
    }

    /// Get validators below minimum reputation (candidates for slashing)
    pub async fn get_low_reputation_validators(&self) -> Vec<ValidatorMetrics> {
        let metrics = self.metrics.read().await;
        metrics
            .values()
            .filter(|m| m.reputation <= MIN_REPUTATION)
            .cloned()
            .collect()
    }

    /// Get total validator count
    pub async fn validator_count(&self) -> usize {
        let metrics = self.metrics.read().await;
        metrics.len()
    }
}

impl Default for ReputationTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_metrics_creation() {
        let node_id = NodeId(vec![1]);
        let metrics = ValidatorMetrics::new(node_id.clone());

        assert_eq!(metrics.node_id, node_id);
        assert_eq!(metrics.reputation, BASE_REPUTATION);
        assert_eq!(metrics.total_verifications, 0);
        assert_eq!(metrics.success_rate(), 1.0);
    }

    #[test]
    fn test_success_rate_calculation() {
        let mut metrics = ValidatorMetrics::new(NodeId(vec![1]));

        // Perfect rate with no verifications
        assert_eq!(metrics.success_rate(), 1.0);

        // 3 successes out of 5
        metrics.total_verifications = 5;
        metrics.successful_verifications = 3;
        assert!((metrics.success_rate() - 0.6).abs() < 0.001);

        // 100% success rate
        metrics.successful_verifications = 5;
        assert_eq!(metrics.success_rate(), 1.0);
    }

    #[tokio::test]
    async fn test_register_validator() {
        let tracker = ReputationTracker::new();
        let node_id = NodeId(vec![1]);

        tracker.register_validator(node_id.clone()).await;

        let reputation = tracker.get_reputation(&node_id).await;
        assert_eq!(reputation, Some(BASE_REPUTATION));
    }

    #[tokio::test]
    async fn test_record_success() {
        let tracker = ReputationTracker::new();
        let node_id = NodeId(vec![1]);

        tracker.register_validator(node_id.clone()).await;

        let new_reputation = tracker.record_success(&node_id).await.unwrap();
        assert_eq!(
            new_reputation,
            BASE_REPUTATION + REPUTATION_INCREASE_SUCCESS + REPUTATION_BONUS_CONSENSUS
        );

        let metrics = tracker.get_metrics(&node_id).await.unwrap();
        assert_eq!(metrics.total_verifications, 1);
        assert_eq!(metrics.successful_verifications, 1);
        assert_eq!(metrics.success_rate(), 1.0);
    }

    #[tokio::test]
    async fn test_record_failure() {
        let tracker = ReputationTracker::new();
        let node_id = NodeId(vec![1]);

        tracker.register_validator(node_id.clone()).await;

        let new_reputation = tracker.record_failure(&node_id).await.unwrap();
        assert_eq!(
            new_reputation,
            BASE_REPUTATION.saturating_sub(REPUTATION_DECREASE_FAILURE)
        );

        let metrics = tracker.get_metrics(&node_id).await.unwrap();
        assert_eq!(metrics.total_verifications, 1);
        assert_eq!(metrics.failed_verifications, 1);
        assert_eq!(metrics.success_rate(), 0.0);
    }

    #[tokio::test]
    async fn test_record_timeout() {
        let tracker = ReputationTracker::new();
        let node_id = NodeId(vec![1]);

        tracker.register_validator(node_id.clone()).await;

        let new_reputation = tracker.record_timeout(&node_id).await.unwrap();
        assert_eq!(
            new_reputation,
            BASE_REPUTATION.saturating_sub(REPUTATION_DECREASE_TIMEOUT)
        );

        let metrics = tracker.get_metrics(&node_id).await.unwrap();
        assert_eq!(metrics.timeouts, 1);
    }

    #[tokio::test]
    async fn test_reputation_bounds() {
        let tracker = ReputationTracker::new();
        let node_id = NodeId(vec![1]);

        tracker.register_validator(node_id.clone()).await;

        // Test maximum bound
        for _ in 0..1000 {
            tracker.record_success(&node_id).await.unwrap();
        }

        let reputation = tracker.get_reputation(&node_id).await.unwrap();
        assert_eq!(reputation, MAX_REPUTATION);

        // Test minimum bound
        for _ in 0..1000 {
            tracker.record_failure(&node_id).await.unwrap();
        }

        let reputation = tracker.get_reputation(&node_id).await.unwrap();
        assert_eq!(reputation, MIN_REPUTATION);
    }

    #[tokio::test]
    async fn test_get_top_validators() {
        let tracker = ReputationTracker::new();

        // Register 5 validators with different reputations
        for i in 1..=5 {
            let node_id = NodeId(vec![i]);
            tracker.register_validator(node_id.clone()).await;

            // Give different reputation levels
            for _ in 0..i {
                tracker.record_success(&node_id).await.unwrap();
            }
        }

        let top_3 = tracker.get_top_validators(3).await;
        assert_eq!(top_3.len(), 3);

        // Should be sorted by reputation (descending)
        assert!(top_3[0].reputation >= top_3[1].reputation);
        assert!(top_3[1].reputation >= top_3[2].reputation);
    }

    #[tokio::test]
    async fn test_get_low_reputation_validators() {
        let tracker = ReputationTracker::new();

        // Register validator and lower reputation below minimum
        let node_id = NodeId(vec![1]);
        tracker.register_validator(node_id.clone()).await;

        // Cause many failures to drop below MIN_REPUTATION
        for _ in 0..100 {
            tracker.record_failure(&node_id).await.unwrap();
        }

        let low_rep = tracker.get_low_reputation_validators().await;
        assert_eq!(low_rep.len(), 1);
        assert!(low_rep[0].reputation <= MIN_REPUTATION);
    }

    #[tokio::test]
    async fn test_unregister_validator() {
        let tracker = ReputationTracker::new();
        let node_id = NodeId(vec![1]);

        tracker.register_validator(node_id.clone()).await;
        assert_eq!(tracker.validator_count().await, 1);

        tracker.unregister_validator(&node_id).await;
        assert_eq!(tracker.validator_count().await, 0);
    }

    #[test]
    fn test_reputation_decay() {
        let mut metrics = ValidatorMetrics::new(NodeId(vec![1]));

        // Set last active to 10 days ago
        metrics.last_active = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - (10 * SECONDS_PER_DAY);

        let old_reputation = metrics.reputation;
        metrics.apply_decay();

        // Reputation should have decayed
        assert!(metrics.reputation < old_reputation);
        assert!(metrics.reputation >= MIN_REPUTATION);
    }
}
