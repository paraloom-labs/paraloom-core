//! Leader selection for consensus coordination
//!
//! Implements weighted random leader selection based on:
//! - Validator stake amount
//! - Validator reputation score
//! - Deterministic randomness (all validators agree on the same leader)

use crate::types::NodeId;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Validator information for leader selection
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ValidatorInfo {
    /// Validator node ID
    pub node_id: NodeId,

    /// Stake amount (in lamports)
    pub stake_amount: u64,

    /// Reputation score (0-10000, higher is better)
    pub reputation: u64,

    /// Is validator currently active
    pub is_active: bool,
}

impl ValidatorInfo {
    /// Create new validator info
    pub fn new(node_id: NodeId, stake_amount: u64, reputation: u64) -> Self {
        Self {
            node_id,
            stake_amount,
            reputation,
            is_active: true,
        }
    }

    /// Calculate weight for leader selection
    /// Weight = stake_amount * (reputation / 1000)
    /// This gives more weight to validators with both high stake and high reputation
    pub fn selection_weight(&self) -> u128 {
        if !self.is_active {
            return 0;
        }

        // Convert to u128 to prevent overflow
        let stake = self.stake_amount as u128;
        let reputation = self.reputation as u128;

        // Weight formula: stake * (reputation / 1000)
        // Reputation range: 0-10000 (base 1000, max 10x multiplier)
        // Example:
        // - 10 SOL stake + 1000 reputation = 10 * 1.0 = 10 weight
        // - 10 SOL stake + 5000 reputation = 10 * 5.0 = 50 weight
        // - 100 SOL stake + 1000 reputation = 100 * 1.0 = 100 weight
        stake * reputation / 1000
    }
}

/// Leader selection algorithm
pub struct LeaderSelector {
    /// Registered validators
    validators: HashMap<NodeId, ValidatorInfo>,
}

impl LeaderSelector {
    /// Create new leader selector
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
        }
    }

    /// Register a validator
    pub fn register_validator(&mut self, validator: ValidatorInfo) {
        log::info!(
            "Registering validator for leader selection: {:?} (stake: {}, reputation: {})",
            validator.node_id,
            validator.stake_amount,
            validator.reputation
        );
        self.validators.insert(validator.node_id.clone(), validator);
    }

    /// Unregister a validator
    pub fn unregister_validator(&mut self, node_id: &NodeId) {
        self.validators.remove(node_id);
        log::info!(
            "Unregistered validator from leader selection: {:?}",
            node_id
        );
    }

    /// Update validator info
    pub fn update_validator(&mut self, validator: ValidatorInfo) {
        self.validators.insert(validator.node_id.clone(), validator);
    }

    /// Get number of active validators
    pub fn active_validator_count(&self) -> usize {
        self.validators.values().filter(|v| v.is_active).count()
    }

    /// Select leader using weighted random selection
    ///
    /// Uses deterministic randomness based on seed, so all validators
    /// will select the same leader given the same seed.
    ///
    /// # Arguments
    /// * `seed` - Deterministic seed (e.g., request_id hash)
    ///
    /// # Returns
    /// Selected leader's NodeId
    pub fn select_leader(&self, seed: &[u8]) -> Result<NodeId> {
        let active_validators: Vec<_> = self.validators.values().filter(|v| v.is_active).collect();

        if active_validators.is_empty() {
            return Err(anyhow!("No active validators available"));
        }

        // Calculate total weight
        let total_weight: u128 = active_validators.iter().map(|v| v.selection_weight()).sum();

        if total_weight == 0 {
            return Err(anyhow!("All validators have zero weight"));
        }

        // Generate deterministic random number from seed
        let random_value = Self::deterministic_random(seed, total_weight);

        // Select validator based on weighted random
        let mut cumulative_weight = 0u128;
        for validator in active_validators {
            cumulative_weight += validator.selection_weight();
            if random_value < cumulative_weight {
                log::debug!(
                    "Selected leader: {:?} (weight: {}/{})",
                    validator.node_id,
                    validator.selection_weight(),
                    total_weight
                );
                return Ok(validator.node_id.clone());
            }
        }

        // Fallback to last validator (should never happen due to cumulative math)
        Ok(self
            .validators
            .values()
            .filter(|v| v.is_active)
            .last()
            .ok_or_else(|| anyhow!("No active validators"))?
            .node_id
            .clone())
    }

    /// Generate deterministic random number in range [0, max)
    ///
    /// Uses SHA-256 hash of seed to generate deterministic randomness
    fn deterministic_random(seed: &[u8], max: u128) -> u128 {
        use sha2::{Digest, Sha256};

        // Hash the seed
        let mut hasher = Sha256::new();
        hasher.update(seed);
        let hash = hasher.finalize();

        // Convert first 16 bytes of hash to u128
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[0..16]);
        let random_full = u128::from_le_bytes(bytes);

        // Map to range [0, max)
        random_full % max
    }

    /// Get validator info
    pub fn get_validator(&self, node_id: &NodeId) -> Option<&ValidatorInfo> {
        self.validators.get(node_id)
    }

    /// Get all active validators sorted by weight (descending)
    pub fn get_validators_by_weight(&self) -> Vec<ValidatorInfo> {
        let mut validators: Vec<_> = self
            .validators
            .values()
            .filter(|v| v.is_active)
            .cloned()
            .collect();

        validators.sort_by_key(|b| std::cmp::Reverse(b.selection_weight()));
        validators
    }

    /// Calculate probability of being selected as leader (0.0 - 1.0)
    pub fn leader_probability(&self, node_id: &NodeId) -> f64 {
        let validator = match self.validators.get(node_id) {
            Some(v) if v.is_active => v,
            _ => return 0.0,
        };

        let total_weight: u128 = self
            .validators
            .values()
            .filter(|v| v.is_active)
            .map(|v| v.selection_weight())
            .sum();

        if total_weight == 0 {
            return 0.0;
        }

        let validator_weight = validator.selection_weight();
        (validator_weight as f64) / (total_weight as f64)
    }
}

impl Default for LeaderSelector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_weight_calculation() {
        // Base case: 10 SOL with 1000 reputation = 10 * 1.0 = 10
        let v1 = ValidatorInfo::new(NodeId(vec![1]), 10_000_000_000, 1000);
        assert_eq!(v1.selection_weight(), 10_000_000_000);

        // High reputation: 10 SOL with 5000 reputation = 10 * 5.0 = 50
        let v2 = ValidatorInfo::new(NodeId(vec![2]), 10_000_000_000, 5000);
        assert_eq!(v2.selection_weight(), 50_000_000_000);

        // High stake: 100 SOL with 1000 reputation = 100 * 1.0 = 100
        let v3 = ValidatorInfo::new(NodeId(vec![3]), 100_000_000_000, 1000);
        assert_eq!(v3.selection_weight(), 100_000_000_000);

        // Both high: 100 SOL with 5000 reputation = 100 * 5.0 = 500
        let v4 = ValidatorInfo::new(NodeId(vec![4]), 100_000_000_000, 5000);
        assert_eq!(v4.selection_weight(), 500_000_000_000);

        // Inactive validator has zero weight
        let mut v5 = ValidatorInfo::new(NodeId(vec![5]), 100_000_000_000, 5000);
        v5.is_active = false;
        assert_eq!(v5.selection_weight(), 0);
    }

    #[test]
    fn test_leader_selection_deterministic() {
        let mut selector = LeaderSelector::new();

        // Register 3 validators with different weights
        selector.register_validator(ValidatorInfo::new(NodeId(vec![1]), 10_000_000_000, 1000));
        selector.register_validator(ValidatorInfo::new(NodeId(vec![2]), 20_000_000_000, 1000));
        selector.register_validator(ValidatorInfo::new(NodeId(vec![3]), 30_000_000_000, 1000));

        // Same seed should always produce same leader
        let seed = b"test_request_123";
        let leader1 = selector.select_leader(seed).unwrap();
        let leader2 = selector.select_leader(seed).unwrap();
        let leader3 = selector.select_leader(seed).unwrap();

        assert_eq!(leader1, leader2);
        assert_eq!(leader2, leader3);
    }

    #[test]
    fn test_leader_selection_distribution() {
        let mut selector = LeaderSelector::new();

        // Register 3 validators with different weights
        // v1: 10 SOL = weight 10
        // v2: 20 SOL = weight 20
        // v3: 30 SOL = weight 30
        // Total: 60, probabilities: 16.67%, 33.33%, 50%
        selector.register_validator(ValidatorInfo::new(NodeId(vec![1]), 10_000_000_000, 1000));
        selector.register_validator(ValidatorInfo::new(NodeId(vec![2]), 20_000_000_000, 1000));
        selector.register_validator(ValidatorInfo::new(NodeId(vec![3]), 30_000_000_000, 1000));

        // Test with multiple seeds
        let mut counts = HashMap::new();
        for i in 0..1000 {
            let seed = format!("request_{}", i);
            let leader = selector.select_leader(seed.as_bytes()).unwrap();
            *counts.entry(leader).or_insert(0) += 1;
        }

        // Validator 3 (highest weight) should be selected most often
        let v3_count = counts.get(&NodeId(vec![3])).unwrap_or(&0);
        let v2_count = counts.get(&NodeId(vec![2])).unwrap_or(&0);
        let v1_count = counts.get(&NodeId(vec![1])).unwrap_or(&0);

        assert!(*v3_count > *v2_count);
        assert!(*v2_count > *v1_count);

        // Check approximate distribution (with 20% tolerance)
        // v3 should be ~50% (400-600 out of 1000)
        assert!(*v3_count > 400 && *v3_count < 600);
    }

    #[test]
    fn test_leader_probability() {
        let mut selector = LeaderSelector::new();

        selector.register_validator(ValidatorInfo::new(NodeId(vec![1]), 10_000_000_000, 1000));
        selector.register_validator(ValidatorInfo::new(NodeId(vec![2]), 20_000_000_000, 1000));
        selector.register_validator(ValidatorInfo::new(NodeId(vec![3]), 30_000_000_000, 1000));

        // Total weight: 60
        // Probabilities: 10/60, 20/60, 30/60
        let p1 = selector.leader_probability(&NodeId(vec![1]));
        let p2 = selector.leader_probability(&NodeId(vec![2]));
        let p3 = selector.leader_probability(&NodeId(vec![3]));

        assert!((p1 - 0.1667).abs() < 0.001);
        assert!((p2 - 0.3333).abs() < 0.001);
        assert!((p3 - 0.5).abs() < 0.001);

        // Total probability should be 1.0
        assert!((p1 + p2 + p3 - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_reputation_impact() {
        let mut selector = LeaderSelector::new();

        // Same stake, different reputation
        // v1: 10 SOL, 1000 rep = weight 10
        // v2: 10 SOL, 5000 rep = weight 50
        selector.register_validator(ValidatorInfo::new(NodeId(vec![1]), 10_000_000_000, 1000));
        selector.register_validator(ValidatorInfo::new(NodeId(vec![2]), 10_000_000_000, 5000));

        // v2 should have 5x higher probability
        let p1 = selector.leader_probability(&NodeId(vec![1]));
        let p2 = selector.leader_probability(&NodeId(vec![2]));

        assert!((p2 / p1 - 5.0).abs() < 0.01);
    }

    #[test]
    fn test_active_validator_count() {
        let mut selector = LeaderSelector::new();

        selector.register_validator(ValidatorInfo::new(NodeId(vec![1]), 10_000_000_000, 1000));
        selector.register_validator(ValidatorInfo::new(NodeId(vec![2]), 20_000_000_000, 1000));

        assert_eq!(selector.active_validator_count(), 2);

        // Mark one as inactive
        let mut v3 = ValidatorInfo::new(NodeId(vec![3]), 30_000_000_000, 1000);
        v3.is_active = false;
        selector.register_validator(v3);

        assert_eq!(selector.active_validator_count(), 2);
    }

    #[test]
    fn test_get_validators_by_weight() {
        let mut selector = LeaderSelector::new();

        selector.register_validator(ValidatorInfo::new(NodeId(vec![1]), 10_000_000_000, 1000));
        selector.register_validator(ValidatorInfo::new(NodeId(vec![2]), 30_000_000_000, 1000));
        selector.register_validator(ValidatorInfo::new(NodeId(vec![3]), 20_000_000_000, 1000));

        let validators = selector.get_validators_by_weight();

        // Should be sorted by weight descending: v2, v3, v1
        assert_eq!(validators[0].node_id, NodeId(vec![2]));
        assert_eq!(validators[1].node_id, NodeId(vec![3]));
        assert_eq!(validators[2].node_id, NodeId(vec![1]));
    }

    #[test]
    fn test_no_active_validators() {
        let selector = LeaderSelector::new();
        let result = selector.select_leader(b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_unregister_validator() {
        let mut selector = LeaderSelector::new();

        selector.register_validator(ValidatorInfo::new(NodeId(vec![1]), 10_000_000_000, 1000));
        selector.register_validator(ValidatorInfo::new(NodeId(vec![2]), 20_000_000_000, 1000));

        assert_eq!(selector.active_validator_count(), 2);

        selector.unregister_validator(&NodeId(vec![1]));

        assert_eq!(selector.active_validator_count(), 1);
    }
}
