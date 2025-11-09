//! Nullifier set management for preventing double-spending
//!
//! A nullifier is derived when spending a note. Once a nullifier is revealed,
//! the note cannot be spent again. The nullifier set tracks all revealed nullifiers.

use crate::privacy::types::Nullifier;
use crate::storage::PrivacyStorage;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Nullifier set maintains all revealed nullifiers
pub struct NullifierSet {
    /// The set of all nullifiers that have been revealed
    nullifiers: Arc<RwLock<HashSet<Nullifier>>>,
    /// Optional persistent storage
    storage: Option<Arc<PrivacyStorage>>,
}

impl NullifierSet {
    /// Create a new empty nullifier set (in-memory only)
    pub fn new() -> Self {
        NullifierSet {
            nullifiers: Arc::new(RwLock::new(HashSet::new())),
            storage: None,
        }
    }

    /// Create a nullifier set with persistent storage
    pub async fn with_storage(storage: Arc<PrivacyStorage>) -> Result<Self, anyhow::Error> {
        // Load existing nullifiers from storage
        let nullifiers_vec = storage.get_all_nullifiers()?;
        let nullifiers_set: HashSet<Nullifier> = nullifiers_vec.into_iter().collect();

        Ok(NullifierSet {
            nullifiers: Arc::new(RwLock::new(nullifiers_set)),
            storage: Some(storage),
        })
    }

    /// Check if a nullifier has been revealed (spent)
    pub async fn contains(&self, nullifier: &Nullifier) -> bool {
        let set = self.nullifiers.read().await;
        set.contains(nullifier)
    }

    /// Add a nullifier to the set (mark as spent)
    /// Returns true if successfully added, false if already exists
    pub async fn insert(&self, nullifier: Nullifier) -> bool {
        let mut set = self.nullifiers.write().await;
        let inserted = set.insert(nullifier.clone());

        // Persist to storage if available and if newly inserted
        if inserted {
            if let Some(storage) = &self.storage {
                let _ = storage.insert_nullifier(&nullifier);
            }
        }

        inserted
    }

    /// Batch check multiple nullifiers
    /// Returns true if ALL nullifiers are new (not yet spent)
    pub async fn check_batch(&self, nullifiers: &[Nullifier]) -> bool {
        let set = self.nullifiers.read().await;
        nullifiers.iter().all(|n| !set.contains(n))
    }

    /// Batch insert multiple nullifiers
    /// Returns the count of successfully inserted (new) nullifiers
    pub async fn insert_batch(&self, nullifiers: Vec<Nullifier>) -> usize {
        let mut set = self.nullifiers.write().await;
        let mut count = 0;
        let mut new_nullifiers = Vec::new();

        for nullifier in nullifiers {
            if set.insert(nullifier.clone()) {
                count += 1;
                new_nullifiers.push(nullifier);
            }
        }

        // Persist to storage if available
        if !new_nullifiers.is_empty() {
            if let Some(storage) = &self.storage {
                let _ = storage.insert_nullifiers_batch(&new_nullifiers);
            }
        }

        count
    }

    /// Get the total count of revealed nullifiers
    pub async fn len(&self) -> usize {
        let set = self.nullifiers.read().await;
        set.len()
    }

    /// Check if the nullifier set is empty
    pub async fn is_empty(&self) -> bool {
        let set = self.nullifiers.read().await;
        set.is_empty()
    }

    /// Clear all nullifiers (dangerous - for testing only)
    #[cfg(test)]
    pub async fn clear(&self) {
        let mut set = self.nullifiers.write().await;
        set.clear();
    }
}

impl Default for NullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for NullifierSet {
    fn clone(&self) -> Self {
        NullifierSet {
            nullifiers: Arc::clone(&self.nullifiers),
            storage: self.storage.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nullifier_set_insert() {
        let set = NullifierSet::new();
        let nullifier = Nullifier([1u8; 32]);

        // First insert should succeed
        assert!(set.insert(nullifier.clone()).await);

        // Second insert should fail (already exists)
        assert!(!set.insert(nullifier.clone()).await);

        // Set should contain the nullifier
        assert!(set.contains(&nullifier).await);
    }

    #[tokio::test]
    async fn test_nullifier_set_contains() {
        let set = NullifierSet::new();
        let nullifier1 = Nullifier([1u8; 32]);
        let nullifier2 = Nullifier([2u8; 32]);

        // Initially empty
        assert!(!set.contains(&nullifier1).await);
        assert!(!set.contains(&nullifier2).await);

        // After insert
        set.insert(nullifier1.clone()).await;
        assert!(set.contains(&nullifier1).await);
        assert!(!set.contains(&nullifier2).await);
    }

    #[tokio::test]
    async fn test_nullifier_set_batch_check() {
        let set = NullifierSet::new();
        let nullifier1 = Nullifier([1u8; 32]);
        let nullifier2 = Nullifier([2u8; 32]);
        let nullifier3 = Nullifier([3u8; 32]);

        // All new - should pass
        assert!(
            set.check_batch(&[nullifier1.clone(), nullifier2.clone()])
                .await
        );

        // Insert one
        set.insert(nullifier1.clone()).await;

        // Batch with spent nullifier - should fail
        assert!(
            !set.check_batch(&[nullifier1.clone(), nullifier3.clone()])
                .await
        );

        // Batch with only new nullifiers - should pass
        assert!(
            set.check_batch(&[nullifier2.clone(), nullifier3.clone()])
                .await
        );
    }

    #[tokio::test]
    async fn test_nullifier_set_batch_insert() {
        let set = NullifierSet::new();
        let nullifiers = vec![
            Nullifier([1u8; 32]),
            Nullifier([2u8; 32]),
            Nullifier([3u8; 32]),
        ];

        // First batch insert
        let count = set.insert_batch(nullifiers.clone()).await;
        assert_eq!(count, 3);
        assert_eq!(set.len().await, 3);

        // Second batch insert (duplicates)
        let count = set.insert_batch(nullifiers).await;
        assert_eq!(count, 0); // No new inserts
        assert_eq!(set.len().await, 3);
    }

    #[tokio::test]
    async fn test_nullifier_set_len() {
        let set = NullifierSet::new();

        assert_eq!(set.len().await, 0);
        assert!(set.is_empty().await);

        set.insert(Nullifier([1u8; 32])).await;
        assert_eq!(set.len().await, 1);
        assert!(!set.is_empty().await);

        set.insert(Nullifier([2u8; 32])).await;
        assert_eq!(set.len().await, 2);
    }

    #[tokio::test]
    async fn test_nullifier_set_clear() {
        let set = NullifierSet::new();

        set.insert(Nullifier([1u8; 32])).await;
        set.insert(Nullifier([2u8; 32])).await;
        assert_eq!(set.len().await, 2);

        set.clear().await;
        assert_eq!(set.len().await, 0);
        assert!(set.is_empty().await);
    }

    #[tokio::test]
    async fn test_nullifier_set_clone() {
        let set1 = NullifierSet::new();
        let nullifier = Nullifier([42u8; 32]);

        set1.insert(nullifier.clone()).await;

        // Clone should share the same underlying data
        let set2 = set1.clone();
        assert!(set2.contains(&nullifier).await);

        // Insert in set2 should reflect in set1
        let nullifier2 = Nullifier([43u8; 32]);
        set2.insert(nullifier2.clone()).await;
        assert!(set1.contains(&nullifier2).await);
    }
}
