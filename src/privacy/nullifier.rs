EXPLANATION:
I updated `check_batch` to use a temporary `HashSet` for checking intra-batch duplicates so that batches with repeating nullifiers correctly fail validation. I also refactored `insert_batch` to deduplicate incoming nullifiers into a distinct set prior to checking storage and performing inserts, ensuring the reported count accurately reflects truly new additions.

CODE:
```rust
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

    /// Add a nullifier to the set (mark as spent).
    ///
    /// Returns `Ok(true)` if the nullifier is newly inserted, `Ok(false)`
    /// if it was already present. When persistent storage is configured,
    /// the on-disk write happens *before* the in-memory mutation; a
    /// storage failure leaves the in-memory set untouched, so a future
    /// retry sees the same "already present?" answer it would have seen
    /// otherwise. This preserves crash-consistency on the spend path —
    /// the most safety-critical write in the privacy layer.
    pub async fn insert(&self, nullifier: Nullifier) -> Result<bool, anyhow::Error> {
        let mut set = self.nullifiers.write().await;

        if set.contains(&nullifier) {
            return Ok(false);
        }

        if let Some(storage) = &self.storage {
            storage.insert_nullifier(&nullifier).map_err(|e| {
                log::error!(
                    target: "paraloom::privacy::nullifier",
                    "failed to persist nullifier {}…: {} — in-memory set not advanced",
                    hex::encode(&nullifier.as_bytes()[..8]),
                    e
                );
                e
            })?;
        }

        set.insert(nullifier);
        Ok(true)
    }

    /// Batch check multiple nullifiers
    /// Returns true if ALL nullifiers are new (not yet spent) and there are no intra-batch duplicates
    pub async fn check_batch(&self, nullifiers: &[Nullifier]) -> bool {
        let set = self.nullifiers.read().await;
        let mut seen = HashSet::with_capacity(nullifiers.len());
        nullifiers.iter().all(|n| !set.contains(n) && seen.insert(n))
    }

    /// Batch insert multiple nullifiers, returning the count of newly
    /// added entries. Same crash-consistency contract as
    /// [`NullifierSet::insert`]: persist first, mutate the in-memory
    /// set only if persistence succeeded. On storage failure no
    /// nullifier in the batch is recorded — the caller is expected to
    /// either retry the entire batch.
    pub async fn insert_batch(&