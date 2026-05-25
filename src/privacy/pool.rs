//! Shielded pool state management
//!
//! The shielded pool maintains:
//! - Merkle tree of all commitments
//! - Nullifier set to prevent double-spending
//! - Balance tracking (encrypted)

use crate::privacy::merkle::MerkleTree;
use crate::privacy::nullifier::NullifierSet;
use crate::privacy::types::{Commitment, Note, Nullifier};
use crate::storage::PrivacyStorage;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// The shielded pool state
pub struct ShieldedPool {
    /// Merkle tree tracking all commitments
    commitment_tree: MerkleTree,

    /// Nullifier set preventing double-spending
    nullifier_set: NullifierSet,

    /// Note storage (commitment -> encrypted note)
    /// In production, notes would be encrypted
    notes: Arc<RwLock<HashMap<Commitment, Note>>>,

    /// Total shielded supply (in lamports)
    total_supply: Arc<RwLock<u64>>,

    /// Optional persistent storage
    storage: Option<Arc<PrivacyStorage>>,
}

impl ShieldedPool {
    /// Create a new empty shielded pool (in-memory only)
    pub fn new() -> Self {
        ShieldedPool {
            commitment_tree: MerkleTree::new(),
            nullifier_set: NullifierSet::new(),
            notes: Arc::new(RwLock::new(HashMap::new())),
            total_supply: Arc::new(RwLock::new(0)),
            storage: None,
        }
    }

    /// Create a shielded pool with persistent storage
    pub async fn with_storage(storage: Arc<PrivacyStorage>) -> Result<Self> {
        // Load Merkle tree from storage
        let commitment_tree = MerkleTree::with_storage(storage.clone()).await?;

        // Load nullifier set from storage
        let nullifier_set = NullifierSet::with_storage(storage.clone()).await?;

        // Load total supply from storage
        let total_supply = storage.get_total_supply()?;

        Ok(ShieldedPool {
            commitment_tree,
            nullifier_set,
            notes: Arc::new(RwLock::new(HashMap::new())),
            total_supply: Arc::new(RwLock::new(total_supply)),
            storage: Some(storage),
        })
    }

    /// Deposit funds into the shielded pool
    /// Creates a new commitment and adds it to the tree
    pub async fn deposit(&self, note: Note, amount: u64) -> Result<Commitment> {
        // Create commitment
        let commitment = note.commitment();

        // Add to commitment tree (auto-persists if storage available).
        // Storage failure leaves the tree's in-memory state untouched
        // and propagates here so the deposit fails atomically.
        let _index = self.commitment_tree.insert(&commitment).await?;

        // Store note
        let mut notes = self.notes.write().await;
        notes.insert(commitment.clone(), note);

        // Update total supply
        let mut supply = self.total_supply.write().await;
        *supply += amount;

        // Persist total supply to storage if available
        if let Some(storage) = &self.storage {
            storage.set_total_supply(*supply)?;
        }

        Ok(commitment)
    }

    /// Process a shielded transfer
    /// Spends input commitments (via nullifiers) and creates output commitments
    pub async fn transfer(
        &self,
        input_nullifiers: Vec<Nullifier>,
        output_notes: Vec<Note>,
    ) -> Result<Vec<Commitment>> {
        // Verify all nullifiers are new (not double-spent)
        if !self.nullifier_set.check_batch(&input_nullifiers).await {
            return Err(anyhow!("Double-spend detected: nullifier already used"));
        }

        // Add nullifiers to prevent future double-spending. If
        // persistence fails the in-memory set is left untouched and
        // the transfer is aborted — the alternative would be a half-
        // committed state where in-memory says spent but disk does
        // not, opening a double-spend window across restarts.
        self.nullifier_set.insert_batch(input_nullifiers).await?;

        // Create output commitments
        let mut output_commitments = Vec::new();
        let mut notes_map = self.notes.write().await;

        for note in output_notes {
            let commitment = note.commitment();
            self.commitment_tree.insert(&commitment).await?;
            notes_map.insert(commitment.clone(), note);
            output_commitments.push(commitment);
        }

        Ok(output_commitments)
    }

    /// Withdraw from the shielded pool
    /// Burns a commitment (via nullifier) and releases funds
    pub async fn withdraw(
        &self,
        nullifier: Nullifier,
        amount: u64,
        _recipient: &[u8], // Public address receiving withdrawal
    ) -> Result<()> {
        // Check nullifier hasn't been used
        if self.nullifier_set.contains(&nullifier).await {
            return Err(anyhow!("Double-spend: nullifier already used"));
        }

        // Add nullifier. Persistence-first ordering means a storage
        // failure aborts the withdraw before any in-memory mutation,
        // preventing the disk-vs-memory divergence that would let a
        // restarted node accept a replay of the same withdrawal.
        self.nullifier_set.insert(nullifier).await?;

        // Decrease total supply
        let mut supply = self.total_supply.write().await;
        if *supply < amount {
            return Err(anyhow!("Insufficient shielded supply"));
        }
        *supply -= amount;

        // Persist total supply to storage if available
        if let Some(storage) = &self.storage {
            storage.set_total_supply(*supply)?;
        }

        Ok(())
    }

    /// Get the current Merkle root
    pub async fn root(&self) -> [u8; 32] {
        self.commitment_tree.root().await
    }

    /// Get the Merkle authentication path for a commitment.
    ///
    /// Resolves the commitment to its leaf index in the tree and returns
    /// the path from that leaf to the current root. A withdrawing client
    /// pairs this with [`ShieldedPool::root`] to build the public inputs
    /// for its withdrawal proof. Errors if the commitment was never
    /// inserted into this pool.
    pub async fn path(&self, commitment: &Commitment) -> Result<crate::privacy::types::MerklePath> {
        let index = self
            .commitment_tree
            .index_of(commitment)
            .await
            .ok_or_else(|| anyhow!("commitment not found in pool"))?;

        self.commitment_tree
            .path(index)
            .await
            .ok_or_else(|| anyhow!("commitment index {} out of range", index))
    }

    /// Check if a nullifier has been spent
    pub async fn is_spent(&self, nullifier: &Nullifier) -> bool {
        self.nullifier_set.contains(nullifier).await
    }

    /// Get total shielded supply
    pub async fn total_supply(&self) -> u64 {
        let supply = self.total_supply.read().await;
        *supply
    }

    /// Get number of commitments in the pool
    pub async fn commitment_count(&self) -> usize {
        self.commitment_tree.len().await
    }

    /// Get number of spent notes (nullifiers revealed)
    pub async fn spent_count(&self) -> usize {
        self.nullifier_set.len().await
    }

    /// Get a note by its commitment (if exists)
    pub async fn get_note(&self, commitment: &Commitment) -> Option<Note> {
        let notes = self.notes.read().await;
        notes.get(commitment).cloned()
    }

    /// Verify the shielded pool's internal consistency
    pub async fn verify_consistency(&self) -> Result<()> {
        // Check that nullifier count <= commitment count
        let commitments = self.commitment_count().await;
        let nullifiers = self.spent_count().await;

        if nullifiers > commitments {
            return Err(anyhow!(
                "Inconsistency: More nullifiers ({}) than commitments ({})",
                nullifiers,
                commitments
            ));
        }

        Ok(())
    }
}

impl Default for ShieldedPool {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ShieldedPool {
    fn clone(&self) -> Self {
        ShieldedPool {
            commitment_tree: self.commitment_tree.clone(),
            nullifier_set: self.nullifier_set.clone(),
            notes: Arc::clone(&self.notes),
            total_supply: Arc::clone(&self.total_supply),
            storage: self.storage.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::types::ShieldedAddress;

    #[tokio::test]
    async fn test_shielded_pool_deposit() {
        let pool = ShieldedPool::new();
        let addr = ShieldedAddress([1u8; 32]);
        let note = Note::new(addr, 1000, [42u8; 32]);

        let commitment = pool.deposit(note, 1000).await.unwrap();

        assert_eq!(pool.total_supply().await, 1000);
        assert_eq!(pool.commitment_count().await, 1);
        assert!(pool.get_note(&commitment).await.is_some());
    }

    #[tokio::test]
    async fn test_shielded_pool_transfer() {
        let pool = ShieldedPool::new();

        // Create input nullifiers
        let nullifier1 = Nullifier([1u8; 32]);
        let nullifier2 = Nullifier([2u8; 32]);

        // Create output notes
        let addr1 = ShieldedAddress([10u8; 32]);
        let addr2 = ShieldedAddress([20u8; 32]);
        let note1 = Note::new(addr1, 500, [1u8; 32]);
        let note2 = Note::new(addr2, 500, [2u8; 32]);

        // Process transfer
        let outputs = pool
            .transfer(vec![nullifier1, nullifier2], vec![note1, note2])
            .await
            .unwrap();

        assert_eq!(outputs.len(), 2);
        assert_eq!(pool.commitment_count().await, 2);
        assert_eq!(pool.spent_count().await, 2);
    }

    #[tokio::test]
    async fn test_shielded_pool_double_spend() {
        let pool = ShieldedPool::new();

        let nullifier = Nullifier([1u8; 32]);
        let addr = ShieldedAddress([1u8; 32]);
        let note = Note::new(addr, 100, [1u8; 32]);

        // First transfer succeeds
        pool.transfer(vec![nullifier.clone()], vec![note.clone()])
            .await
            .unwrap();

        // Second transfer with same nullifier should fail
        let result = pool.transfer(vec![nullifier], vec![note]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_shielded_pool_withdraw() {
        let pool = ShieldedPool::new();

        // Deposit first
        let addr = ShieldedAddress([1u8; 32]);
        let note = Note::new(addr, 1000, [1u8; 32]);
        pool.deposit(note, 1000).await.unwrap();

        // Withdraw
        let nullifier = Nullifier([100u8; 32]);
        let recipient = [5u8; 32];
        pool.withdraw(nullifier.clone(), 500, &recipient)
            .await
            .unwrap();

        assert_eq!(pool.total_supply().await, 500);
        assert!(pool.is_spent(&nullifier).await);

        // Double withdraw should fail
        let result = pool.withdraw(nullifier, 100, &recipient).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_shielded_pool_withdraw_insufficient() {
        let pool = ShieldedPool::new();

        // Deposit 1000
        let addr = ShieldedAddress([1u8; 32]);
        let note = Note::new(addr, 1000, [1u8; 32]);
        pool.deposit(note, 1000).await.unwrap();

        // Try to withdraw more than available
        let nullifier = Nullifier([1u8; 32]);
        let recipient = [5u8; 32];
        let result = pool.withdraw(nullifier, 2000, &recipient).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_shielded_pool_consistency() {
        let pool = ShieldedPool::new();

        // Add some commitments and nullifiers
        let addr = ShieldedAddress([1u8; 32]);
        let note1 = Note::new(addr.clone(), 100, [1u8; 32]);
        let note2 = Note::new(addr, 200, [2u8; 32]);

        pool.deposit(note1.clone(), 100).await.unwrap();
        pool.deposit(note2, 200).await.unwrap();

        let nullifier = Nullifier([10u8; 32]);
        pool.transfer(vec![nullifier], vec![note1]).await.unwrap();

        // Should be consistent
        pool.verify_consistency().await.unwrap();
    }

    #[tokio::test]
    async fn test_shielded_pool_root_changes() {
        let pool = ShieldedPool::new();

        let root1 = pool.root().await;

        // Add commitment - root should change
        let addr = ShieldedAddress([1u8; 32]);
        let note = Note::new(addr, 100, [1u8; 32]);
        pool.deposit(note, 100).await.unwrap();

        let root2 = pool.root().await;
        assert_ne!(root1, root2);
    }

    #[tokio::test]
    async fn path_round_trips_for_deposited_commitments() {
        let pool = ShieldedPool::new();
        let addr = ShieldedAddress([7u8; 32]);

        let note_a = Note::new(addr.clone(), 100, [1u8; 32]);
        let note_b = Note::new(addr, 200, [2u8; 32]);
        let commitment_a = pool.deposit(note_a, 100).await.unwrap();
        let commitment_b = pool.deposit(note_b, 200).await.unwrap();

        // Each path must authenticate its own leaf against the current
        // root — this is exactly what a withdrawing client checks before
        // building its proof.
        let root = pool.root().await;
        let path_a = pool.path(&commitment_a).await.unwrap();
        let path_b = pool.path(&commitment_b).await.unwrap();
        assert!(path_a.verify(commitment_a.as_bytes(), &root));
        assert!(path_b.verify(commitment_b.as_bytes(), &root));

        // A path must not authenticate a different leaf.
        assert!(!path_a.verify(commitment_b.as_bytes(), &root));
    }

    #[tokio::test]
    async fn path_errors_for_unknown_commitment() {
        let pool = ShieldedPool::new();
        let unknown = Commitment::from_bytes([9u8; 32]);
        assert!(pool.path(&unknown).await.is_err());
    }
}
