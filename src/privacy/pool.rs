//! Shielded pool state management
//!
//! The shielded pool maintains:
//! - Merkle tree of all commitments
//! - Nullifier set to prevent double-spending
//! - Balance tracking (encrypted)

use crate::privacy::merkle::MerkleTree;
use crate::privacy::nullifier::NullifierSet;
use crate::privacy::types::{AssetId, Commitment, Note, Nullifier, NATIVE_SOL_ASSET};
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

    /// Per-asset shielded supply (#236). Keyed by [`AssetId`]; native SOL
    /// uses [`NATIVE_SOL_ASSET`] and the smallest-unit amount (lamports),
    /// SPL tokens use their mint id and base units. An absent key means a
    /// zero supply for that asset.
    supplies: Arc<RwLock<HashMap<AssetId, u64>>>,

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
            supplies: Arc::new(RwLock::new(HashMap::new())),
            storage: None,
        }
    }

    /// Create a shielded pool with persistent storage
    pub async fn with_storage(storage: Arc<PrivacyStorage>) -> Result<Self> {
        // Load Merkle tree from storage
        let commitment_tree = MerkleTree::with_storage(storage.clone()).await?;

        // Load nullifier set from storage
        let nullifier_set = NullifierSet::with_storage(storage.clone()).await?;

        // Load per-asset supplies from storage (native SOL + any SPL assets)
        let supplies = storage.get_all_asset_supplies()?;

        Ok(ShieldedPool {
            commitment_tree,
            nullifier_set,
            notes: Arc::new(RwLock::new(HashMap::new())),
            supplies: Arc::new(RwLock::new(supplies)),
            storage: Some(storage),
        })
    }

    /// Deposit native SOL into the shielded pool.
    ///
    /// Convenience wrapper over [`deposit_asset`](Self::deposit_asset) with
    /// [`NATIVE_SOL_ASSET`], preserving the pre-multi-asset signature.
    pub async fn deposit(&self, note: Note, amount: u64) -> Result<Commitment> {
        self.deposit_asset(note, amount, NATIVE_SOL_ASSET).await
    }

    /// Deposit `amount` of `asset_id` into the shielded pool (#236).
    /// Creates a new commitment, adds it to the tree, and credits the
    /// asset's supply.
    pub async fn deposit_asset(
        &self,
        note: Note,
        amount: u64,
        asset_id: AssetId,
    ) -> Result<Commitment> {
        // Create commitment
        let commitment = note.commitment();

        // Idempotent: a deposit whose commitment is already in the pool must not
        // be inserted or credited again. The bridge listener re-fetches a
        // deposit that failed to process on a prior poll, and a restart replays
        // recent signatures against a pool reloaded from storage — without this
        // guard either path would append a duplicate leaf and double-credit the
        // asset's supply. The note carries fresh randomness per deposit, so an
        // equal commitment means the same deposit, not a distinct one.
        if self.notes.read().await.contains_key(&commitment) {
            return Ok(commitment);
        }

        // Add to commitment tree (auto-persists if storage available).
        // Storage failure leaves the tree's in-memory state untouched
        // and propagates here so the deposit fails atomically.
        let _index = self.commitment_tree.insert(&commitment).await?;

        // Store note
        let mut notes = self.notes.write().await;
        notes.insert(commitment.clone(), note);

        // Credit this asset's supply
        let mut supplies = self.supplies.write().await;
        let supply = supplies.entry(asset_id).or_insert(0);
        *supply += amount;

        // Persist the asset's supply to storage if available
        if let Some(storage) = &self.storage {
            storage.set_asset_supply(&asset_id, *supply)?;
        }

        Ok(commitment)
    }

    /// Get the current Merkle root
    pub async fn root(&self) -> [u8; 32] {
        self.commitment_tree.root().await
    }

    /// Whether `root` is the pool's current root or one it computed recently
    /// (see [`crate::privacy::merkle::MerkleTree::knows_root`]). A withdrawal /
    /// transfer verifier checks the prover's root against this so a validator
    /// whose tree has advanced past the proof's root still accepts the proof.
    pub async fn knows_root(&self, root: &[u8; 32]) -> bool {
        self.commitment_tree.knows_root(root).await
    }

    /// The root this pool would publish after a transfer appends `commitments`,
    /// without mutating the pool. A settling validator checks a proposed
    /// `new_merkle_root` against this so it cannot be advanced to an arbitrary
    /// value (see [`crate::privacy::merkle::MerkleTree::root_after`]).
    pub async fn root_after(&self, commitments: &[Commitment]) -> [u8; 32] {
        self.commitment_tree.root_after(commitments).await
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

    /// Record input nullifiers as spent once their settlement has landed on
    /// chain, so a later `check_batch` pre-filters replays of that spend before
    /// they reach consensus (#624). The on-chain nullifier PDAs remain the
    /// authoritative double-spend gate; this only keeps the off-chain filter in
    /// step. Best-effort: a set-write error must not fail a settlement that has
    /// already landed on chain.
    pub async fn record_spent(&self, nullifiers: [[u8; 32]; 2]) {
        for n in nullifiers {
            if let Err(e) = self.nullifier_set.insert(Nullifier(n)).await {
                log::warn!("failed to record spent nullifier off-chain: {e}");
            }
        }
    }

    /// Get the native-SOL shielded supply.
    ///
    /// Back-compat accessor preserved from the single-asset pool; equivalent
    /// to [`supply_of`](Self::supply_of) with [`NATIVE_SOL_ASSET`].
    pub async fn total_supply(&self) -> u64 {
        self.supply_of(NATIVE_SOL_ASSET).await
    }

    /// Get the shielded supply of a specific asset (#236). Returns 0 for an
    /// asset the pool has never held.
    pub async fn supply_of(&self, asset_id: AssetId) -> u64 {
        let supplies = self.supplies.read().await;
        supplies.get(&asset_id).copied().unwrap_or(0)
    }

    /// Snapshot every asset's shielded supply (#236). Assets with a zero
    /// balance are omitted.
    pub async fn all_supplies(&self) -> HashMap<AssetId, u64> {
        self.supplies.read().await.clone()
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
            supplies: Arc::clone(&self.supplies),
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
        let note = Note::new_native(addr, 1000, [42u8; 32]);

        let commitment = pool.deposit(note, 1000).await.unwrap();

        assert_eq!(pool.total_supply().await, 1000);
        assert_eq!(pool.commitment_count().await, 1);
        assert!(pool.get_note(&commitment).await.is_some());
    }

    #[tokio::test]
    async fn deposit_is_idempotent_for_a_repeated_commitment() {
        let pool = ShieldedPool::new();
        let addr = ShieldedAddress([7u8; 32]);
        // The same deposit (same recipient, amount and randomness → same
        // commitment) processed twice — as the bridge listener does when it
        // retries a deposit that failed on a prior poll, or replays recent
        // signatures after a restart.
        let note = Note::new_native(addr, 1000, [9u8; 32]);
        let first = pool.deposit(note.clone(), 1000).await.unwrap();
        let second = pool.deposit(note, 1000).await.unwrap();

        // Same commitment, but the second deposit is a no-op: no duplicate leaf
        // and no double-credited supply.
        assert_eq!(first, second);
        assert_eq!(pool.commitment_count().await, 1);
        assert_eq!(pool.total_supply().await, 1000);
    }

    #[tokio::test]
    async fn test_shielded_pool_consistency() {
        let pool = ShieldedPool::new();

        // Add some commitments; with no spends the nullifier count stays
        // at zero, which must still satisfy nullifiers <= commitments.
        let addr = ShieldedAddress([1u8; 32]);
        let note1 = Note::new_native(addr.clone(), 100, [1u8; 32]);
        let note2 = Note::new_native(addr, 200, [2u8; 32]);

        pool.deposit(note1, 100).await.unwrap();
        pool.deposit(note2, 200).await.unwrap();

        // Should be consistent
        pool.verify_consistency().await.unwrap();
    }

    #[tokio::test]
    async fn test_shielded_pool_root_changes() {
        let pool = ShieldedPool::new();

        let root1 = pool.root().await;

        // Add commitment - root should change
        let addr = ShieldedAddress([1u8; 32]);
        let note = Note::new_native(addr, 100, [1u8; 32]);
        pool.deposit(note, 100).await.unwrap();

        let root2 = pool.root().await;
        assert_ne!(root1, root2);
    }

    #[tokio::test]
    async fn path_round_trips_for_deposited_commitments() {
        let pool = ShieldedPool::new();
        let addr = ShieldedAddress([7u8; 32]);

        let note_a = Note::new_native(addr.clone(), 100, [1u8; 32]);
        let note_b = Note::new_native(addr, 200, [2u8; 32]);
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

    #[tokio::test]
    async fn per_asset_supply_is_tracked_independently() {
        let pool = ShieldedPool::new();
        let addr = ShieldedAddress([3u8; 32]);
        let usdc: AssetId = [9u8; 32];

        // Native SOL via the back-compat path; a second asset via the
        // asset-aware path. Their supplies must not bleed into each other.
        pool.deposit(Note::new_native(addr.clone(), 1000, [1u8; 32]), 1000)
            .await
            .unwrap();
        pool.deposit_asset(Note::new(addr, 500, [2u8; 32], usdc), 500, usdc)
            .await
            .unwrap();

        assert_eq!(pool.total_supply().await, 1000);
        assert_eq!(pool.supply_of(NATIVE_SOL_ASSET).await, 1000);
        assert_eq!(pool.supply_of(usdc).await, 500);
        assert_eq!(pool.supply_of([1u8; 32]).await, 0); // never held

        // Each asset's supply is snapshotted independently.
        let all = pool.all_supplies().await;
        assert_eq!(all.len(), 2);
        assert_eq!(all[&NATIVE_SOL_ASSET], 1000);
        assert_eq!(all[&usdc], 500);
    }

    #[tokio::test]
    async fn record_spent_marks_input_nullifiers() {
        // After a settlement lands, its input nullifiers must read as spent so a
        // later check_batch pre-filters replays (#624).
        let pool = ShieldedPool::new();
        let n0 = [1u8; 32];
        let n1 = [2u8; 32];
        assert!(!pool.is_spent(&Nullifier(n0)).await);

        pool.record_spent([n0, n1]).await;

        assert!(pool.is_spent(&Nullifier(n0)).await);
        assert!(pool.is_spent(&Nullifier(n1)).await);
    }
}
