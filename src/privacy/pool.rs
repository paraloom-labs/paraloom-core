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

    /// Apply a quorum-approved transfer to the local pool from its public
    /// parts only (#194).
    ///
    /// Unlike [`transfer`](Self::transfer), the settling node does not hold the
    /// private output notes — only their commitments — so it marks the input
    /// nullifiers spent and appends the raw output commitments to the tree
    /// without storing any note. Recipients learn and store their own output
    /// notes out of band (viewing-key discovery, #196). Nullifier insertion is
    /// persistence-first, matching [`transfer`](Self::transfer)/[`withdraw`](Self::withdraw):
    /// a storage failure aborts before any in-memory mutation.
    pub async fn apply_transfer(
        &self,
        input_nullifiers: Vec<Nullifier>,
        output_commitments: Vec<Commitment>,
    ) -> Result<()> {
        if !self.nullifier_set.check_batch(&input_nullifiers).await {
            return Err(anyhow!("Double-spend detected: nullifier already used"));
        }
        self.nullifier_set.insert_batch(input_nullifiers).await?;

        for commitment in output_commitments {
            self.commitment_tree.insert(&commitment).await?;
        }

        Ok(())
    }

    /// Withdraw native SOL from the shielded pool.
    ///
    /// Convenience wrapper over [`withdraw_asset`](Self::withdraw_asset) with
    /// [`NATIVE_SOL_ASSET`], preserving the pre-multi-asset signature.
    pub async fn withdraw(
        &self,
        nullifier: Nullifier,
        amount: u64,
        recipient: &[u8], // Public address receiving withdrawal
    ) -> Result<()> {
        self.withdraw_asset(nullifier, amount, recipient, NATIVE_SOL_ASSET)
            .await
    }

    /// Withdraw `amount` of `asset_id` from the shielded pool (#236).
    /// Burns a commitment (via nullifier) and debits the asset's supply.
    pub async fn withdraw_asset(
        &self,
        nullifier: Nullifier,
        amount: u64,
        _recipient: &[u8], // Public address receiving withdrawal
        asset_id: AssetId,
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

        // Decrease this asset's supply
        let mut supplies = self.supplies.write().await;
        let supply = supplies.entry(asset_id).or_insert(0);
        if *supply < amount {
            return Err(anyhow!("Insufficient shielded supply"));
        }
        *supply -= amount;

        // Persist the asset's supply to storage if available
        if let Some(storage) = &self.storage {
            storage.set_asset_supply(&asset_id, *supply)?;
        }

        Ok(())
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
    async fn test_shielded_pool_transfer() {
        let pool = ShieldedPool::new();

        // Create input nullifiers
        let nullifier1 = Nullifier([1u8; 32]);
        let nullifier2 = Nullifier([2u8; 32]);

        // Create output notes
        let addr1 = ShieldedAddress([10u8; 32]);
        let addr2 = ShieldedAddress([20u8; 32]);
        let note1 = Note::new_native(addr1, 500, [1u8; 32]);
        let note2 = Note::new_native(addr2, 500, [2u8; 32]);

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
        let note = Note::new_native(addr, 100, [1u8; 32]);

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
        let note = Note::new_native(addr, 1000, [1u8; 32]);
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
        let note = Note::new_native(addr, 1000, [1u8; 32]);
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
        let note1 = Note::new_native(addr.clone(), 100, [1u8; 32]);
        let note2 = Note::new_native(addr, 200, [2u8; 32]);

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

        // Withdrawing one asset leaves the other untouched.
        pool.withdraw_asset(Nullifier([4u8; 32]), 200, &[0u8; 32], usdc)
            .await
            .unwrap();
        assert_eq!(pool.supply_of(usdc).await, 300);
        assert_eq!(pool.total_supply().await, 1000);

        let all = pool.all_supplies().await;
        assert_eq!(all.len(), 2);
        assert_eq!(all[&NATIVE_SOL_ASSET], 1000);
        assert_eq!(all[&usdc], 300);
    }
}
