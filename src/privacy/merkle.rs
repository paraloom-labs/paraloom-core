//! Merkle tree for tracking commitments in the shielded pool
//!
//! This implements an incremental Merkle tree where each commitment is inserted
//! as a leaf. The tree root is used in ZK proofs to prove a commitment exists
//! without revealing which one.

use crate::privacy::poseidon::poseidon_merkle_pair;
use crate::privacy::types::{Commitment, MerklePath};
use crate::storage::PrivacyStorage;
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Default tree depth (supports 2^32 leaves)
pub const DEFAULT_TREE_DEPTH: usize = 32;

/// Merkle tree for commitments
pub struct MerkleTree {
    /// Tree depth
    depth: usize,
    /// Current leaves (commitments)
    leaves: Arc<RwLock<Vec<[u8; 32]>>>,
    /// Cached root
    cached_root: Arc<RwLock<Option<[u8; 32]>>>,
    /// Optional persistent storage
    storage: Option<Arc<PrivacyStorage>>,
}

impl MerkleTree {
    /// Create a new Merkle tree with default depth (in-memory only)
    pub fn new() -> Self {
        Self::with_depth(DEFAULT_TREE_DEPTH)
    }

    /// Create a new Merkle tree with specific depth (in-memory only)
    pub fn with_depth(depth: usize) -> Self {
        MerkleTree {
            depth,
            leaves: Arc::new(RwLock::new(Vec::new())),
            cached_root: Arc::new(RwLock::new(None)),
            storage: None,
        }
    }

    /// Create a Merkle tree with persistent storage
    pub async fn with_storage(storage: Arc<PrivacyStorage>) -> Result<Self, anyhow::Error> {
        // Load existing commitments from storage
        let commitments = storage.get_all_commitments()?;
        let leaves: Vec<[u8; 32]> = commitments.iter().map(|c| *c.as_bytes()).collect();

        // Load cached root if available
        let cached_root = storage.get_merkle_root()?;

        Ok(MerkleTree {
            depth: DEFAULT_TREE_DEPTH,
            leaves: Arc::new(RwLock::new(leaves)),
            cached_root: Arc::new(RwLock::new(cached_root)),
            storage: Some(storage),
        })
    }

    /// Insert a commitment as a leaf, returning the index it was placed
    /// at. When persistent storage is configured, the on-disk write is
    /// performed *before* the in-memory mutation, so a storage failure
    /// is observable and leaves the tree's in-memory state unchanged.
    /// This preserves crash-consistency: a leaf either reaches both
    /// memory and disk, or neither.
    pub async fn insert(&self, commitment: &Commitment) -> Result<usize, anyhow::Error> {
        let mut leaves = self.leaves.write().await;
        let index = leaves.len();

        if let Some(storage) = &self.storage {
            storage.insert_commitment(index as u64, commitment).map_err(|e| {
                log::error!(
                    target: "paraloom::privacy::merkle",
                    "failed to persist commitment at index {}: {} — in-memory state not advanced",
                    index, e
                );
                e
            })?;
        }

        leaves.push(*commitment.as_bytes());

        let mut cached_root = self.cached_root.write().await;
        *cached_root = None;

        Ok(index)
    }

    /// Batch insert multiple commitments. Same crash-consistency
    /// contract as [`MerkleTree::insert`]: persist first, mutate
    /// memory only if persistence succeeded.
    pub async fn insert_batch(
        &self,
        commitments: &[Commitment],
    ) -> Result<Vec<usize>, anyhow::Error> {
        let mut leaves = self.leaves.write().await;
        let start_index = leaves.len();
        let indices: Vec<usize> = (start_index..start_index + commitments.len()).collect();

        if let Some(storage) = &self.storage {
            storage
                .insert_commitments_batch(start_index as u64, commitments)
                .map_err(|e| {
                    log::error!(
                        target: "paraloom::privacy::merkle",
                        "failed to persist commitment batch starting at index {}: {} — in-memory state not advanced",
                        start_index, e
                    );
                    e
                })?;
        }

        for commitment in commitments {
            leaves.push(*commitment.as_bytes());
        }

        let mut cached_root = self.cached_root.write().await;
        *cached_root = None;

        Ok(indices)
    }

    /// Get the current root of the tree
    pub async fn root(&self) -> [u8; 32] {
        // Check cache first
        {
            let cached = self.cached_root.read().await;
            if let Some(root) = *cached {
                return root;
            }
        }

        // Compute root
        let leaves = self.leaves.read().await;
        let root = self.compute_root(&leaves);

        // Cache it
        let mut cached_root = self.cached_root.write().await;
        *cached_root = Some(root);

        // Persist root to storage if available. Unlike leaf inserts,
        // root persistence is a cache: on restart the tree rebuilds the
        // root from the stored leaves, so a missed write here costs
        // a one-time recomputation rather than data loss. We log the
        // failure loudly so an operator can investigate, but do not
        // propagate it — read paths that take a root must keep working
        // even if the disk is misbehaving.
        if let Some(storage) = &self.storage {
            if let Err(e) = storage.set_merkle_root(&root) {
                log::warn!(
                    target: "paraloom::privacy::merkle",
                    "failed to persist Merkle root cache: {} — recomputation will trigger on next restart",
                    e
                );
            }
        }

        root
    }

    /// Find the index of a commitment among the current leaves, if it is
    /// present. The stored leaf bytes are exactly `commitment.as_bytes()`
    /// (see [`MerkleTree::insert`]), so raw-byte equality identifies the
    /// leaf. A linear scan is acceptable here: path queries are
    /// infrequent relative to inserts, and this keeps the lookup correct
    /// for both in-memory and storage-restored trees without a parallel
    /// index map that could drift out of sync.
    pub async fn index_of(&self, commitment: &Commitment) -> Option<usize> {
        let target = commitment.as_bytes();
        let leaves = self.leaves.read().await;
        leaves.iter().position(|leaf| leaf == target)
    }

    /// Get the Merkle path for a leaf at given index
    pub async fn path(&self, index: usize) -> Option<MerklePath> {
        let leaves = self.leaves.read().await;

        if index >= leaves.len() {
            return None;
        }

        Some(self.compute_path(&leaves, index))
    }

    /// Get the number of leaves
    pub async fn len(&self) -> usize {
        let leaves = self.leaves.read().await;
        leaves.len()
    }

    /// Check if tree is empty
    pub async fn is_empty(&self) -> bool {
        let leaves = self.leaves.read().await;
        leaves.is_empty()
    }

    /// Verify a Merkle path
    pub async fn verify(&self, leaf: &[u8; 32], path: &MerklePath) -> bool {
        let root = self.root().await;
        path.verify(leaf, &root)
    }

    /// Compute the root from current leaves
    fn compute_root(&self, leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32]; // Empty tree root
        }

        let mut layer = leaves.to_vec();

        // Build tree bottom-up
        while layer.len() > 1 {
            let mut next_layer = Vec::new();

            for chunk in layer.chunks(2) {
                let hash = if chunk.len() == 2 {
                    Self::hash_pair(&chunk[0], &chunk[1])
                } else {
                    // Odd number of nodes - hash with itself
                    Self::hash_pair(&chunk[0], &chunk[0])
                };
                next_layer.push(hash);
            }

            layer = next_layer;
        }

        layer[0]
    }

    /// Compute the Merkle path for a leaf
    fn compute_path(&self, leaves: &[[u8; 32]], index: usize) -> MerklePath {
        let mut path = Vec::new();
        let mut indices = Vec::new();
        let mut layer = leaves.to_vec();
        let mut current_index = index;

        while layer.len() > 1 {
            let is_right_child = current_index % 2 == 1;
            let sibling_index = if is_right_child {
                current_index - 1
            } else {
                current_index + 1
            };

            // Get sibling (or duplicate if it doesn't exist)
            let sibling = if sibling_index < layer.len() {
                layer[sibling_index]
            } else {
                layer[current_index]
            };

            path.push(sibling);
            // Push !is_right_child because we need to know if sibling is on right
            // If we're the right child (is_right_child=true), sibling is on left (false)
            // If we're the left child (is_right_child=false), sibling is on right (true)
            indices.push(!is_right_child);

            // Build next layer
            let mut next_layer = Vec::new();
            for chunk in layer.chunks(2) {
                let hash = if chunk.len() == 2 {
                    Self::hash_pair(&chunk[0], &chunk[1])
                } else {
                    Self::hash_pair(&chunk[0], &chunk[0])
                };
                next_layer.push(hash);
            }

            layer = next_layer;
            current_index /= 2;
        }

        MerklePath { path, indices }
    }

    /// Hash two child nodes into their parent using domain-separated
    /// Poseidon (`poseidon::domain::MERKLE_PAIR`).
    ///
    /// Matches the circuit-side `poseidon_merkle_pair_gadget` and the
    /// host-side `MerklePath::verify` exactly — the three paths form
    /// a single consistent hash family. Changing any of them requires
    /// changing all three together (and regenerating every proving key).
    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let l = Fr::from_le_bytes_mod_order(left);
        let r = Fr::from_le_bytes_mod_order(right);
        let digest = poseidon_merkle_pair(l, r);
        let bytes = digest.into_bigint().to_bytes_le();
        let mut out = [0u8; 32];
        let len = bytes.len().min(32);
        out[..len].copy_from_slice(&bytes[..len]);
        out
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MerkleTree {
    fn clone(&self) -> Self {
        MerkleTree {
            depth: self.depth,
            leaves: Arc::clone(&self.leaves),
            cached_root: Arc::clone(&self.cached_root),
            storage: self.storage.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_merkle_tree_insert() {
        let tree = MerkleTree::new();
        let commitment = Commitment([1u8; 32]);

        let index = tree.insert(&commitment).await.expect("in-memory insert");
        assert_eq!(index, 0);
        assert_eq!(tree.len().await, 1);

        let commitment2 = Commitment([2u8; 32]);
        let index2 = tree.insert(&commitment2).await.expect("in-memory insert");
        assert_eq!(index2, 1);
        assert_eq!(tree.len().await, 2);
    }

    #[tokio::test]
    async fn test_merkle_tree_root() {
        let tree = MerkleTree::new();

        // Empty tree
        let root1 = tree.root().await;
        assert_eq!(root1, [0u8; 32]);

        // Add commitment
        tree.insert(&Commitment([1u8; 32]))
            .await
            .expect("in-memory insert");
        let root2 = tree.root().await;
        assert_ne!(root2, [0u8; 32]);

        // Add another commitment - root should change
        tree.insert(&Commitment([2u8; 32]))
            .await
            .expect("in-memory insert");
        let root3 = tree.root().await;
        assert_ne!(root3, root2);
    }

    #[tokio::test]
    async fn test_merkle_tree_path_and_verify() {
        let tree = MerkleTree::new();

        let commitment1 = Commitment([1u8; 32]);
        let commitment2 = Commitment([2u8; 32]);
        let commitment3 = Commitment([3u8; 32]);

        tree.insert(&commitment1).await.expect("in-memory insert");
        tree.insert(&commitment2).await.expect("in-memory insert");
        tree.insert(&commitment3).await.expect("in-memory insert");

        // Get path for first commitment
        let path = tree.path(0).await.unwrap();

        // Should verify
        assert!(tree.verify(commitment1.as_bytes(), &path).await);

        // Wrong commitment should not verify
        assert!(!tree.verify(commitment2.as_bytes(), &path).await);
    }

    #[tokio::test]
    async fn test_merkle_tree_batch_insert() {
        let tree = MerkleTree::new();

        let commitments = vec![
            Commitment([1u8; 32]),
            Commitment([2u8; 32]),
            Commitment([3u8; 32]),
        ];

        let indices = tree
            .insert_batch(&commitments)
            .await
            .expect("in-memory batch insert");
        assert_eq!(indices, vec![0, 1, 2]);
        assert_eq!(tree.len().await, 3);
    }

    #[tokio::test]
    async fn test_merkle_tree_deterministic_root() {
        let tree1 = MerkleTree::new();
        let tree2 = MerkleTree::new();

        let commitments = vec![
            Commitment([1u8; 32]),
            Commitment([2u8; 32]),
            Commitment([3u8; 32]),
        ];

        // Insert same commitments in both trees
        for commitment in &commitments {
            tree1.insert(commitment).await.expect("in-memory insert");
            tree2.insert(commitment).await.expect("in-memory insert");
        }

        // Roots should be identical
        assert_eq!(tree1.root().await, tree2.root().await);
    }

    #[tokio::test]
    async fn test_merkle_tree_caching() {
        let tree = MerkleTree::new();

        tree.insert(&Commitment([1u8; 32]))
            .await
            .expect("in-memory insert");
        tree.insert(&Commitment([2u8; 32]))
            .await
            .expect("in-memory insert");

        // First root call computes
        let root1 = tree.root().await;

        // Second root call uses cache (should be same)
        let root2 = tree.root().await;
        assert_eq!(root1, root2);

        // Insert invalidates cache
        tree.insert(&Commitment([3u8; 32]))
            .await
            .expect("in-memory insert");
        let root3 = tree.root().await;
        assert_ne!(root3, root1);
    }

    #[tokio::test]
    async fn test_merkle_path_nonexistent() {
        let tree = MerkleTree::new();

        tree.insert(&Commitment([1u8; 32]))
            .await
            .expect("in-memory insert");

        // Path for nonexistent leaf
        let path = tree.path(10).await;
        assert!(path.is_none());
    }
}
