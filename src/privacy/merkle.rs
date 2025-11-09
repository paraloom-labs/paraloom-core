//! Merkle tree for tracking commitments in the shielded pool
//!
//! This implements an incremental Merkle tree where each commitment is inserted
//! as a leaf. The tree root is used in ZK proofs to prove a commitment exists
//! without revealing which one.

use crate::privacy::types::{Commitment, MerklePath};
use crate::storage::PrivacyStorage;
use sha2::{Digest, Sha256};
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

    /// Insert a commitment as a leaf
    /// Returns the index where it was inserted
    pub async fn insert(&self, commitment: &Commitment) -> usize {
        let mut leaves = self.leaves.write().await;
        let index = leaves.len();
        leaves.push(*commitment.as_bytes());

        // Persist to storage if available
        if let Some(storage) = &self.storage {
            let _ = storage.insert_commitment(index as u64, commitment);
        }

        // Invalidate cached root
        let mut cached_root = self.cached_root.write().await;
        *cached_root = None;

        index
    }

    /// Batch insert multiple commitments
    pub async fn insert_batch(&self, commitments: &[Commitment]) -> Vec<usize> {
        let mut leaves = self.leaves.write().await;
        let start_index = leaves.len();

        let indices: Vec<usize> = (start_index..start_index + commitments.len()).collect();

        for commitment in commitments {
            leaves.push(*commitment.as_bytes());
        }

        // Persist to storage if available
        if let Some(storage) = &self.storage {
            let _ = storage.insert_commitments_batch(start_index as u64, commitments);
        }

        // Invalidate cached root
        let mut cached_root = self.cached_root.write().await;
        *cached_root = None;

        indices
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

        // Persist root to storage if available
        if let Some(storage) = &self.storage {
            let _ = storage.set_merkle_root(&root);
        }

        root
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

    /// Hash two nodes together
    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        let result = hasher.finalize();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
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

        let index = tree.insert(&commitment).await;
        assert_eq!(index, 0);
        assert_eq!(tree.len().await, 1);

        let commitment2 = Commitment([2u8; 32]);
        let index2 = tree.insert(&commitment2).await;
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
        tree.insert(&Commitment([1u8; 32])).await;
        let root2 = tree.root().await;
        assert_ne!(root2, [0u8; 32]);

        // Add another commitment - root should change
        tree.insert(&Commitment([2u8; 32])).await;
        let root3 = tree.root().await;
        assert_ne!(root3, root2);
    }

    #[tokio::test]
    async fn test_merkle_tree_path_and_verify() {
        let tree = MerkleTree::new();

        let commitment1 = Commitment([1u8; 32]);
        let commitment2 = Commitment([2u8; 32]);
        let commitment3 = Commitment([3u8; 32]);

        tree.insert(&commitment1).await;
        tree.insert(&commitment2).await;
        tree.insert(&commitment3).await;

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

        let indices = tree.insert_batch(&commitments).await;
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
            tree1.insert(commitment).await;
            tree2.insert(commitment).await;
        }

        // Roots should be identical
        assert_eq!(tree1.root().await, tree2.root().await);
    }

    #[tokio::test]
    async fn test_merkle_tree_caching() {
        let tree = MerkleTree::new();

        tree.insert(&Commitment([1u8; 32])).await;
        tree.insert(&Commitment([2u8; 32])).await;

        // First root call computes
        let root1 = tree.root().await;

        // Second root call uses cache (should be same)
        let root2 = tree.root().await;
        assert_eq!(root1, root2);

        // Insert invalidates cache
        tree.insert(&Commitment([3u8; 32])).await;
        let root3 = tree.root().await;
        assert_ne!(root3, root1);
    }

    #[tokio::test]
    async fn test_merkle_path_nonexistent() {
        let tree = MerkleTree::new();

        tree.insert(&Commitment([1u8; 32])).await;

        // Path for nonexistent leaf
        let path = tree.path(10).await;
        assert!(path.is_none());
    }
}
