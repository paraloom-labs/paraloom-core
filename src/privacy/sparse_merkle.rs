//! Sparse Merkle Tree for efficient commitment storage
//!
//! A Sparse Merkle Tree is optimized for trees with many empty leaves.
//! Instead of storing all 2^depth leaves, we only store non-empty ones.
//!
//! Benefits over dense Merkle tree:
//! - Memory: O(n) instead of O(2^depth) where n = number of inserted leaves
//! - Speed: Faster path computation (skip empty subtrees)
//! - Privacy: Same security guarantees as dense tree
//!
//! Used by: ZCash, Tornado Cash, Aztec, and other privacy protocols

use crate::privacy::poseidon::poseidon_hash_pair;
use crate::privacy::types::{Commitment, MerklePath};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Default depth for sparse Merkle tree (2^32 leaves capacity)
pub const SPARSE_TREE_DEPTH: usize = 32;

/// Default hash for empty nodes (hash of "PARALOOM_EMPTY_NODE")
pub const EMPTY_NODE_HASH: [u8; 32] = [
    0x7e, 0x87, 0x24, 0x3f, 0x92, 0x1a, 0xc5, 0x68, 0xd1, 0x42, 0x9e, 0xf3, 0xba, 0x76, 0x5c, 0x18,
    0x3d, 0xa4, 0x91, 0x6f, 0xe2, 0x55, 0xc8, 0x7b, 0x2e, 0x61, 0xd9, 0x4c, 0xaf, 0x72, 0x35, 0x98,
];

/// Sparse Merkle Tree
///
/// Only stores non-empty nodes in a HashMap.
/// Empty subtrees are represented by EMPTY_NODE_HASH.
pub struct SparseMerkleTree {
    /// Tree depth
    depth: usize,

    /// Sparse storage: index -> hash
    /// Only stores non-empty leaves and intermediate nodes
    nodes: Arc<RwLock<HashMap<u64, [u8; 32]>>>,

    /// Next available leaf index
    next_index: Arc<RwLock<u64>>,

    /// Cached root hash
    cached_root: Arc<RwLock<Option<[u8; 32]>>>,

    /// Pre-computed empty hashes for each level
    /// empty_hashes[i] = hash of empty subtree at level i
    empty_hashes: Vec<[u8; 32]>,
}

impl SparseMerkleTree {
    /// Create a new sparse Merkle tree
    pub fn new() -> Self {
        Self::with_depth(SPARSE_TREE_DEPTH)
    }

    /// Create a sparse Merkle tree with specific depth
    pub fn with_depth(depth: usize) -> Self {
        // Pre-compute empty hashes for each level
        let empty_hashes = Self::compute_empty_hashes(depth);

        SparseMerkleTree {
            depth,
            nodes: Arc::new(RwLock::new(HashMap::new())),
            next_index: Arc::new(RwLock::new(0)),
            cached_root: Arc::new(RwLock::new(None)),
            empty_hashes,
        }
    }

    /// Pre-compute hash of empty subtree at each level
    ///
    /// Level 0 (leaves): EMPTY_NODE_HASH
    /// Level i: Hash(empty[i-1] || empty[i-1])
    fn compute_empty_hashes(depth: usize) -> Vec<[u8; 32]> {
        let mut hashes = Vec::with_capacity(depth + 1);
        hashes.push(EMPTY_NODE_HASH);

        for _ in 1..=depth {
            let prev = hashes.last().unwrap();
            let hash = poseidon_hash_pair(prev, prev);
            hashes.push(hash);
        }

        hashes
    }

    /// Insert a commitment and return its index
    pub async fn insert(&self, commitment: &Commitment) -> u64 {
        let mut next_index = self.next_index.write().await;
        let index = *next_index;
        *next_index += 1;

        // Insert the leaf
        let mut nodes = self.nodes.write().await;
        nodes.insert(index, *commitment.as_bytes());

        // Invalidate cache
        let mut cached_root = self.cached_root.write().await;
        *cached_root = None;

        drop(nodes);
        drop(next_index);
        drop(cached_root);

        index
    }

    /// Batch insert multiple commitments
    pub async fn insert_batch(&self, commitments: &[Commitment]) -> Vec<u64> {
        let mut indices = Vec::with_capacity(commitments.len());
        let mut next_index = self.next_index.write().await;
        let mut nodes = self.nodes.write().await;

        for commitment in commitments {
            let index = *next_index;
            nodes.insert(index, *commitment.as_bytes());
            indices.push(index);
            *next_index += 1;
        }

        // Invalidate cache
        let mut cached_root = self.cached_root.write().await;
        *cached_root = None;

        indices
    }

    /// Get the current root hash
    pub async fn root(&self) -> [u8; 32] {
        // Check cache
        {
            let cached = self.cached_root.read().await;
            if let Some(root) = *cached {
                return root;
            }
        }

        // Compute root
        let root = self.compute_root().await;

        // Update cache
        let mut cached = self.cached_root.write().await;
        *cached = Some(root);

        root
    }

    /// Compute the Merkle root
    ///
    /// Uses sparse representation: only traverse non-empty paths
    async fn compute_root(&self) -> [u8; 32] {
        let nodes = self.nodes.read().await;
        let next_index = *self.next_index.read().await;

        if next_index == 0 {
            // Empty tree
            return self.empty_hashes[self.depth];
        }

        // Build tree level by level, bottom-up
        let mut current_level: HashMap<u64, [u8; 32]> = nodes.clone();

        for level in 0..self.depth {
            let mut next_level: HashMap<u64, [u8; 32]> = HashMap::new();
            let empty_hash = self.empty_hashes[level];

            // Group nodes by parent
            let mut parent_indices: Vec<u64> = current_level.keys().map(|&idx| idx / 2).collect();
            parent_indices.sort_unstable();
            parent_indices.dedup();

            for parent_idx in parent_indices {
                let left_idx = parent_idx * 2;
                let right_idx = parent_idx * 2 + 1;

                let left_hash = current_level.get(&left_idx).unwrap_or(&empty_hash);
                let right_hash = current_level.get(&right_idx).unwrap_or(&empty_hash);

                let parent_hash = poseidon_hash_pair(left_hash, right_hash);
                next_level.insert(parent_idx, parent_hash);
            }

            current_level = next_level;
        }

        // Root is at index 0 of the top level
        current_level
            .get(&0)
            .copied()
            .unwrap_or(self.empty_hashes[self.depth])
    }

    /// Get Merkle path for a leaf at given index
    pub async fn path(&self, index: u64) -> Option<MerklePath> {
        let next_index = *self.next_index.read().await;
        if index >= next_index {
            return None;
        }

        let nodes = self.nodes.read().await;
        let mut path = Vec::with_capacity(self.depth);
        let mut indices = Vec::with_capacity(self.depth);
        let mut current_idx = index;

        // Build path from leaf to root
        for level in 0..self.depth {
            let sibling_idx = current_idx ^ 1; // XOR to get sibling
            let is_right = current_idx % 2 == 1;

            // Get sibling hash (or empty hash if not in tree)
            let sibling_hash = nodes
                .get(&sibling_idx)
                .copied()
                .unwrap_or(self.empty_hashes[level]);

            path.push(sibling_hash);
            indices.push(is_right);
            current_idx /= 2;
        }

        Some(MerklePath { path, indices })
    }

    /// Get number of leaves in the tree
    pub async fn len(&self) -> u64 {
        *self.next_index.read().await
    }

    /// Check if tree is empty
    pub async fn is_empty(&self) -> bool {
        *self.next_index.read().await == 0
    }

    /// Get memory usage statistics
    pub async fn memory_stats(&self) -> MemoryStats {
        let nodes = self.nodes.read().await;
        let num_nodes = nodes.len();
        let num_leaves = *self.next_index.read().await;

        // Calculate memory usage
        // Each node: 8 bytes (key) + 32 bytes (hash) = 40 bytes
        let bytes_used = num_nodes * 40;

        // Dense tree would use: 2^depth * 32 bytes
        let dense_bytes = (1u64 << self.depth) * 32;

        MemoryStats {
            num_leaves,
            num_stored_nodes: num_nodes as u64,
            bytes_used: bytes_used as u64,
            dense_tree_bytes: dense_bytes,
            compression_ratio: if bytes_used > 0 {
                dense_bytes as f64 / bytes_used as f64
            } else {
                f64::INFINITY
            },
        }
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory usage statistics for sparse Merkle tree
#[derive(Debug, Clone)]
pub struct MemoryStats {
    /// Number of leaves inserted
    pub num_leaves: u64,
    /// Number of nodes actually stored
    pub num_stored_nodes: u64,
    /// Bytes used by sparse tree
    pub bytes_used: u64,
    /// Bytes a dense tree would use
    pub dense_tree_bytes: u64,
    /// Compression ratio (dense / sparse)
    pub compression_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sparse_merkle_creation() {
        let tree = SparseMerkleTree::new();
        assert_eq!(tree.depth, SPARSE_TREE_DEPTH);
        assert!(tree.is_empty().await);
    }

    #[tokio::test]
    async fn test_empty_hashes() {
        let tree = SparseMerkleTree::with_depth(4);
        assert_eq!(tree.empty_hashes.len(), 5); // depth + 1
        assert_eq!(tree.empty_hashes[0], EMPTY_NODE_HASH);
    }

    #[tokio::test]
    async fn test_insert_single() {
        let tree = SparseMerkleTree::new();
        let commitment = Commitment([1u8; 32]);

        let index = tree.insert(&commitment).await;
        assert_eq!(index, 0);
        assert_eq!(tree.len().await, 1);
        assert!(!tree.is_empty().await);
    }

    #[tokio::test]
    async fn test_insert_multiple() {
        let tree = SparseMerkleTree::new();

        let c1 = Commitment([1u8; 32]);
        let c2 = Commitment([2u8; 32]);
        let c3 = Commitment([3u8; 32]);

        let i1 = tree.insert(&c1).await;
        let i2 = tree.insert(&c2).await;
        let i3 = tree.insert(&c3).await;

        assert_eq!(i1, 0);
        assert_eq!(i2, 1);
        assert_eq!(i3, 2);
        assert_eq!(tree.len().await, 3);
    }

    #[tokio::test]
    async fn test_batch_insert() {
        let tree = SparseMerkleTree::new();

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
    async fn test_root_computation() {
        let tree = SparseMerkleTree::with_depth(4);

        // Empty tree root should be empty hash
        let empty_root = tree.root().await;
        assert_eq!(empty_root, tree.empty_hashes[4]);

        // Insert one commitment
        let c1 = Commitment([1u8; 32]);
        tree.insert(&c1).await;

        let root1 = tree.root().await;
        assert_ne!(root1, empty_root);

        // Insert another commitment - root should change
        let c2 = Commitment([2u8; 32]);
        tree.insert(&c2).await;

        let root2 = tree.root().await;
        assert_ne!(root2, root1);
    }

    #[tokio::test]
    async fn test_root_caching() {
        let tree = SparseMerkleTree::new();

        let c1 = Commitment([1u8; 32]);
        tree.insert(&c1).await;

        let root1 = tree.root().await;
        let root2 = tree.root().await; // Should use cache

        assert_eq!(root1, root2);
    }

    #[tokio::test]
    async fn test_merkle_path() {
        let tree = SparseMerkleTree::with_depth(4);

        let c1 = Commitment([1u8; 32]);
        let c2 = Commitment([2u8; 32]);

        tree.insert(&c1).await;
        tree.insert(&c2).await;

        // Get path for first commitment
        let path0 = tree.path(0).await;
        assert!(path0.is_some());
        let path0 = path0.unwrap();
        assert_eq!(path0.path.len(), 4); // depth

        // Get path for second commitment
        let path1 = tree.path(1).await;
        assert!(path1.is_some());

        // Path for non-existent leaf
        let path_none = tree.path(999).await;
        assert!(path_none.is_none());
    }

    #[tokio::test]
    async fn test_memory_stats() {
        let tree = SparseMerkleTree::with_depth(32);

        // Insert a few commitments
        for i in 0..10 {
            let commitment = Commitment([i; 32]);
            tree.insert(&commitment).await;
        }

        let stats = tree.memory_stats().await;

        assert_eq!(stats.num_leaves, 10);
        assert!(stats.num_stored_nodes > 0);
        assert!(stats.bytes_used > 0);
        assert!(stats.compression_ratio > 1.0); // Sparse should be smaller

        println!("Sparse tree stats: {:?}", stats);
        println!("Compression ratio: {:.2}x", stats.compression_ratio);
    }

    #[tokio::test]
    async fn test_path_verification() {
        let tree = SparseMerkleTree::with_depth(4);

        let commitment = Commitment([42u8; 32]);
        let index = tree.insert(&commitment).await;

        let root = tree.root().await;
        let path = tree.path(index).await.unwrap();

        // Manually verify path using Poseidon hash (same as tree uses)
        let mut current = *commitment.as_bytes();

        for (sibling, is_right) in path.path.iter().zip(path.indices.iter()) {
            // is_right = true means current node is on the right
            // So we hash: left (sibling) || right (current)
            current = if *is_right {
                poseidon_hash_pair(sibling, &current)
            } else {
                poseidon_hash_pair(&current, sibling)
            };
        }

        // Computed root should match tree root
        assert_eq!(&current, &root, "Path verification failed");
    }

    #[tokio::test]
    async fn test_sparse_vs_dense_memory() {
        let tree = SparseMerkleTree::with_depth(20); // 2^20 = 1M capacity

        // Insert only 100 leaves
        for i in 0..100 {
            let commitment = Commitment([i; 32]);
            tree.insert(&commitment).await;
        }

        let stats = tree.memory_stats().await;

        // Sparse should use MUCH less memory than dense
        println!("Leaves: {}", stats.num_leaves);
        println!("Sparse: {} bytes", stats.bytes_used);
        println!("Dense would use: {} bytes", stats.dense_tree_bytes);
        println!("Compression: {:.0}x smaller!", stats.compression_ratio);

        assert!(stats.compression_ratio > 1000.0); // At least 1000x smaller!
    }
}
