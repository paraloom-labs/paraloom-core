//! Merkle tree for tracking commitments in the shielded pool
//!
//! This implements an incremental Merkle tree where each commitment is inserted
//! as a leaf. The tree root is used in ZK proofs to prove a commitment exists
//! without revealing which one.

use crate::privacy::poseidon::poseidon_merkle_pair;
use crate::privacy::types::{Commitment, MerklePath};
use crate::storage::PrivacyStorage;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Default tree depth (supports 2^32 leaves)
pub const DEFAULT_TREE_DEPTH: usize = 32;

/// Merkle tree for commitments
/// How many recent roots the tree remembers for withdrawal/transfer proof
/// verification. A proof is built against the root the prover observed (served
/// by the path server); by the time a validator verifies it, more deposits may
/// have advanced the tree past that root. Accepting any of the last
/// `ROOT_HISTORY_LEN` roots lets independently-advancing validators verify the
/// same proof without holding byte-identical trees, the way Tornado-style pools
/// keep a roots ring buffer. Double-spend is still prevented by the nullifier,
/// independent of which historical root a proof names.
pub const ROOT_HISTORY_LEN: usize = 256;

pub struct MerkleTree {
    /// Tree depth
    depth: usize,
    /// Current leaves (commitments)
    leaves: Arc<RwLock<Vec<[u8; 32]>>>,
    /// Cached root
    cached_root: Arc<RwLock<Option<[u8; 32]>>>,
    /// Bounded history of recently-computed roots (newest at the back), for
    /// [`Self::knows_root`]. Capped at [`ROOT_HISTORY_LEN`].
    recent_roots: Arc<RwLock<std::collections::VecDeque<[u8; 32]>>>,
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
            recent_roots: Arc::new(RwLock::new(std::collections::VecDeque::new())),
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

        // Seed the recent-roots window with the reloaded tip so a proof built
        // against the just-restored root verifies immediately after a restart.
        let recent_roots = match cached_root {
            Some(r) => std::collections::VecDeque::from([r]),
            None => std::collections::VecDeque::new(),
        };
        Ok(MerkleTree {
            depth: DEFAULT_TREE_DEPTH,
            leaves: Arc::new(RwLock::new(leaves)),
            cached_root: Arc::new(RwLock::new(cached_root)),
            recent_roots: Arc::new(RwLock::new(recent_roots)),
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
        drop(cached_root);

        // Record this root in the bounded history so a proof naming it still
        // verifies after later deposits advance the tree (see [`knows_root`] and
        // [`ROOT_HISTORY_LEN`]). Skip consecutive duplicates.
        {
            let mut recent = self.recent_roots.write().await;
            if recent.back() != Some(&root) {
                recent.push_back(root);
                while recent.len() > ROOT_HISTORY_LEN {
                    recent.pop_front();
                }
            }
        }

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

    /// Whether `root` is the current tip or one of the last [`ROOT_HISTORY_LEN`]
    /// roots this tree computed. A verifier accepts a withdrawal/transfer proof
    /// built against any such root, so nodes whose trees have advanced by
    /// different amounts can still verify the same proof without holding
    /// byte-identical trees. Computing the current root first guarantees the
    /// live tip is always considered even before it entered the history.
    pub async fn knows_root(&self, root: &[u8; 32]) -> bool {
        if &self.root().await == root {
            return true;
        }
        let recent = self.recent_roots.read().await;
        recent.iter().any(|r| r == root)
    }

    /// The root the tree WOULD have after appending `commitments`, computed
    /// without mutating the tree. A settling validator uses this to check a
    /// proposed post-transfer root against the commitments the transfer
    /// actually adds: the root is not a proof input, so without this check a
    /// settler could advance the published root to an arbitrary (e.g.
    /// fabricated-note) tree and then withdraw against it. Append order matches
    /// `insert`, so it agrees with the state `apply_transfer` later commits.
    pub async fn root_after(&self, commitments: &[Commitment]) -> [u8; 32] {
        let leaves = self.leaves.read().await;
        let mut extended = leaves.clone();
        for c in commitments {
            extended.push(*c.as_bytes());
        }
        self.compute_root(&extended)
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

    /// Precomputed empty-subtree hashes. `empty[k]` is the root of a fully
    /// empty subtree of height `k`: `empty[0]` is the empty-leaf value and
    /// each level hashes two empty subtrees of the level below. Used to pad
    /// absent siblings so the tree is a fixed-depth tree — every leaf has a
    /// path of exactly `self.depth` siblings, and one set of Groth16 keys
    /// verifies a withdrawal regardless of how many notes the pool holds.
    fn empty_subtree_hashes(&self) -> Vec<[u8; 32]> {
        let mut empties = Vec::with_capacity(self.depth + 1);
        empties.push([0u8; 32]); // empty leaf
        for k in 0..self.depth {
            let prev = empties[k];
            empties.push(Self::hash_pair(&prev, &prev));
        }
        empties
    }

    /// Compute the fixed-depth root from the current leaves.
    ///
    /// Hashes the leaves up exactly `self.depth` levels, filling any absent
    /// position with the empty-subtree hash for that level. The shape is
    /// fixed (unlike the earlier dynamic tree, whose height — and so its key
    /// requirements — changed with the leaf count), so a single trusted setup
    /// covers a pool of any size up to `2^depth` notes.
    fn compute_root(&self, leaves: &[[u8; 32]]) -> [u8; 32] {
        let empties = self.empty_subtree_hashes();
        if leaves.is_empty() {
            return empties[self.depth];
        }

        let mut layer = leaves.to_vec();
        for empty in empties.iter().take(self.depth) {
            let parent_count = layer.len().div_ceil(2);
            let mut next_layer = Vec::with_capacity(parent_count);
            for j in 0..parent_count {
                let left = layer.get(2 * j).copied().unwrap_or(*empty);
                let right = layer.get(2 * j + 1).copied().unwrap_or(*empty);
                next_layer.push(Self::hash_pair(&left, &right));
            }
            layer = next_layer;
        }

        layer[0]
    }

    /// Compute the fixed-depth Merkle path for the leaf at `index`: exactly
    /// `self.depth` `(sibling, is_sibling_on_right)` pairs, padding absent
    /// siblings with the empty-subtree hash for the level. Hashing the leaf
    /// up this path reproduces [`compute_root`]'s root and matches both
    /// `MerklePath::verify` and the circuit gadget (same `hash_pair`, same
    /// direction convention).
    fn compute_path(&self, leaves: &[[u8; 32]], index: usize) -> MerklePath {
        let empties = self.empty_subtree_hashes();
        let mut path = Vec::with_capacity(self.depth);
        let mut indices = Vec::with_capacity(self.depth);
        let mut layer = leaves.to_vec();
        let mut current_index = index;

        for empty in empties.iter().take(self.depth) {
            let is_right_child = current_index % 2 == 1;
            let sibling_index = if is_right_child {
                current_index - 1
            } else {
                current_index + 1
            };
            let sibling = layer.get(sibling_index).copied().unwrap_or(*empty);

            path.push(sibling);
            // Push !is_right_child: if we are the right child the sibling is
            // on the left (false); if we are the left child it is on the
            // right (true). Matches `MerklePath::verify` and the circuit.
            indices.push(!is_right_child);

            let parent_count = layer.len().div_ceil(2);
            let mut next_layer = Vec::with_capacity(parent_count);
            for j in 0..parent_count {
                let left = layer.get(2 * j).copied().unwrap_or(*empty);
                let right = layer.get(2 * j + 1).copied().unwrap_or(*empty);
                next_layer.push(Self::hash_pair(&left, &right));
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
            recent_roots: Arc::clone(&self.recent_roots),
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

        // Empty tree: a deterministic fixed-depth empty root (the all-empty
        // subtree hash), not the zero word — the tree always hashes up to
        // `depth` levels now.
        let root1 = tree.root().await;
        assert_eq!(root1, MerkleTree::new().root().await);

        // Add commitment — root moves off the empty-tree value.
        tree.insert(&Commitment([1u8; 32]))
            .await
            .expect("in-memory insert");
        let root2 = tree.root().await;
        assert_ne!(root2, root1);

        // Add another commitment - root should change
        tree.insert(&Commitment([2u8; 32]))
            .await
            .expect("in-memory insert");
        let root3 = tree.root().await;
        assert_ne!(root3, root2);
    }

    #[tokio::test]
    async fn test_root_after_matches_real_insert_and_does_not_mutate() {
        let tree = MerkleTree::new();
        tree.insert(&Commitment([7u8; 32])).await.unwrap();
        let before = tree.root().await;

        let appended = [Commitment([8u8; 32]), Commitment([9u8; 32])];

        // The preview equals the root we'd get by actually inserting both, in
        // the same order — so a validator can validate a proposed new root.
        let preview = tree.root_after(&appended).await;
        assert_ne!(preview, before, "appending must move the root");
        // ...and it left the tree untouched.
        assert_eq!(tree.root().await, before, "root_after must not mutate");

        tree.insert(&appended[0]).await.unwrap();
        tree.insert(&appended[1]).await.unwrap();
        assert_eq!(
            tree.root().await,
            preview,
            "root_after must equal the post-insert root"
        );
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
    async fn test_fixed_depth_path_length_and_verify() {
        // Every leaf gets a path of exactly DEFAULT_TREE_DEPTH siblings, and
        // each verifies against the tree root via the same hash family the
        // circuit uses — for a multi-leaf tree, not just a single leaf.
        let tree = MerkleTree::new();
        let commitments: Vec<Commitment> = (0..10u8).map(|i| Commitment([i + 1; 32])).collect();
        for c in &commitments {
            tree.insert(c).await.expect("in-memory insert");
        }

        let root = tree.root().await;
        for (i, c) in commitments.iter().enumerate() {
            let path = tree.path(i).await.expect("path for inserted leaf");
            assert_eq!(
                path.path.len(),
                DEFAULT_TREE_DEPTH,
                "leaf {i} path must be fixed depth"
            );
            assert_eq!(path.indices.len(), DEFAULT_TREE_DEPTH);
            assert!(
                path.verify(c.as_bytes(), &root),
                "leaf {i} must verify against the root"
            );
        }

        // A leaf's path must not verify a different leaf.
        let path0 = tree.path(0).await.unwrap();
        assert!(!path0.verify(commitments[1].as_bytes(), &root));
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

    #[tokio::test]
    async fn knows_root_recognizes_recent_roots_not_strangers() {
        let tree = MerkleTree::new();

        // Capture the root at each tree state as deposits advance it.
        let r0 = tree.root().await;
        tree.insert(&Commitment([1u8; 32])).await.unwrap();
        let r1 = tree.root().await;
        tree.insert(&Commitment([2u8; 32])).await.unwrap();
        let r2 = tree.root().await;

        // Each distinct state advanced the root.
        assert_ne!(r0, r1);
        assert_ne!(r1, r2);

        // A proof built against any of these roots is still recognized after the
        // tree advanced past it — this is what lets a validator on a divergent
        // tip verify a proof a slower peer built earlier.
        assert!(tree.knows_root(&r0).await, "empty-tree root must be known");
        assert!(tree.knows_root(&r1).await, "prior root must be known");
        assert!(tree.knows_root(&r2).await, "current tip must be known");

        // A root the tree never computed is rejected.
        assert!(!tree.knows_root(&[0xAB; 32]).await);
    }

    #[tokio::test]
    async fn recent_roots_history_is_bounded() {
        let tree = MerkleTree::new();
        // Advance the tree well past the history bound; the oldest roots fall
        // out of the window while recent ones stay known.
        let early = tree.root().await;
        for i in 0..(ROOT_HISTORY_LEN as u32 + 10) {
            let mut leaf = [0u8; 32];
            leaf[..4].copy_from_slice(&i.to_le_bytes());
            tree.insert(&Commitment(leaf)).await.unwrap();
            tree.root().await;
        }
        let tip = tree.root().await;
        assert!(tree.knows_root(&tip).await, "tip stays known");
        assert!(
            !tree.knows_root(&early).await,
            "a root older than the history window is forgotten"
        );
    }
}
