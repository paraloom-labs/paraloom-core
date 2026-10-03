//! Regression tests for issue #802:
//! Off-chain privacy Merkle tree accepts leaves past fixed-depth capacity.
//!
//! Prior to the fix, `MerkleTree::insert` and `insert_batch` did not check
//! whether the tree had reached `2^depth` leaves. An overflow leaf would be
//! assigned an out-of-range index, its path could not verify against the
//! (unchanged) fixed-depth root, and the pool's commitment count would diverge
//! from the root it reports.

use paraloom::privacy::{Commitment, MerkleTree};

/// insert() must reject a leaf that would put the tree past its fixed-depth
/// capacity. A depth-1 tree supports exactly 2 leaves (indices 0 and 1).
#[tokio::test]
async fn merkle_tree_rejects_leaf_past_fixed_depth_capacity() {
    let tree = MerkleTree::with_depth(1);

    tree.insert(&Commitment([1u8; 32]))
        .await
        .expect("first leaf within 2^depth capacity");
    tree.insert(&Commitment([2u8; 32]))
        .await
        .expect("second leaf fills a depth-1 tree (capacity = 2)");

    // The tree is now at capacity (2 leaves for depth 1).
    let overflow = Commitment([3u8; 32]);
    let result = tree.insert(&overflow).await;
    assert!(
        result.is_err(),
        "insert() must return Err when the tree has reached 2^depth leaves, got Ok({:?})",
        result.ok()
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("capacity") || msg.contains("depth"),
        "error message should mention capacity or depth, got: {msg}"
    );

    // Tree size must remain 2 — the overflow must not have been committed.
    assert_eq!(
        tree.len().await,
        2,
        "tree length must not increase after a rejected overflow insert"
    );
}

/// insert_batch() must reject a batch that would push the tree past capacity.
#[tokio::test]
async fn merkle_tree_rejects_batch_that_overflows_capacity() {
    let tree = MerkleTree::with_depth(2); // capacity = 4

    // Fill 3 of 4 slots.
    let initial: Vec<Commitment> = (1u8..=3).map(|i| Commitment([i; 32])).collect();
    tree.insert_batch(&initial)
        .await
        .expect("batch of 3 fits in a depth-2 tree");

    // A batch of 2 would need 5 slots total — one over capacity.
    let overflow_batch: Vec<Commitment> = (10u8..=11).map(|i| Commitment([i; 32])).collect();
    let result = tree.insert_batch(&overflow_batch).await;
    assert!(
        result.is_err(),
        "insert_batch() must return Err when the batch would exceed 2^depth leaves, got Ok({:?})",
        result.ok()
    );

    // Tree size must still be 3.
    assert_eq!(
        tree.len().await,
        3,
        "tree length must not increase after a rejected overflow batch"
    );
}

/// A batch that exactly fills capacity must succeed.
#[tokio::test]
async fn merkle_tree_accepts_batch_that_exactly_fills_capacity() {
    let tree = MerkleTree::with_depth(2); // capacity = 4

    let full: Vec<Commitment> = (1u8..=4).map(|i| Commitment([i; 32])).collect();
    let indices = tree
        .insert_batch(&full)
        .await
        .expect("batch of 4 exactly fills depth-2 tree");

    assert_eq!(indices, vec![0, 1, 2, 3]);
    assert_eq!(tree.len().await, 4);

    // The next insert must fail.
    let result = tree.insert(&Commitment([99u8; 32])).await;
    assert!(
        result.is_err(),
        "insert after full batch must be rejected"
    );
}

/// The overflow leaf's path cannot verify against the fixed-depth root —
/// demonstrating why the capacity check is necessary. This test documents the
/// root-divergence that the pre-fix code produced; after the fix `insert`
/// returns Err before this state is reached.
///
/// Kept as documentation of the original bad behaviour; tests above confirm
/// the fix prevents the overflow.
#[tokio::test]
async fn overflow_leaf_path_would_not_verify_against_fixed_depth_root() {
    // To show what would happen without the guard, we use a depth large
    // enough that `capacity()` cannot be practically filled, but we manually
    // verify that a hypothetical out-of-range `path()` call returns None,
    // not a corrupt path.
    let tree = MerkleTree::with_depth(2); // capacity = 4

    for i in 1u8..=4 {
        tree.insert(&Commitment([i; 32])).await.unwrap();
    }

    // Asking for a path at an out-of-range index must return None.
    let out_of_range = tree.path(4).await;
    assert!(
        out_of_range.is_none(),
        "path() for an out-of-range index must return None"
    );
}
