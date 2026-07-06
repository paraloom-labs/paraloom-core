//! On-chain incremental Merkle tree for circuit v3 (#350).
//!
//! The program owns the commitment tree and appends output commitments itself,
//! recomputing the root on-chain. This is what removes the attacker-choosable
//! `new_merkle_root` (audit #1): a settled transaction can only advance the root
//! to `insert(old_root, outputs)`, because the program — not the prover —
//! computes it. It also keeps ONE canonical root (no cross-node divergence).
//!
//! Hashing is `sol_poseidon` (circomlib BN254 x5, big-endian), which is
//! bit-identical to the circuit's membership hash (workspace crate's
//! `circom_poseidon`); see the parity note in `poseidon_circom.rs`. All node
//! values are 32-byte big-endian field-element representations.
//!
//! Ported from the Light Protocol / privacy-cash incremental tree (audited).
//!
//! This module is self-contained and fully tested; it is wired into the
//! `transact` instruction (and the pool account) in a follow-up PR, so its
//! items are not yet referenced from the program entrypoints.
#![allow(dead_code)]

use anchor_lang::prelude::*;
use solana_poseidon::{hashv, Endianness, Parameters};

use crate::BridgeError;

/// Tree depth — 2^32 leaves, matching the workspace `DEFAULT_TREE_DEPTH` so the
/// circuit's membership fold has the same height.
pub const TREE_DEPTH: usize = 32;

/// Number of recent roots kept so a proof built against a slightly-stale root
/// (one that was current when the prover fetched its path) still verifies.
pub const ROOT_HISTORY_SIZE: usize = 64;

/// Poseidon(2) of two big-endian 32-byte field elements, via the syscall.
fn poseidon2(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32]> {
    let h = hashv(Parameters::Bn254X5, Endianness::BigEndian, &[left, right])
        .map_err(|_| error!(BridgeError::InvalidProof))?;
    Ok(h.to_bytes())
}

/// Empty-subtree hashes: `ZERO_HASHES[0]` is the empty leaf (`0`) and
/// `ZERO_HASHES[k+1] = Poseidon(ZERO_HASHES[k], ZERO_HASHES[k])`, the root of a
/// fully empty subtree of height `k` — the sibling for never-filled positions.
///
/// Hardcoded (not recomputed) so `append` spends no syscall Poseidon on empty
/// siblings; the values are deterministic constants of the hash. The
/// `zero_hashes_const_matches_recompute` test proves this array equals a
/// from-scratch Poseidon recompute, so a wrong constant cannot slip in.
#[rustfmt::skip]
pub const ZERO_HASHES: [[u8; 32]; TREE_DEPTH + 1] = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [32, 152, 245, 251, 158, 35, 158, 171, 60, 234, 195, 242, 123, 129, 228, 129, 220, 49, 36, 213, 95, 254, 213, 35, 168, 57, 238, 132, 70, 182, 72, 100],
    [16, 105, 103, 61, 205, 177, 34, 99, 223, 48, 26, 111, 245, 132, 167, 236, 38, 26, 68, 203, 157, 198, 141, 240, 103, 164, 119, 68, 96, 177, 241, 225],
    [24, 244, 51, 49, 83, 126, 226, 175, 46, 61, 117, 141, 80, 247, 33, 6, 70, 124, 110, 234, 80, 55, 29, 213, 40, 213, 126, 178, 184, 86, 210, 56],
    [7, 249, 216, 55, 203, 23, 176, 211, 99, 32, 255, 233, 59, 165, 35, 69, 241, 183, 40, 87, 26, 86, 130, 101, 202, 172, 151, 85, 157, 188, 149, 42],
    [43, 148, 207, 94, 135, 70, 179, 245, 201, 99, 31, 76, 93, 243, 41, 7, 166, 153, 197, 140, 148, 178, 173, 77, 123, 92, 236, 22, 57, 24, 63, 85],
    [45, 238, 147, 197, 166, 102, 69, 150, 70, 234, 125, 34, 204, 169, 225, 188, 254, 215, 30, 105, 81, 185, 83, 97, 29, 17, 221, 163, 46, 160, 157, 120],
    [7, 130, 149, 229, 162, 43, 132, 233, 130, 207, 96, 30, 182, 57, 89, 123, 139, 5, 21, 168, 140, 181, 172, 127, 168, 164, 170, 190, 60, 135, 52, 157],
    [47, 165, 229, 241, 143, 96, 39, 166, 80, 27, 236, 134, 69, 100, 71, 42, 97, 107, 46, 39, 74, 65, 33, 26, 68, 76, 190, 58, 153, 243, 204, 97],
    [14, 136, 67, 118, 208, 216, 253, 33, 236, 183, 128, 56, 158, 148, 31, 102, 228, 94, 122, 204, 227, 226, 40, 171, 62, 33, 86, 166, 20, 252, 215, 71],
    [27, 114, 1, 218, 114, 73, 79, 30, 40, 113, 122, 209, 165, 46, 180, 105, 249, 88, 146, 249, 87, 113, 53, 51, 222, 97, 117, 229, 218, 25, 10, 242],
    [31, 141, 136, 34, 114, 94, 54, 56, 82, 0, 192, 178, 1, 36, 152, 25, 166, 230, 225, 228, 101, 8, 8, 181, 190, 188, 107, 250, 206, 125, 118, 54],
    [44, 93, 130, 246, 108, 145, 75, 175, 185, 112, 21, 137, 186, 140, 252, 251, 97, 98, 176, 161, 42, 207, 136, 168, 208, 135, 154, 4, 113, 181, 248, 90],
    [20, 197, 65, 72, 160, 148, 11, 184, 32, 149, 127, 90, 223, 63, 161, 19, 78, 245, 196, 170, 161, 19, 244, 100, 100, 88, 242, 112, 224, 191, 191, 208],
    [25, 13, 51, 177, 47, 152, 111, 150, 30, 16, 192, 238, 68, 216, 185, 175, 17, 190, 37, 88, 140, 173, 137, 212, 22, 17, 142, 75, 244, 235, 232, 12],
    [34, 249, 138, 169, 206, 112, 65, 82, 172, 23, 53, 73, 20, 173, 115, 237, 17, 103, 174, 101, 150, 175, 81, 10, 165, 179, 100, 147, 37, 224, 108, 146],
    [42, 124, 124, 155, 108, 229, 136, 11, 159, 111, 34, 141, 114, 191, 106, 87, 90, 82, 111, 41, 198, 110, 204, 238, 248, 183, 83, 211, 139, 186, 115, 35],
    [46, 129, 134, 229, 88, 105, 142, 193, 198, 122, 249, 193, 77, 70, 63, 252, 71, 0, 67, 201, 194, 152, 139, 149, 77, 117, 221, 100, 63, 54, 185, 146],
    [15, 87, 197, 87, 30, 154, 78, 171, 73, 226, 200, 207, 5, 13, 174, 148, 138, 239, 110, 173, 100, 115, 146, 39, 53, 70, 36, 157, 28, 31, 241, 15],
    [24, 48, 238, 103, 181, 251, 85, 74, 213, 246, 61, 67, 136, 128, 14, 28, 254, 120, 227, 16, 105, 125, 70, 228, 60, 156, 227, 97, 52, 247, 44, 202],
    [33, 52, 231, 106, 197, 210, 26, 171, 24, 108, 43, 225, 221, 143, 132, 238, 136, 10, 30, 70, 234, 247, 18, 249, 211, 113, 182, 223, 34, 25, 31, 62],
    [25, 223, 144, 236, 132, 78, 188, 79, 254, 235, 216, 102, 243, 56, 89, 176, 192, 81, 216, 201, 88, 238, 58, 168, 143, 143, 141, 243, 219, 145, 165, 177],
    [24, 204, 162, 166, 107, 92, 7, 135, 152, 30, 105, 174, 253, 132, 133, 45, 116, 175, 14, 147, 239, 73, 18, 180, 100, 140, 5, 247, 34, 239, 229, 43],
    [35, 136, 144, 148, 21, 35, 13, 27, 77, 19, 4, 210, 213, 79, 71, 58, 98, 131, 56, 242, 239, 173, 131, 250, 223, 5, 100, 69, 73, 210, 83, 141],
    [39, 23, 31, 180, 169, 123, 108, 192, 233, 232, 245, 67, 181, 41, 77, 232, 102, 162, 175, 44, 156, 141, 11, 29, 150, 230, 115, 228, 82, 158, 213, 64],
    [47, 246, 101, 5, 64, 246, 41, 253, 87, 17, 160, 188, 116, 252, 13, 40, 220, 178, 48, 185, 57, 37, 131, 229, 248, 213, 150, 150, 221, 230, 174, 33],
    [18, 12, 88, 241, 67, 212, 145, 233, 89, 2, 247, 245, 39, 119, 120, 162, 224, 173, 81, 104, 246, 173, 215, 86, 105, 147, 38, 48, 206, 97, 21, 24],
    [31, 33, 254, 183, 13, 63, 33, 176, 123, 248, 83, 213, 229, 219, 3, 7, 30, 196, 149, 160, 165, 101, 162, 29, 162, 214, 101, 210, 121, 72, 55, 149],
    [36, 190, 144, 95, 167, 19, 53, 225, 76, 99, 140, 192, 246, 106, 134, 35, 168, 38, 231, 104, 6, 138, 158, 150, 139, 177, 161, 221, 225, 138, 114, 210],
    [15, 134, 102, 182, 46, 209, 116, 145, 197, 12, 234, 222, 173, 87, 212, 205, 89, 126, 243, 130, 29, 101, 195, 40, 116, 76, 116, 229, 83, 218, 194, 109],
    [9, 24, 212, 107, 245, 45, 152, 176, 52, 65, 63, 74, 26, 28, 65, 89, 78, 122, 122, 63, 106, 224, 140, 180, 61, 26, 42, 35, 14, 25, 89, 239],
    [27, 190, 176, 27, 76, 71, 158, 205, 231, 105, 23, 100, 94, 64, 77, 250, 46, 38, 249, 13, 10, 252, 90, 101, 18, 133, 19, 173, 55, 92, 95, 242],
    [47, 104, 161, 197, 142, 37, 126, 66, 161, 122, 108, 97, 223, 245, 85, 30, 213, 96, 185, 146, 42, 177, 25, 213, 172, 142, 24, 76, 151, 52, 234, 217],
];

/// The incremental Merkle tree state embedded in the on-chain pool account.
///
/// `filled_subtrees[i]` is the last-seen left-child hash at level `i` (the
/// value an even index deposits there and an odd index pairs against), the
/// standard append-only incremental-tree working set.
#[derive(Clone)]
pub struct IncrementalMerkleTree {
    pub next_index: u64,
    pub root: [u8; 32],
    pub filled_subtrees: [[u8; 32]; TREE_DEPTH],
    pub root_history: [[u8; 32]; ROOT_HISTORY_SIZE],
    pub root_index: u64,
}

impl IncrementalMerkleTree {
    /// Initialise an empty tree: every `filled_subtree[i]` and the root are the
    /// empty-subtree hashes, and root-history slot 0 holds the empty root.
    pub fn initialize(&mut self) -> Result<()> {
        self.filled_subtrees
            .copy_from_slice(&ZERO_HASHES[..TREE_DEPTH]);
        self.next_index = 0;
        self.root = ZERO_HASHES[TREE_DEPTH];
        self.root_index = 0;
        self.root_history = [[0u8; 32]; ROOT_HISTORY_SIZE];
        self.root_history[0] = ZERO_HASHES[TREE_DEPTH];
        Ok(())
    }

    /// Append one leaf, recomputing the root and recording it in the history
    /// ring buffer. Returns the new root.
    pub fn append(&mut self, leaf: [u8; 32]) -> Result<[u8; 32]> {
        require!(
            (self.next_index as u128) < (1u128 << TREE_DEPTH),
            BridgeError::InvalidProof
        );

        let mut current_index = self.next_index;
        let mut current_hash = leaf;
        for i in 0..TREE_DEPTH {
            if current_index % 2 == 0 {
                // Even index: current node is a left child; record it and pair
                // with the empty-subtree hash on the right.
                self.filled_subtrees[i] = current_hash;
                current_hash = poseidon2(&current_hash, &ZERO_HASHES[i])?;
            } else {
                // Odd index: pair against the stored left sibling.
                current_hash = poseidon2(&self.filled_subtrees[i], &current_hash)?;
            }
            current_index /= 2;
        }

        self.root = current_hash;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or(error!(BridgeError::InvalidProof))?;
        self.root_index = (self.root_index + 1) % (ROOT_HISTORY_SIZE as u64);
        self.root_history[self.root_index as usize] = current_hash;
        Ok(current_hash)
    }

    /// Whether `root` is the current root or a recent one still in the history
    /// window. The all-zero root is never accepted.
    pub fn is_known_root(&self, root: [u8; 32]) -> bool {
        if root == [0u8; 32] {
            return false;
        }
        let start = self.root_index as usize;
        let mut i = start;
        loop {
            if self.root_history[i] == root {
                return true;
            }
            i = if i == 0 { ROOT_HISTORY_SIZE - 1 } else { i - 1 };
            if i == start {
                break;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> IncrementalMerkleTree {
        let mut t = IncrementalMerkleTree {
            next_index: 0,
            root: [0u8; 32],
            filled_subtrees: [[0u8; 32]; TREE_DEPTH],
            root_history: [[0u8; 32]; ROOT_HISTORY_SIZE],
            root_index: 0,
        };
        t.initialize().unwrap();
        t
    }

    /// Independent full recompute of the root of a tree holding `leaves` at
    /// positions `0..leaves.len()` and empty-subtree hashes everywhere else,
    /// folding level by level — no incremental state. `append` must agree.
    fn recompute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        let mut level: Vec<[u8; 32]> = leaves.to_vec();
        for lvl in 0..TREE_DEPTH {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut j = 0;
            while j < level.len() {
                let left = level[j];
                let right = if j + 1 < level.len() {
                    level[j + 1]
                } else {
                    ZERO_HASHES[lvl]
                };
                next.push(poseidon2(&left, &right).unwrap());
                j += 2;
            }
            if next.is_empty() {
                return ZERO_HASHES[TREE_DEPTH];
            }
            level = next;
        }
        level[0]
    }

    /// The hardcoded `ZERO_HASHES` const equals a from-scratch Poseidon
    /// recompute — proves the constant and guards against a wrong paste.
    #[test]
    fn zero_hashes_const_matches_recompute() {
        let mut z = [[0u8; 32]; TREE_DEPTH + 1];
        for k in 0..TREE_DEPTH {
            z[k + 1] = poseidon2(&z[k], &z[k]).unwrap();
        }
        assert_eq!(z, ZERO_HASHES);
    }

    #[test]
    fn append_matches_independent_recompute() {
        let mut t = empty();
        let mut leaves = Vec::new();
        for k in 1u64..=6 {
            let mut leaf = [0u8; 32];
            leaf[24..].copy_from_slice(&k.to_be_bytes()); // small BE field element
            t.append(leaf).unwrap();
            leaves.push(leaf);
            assert_eq!(
                t.root,
                recompute_root(&leaves),
                "append root != recompute at {} leaves",
                leaves.len()
            );
        }
    }

    #[test]
    fn empty_tree_root_is_zero_subtree_hash() {
        let t = empty();
        let z = ZERO_HASHES;
        assert_eq!(t.root, z[TREE_DEPTH]);
        assert!(t.is_known_root(z[TREE_DEPTH]));
    }

    #[test]
    fn is_known_root_tracks_recent_and_rejects_zero_and_unknown() {
        let mut t = empty();
        let mut roots = Vec::new();
        for k in 1u64..=5 {
            let mut leaf = [0u8; 32];
            leaf[24..].copy_from_slice(&k.to_be_bytes());
            roots.push(t.append(leaf).unwrap());
        }
        for r in &roots {
            assert!(t.is_known_root(*r), "recent root must be known");
        }
        assert!(!t.is_known_root([0u8; 32]), "zero root never known");
        assert!(!t.is_known_root([9u8; 32]), "unknown root rejected");
    }

    /// Ties the on-chain hasher to the same canonical circomlib value PR-0
    /// anchored `circom_poseidon` to (Poseidon(2) of [1,2]) — so the tree hash
    /// equals the circuit's membership hash.
    #[test]
    fn poseidon2_matches_circomlib_kat() {
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut two = [0u8; 32];
        two[31] = 2;
        // 7853200120776062878684798364095072458815029376092732009249414926327459813530
        // big-endian bytes:
        let expected: [u8; 32] = [
            17, 92, 192, 245, 231, 214, 144, 65, 61, 246, 76, 107, 150, 98, 233, 207, 42, 54, 23,
            242, 116, 50, 69, 81, 158, 25, 96, 122, 68, 23, 24, 154,
        ];
        assert_eq!(poseidon2(&one, &two).unwrap(), expected);
    }
}
