//! On-chain incremental Merkle tree for circuit v3 (#350).
//!
//! The program owns the commitment tree and appends output commitments itself,
//! recomputing the root on-chain. This is what removes the attacker-choosable
//! `new_merkle_root` (audit #1): a settled transaction can only advance the root
//! to `insert(old_root, outputs)`, because the program — not the prover —
//! computes it. It also keeps ONE canonical root (no cross-node divergence).
//!
//! Hashing is `sol_poseidon` (circomlib BN254 x5, little-endian), which is
//! bit-identical to the circuit's membership hash (workspace crate's
//! `circom_poseidon`); see the parity note in `poseidon_circom.rs`. All node
//! values are 32-byte little-endian field-element representations (matching
//! the wallet's public-input encoding and the on-chain verifier).
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

/// Poseidon(2) of two 32-byte field elements, via the syscall.
///
/// Little-endian throughout: field-element bytes across the whole program —
/// the wallet's proof public inputs, the on-chain verifier
/// (`Fr::from_le_bytes_mod_order`), and this tree — are little-endian, so the
/// tree's root passed to `verify_transact` deserialises to the same field
/// element the circuit proved membership against.
fn poseidon2(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32]> {
    let h = hashv(
        Parameters::Bn254X5,
        Endianness::LittleEndian,
        &[left, right],
    )
    .map_err(|_| error!(BridgeError::InvalidProof))?;
    Ok(h.to_bytes())
}

/// The v3 note commitment `Poseidon(4)([amount, pubkey, blinding, asset])`,
/// computed on-chain so a deposit's appended leaf is bound to the amount it
/// actually moved into the vault (a depositor cannot append a leaf claiming
/// more value than it deposited). Bit-identical to the circuit's `v3_commit`:
/// the same circomlib `Poseidon(4)` over the same little-endian field-element
/// bytes (`amount` is the u64 as a little-endian field element).
pub fn commitment(
    amount: u64,
    pubkey: &[u8; 32],
    blinding: &[u8; 32],
    asset: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut amount_le = [0u8; 32];
    amount_le[..8].copy_from_slice(&amount.to_le_bytes());
    let h = hashv(
        Parameters::Bn254X5,
        Endianness::LittleEndian,
        &[&amount_le, pubkey, blinding, asset],
    )
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
    [100, 72, 182, 70, 132, 238, 57, 168, 35, 213, 254, 95, 213, 36, 49, 220, 129, 228, 129, 123, 242, 195, 234, 60, 171, 158, 35, 158, 251, 245, 152, 32],
    [225, 241, 177, 96, 68, 119, 164, 103, 240, 141, 198, 157, 203, 68, 26, 38, 236, 167, 132, 245, 111, 26, 48, 223, 99, 34, 177, 205, 61, 103, 105, 16],
    [56, 210, 86, 184, 178, 126, 213, 40, 213, 29, 55, 80, 234, 110, 124, 70, 6, 33, 247, 80, 141, 117, 61, 46, 175, 226, 126, 83, 49, 51, 244, 24],
    [42, 149, 188, 157, 85, 151, 172, 202, 101, 130, 86, 26, 87, 40, 183, 241, 69, 35, 165, 59, 233, 255, 32, 99, 211, 176, 23, 203, 55, 216, 249, 7],
    [85, 63, 24, 57, 22, 236, 92, 123, 77, 173, 178, 148, 140, 197, 153, 166, 7, 41, 243, 93, 76, 31, 99, 201, 245, 179, 70, 135, 94, 207, 148, 43],
    [120, 157, 160, 46, 163, 221, 17, 29, 97, 83, 185, 81, 105, 30, 215, 254, 188, 225, 169, 204, 34, 125, 234, 70, 150, 69, 102, 166, 197, 147, 238, 45],
    [157, 52, 135, 60, 190, 170, 164, 168, 127, 172, 181, 140, 168, 21, 5, 139, 123, 89, 57, 182, 30, 96, 207, 130, 233, 132, 43, 162, 229, 149, 130, 7],
    [97, 204, 243, 153, 58, 190, 76, 68, 26, 33, 65, 74, 39, 46, 107, 97, 42, 71, 100, 69, 134, 236, 27, 80, 166, 39, 96, 143, 241, 229, 165, 47],
    [71, 215, 252, 20, 166, 86, 33, 62, 171, 40, 226, 227, 204, 122, 94, 228, 102, 31, 148, 158, 56, 128, 183, 236, 33, 253, 216, 208, 118, 67, 136, 14],
    [242, 10, 25, 218, 229, 117, 97, 222, 51, 53, 113, 87, 249, 146, 88, 249, 105, 180, 46, 165, 209, 122, 113, 40, 30, 79, 73, 114, 218, 1, 114, 27],
    [54, 118, 125, 206, 250, 107, 188, 190, 181, 8, 8, 101, 228, 225, 230, 166, 25, 152, 36, 1, 178, 192, 0, 82, 56, 54, 94, 114, 34, 136, 141, 31],
    [90, 248, 181, 113, 4, 154, 135, 208, 168, 136, 207, 42, 161, 176, 98, 97, 251, 252, 140, 186, 137, 21, 112, 185, 175, 75, 145, 108, 246, 130, 93, 44],
    [208, 191, 191, 224, 112, 242, 88, 100, 100, 244, 19, 161, 170, 196, 245, 78, 19, 161, 63, 223, 90, 127, 149, 32, 184, 11, 148, 160, 72, 65, 197, 20],
    [12, 232, 235, 244, 75, 142, 17, 22, 212, 137, 173, 140, 88, 37, 190, 17, 175, 185, 216, 68, 238, 192, 16, 30, 150, 111, 152, 47, 177, 51, 13, 25],
    [146, 108, 224, 37, 147, 100, 179, 165, 10, 81, 175, 150, 101, 174, 103, 17, 237, 115, 173, 20, 73, 53, 23, 172, 82, 65, 112, 206, 169, 138, 249, 34],
    [35, 115, 186, 139, 211, 83, 183, 248, 238, 204, 110, 198, 41, 111, 82, 90, 87, 106, 191, 114, 141, 34, 111, 159, 11, 136, 229, 108, 155, 124, 124, 42],
    [146, 185, 54, 63, 100, 221, 117, 77, 149, 139, 152, 194, 201, 67, 0, 71, 252, 63, 70, 77, 193, 249, 122, 198, 193, 142, 105, 88, 229, 134, 129, 46],
    [15, 241, 31, 28, 157, 36, 70, 53, 39, 146, 115, 100, 173, 110, 239, 138, 148, 174, 13, 5, 207, 200, 226, 73, 171, 78, 154, 30, 87, 197, 87, 15],
    [202, 44, 247, 52, 97, 227, 156, 60, 228, 70, 125, 105, 16, 227, 120, 254, 28, 14, 128, 136, 67, 61, 246, 213, 74, 85, 251, 181, 103, 238, 48, 24],
    [62, 31, 25, 34, 223, 182, 113, 211, 249, 18, 247, 234, 70, 30, 10, 136, 238, 132, 143, 221, 225, 43, 108, 24, 171, 26, 210, 197, 106, 231, 52, 33],
    [177, 165, 145, 219, 243, 141, 143, 143, 168, 58, 238, 88, 201, 216, 81, 192, 176, 89, 56, 243, 102, 216, 235, 254, 79, 188, 78, 132, 236, 144, 223, 25],
    [43, 229, 239, 34, 247, 5, 140, 100, 180, 18, 73, 239, 147, 14, 175, 116, 45, 133, 132, 253, 174, 105, 30, 152, 135, 7, 92, 107, 166, 162, 204, 24],
    [141, 83, 210, 73, 69, 100, 5, 223, 250, 131, 173, 239, 242, 56, 131, 98, 58, 71, 79, 213, 210, 4, 19, 77, 27, 13, 35, 21, 148, 144, 136, 35],
    [64, 213, 158, 82, 228, 115, 230, 150, 29, 11, 141, 156, 44, 175, 162, 102, 232, 77, 41, 181, 67, 245, 232, 233, 192, 108, 123, 169, 180, 31, 23, 39],
    [33, 174, 230, 221, 150, 150, 213, 248, 229, 131, 37, 57, 185, 48, 178, 220, 40, 13, 252, 116, 188, 160, 17, 87, 253, 41, 246, 64, 5, 101, 246, 47],
    [24, 21, 97, 206, 48, 38, 147, 105, 86, 215, 173, 246, 104, 81, 173, 224, 162, 120, 119, 39, 245, 247, 2, 89, 233, 145, 212, 67, 241, 88, 12, 18],
    [149, 55, 72, 121, 210, 101, 214, 162, 29, 162, 101, 165, 160, 149, 196, 30, 7, 3, 219, 229, 213, 83, 248, 123, 176, 33, 63, 13, 183, 254, 33, 31],
    [210, 114, 138, 225, 221, 161, 177, 139, 150, 158, 138, 6, 104, 231, 38, 168, 35, 134, 106, 246, 192, 140, 99, 76, 225, 53, 19, 167, 95, 144, 190, 36],
    [109, 194, 218, 83, 229, 116, 76, 116, 40, 195, 101, 29, 130, 243, 126, 89, 205, 212, 87, 173, 222, 234, 12, 197, 145, 116, 209, 46, 182, 102, 134, 15],
    [239, 89, 25, 14, 35, 42, 26, 61, 180, 140, 224, 106, 63, 122, 122, 78, 89, 65, 28, 26, 74, 63, 65, 52, 176, 152, 45, 245, 107, 212, 24, 9],
    [242, 95, 92, 55, 173, 19, 133, 18, 101, 90, 252, 10, 13, 249, 38, 46, 250, 77, 64, 94, 100, 23, 105, 231, 205, 158, 71, 76, 27, 176, 190, 27],
    [217, 234, 52, 151, 76, 24, 142, 172, 213, 25, 177, 42, 146, 185, 96, 213, 30, 85, 245, 223, 97, 108, 122, 161, 66, 126, 37, 142, 197, 161, 104, 47],
];

/// The incremental Merkle commitment tree, a program-owned account (`seeds =
/// [b"merkle_tree"]`). The program appends output commitments and recomputes
/// the root here, so a settled transaction can only advance the root to
/// `insert(old_root, outputs)` — the prover never supplies it.
///
/// `filled_subtrees[i]` is the last-seen left-child hash at level `i` (the
/// value an even index deposits there and an odd index pairs against), the
/// standard append-only incremental-tree working set.
/// Zero-copy: the tree is ~3.1KB (32 filled subtrees + a 64-root ring buffer),
/// which overflows the 4KB BPF stack frame if Anchor deserializes it as a plain
/// `Account<T>` (`cargo build-sbf` flags `try_accounts`/`try_deserialize` at
/// 5248 bytes). `AccountLoader` accesses the account data in place instead, so
/// nothing large lands on the stack. The two `u64`s lead so the byte arrays are
/// contiguous and the `repr(C)` layout has no interior padding (bytemuck `Pod`
/// requires it); total 3120 bytes, 8-aligned.
#[account(zero_copy)]
#[repr(C)]
pub struct IncrementalMerkleTree {
    pub next_index: u64,
    pub root_index: u64,
    pub root: [u8; 32],
    pub filled_subtrees: [[u8; 32]; TREE_DEPTH],
    pub root_history: [[u8; 32]; ROOT_HISTORY_SIZE],
}

/// On-chain byte size of the zero-copy account (excluding the 8-byte
/// discriminator): `2*8 + 32 + 32*32 + 64*32`.
pub const MERKLE_TREE_SIZE: usize = core::mem::size_of::<IncrementalMerkleTree>();

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
        one[0] = 1; // little-endian 1
        let mut two = [0u8; 32];
        two[0] = 2; // little-endian 2
                    // circomlib Poseidon(2) of [1,2] =
                    // 7853200120776062878684798364095072458815029376092732009249414926327459813530,
                    // little-endian bytes:
        let expected: [u8; 32] = [
            154, 24, 23, 68, 122, 96, 25, 158, 81, 69, 50, 116, 242, 23, 54, 42, 207, 233, 98, 150,
            107, 76, 246, 61, 65, 144, 214, 231, 245, 192, 92, 17,
        ];
        assert_eq!(poseidon2(&one, &two).unwrap(), expected);
    }

    /// The on-chain `commitment` equals the circuit's `v3_commit` for the same
    /// note. Pinned against a value computed by the workspace crate's
    /// `v3_commit(1000, v3_pubkey(51), 5, 0)` (little-endian), so a divergence
    /// between the on-chain leaf and the proven commitment is caught here.
    #[test]
    fn commitment_matches_circuit_v3_commit() {
        // v3_pubkey(51) little-endian bytes.
        let pubkey: [u8; 32] = [
            132, 52, 141, 61, 228, 27, 184, 227, 184, 242, 182, 222, 39, 209, 111, 33, 111, 92,
            165, 142, 254, 122, 175, 141, 206, 84, 88, 88, 9, 26, 87, 8,
        ];
        let mut blinding = [0u8; 32];
        blinding[0] = 5; // little-endian 5
        let asset = [0u8; 32]; // native SOL
                               // v3_commit(1000, pubkey, 5, 0) little-endian bytes.
        let expected: [u8; 32] = [
            133, 56, 189, 24, 154, 24, 130, 156, 210, 94, 242, 255, 117, 193, 232, 59, 154, 76,
            231, 28, 0, 114, 32, 27, 219, 31, 106, 201, 217, 38, 252, 14,
        ];
        assert_eq!(
            commitment(1000, &pubkey, &blinding, &asset).unwrap(),
            expected
        );
    }
}
