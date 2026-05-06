//! Privacy-specific types for the shielded pool

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};

use crate::privacy::poseidon::{poseidon_commit, poseidon_merkle_pair, poseidon_nullifier};

/// Serialize an `Fr` to 32 little-endian bytes. BLS12-381 `Fr` is 255-bit,
/// so the 32-byte buffer always fits and we pad trailing zeros if
/// arkworks' `to_bytes_le` emits fewer than 32 bytes.
fn fr_to_bytes_32(fr: Fr) -> [u8; 32] {
    let bytes = fr.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let len = bytes.len().min(32);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// A shielded address (z-address) - 32 bytes
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShieldedAddress(pub [u8; 32]);

impl ShieldedAddress {
    /// Create a new shielded address from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        ShieldedAddress(bytes)
    }

    /// Get the bytes of the address
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string for display
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// A commitment to a value and randomness (Pedersen commitment)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Commitment(pub [u8; 32]);

impl Commitment {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Commitment(bytes)
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// A nullifier prevents double-spending
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Nullifier(bytes)
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive nullifier from commitment and spending key.
    ///
    /// Uses domain-separated Poseidon (`poseidon::domain::NULLIFIER`) to
    /// match the circuit-side `poseidon_nullifier_gadget`. Both the
    /// commitment and the spending key are lifted to `Fr` via modular
    /// reduction — these inputs are random 32-byte values, so the
    /// reduction is a safe one-way injection.
    pub fn derive(commitment: &Commitment, spending_key: &[u8; 32]) -> Self {
        let c_fr = Fr::from_le_bytes_mod_order(commitment.as_bytes());
        let s_fr = Fr::from_le_bytes_mod_order(spending_key);
        let digest = poseidon_nullifier(c_fr, s_fr);
        Nullifier(fr_to_bytes_32(digest))
    }

    /// Convert to hex
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Viewing key allows selective disclosure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewingKey {
    /// The viewing key bytes
    pub key: [u8; 32],
}

impl ViewingKey {
    /// Create new viewing key
    pub fn new(key: [u8; 32]) -> Self {
        ViewingKey { key }
    }

    /// Decrypt a note if this viewing key matches
    pub fn can_decrypt(&self, _note: &Note) -> bool {
        // Placeholder - would implement actual decryption logic
        false
    }
}

/// A note represents a shielded value
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Note {
    /// Recipient's shielded address
    pub recipient: ShieldedAddress,
    /// Amount (in lamports)
    pub amount: u64,
    /// Random blinding factor
    pub randomness: [u8; 32],
    /// Memo (optional encrypted message)
    pub memo: Option<Vec<u8>>,
}

impl Note {
    /// Create a new note
    pub fn new(recipient: ShieldedAddress, amount: u64, randomness: [u8; 32]) -> Self {
        Note {
            recipient,
            amount,
            randomness,
            memo: None,
        }
    }

    /// Compute commitment for this note.
    ///
    /// Uses domain-separated Poseidon (`poseidon::domain::COMMITMENT`) to
    /// match the circuit-side `poseidon_commit_gadget`. The amount maps
    /// directly via `Fr::from(u64)`; randomness and recipient are
    /// 32-byte blobs lifted to `Fr` via modular reduction.
    ///
    /// Argument order to the hash function is fixed as
    /// `(amount, randomness, recipient)` — callers must not reorder.
    pub fn commitment(&self) -> Commitment {
        let amount_fr = Fr::from(self.amount);
        let randomness_fr = Fr::from_le_bytes_mod_order(&self.randomness);
        let recipient_fr = Fr::from_le_bytes_mod_order(self.recipient.as_bytes());
        let digest = poseidon_commit(amount_fr, randomness_fr, recipient_fr);
        Commitment(fr_to_bytes_32(digest))
    }
}

/// Merkle tree path for proving commitment inclusion
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePath {
    /// Path elements from leaf to root
    pub path: Vec<[u8; 32]>,
    /// Position indices (0 = left, 1 = right)
    pub indices: Vec<bool>,
}

impl MerklePath {
    /// Create an empty path
    pub fn empty() -> Self {
        MerklePath {
            path: Vec::new(),
            indices: Vec::new(),
        }
    }

    /// Verify that a leaf is in the tree with given root.
    ///
    /// Walks the authentication path hashing each `(left, right)` pair with
    /// domain-separated Poseidon (`poseidon::domain::MERKLE_PAIR`) — the
    /// exact same function used by `MerkleTree::hash_pair` and the circuit
    /// gadget. Any divergence between these three paths would break
    /// inclusion proofs.
    pub fn verify(&self, leaf: &[u8; 32], root: &[u8; 32]) -> bool {
        let mut current = *leaf;

        for (sibling, is_right) in self.path.iter().zip(self.indices.iter()) {
            let (l_bytes, r_bytes) = if *is_right {
                (&current, sibling)
            } else {
                (sibling, &current)
            };
            let l = Fr::from_le_bytes_mod_order(l_bytes);
            let r = Fr::from_le_bytes_mod_order(r_bytes);
            current = fr_to_bytes_32(poseidon_merkle_pair(l, r));
        }

        &current == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_derivation() {
        let commitment = Commitment([1u8; 32]);
        let spending_key = [2u8; 32];

        let nullifier1 = Nullifier::derive(&commitment, &spending_key);
        let nullifier2 = Nullifier::derive(&commitment, &spending_key);

        // Same inputs should produce same nullifier
        assert_eq!(nullifier1, nullifier2);

        // Different spending key should produce different nullifier
        let different_key = [3u8; 32];
        let nullifier3 = Nullifier::derive(&commitment, &different_key);
        assert_ne!(nullifier1, nullifier3);
    }

    #[test]
    fn test_note_commitment() {
        let addr = ShieldedAddress([5u8; 32]);
        let note = Note::new(addr, 1000, [10u8; 32]);

        let commitment1 = note.commitment();
        let commitment2 = note.commitment();

        // Same note should produce same commitment
        assert_eq!(commitment1, commitment2);
    }

    #[test]
    fn test_merkle_path_verification() {
        let leaf = [1u8; 32];
        let root = [2u8; 32];

        let path = MerklePath::empty();

        // Empty path should verify leaf == root
        assert!(path.verify(&leaf, &leaf));
        assert!(!path.verify(&leaf, &root));
    }

    // ── Adversarial / property coverage for `MerklePath::verify` ─────
    //
    // The audit (#71) called for fuzz coverage of the Merkle path
    // verifier — a malicious peer can hand the L2 any
    // `(path, indices)` pair through the network codec, and a panic
    // here crashes a validator. The tests below cover the three
    // behaviours that matter:
    //   1. random adversarial paths never panic
    //   2. an honestly-constructed path verifies, and any bit-flip
    //      breaks it
    //   3. structural shapes (mismatched path/indices, zero-length,
    //      excess depth) all return cleanly

    /// Compute the Merkle root for a single-leaf tree by hashing the
    /// leaf with its sibling at each level — same recipe the
    /// constructor of an honest `MerklePath` would follow.
    fn root_for(leaf: &[u8; 32], path: &[[u8; 32]], indices: &[bool]) -> [u8; 32] {
        let mut current = *leaf;
        for (sibling, is_right) in path.iter().zip(indices.iter()) {
            let (l_bytes, r_bytes) = if *is_right {
                (&current, sibling)
            } else {
                (sibling, &current)
            };
            let l = Fr::from_le_bytes_mod_order(l_bytes);
            let r = Fr::from_le_bytes_mod_order(r_bytes);
            current = fr_to_bytes_32(poseidon_merkle_pair(l, r));
        }
        current
    }

    /// Honestly-built path of moderate depth verifies; any single-bit
    /// flip in the leaf, the path, the indices, or the root breaks it.
    /// This is the "tamper detection" property the privacy layer
    /// relies on for inclusion proofs.
    #[test]
    fn merkle_path_detects_single_bit_flips() {
        let leaf = [0xA1u8; 32];
        let path_data = vec![[0x55u8; 32], [0xAAu8; 32], [0x11u8; 32], [0x22u8; 32]];
        let indices = vec![true, false, true, false];
        let root = root_for(&leaf, &path_data, &indices);

        let path = MerklePath {
            path: path_data.clone(),
            indices: indices.clone(),
        };
        assert!(path.verify(&leaf, &root), "honest path must verify");

        // Flip one bit in the leaf → must fail.
        let mut tampered_leaf = leaf;
        tampered_leaf[0] ^= 0x01;
        assert!(!path.verify(&tampered_leaf, &root));

        // Flip one bit in the root → must fail.
        let mut tampered_root = root;
        tampered_root[0] ^= 0x01;
        assert!(!path.verify(&leaf, &tampered_root));

        // Flip one bit in a sibling → must fail.
        let mut tampered_path = path_data.clone();
        tampered_path[1][3] ^= 0x10;
        let tampered = MerklePath {
            path: tampered_path,
            indices: indices.clone(),
        };
        assert!(!tampered.verify(&leaf, &root));

        // Flip an index → must fail.
        let mut tampered_indices = indices;
        tampered_indices[2] = !tampered_indices[2];
        let tampered = MerklePath {
            path: path_data,
            indices: tampered_indices,
        };
        assert!(!tampered.verify(&leaf, &root));
    }

    /// Mismatched `path.len()` vs `indices.len()` is a malformed
    /// input. The current implementation silently zips to the shorter
    /// of the two — pin that behaviour explicitly so a future change
    /// to "panic" or "Err" is a deliberate API decision rather than
    /// an accidental drift.
    #[test]
    fn merkle_path_mismatched_lengths_truncate_via_zip() {
        let leaf = [0u8; 32];
        let path = MerklePath {
            path: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            indices: vec![true], // strictly shorter
        };
        // Build the root the implementation would compute (1 level).
        let expected_root = root_for(&leaf, &path.path[..1], &path.indices);
        // Verify against that — the verifier walks only `min(len)`
        // levels, so the path lengths can disagree without panicking.
        assert!(path.verify(&leaf, &expected_root));
    }

    /// Random `(path, indices)` pairs of varying shapes must never
    /// panic — they may verify (vanishingly unlikely) or not.
    #[test]
    fn merkle_path_verify_random_inputs_never_panic() {
        use ark_std::rand::rngs::StdRng;
        use ark_std::rand::{Rng, RngCore, SeedableRng};

        let mut rng = StdRng::seed_from_u64(0xDEC0_DE13u64);
        for _ in 0..512 {
            let depth = rng.gen_range(0..32);
            let mut path = Vec::with_capacity(depth);
            let mut indices = Vec::with_capacity(depth);
            for _ in 0..depth {
                let mut sibling = [0u8; 32];
                rng.fill_bytes(&mut sibling);
                path.push(sibling);
                indices.push(rng.gen());
            }
            let mp = MerklePath { path, indices };

            let mut leaf = [0u8; 32];
            let mut root = [0u8; 32];
            rng.fill_bytes(&mut leaf);
            rng.fill_bytes(&mut root);

            // Result is uninteresting; the assertion is "no panic".
            let _ = mp.verify(&leaf, &root);
        }
    }

    /// Very deep paths (depth 256) must not stack-overflow or panic.
    /// 256 is well above any realistic shielded-pool depth and a
    /// natural stress point for an iterative implementation.
    #[test]
    fn merkle_path_deep_path_does_not_panic() {
        let leaf = [0xCDu8; 32];
        let path: Vec<[u8; 32]> = (0..256).map(|i| [i as u8; 32]).collect();
        let indices: Vec<bool> = (0..256).map(|i| i % 2 == 0).collect();
        let root = root_for(&leaf, &path, &indices);
        let mp = MerklePath { path, indices };
        assert!(mp.verify(&leaf, &root));
    }
}
