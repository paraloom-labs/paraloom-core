//! Privacy-specific types for the shielded pool

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};

use crate::privacy::poseidon::{poseidon_commit, poseidon_merkle_pair, poseidon_nullifier};

/// Serialize an `Fr` to 32 little-endian bytes. BN254 `Fr` is 254-bit,
/// so the 32-byte buffer always fits and we pad trailing zeros if
/// arkworks' `to_bytes_le` emits fewer than 32 bytes.
fn fr_to_bytes_32(fr: Fr) -> [u8; 32] {
    let bytes = fr.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let len = bytes.len().min(32);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// Identifies an asset in the multi-asset shielded pool. SPL tokens use
/// their mint pubkey bytes; native SOL uses the canonical all-zero id
/// [`NATIVE_SOL_ASSET`]. This is both the storage/accounting key (#236) and,
/// lifted to `Fr`, the 5th note-commitment input bound in every circuit (#235).
pub type AssetId = [u8; 32];

/// Canonical asset id for native SOL — the single asset the pool tracked
/// before multi-asset support. Persisted under the legacy `total_supply`
/// key so pools created before #236 load unchanged.
pub const NATIVE_SOL_ASSET: AssetId = [0u8; 32];

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

/// Viewing key for discovering received notes (#196).
///
/// Holds the recipient's X25519 secret. A sender encrypts an output note to the
/// matching public key (the recipient's shielded address); the recipient trial-
/// decrypts delivered ciphertexts with this key. See [`crate::privacy::note_crypto`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewingKey {
    /// The X25519 secret key
    pub key: [u8; 32],
}

impl ViewingKey {
    /// Create a viewing key from an X25519 secret.
    pub fn new(key: [u8; 32]) -> Self {
        ViewingKey { key }
    }

    /// Trial-decrypt an encrypted note. `Some(plaintext)` if this key owns it,
    /// `None` otherwise (silent — the caller scans every delivered note).
    pub fn try_decrypt(
        &self,
        note: &crate::privacy::note_crypto::EncryptedNote,
    ) -> Option<crate::privacy::note_crypto::NotePlaintext> {
        crate::privacy::note_crypto::decrypt_note(&self.key, note)
    }

    /// Whether this key can decrypt `note` (convenience over [`try_decrypt`](Self::try_decrypt)).
    pub fn can_decrypt(&self, note: &crate::privacy::note_crypto::EncryptedNote) -> bool {
        self.try_decrypt(note).is_some()
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
    /// Asset this note holds. Bound into the commitment as the 5th Poseidon
    /// input so value conservation is enforced per asset (#235). Native SOL
    /// uses [`NATIVE_SOL_ASSET`].
    pub asset_id: AssetId,
    /// Memo (optional encrypted message)
    pub memo: Option<Vec<u8>>,
}

impl Note {
    /// Create a new note for a specific asset.
    pub fn new(
        recipient: ShieldedAddress,
        amount: u64,
        randomness: [u8; 32],
        asset_id: AssetId,
    ) -> Self {
        Note {
            recipient,
            amount,
            randomness,
            asset_id,
            memo: None,
        }
    }

    /// Create a native-SOL note (`asset_id == NATIVE_SOL_ASSET`). Convenience
    /// for callers on the pre-multi-asset native path.
    pub fn new_native(recipient: ShieldedAddress, amount: u64, randomness: [u8; 32]) -> Self {
        Note::new(recipient, amount, randomness, NATIVE_SOL_ASSET)
    }

    /// Compute commitment for this note.
    ///
    /// Uses domain-separated Poseidon (`poseidon::domain::COMMITMENT`) to
    /// match the circuit-side `poseidon_commit_gadget`. The amount maps
    /// directly via `Fr::from(u64)`; randomness and recipient are
    /// 32-byte blobs lifted to `Fr` via modular reduction.
    ///
    /// Argument order to the hash function is fixed as
    /// `(amount, randomness, recipient, asset_id)` — callers must not reorder.
    pub fn commitment(&self) -> Commitment {
        let amount_fr = Fr::from(self.amount);
        let randomness_fr = Fr::from_le_bytes_mod_order(&self.randomness);
        let recipient_fr = Fr::from_le_bytes_mod_order(self.recipient.as_bytes());
        let asset_id_fr = Fr::from_le_bytes_mod_order(&self.asset_id);
        let digest = poseidon_commit(amount_fr, randomness_fr, recipient_fr, asset_id_fr);
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
        let note = Note::new_native(addr, 1000, [10u8; 32]);

        let commitment1 = note.commitment();
        let commitment2 = note.commitment();

        // Same note should produce same commitment
        assert_eq!(commitment1, commitment2);
    }

    /// Two notes identical in every field EXCEPT `asset_id` must produce
    /// different commitments (#235). asset_id is the 5th Poseidon input, so
    /// it is bound into the commitment; without this binding, a note of one
    /// asset could be replayed as another.
    #[test]
    fn note_commitment_differs_with_asset_id() {
        let addr = ShieldedAddress([5u8; 32]);
        let amount = 1_000u64;
        let randomness = [10u8; 32];

        let native = Note::new(addr.clone(), amount, randomness, NATIVE_SOL_ASSET);
        let other_asset = Note::new(addr.clone(), amount, randomness, [9u8; 32]);

        assert_ne!(
            native.commitment(),
            other_asset.commitment(),
            "notes differing only in asset_id must have distinct commitments"
        );

        // And the native constructor must agree with the explicit native id.
        let native_via_helper = Note::new_native(addr, amount, randomness);
        assert_eq!(native.commitment(), native_via_helper.commitment());
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

    // ── Property-based tests via `proptest` (#71) ─────────────────────
    //
    // The discrete tests above cover known boundaries; these
    // property tests check that the same shape holds across the
    // proptest-default 256 random inputs per case. The properties
    // are the fundamental ones the privacy layer's integrity rests
    // on, so a regression that broke any of them would be silently
    // catastrophic without coverage at this level.

    use proptest::prelude::*;

    proptest! {
        /// `Note::commitment` is deterministic: same (recipient,
        /// amount, randomness) must always produce the same
        /// commitment. Required for the verifier to reproduce the
        /// commitment from witness data.
        #[test]
        fn note_commitment_is_deterministic(
            recipient_bytes in any::<[u8; 32]>(),
            amount in any::<u64>(),
            randomness in any::<[u8; 32]>(),
        ) {
            let note = Note::new_native(ShieldedAddress(recipient_bytes), amount, randomness);
            prop_assert_eq!(note.commitment(), note.commitment());
        }

        /// Distinct amounts must produce distinct commitments when
        /// recipient and randomness are held constant. This is the
        /// hiding-yet-binding property: a verifier must not be able
        /// to confuse commitments to different amounts.
        #[test]
        fn note_commitment_differs_with_amount(
            recipient_bytes in any::<[u8; 32]>(),
            amount_a in any::<u64>(),
            amount_b in any::<u64>(),
            randomness in any::<[u8; 32]>(),
        ) {
            prop_assume!(amount_a != amount_b);
            let note_a = Note::new_native(ShieldedAddress(recipient_bytes), amount_a, randomness);
            let note_b = Note::new_native(ShieldedAddress(recipient_bytes), amount_b, randomness);
            prop_assert_ne!(note_a.commitment(), note_b.commitment());
        }

        /// Distinct randomness with the same amount and recipient
        /// must produce distinct commitments. This is the
        /// blinding-factor property: two deposits of the same amount
        /// to the same address must be unlinkable.
        #[test]
        fn note_commitment_differs_with_randomness(
            recipient_bytes in any::<[u8; 32]>(),
            amount in any::<u64>(),
            randomness_a in any::<[u8; 32]>(),
            randomness_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(randomness_a != randomness_b);
            let note_a = Note::new_native(ShieldedAddress(recipient_bytes), amount, randomness_a);
            let note_b = Note::new_native(ShieldedAddress(recipient_bytes), amount, randomness_b);
            prop_assert_ne!(note_a.commitment(), note_b.commitment());
        }

        /// `Nullifier::derive(commitment, spending_key)` is
        /// deterministic. Same inputs → same nullifier; the verifier
        /// can therefore reproduce the nullifier from the witness.
        #[test]
        fn nullifier_derive_is_deterministic(
            commitment_bytes in any::<[u8; 32]>(),
            spending_key in any::<[u8; 32]>(),
        ) {
            let commitment = Commitment(commitment_bytes);
            let n1 = Nullifier::derive(&commitment, &spending_key);
            let n2 = Nullifier::derive(&commitment, &spending_key);
            prop_assert_eq!(n1, n2);
        }

        /// Distinct spending keys against the same commitment must
        /// produce distinct nullifiers. Required for spend privacy
        /// across different owners of structurally similar notes.
        #[test]
        fn nullifier_differs_with_spending_key(
            commitment_bytes in any::<[u8; 32]>(),
            sk_a in any::<[u8; 32]>(),
            sk_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(sk_a != sk_b);
            let commitment = Commitment(commitment_bytes);
            let n_a = Nullifier::derive(&commitment, &sk_a);
            let n_b = Nullifier::derive(&commitment, &sk_b);
            prop_assert_ne!(n_a, n_b);
        }

        /// An honestly-built Merkle path of arbitrary depth and
        /// shape always verifies against the root computed from
        /// the same inputs. Catches regressions that break
        /// inclusion proofs for non-trivial tree topologies.
        #[test]
        fn merkle_path_honest_path_verifies(
            leaf in any::<[u8; 32]>(),
            siblings in proptest::collection::vec(any::<[u8; 32]>(), 0..32),
            indices_seed in any::<u64>(),
        ) {
            // Derive boolean indices from the seed so they're
            // deterministic per shrunken case.
            let indices: Vec<bool> = (0..siblings.len())
                .map(|i| (indices_seed >> (i % 64)) & 1 == 1)
                .collect();
            let root = root_for(&leaf, &siblings, &indices);
            let mp = MerklePath {
                path: siblings,
                indices,
            };
            prop_assert!(mp.verify(&leaf, &root));
        }
    }
}
