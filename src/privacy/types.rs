//! Privacy-specific types for the shielded pool

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

    /// Derive nullifier from commitment and spending key
    pub fn derive(commitment: &Commitment, spending_key: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(commitment.as_bytes());
        hasher.update(spending_key);
        let result = hasher.finalize();

        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&result);
        Nullifier(nullifier)
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

    /// Compute commitment for this note
    pub fn commitment(&self) -> Commitment {
        let mut hasher = Sha256::new();
        hasher.update(self.recipient.as_bytes());
        hasher.update(self.amount.to_le_bytes());
        hasher.update(self.randomness);

        let result = hasher.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&result);

        Commitment(commitment)
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

    /// Verify that a leaf is in the tree with given root
    pub fn verify(&self, leaf: &[u8; 32], root: &[u8; 32]) -> bool {
        let mut current = *leaf;

        for (sibling, is_right) in self.path.iter().zip(self.indices.iter()) {
            let mut hasher = Sha256::new();
            if *is_right {
                hasher.update(current);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(current);
            }
            let result = hasher.finalize();
            current.copy_from_slice(&result);
        }

        &current == root
    }
}

/// Amount range proof (proves value is in valid range without revealing it)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProof {
    /// Proof data (placeholder)
    pub proof: Vec<u8>,
}

impl RangeProof {
    /// Create a placeholder range proof
    pub fn placeholder() -> Self {
        RangeProof { proof: Vec::new() }
    }

    /// Verify the range proof
    pub fn verify(&self, _commitment: &Commitment) -> bool {
        // Placeholder - would implement actual verification
        true
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
}
