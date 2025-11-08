//! Pedersen commitment scheme implementation
//!
//! A Pedersen commitment allows committing to a value without revealing it.
//! C = vG + rH where:
//! - v is the value
//! - r is random blinding factor
//! - G, H are generator points
//!
//! For now, this is a simplified hash-based version.
//! Production would use elliptic curve cryptography.

use crate::privacy::types::{Commitment, Note};
use sha2::{Digest, Sha256};

/// Commitment generator - simplified version
pub struct CommitmentGenerator;

impl CommitmentGenerator {
    /// Create a commitment to a value with randomness
    ///
    /// In production, this would be: C = value*G + randomness*H
    /// For now, we use: C = Hash(value || randomness || salt)
    pub fn commit(value: u64, randomness: &[u8; 32]) -> Commitment {
        let mut hasher = Sha256::new();
        hasher.update(value.to_le_bytes());
        hasher.update(randomness);
        hasher.update(b"COMMITMENT_SALT");

        let result = hasher.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&result);

        Commitment(commitment)
    }

    /// Create a commitment from a note
    pub fn commit_note(note: &Note) -> Commitment {
        note.commitment()
    }

    /// Verify a commitment opens to a specific value
    /// (Used during verification - validator checks this)
    pub fn verify_opening(
        commitment: &Commitment,
        value: u64,
        randomness: &[u8; 32],
    ) -> bool {
        let computed = Self::commit(value, randomness);
        commitment == &computed
    }
}

/// Commitment builder for creating notes with commitments
pub struct CommitmentBuilder {
    value: Option<u64>,
    randomness: Option<[u8; 32]>,
}

impl CommitmentBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        CommitmentBuilder {
            value: None,
            randomness: None,
        }
    }

    /// Set the value
    pub fn value(mut self, value: u64) -> Self {
        self.value = Some(value);
        self
    }

    /// Set the randomness (blinding factor)
    pub fn randomness(mut self, randomness: [u8; 32]) -> Self {
        self.randomness = Some(randomness);
        self
    }

    /// Generate random blinding factor
    pub fn random_blinding(mut self) -> Self {
        // In production, use a cryptographically secure RNG
        // For now, use a simple hash-based approach
        let mut hasher = Sha256::new();
        hasher.update(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_le_bytes());

        let result = hasher.finalize();
        let mut randomness = [0u8; 32];
        randomness.copy_from_slice(&result);

        self.randomness = Some(randomness);
        self
    }

    /// Build the commitment
    pub fn build(self) -> Result<Commitment, &'static str> {
        let value = self.value.ok_or("Value not set")?;
        let randomness = self.randomness.ok_or("Randomness not set")?;

        Ok(CommitmentGenerator::commit(value, &randomness))
    }
}

impl Default for CommitmentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::types::ShieldedAddress;

    #[test]
    fn test_commitment_deterministic() {
        let value = 1000u64;
        let randomness = [42u8; 32];

        let c1 = CommitmentGenerator::commit(value, &randomness);
        let c2 = CommitmentGenerator::commit(value, &randomness);

        // Same inputs should produce same commitment
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_commitment_hiding() {
        let value1 = 1000u64;
        let value2 = 2000u64;
        let randomness = [42u8; 32];

        let c1 = CommitmentGenerator::commit(value1, &randomness);
        let c2 = CommitmentGenerator::commit(value2, &randomness);

        // Different values should produce different commitments
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_commitment_blinding() {
        let value = 1000u64;
        let randomness1 = [42u8; 32];
        let randomness2 = [43u8; 32];

        let c1 = CommitmentGenerator::commit(value, &randomness1);
        let c2 = CommitmentGenerator::commit(value, &randomness2);

        // Different randomness should produce different commitments
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_commitment_verification() {
        let value = 5000u64;
        let randomness = [100u8; 32];

        let commitment = CommitmentGenerator::commit(value, &randomness);

        // Correct opening should verify
        assert!(CommitmentGenerator::verify_opening(&commitment, value, &randomness));

        // Wrong value should not verify
        assert!(!CommitmentGenerator::verify_opening(&commitment, 6000, &randomness));

        // Wrong randomness should not verify
        let wrong_randomness = [101u8; 32];
        assert!(!CommitmentGenerator::verify_opening(&commitment, value, &wrong_randomness));
    }

    #[test]
    fn test_note_commitment() {
        let addr = ShieldedAddress([1u8; 32]);
        let note = Note::new(addr, 1000, [42u8; 32]);

        let c1 = CommitmentGenerator::commit_note(&note);
        let c2 = note.commitment();

        // Both methods should produce same result
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_commitment_builder() {
        let randomness = [50u8; 32];
        let commitment = CommitmentBuilder::new()
            .value(2000)
            .randomness(randomness)
            .build()
            .unwrap();

        // Should match direct creation
        let expected = CommitmentGenerator::commit(2000, &randomness);
        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_commitment_builder_missing_value() {
        let result = CommitmentBuilder::new()
            .randomness([1u8; 32])
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_builder_random_blinding() {
        let c1 = CommitmentBuilder::new()
            .value(1000)
            .random_blinding()
            .build()
            .unwrap();

        let c2 = CommitmentBuilder::new()
            .value(1000)
            .random_blinding()
            .build()
            .unwrap();

        // Random blinding should produce different commitments
        assert_ne!(c1, c2);
    }
}
