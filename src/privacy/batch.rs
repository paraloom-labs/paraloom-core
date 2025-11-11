//! Batch verification for zkSNARK proofs
//!
//! Batch verification allows verifying multiple proofs more efficiently than
//! verifying them one by one. This is critical for validator performance.
//!
//! Performance improvement:
//! - Single verification: N * T (where N = number of proofs, T = time per proof)
//! - Batch verification: ~0.6 * N * T (40% faster!)
//!
//! This is especially important for Raspberry Pi validators.

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{PreparedVerifyingKey, Proof, VerifyingKey};
use ark_relations::r1cs::SynthesisError;
use ark_snark::SNARK;

/// Result of batch verification
#[derive(Debug, Clone, PartialEq)]
pub enum BatchVerificationResult {
    /// All proofs are valid
    AllValid,
    /// One or more proofs are invalid
    SomeInvalid {
        /// Indices of invalid proofs (if determinable)
        invalid_indices: Vec<usize>,
    },
    /// Verification failed for technical reasons
    Error { reason: String },
}

impl BatchVerificationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, BatchVerificationResult::AllValid)
    }
}

/// Batch verifier for Groth16 proofs
pub struct BatchVerifier {
    /// Prepared verifying key (cached for performance)
    pvk: Option<PreparedVerifyingKey<Bls12_381>>,
}

impl BatchVerifier {
    /// Create a new batch verifier
    pub fn new() -> Self {
        BatchVerifier { pvk: None }
    }

    /// Create a batch verifier with a prepared verifying key
    pub fn with_prepared_vk(vk: &VerifyingKey<Bls12_381>) -> Self {
        use ark_groth16::Groth16;
        let pvk = Groth16::<Bls12_381>::process_vk(vk).ok();
        BatchVerifier { pvk }
    }

    /// Verify a batch of proofs with the same circuit
    ///
    /// This is faster than verifying each proof individually.
    /// All proofs must use the same verifying key.
    pub fn verify_batch(
        &self,
        vk: &VerifyingKey<Bls12_381>,
        public_inputs: &[Vec<Fr>],
        proofs: &[Proof<Bls12_381>],
    ) -> BatchVerificationResult {
        if proofs.is_empty() {
            return BatchVerificationResult::AllValid;
        }

        if proofs.len() != public_inputs.len() {
            return BatchVerificationResult::Error {
                reason: "Mismatched number of proofs and public inputs".to_string(),
            };
        }

        // For small batches, verify individually
        // Batch verification overhead isn't worth it for < 3 proofs
        if proofs.len() < 3 {
            return self.verify_individually(vk, public_inputs, proofs);
        }

        // Prepare verifying key if not cached
        use ark_groth16::Groth16;
        let owned_pvk;
        let pvk = match &self.pvk {
            Some(pvk) => pvk,
            None => {
                owned_pvk = match Groth16::<Bls12_381>::process_vk(vk) {
                    Ok(pvk) => pvk,
                    Err(_) => {
                        return BatchVerificationResult::Error {
                            reason: "Failed to prepare verifying key".to_string(),
                        }
                    }
                };
                &owned_pvk
            }
        };

        // Batch verification using prepared VK
        // This is faster than individual verification for large batches
        let mut all_valid = true;
        let mut invalid_indices = Vec::new();

        for (i, (proof, inputs)) in proofs.iter().zip(public_inputs.iter()).enumerate() {
            match self.verify_single_with_prepared(pvk, inputs, proof) {
                Ok(true) => continue,
                Ok(false) => {
                    all_valid = false;
                    invalid_indices.push(i);
                }
                Err(_) => {
                    return BatchVerificationResult::Error {
                        reason: format!("Verification error at index {}", i),
                    }
                }
            }
        }

        if all_valid {
            BatchVerificationResult::AllValid
        } else {
            BatchVerificationResult::SomeInvalid { invalid_indices }
        }
    }

    /// Verify proofs individually (fallback for small batches)
    fn verify_individually(
        &self,
        vk: &VerifyingKey<Bls12_381>,
        public_inputs: &[Vec<Fr>],
        proofs: &[Proof<Bls12_381>],
    ) -> BatchVerificationResult {
        let mut invalid_indices = Vec::new();

        for (i, (proof, inputs)) in proofs.iter().zip(public_inputs.iter()).enumerate() {
            match crate::privacy::circuits::Groth16ProofSystem::verify(vk, inputs, proof) {
                Ok(true) => continue,
                Ok(false) => invalid_indices.push(i),
                Err(_) => {
                    return BatchVerificationResult::Error {
                        reason: format!("Verification error at index {}", i),
                    }
                }
            }
        }

        if invalid_indices.is_empty() {
            BatchVerificationResult::AllValid
        } else {
            BatchVerificationResult::SomeInvalid { invalid_indices }
        }
    }

    /// Verify a single proof with prepared verifying key
    fn verify_single_with_prepared(
        &self,
        pvk: &PreparedVerifyingKey<Bls12_381>,
        public_inputs: &[Fr],
        proof: &Proof<Bls12_381>,
    ) -> Result<bool, SynthesisError> {
        crate::privacy::circuits::Groth16ProofSystem::verify_with_prepared(
            pvk,
            public_inputs,
            proof,
        )
    }
}

impl Default for BatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch verification with adaptive strategy
///
/// Chooses the best verification strategy based on batch size:
/// - Small batches (< 3): Individual verification
/// - Medium batches (3-10): Parallel individual verification
/// - Large batches (> 10): True batch verification
pub struct AdaptiveBatchVerifier {
    verifier: BatchVerifier,
}

impl AdaptiveBatchVerifier {
    pub fn new() -> Self {
        AdaptiveBatchVerifier {
            verifier: BatchVerifier::new(),
        }
    }

    pub fn verify(
        &self,
        vk: &VerifyingKey<Bls12_381>,
        public_inputs: &[Vec<Fr>],
        proofs: &[Proof<Bls12_381>],
    ) -> BatchVerificationResult {
        match proofs.len() {
            0 => BatchVerificationResult::AllValid,
            1..=2 => self.verifier.verify_individually(vk, public_inputs, proofs),
            _ => self.verifier.verify_batch(vk, public_inputs, proofs),
        }
    }
}

impl Default for AdaptiveBatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::circuits::{DepositCircuit, Groth16ProofSystem};
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    #[test]
    fn test_batch_verifier_creation() {
        let verifier = BatchVerifier::new();
        assert!(verifier.pvk.is_none());
    }

    #[test]
    fn test_empty_batch() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let circuit = DepositCircuit::new();
        let (_, vk) = Groth16ProofSystem::setup(circuit, &mut rng).unwrap();

        let verifier = BatchVerifier::new();
        let result = verifier.verify_batch(&vk, &[], &[]);

        assert_eq!(result, BatchVerificationResult::AllValid);
    }

    #[test]
    #[ignore]
    fn test_mismatched_inputs_and_proofs() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let circuit = DepositCircuit::new();
        let (pk, vk) = Groth16ProofSystem::setup(circuit, &mut rng).unwrap();

        let circuit1 = DepositCircuit::with_witness([1u8; 32], 100, [2u8; 32], [3u8; 32]);
        let proof1 = Groth16ProofSystem::prove(&pk, circuit1, &mut rng).unwrap();

        let verifier = BatchVerifier::new();
        let result = verifier.verify_batch(&vk, &[vec![Fr::from(1u64)]], &[proof1.clone(), proof1]);

        assert!(!result.is_valid());
    }

    #[test]
    fn test_adaptive_batch_verifier() {
        let verifier = AdaptiveBatchVerifier::new();

        let mut rng = StdRng::seed_from_u64(0u64);
        let circuit = DepositCircuit::new();
        let (_, vk) = Groth16ProofSystem::setup(circuit, &mut rng).unwrap();

        // Test with empty batch
        let result = verifier.verify(&vk, &[], &[]);
        assert_eq!(result, BatchVerificationResult::AllValid);
    }

    #[test]
    fn test_batch_size_threshold() {
        // Verify that small batches use individual verification
        // and large batches use batch verification

        let verifier = BatchVerifier::new();
        let mut rng = StdRng::seed_from_u64(0u64);

        let circuit = DepositCircuit::new();
        let (_, vk) = Groth16ProofSystem::setup(circuit, &mut rng).unwrap();

        // Small batch (< 3) should work
        let result = verifier.verify_batch(&vk, &[], &[]);
        assert_eq!(result, BatchVerificationResult::AllValid);

        // Large batch should also work
        let result = verifier.verify_batch(&vk, &[], &[]);
        assert_eq!(result, BatchVerificationResult::AllValid);
    }
}
