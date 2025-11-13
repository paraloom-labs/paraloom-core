//! Zero-knowledge proof system interface
//!
//! Implements Groth16 zkSNARK verification for withdrawal proofs using Arkworks.

use crate::privacy::circuits::Groth16ProofSystem;
use crate::privacy::transaction::{DepositTx, TransferTx, WithdrawTx};
use crate::privacy::types::{Commitment, MerklePath, Nullifier};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::ToConstraintField;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Proof verification result
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum VerificationResult {
    /// Proof is valid
    Valid,
    /// Proof is invalid
    Invalid { reason: String },
}

impl VerificationResult {
    /// Check if result is valid
    pub fn is_valid(&self) -> bool {
        matches!(self, VerificationResult::Valid)
    }
}

/// Components that can be verified independently (for distributed verification)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VerificationChunk {
    /// Verify input commitments exist in Merkle tree
    InputCommitments {
        commitments: Vec<Commitment>,
        merkle_paths: Vec<MerklePath>,
        merkle_root: [u8; 32],
    },

    /// Verify output commitments are well-formed
    OutputCommitments { commitments: Vec<Commitment> },

    /// Verify nullifiers are unique
    NullifierUniqueness { nullifiers: Vec<Nullifier> },

    /// Verify Merkle proof
    MerkleProof {
        leaf: [u8; 32],
        path: MerklePath,
        root: [u8; 32],
    },

    /// Verify range proof (amount is valid)
    RangeProof {
        commitment: Commitment,
        proof_data: Vec<u8>,
    },
}

impl VerificationChunk {
    /// Verify this chunk
    pub fn verify(&self) -> VerificationResult {
        match self {
            VerificationChunk::InputCommitments {
                commitments: _,
                merkle_paths,
                merkle_root,
            } => {
                // Placeholder: In production, verify each path
                if merkle_paths.is_empty() {
                    return VerificationResult::Invalid {
                        reason: "No Merkle paths provided".to_string(),
                    };
                }

                // Verify each path against root
                for path in merkle_paths {
                    // Simplified verification
                    if path.path.is_empty() {
                        return VerificationResult::Invalid {
                            reason: "Empty Merkle path".to_string(),
                        };
                    }

                    // In production: path.verify(commitment, merkle_root)
                    let _ = merkle_root; // Suppress warning
                }

                VerificationResult::Valid
            }

            VerificationChunk::OutputCommitments { commitments } => {
                if commitments.is_empty() {
                    return VerificationResult::Invalid {
                        reason: "No output commitments".to_string(),
                    };
                }

                // Commitments must be non-zero
                for commitment in commitments {
                    if commitment.as_bytes() == &[0u8; 32] {
                        return VerificationResult::Invalid {
                            reason: "Zero commitment detected".to_string(),
                        };
                    }
                }

                VerificationResult::Valid
            }

            VerificationChunk::NullifierUniqueness { nullifiers } => {
                if nullifiers.is_empty() {
                    return VerificationResult::Invalid {
                        reason: "No nullifiers provided".to_string(),
                    };
                }

                // Check for duplicates within batch
                use std::collections::HashSet;
                let mut seen = HashSet::new();
                for nullifier in nullifiers {
                    if !seen.insert(nullifier) {
                        return VerificationResult::Invalid {
                            reason: "Duplicate nullifier in transaction".to_string(),
                        };
                    }
                }

                VerificationResult::Valid
            }

            VerificationChunk::MerkleProof { leaf, path, root } => {
                // Verify path
                if path.verify(leaf, root) {
                    VerificationResult::Valid
                } else {
                    VerificationResult::Invalid {
                        reason: "Merkle path verification failed".to_string(),
                    }
                }
            }

            VerificationChunk::RangeProof {
                commitment: _,
                proof_data,
            } => {
                // Placeholder: In production, verify range proof
                if proof_data.is_empty() {
                    // Empty proof is accepted for now (placeholder)
                    return VerificationResult::Valid;
                }

                // In production: verify actual range proof
                VerificationResult::Valid
            }
        }
    }
}

/// Global verifying key for withdrawal proofs
/// Loaded once from disk and cached for all verifications
static WITHDRAWAL_VERIFYING_KEY: OnceLock<VerifyingKey<Bls12_381>> = OnceLock::new();

/// ZK Proof verifier interface
pub struct ProofVerifier;

impl ProofVerifier {
    /// Load withdrawal verifying key from disk (cached)
    fn get_verifying_key() -> Result<&'static VerifyingKey<Bls12_381>, String> {
        WITHDRAWAL_VERIFYING_KEY.get_or_init(|| {
            let key_path = std::env::var("WITHDRAWAL_VERIFYING_KEY_PATH")
                .unwrap_or_else(|_| "keys/withdraw_verifying.key".to_string());

            let key_bytes = std::fs::read(&key_path)
                .map_err(|e| format!("Failed to read verifying key from {}: {}", key_path, e))
                .expect("Verifying key file not found");

            VerifyingKey::<Bls12_381>::deserialize_compressed(&key_bytes[..])
                .expect("Failed to deserialize verifying key")
        });

        WITHDRAWAL_VERIFYING_KEY
            .get()
            .ok_or_else(|| "Verifying key not loaded".to_string())
    }

    /// Verify a deposit transaction
    pub fn verify_deposit(_tx: &DepositTx) -> VerificationResult {
        // Placeholder: Deposits don't need ZK proofs (public -> private)
        // Just verify the structure
        VerificationResult::Valid
    }

    /// Verify a transfer transaction
    pub fn verify_transfer(tx: &TransferTx) -> VerificationResult {
        // In production, this would verify the zk-SNARK proof
        // For now, verify structural correctness

        if !tx.verify_structure() {
            return VerificationResult::Invalid {
                reason: "Invalid transaction structure".to_string(),
            };
        }

        if !tx.verify_range_proofs() {
            return VerificationResult::Invalid {
                reason: "Range proof verification failed".to_string(),
            };
        }

        // Placeholder: Accept for now
        VerificationResult::Valid
    }

    /// Verify a withdraw transaction with real zkSNARK proof
    pub fn verify_withdraw(tx: &WithdrawTx) -> VerificationResult {
        // Basic structure validation
        if !tx.verify() {
            return VerificationResult::Invalid {
                reason: "Invalid withdraw transaction structure".to_string(),
            };
        }

        // Load verifying key
        let verifying_key = match Self::get_verifying_key() {
            Ok(vk) => vk,
            Err(e) => {
                log::error!("Failed to load verifying key: {}", e);
                return VerificationResult::Invalid {
                    reason: format!("Verifying key not available: {}", e),
                };
            }
        };

        // Deserialize proof from bytes
        let proof = match Proof::<Bls12_381>::deserialize_compressed(&tx.zk_proof[..]) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Failed to deserialize proof: {}", e);
                return VerificationResult::Invalid {
                    reason: format!("Invalid proof format: {}", e),
                };
            }
        };

        // Prepare public inputs (5 field elements total)
        // UInt8::new_input_vec in circuit packs 32 bytes into 2 field elements
        let mut public_inputs = Vec::new();

        // Merkle root: 32 bytes → 2 Fr elements
        let root_fes: Vec<Fr> = tx.merkle_root.to_field_elements().unwrap();
        public_inputs.extend(root_fes);

        // Nullifier: 32 bytes → 2 Fr elements
        let null_fes: Vec<Fr> = tx.input_nullifier.0.to_field_elements().unwrap();
        public_inputs.extend(null_fes);

        // Amount: 1 Fr element
        public_inputs.push(Fr::from(tx.amount));

        // Verify the zkSNARK proof
        match Groth16ProofSystem::verify(verifying_key, &public_inputs, &proof) {
            Ok(true) => {
                log::info!(
                    "zkSNARK proof verified successfully for nullifier: {:?}",
                    hex::encode(tx.input_nullifier.0)
                );
                VerificationResult::Valid
            }
            Ok(false) => {
                log::warn!(
                    "zkSNARK proof verification failed for nullifier: {:?}",
                    hex::encode(tx.input_nullifier.0)
                );
                VerificationResult::Invalid {
                    reason: "zkSNARK proof verification failed".to_string(),
                }
            }
            Err(e) => {
                log::error!("zkSNARK verification error: {}", e);
                VerificationResult::Invalid {
                    reason: format!("Verification error: {}", e),
                }
            }
        }
    }

    /// Split verification into chunks for distributed processing
    pub fn create_verification_chunks(tx: &TransferTx) -> Vec<VerificationChunk> {
        let mut chunks = Vec::new();

        // Chunk 1: Output commitments
        chunks.push(VerificationChunk::OutputCommitments {
            commitments: tx.output_commitments.clone(),
        });

        // Chunk 2: Nullifier uniqueness
        chunks.push(VerificationChunk::NullifierUniqueness {
            nullifiers: tx.input_nullifiers.clone(),
        });

        // Chunk 3-N: Range proofs for each output
        for (commitment, proof) in tx.output_commitments.iter().zip(tx.range_proofs.iter()) {
            chunks.push(VerificationChunk::RangeProof {
                commitment: commitment.clone(),
                proof_data: proof.proof.clone(),
            });
        }

        chunks
    }

    /// Aggregate chunk verification results
    pub fn aggregate_results(results: &[VerificationResult]) -> VerificationResult {
        for result in results {
            if !result.is_valid() {
                return result.clone();
            }
        }
        VerificationResult::Valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::types::{Note, ShieldedAddress};

    #[test]
    fn test_output_commitments_chunk() {
        let commitments = vec![Commitment([1u8; 32]), Commitment([2u8; 32])];

        let chunk = VerificationChunk::OutputCommitments { commitments };

        assert!(chunk.verify().is_valid());
    }

    #[test]
    fn test_output_commitments_empty() {
        let chunk = VerificationChunk::OutputCommitments {
            commitments: vec![],
        };

        assert!(!chunk.verify().is_valid());
    }

    #[test]
    fn test_output_commitments_zero() {
        let chunk = VerificationChunk::OutputCommitments {
            commitments: vec![Commitment([0u8; 32])],
        };

        assert!(!chunk.verify().is_valid());
    }

    #[test]
    fn test_nullifier_uniqueness() {
        let nullifiers = vec![Nullifier([1u8; 32]), Nullifier([2u8; 32])];

        let chunk = VerificationChunk::NullifierUniqueness { nullifiers };

        assert!(chunk.verify().is_valid());
    }

    #[test]
    fn test_nullifier_duplicate() {
        let nullifiers = vec![
            Nullifier([1u8; 32]),
            Nullifier([1u8; 32]), // Duplicate
        ];

        let chunk = VerificationChunk::NullifierUniqueness { nullifiers };

        assert!(!chunk.verify().is_valid());
    }

    #[test]
    fn test_verification_chunks_creation() {
        let nullifiers = vec![Nullifier([1u8; 32])];
        let note = Note::new(ShieldedAddress([1u8; 32]), 100, [1u8; 32]);

        let tx = TransferTx::new(nullifiers, vec![note], [0u8; 32], 10);

        let chunks = ProofVerifier::create_verification_chunks(&tx);

        // Should have: outputs, nullifiers, and 1 range proof
        assert_eq!(chunks.len(), 3);
    }

    #[test]
    fn test_aggregate_results_all_valid() {
        let results = vec![
            VerificationResult::Valid,
            VerificationResult::Valid,
            VerificationResult::Valid,
        ];

        let aggregated = ProofVerifier::aggregate_results(&results);
        assert!(aggregated.is_valid());
    }

    #[test]
    fn test_aggregate_results_one_invalid() {
        let results = vec![
            VerificationResult::Valid,
            VerificationResult::Invalid {
                reason: "Test error".to_string(),
            },
            VerificationResult::Valid,
        ];

        let aggregated = ProofVerifier::aggregate_results(&results);
        assert!(!aggregated.is_valid());
    }

    #[test]
    fn test_merkle_proof_chunk() {
        let leaf = [1u8; 32];
        let path = MerklePath::empty();
        let root = [1u8; 32]; // Same as leaf for empty path

        let chunk = VerificationChunk::MerkleProof { leaf, path, root };

        assert!(chunk.verify().is_valid());
    }
}
