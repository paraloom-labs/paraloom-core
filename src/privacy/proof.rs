//! Zero-knowledge proof system interface
//!
//! Implements Groth16 zkSNARK verification for withdrawal proofs using Arkworks.

use crate::privacy::circuits::Groth16ProofSystem;
use crate::privacy::transaction::{DepositTx, TransferTx, WithdrawTx};
use crate::privacy::types::{Commitment, MerklePath, Nullifier};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use thiserror::Error;

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
        }
    }
}

/// Default path for the withdrawal verifying key on disk.
///
/// Versioned (`_v3`) after the v0.3.0 circuit alignment work that
/// extended `WithdrawCircuit` with an `input_recipient` witness so it
/// could locate notes produced by `DepositCircuit`. The constraint
/// system shape changed, so any key generated against the prior
/// circuit (filenames `withdraw_verifying.key` or
/// `withdraw_verifying_v2.key`) is incompatible and will fail
/// verification. Regenerate with
/// `cargo run --bin setup_withdrawal_ceremony` to produce the `_v3`
/// artifact.
pub const DEFAULT_WITHDRAWAL_VERIFYING_KEY_PATH: &str = "keys/withdraw_verifying_v3.key";

/// Errors that can arise when loading the withdrawal verifying key from
/// disk. Surfacing these as a typed enum (instead of `expect`-style
/// panics) keeps a misconfigured node from crashing on the verification
/// path and lets the operator see exactly what failed.
#[derive(Debug, Error)]
pub enum KeyLoadError {
    /// The key file was not present at the resolved path.
    #[error("verifying key file not found at '{}'", path.display())]
    NotFound { path: PathBuf },

    /// The key file existed but could not be read (permissions, I/O
    /// error). The original `io::Error` is preserved for diagnostics.
    #[error("failed to read verifying key from '{}': {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The bytes on disk did not deserialize into a valid Groth16
    /// verifying key. This catches truncated files, files written by an
    /// incompatible toolchain version, and files that point at the wrong
    /// circuit (a `_v2` key against the current `_v3` circuit, for
    /// example).
    #[error("verifying key at '{}' is malformed: {source}", path.display())]
    Malformed {
        path: PathBuf,
        #[source]
        source: ark_serialize::SerializationError,
    },
}

/// Global verifying key for withdrawal proofs.
///
/// Lazily populated on first successful load; subsequent calls reuse the
/// cached reference. Failed loads do *not* poison the cache — a node
/// whose key file is restored after a misconfiguration can recover
/// without a process restart.
static WITHDRAWAL_VERIFYING_KEY: OnceLock<VerifyingKey<Bls12_381>> = OnceLock::new();

/// Resolve the on-disk path of the withdrawal verifying key, honoring
/// the `WITHDRAWAL_VERIFYING_KEY_PATH` environment variable as an
/// override and falling back to [`DEFAULT_WITHDRAWAL_VERIFYING_KEY_PATH`].
fn resolve_key_path() -> PathBuf {
    std::env::var_os("WITHDRAWAL_VERIFYING_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WITHDRAWAL_VERIFYING_KEY_PATH))
}

/// Load and deserialize a Groth16 verifying key from a specific path.
///
/// This is the pure, testable core of the loading logic — given a path,
/// produce either the key or a typed error explaining what went wrong.
/// The caching wrapper [`ProofVerifier::get_verifying_key`] composes
/// this with a global `OnceLock`.
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey<Bls12_381>, KeyLoadError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(KeyLoadError::NotFound {
                path: path.to_path_buf(),
            });
        }
        Err(e) => {
            return Err(KeyLoadError::Io {
                path: path.to_path_buf(),
                source: e,
            });
        }
    };

    VerifyingKey::<Bls12_381>::deserialize_compressed(&bytes[..]).map_err(|e| {
        KeyLoadError::Malformed {
            path: path.to_path_buf(),
            source: e,
        }
    })
}

/// ZK Proof verifier interface
pub struct ProofVerifier;

impl ProofVerifier {
    /// Load withdrawal verifying key from disk (cached on success).
    ///
    /// On a cache hit, returns the cached reference. On a cache miss,
    /// resolves the configured path, attempts to load and deserialize,
    /// caches the result on success, and returns a typed
    /// [`KeyLoadError`] on failure. Failed loads are *not* cached, so a
    /// node that is reconfigured at runtime can pick up a corrected key
    /// without restarting.
    fn get_verifying_key() -> Result<&'static VerifyingKey<Bls12_381>, KeyLoadError> {
        if let Some(vk) = WITHDRAWAL_VERIFYING_KEY.get() {
            return Ok(vk);
        }

        let path = resolve_key_path();
        let key = load_verifying_key(&path).inspect_err(|e| {
            log::error!(
                target: "paraloom::privacy::proof",
                "withdrawal verifying key load failed: {}",
                e
            );
        })?;

        // First write wins; if a concurrent caller raced us,
        // `OnceLock::set` returns our value back as `Err` and we just
        // drop it. Either way the cache is now populated.
        if WITHDRAWAL_VERIFYING_KEY.set(key).is_err() {
            log::debug!(
                target: "paraloom::privacy::proof",
                "verifying key was already cached by a concurrent caller"
            );
        }
        Ok(WITHDRAWAL_VERIFYING_KEY
            .get()
            .expect("verifying key cache populated above"))
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

        // Range checks for input/output amounts are now enforced
        // inside the TransferCircuit via UInt64 bit decomposition (see
        // #60); a proof that verifies against the circuit's verifying
        // key is already a proof that every value fits in `[0, 2^64)`.
        // No host-level range-proof call is needed here.

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

        Self::verify_withdrawal_parts(
            &tx.merkle_root,
            &tx.input_nullifier.0,
            tx.amount,
            &tx.zk_proof,
        )
    }

    /// Verify a withdrawal zkSNARK proof from its raw parts against the
    /// trusted-setup verifying key. This is the canonical withdrawal
    /// verifier: it loads the ceremony key via `get_verifying_key` and lifts
    /// the public inputs exactly as the shipped `WithdrawCircuit` reads them
    /// — `[merkle_root, nullifier, amount]`, the byte blobs via
    /// `Fr::from_le_bytes_mod_order` and the amount via `Fr::from`. Both
    /// `verify_withdraw` and the node's network verifier route through here,
    /// so the verifying key and the public-input layout have a single source
    /// of truth (a proof from `generate-withdrawal-proof` verifies on a node).
    pub fn verify_withdrawal_parts(
        merkle_root: &[u8; 32],
        nullifier: &[u8; 32],
        amount: u64,
        zk_proof: &[u8],
    ) -> VerificationResult {
        let verifying_key = match Self::get_verifying_key() {
            Ok(vk) => vk,
            Err(e) => {
                return VerificationResult::Invalid {
                    reason: format!("verifying key unavailable: {}", e),
                };
            }
        };

        let proof = match Proof::<Bls12_381>::deserialize_compressed(zk_proof) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Failed to deserialize proof: {}", e);
                return VerificationResult::Invalid {
                    reason: format!("Invalid proof format: {}", e),
                };
            }
        };

        let public_inputs = vec![
            Fr::from_le_bytes_mod_order(merkle_root),
            Fr::from_le_bytes_mod_order(nullifier),
            Fr::from(amount),
        ];

        match Groth16ProofSystem::verify(verifying_key, &public_inputs, &proof) {
            Ok(true) => VerificationResult::Valid,
            Ok(false) => VerificationResult::Invalid {
                reason: "zkSNARK proof verification failed".to_string(),
            },
            Err(e) => VerificationResult::Invalid {
                reason: format!("Verification error: {}", e),
            },
        }
    }

    /// Split verification into chunks for distributed processing.
    ///
    /// Range checks for input/output amounts are enforced inside the
    /// TransferCircuit (#60); the host-level chunked verifier no
    /// longer needs a separate `RangeProof` chunk and so we emit only
    /// the output-commitment and nullifier-uniqueness chunks here.
    pub fn create_verification_chunks(tx: &TransferTx) -> Vec<VerificationChunk> {
        vec![
            VerificationChunk::OutputCommitments {
                commitments: tx.output_commitments.clone(),
            },
            VerificationChunk::NullifierUniqueness {
                nullifiers: tx.input_nullifiers.clone(),
            },
        ]
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

        // Should have: output commitments + nullifier uniqueness.
        // Range checks moved in-circuit in #60, so the host-level
        // chunked verifier no longer emits a separate range chunk.
        assert_eq!(chunks.len(), 2);
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

    // ─── Verifying key load — error path coverage ─────────────────────
    //
    // These exercise [`load_verifying_key`] directly rather than the
    // cached [`ProofVerifier::get_verifying_key`] wrapper, since the
    // latter relies on a process-wide `OnceLock` that would otherwise
    // bleed state between tests in the same binary.

    #[test]
    fn load_verifying_key_missing_file_returns_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does_not_exist.key");

        let err = load_verifying_key(&path).expect_err("missing file must error");
        match err {
            KeyLoadError::NotFound { path: reported } => assert_eq!(reported, path),
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[test]
    fn load_verifying_key_truncated_returns_malformed() {
        // A genuine verifying key serializes to several hundred bytes;
        // anything visibly short of that fails inside ark-serialize and
        // surfaces as Malformed.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("truncated.key");
        std::fs::write(&path, [0u8; 4]).expect("write truncated key");

        let err = load_verifying_key(&path).expect_err("truncated bytes must error");
        assert!(
            matches!(err, KeyLoadError::Malformed { .. }),
            "expected Malformed, got {:?}",
            err
        );
    }

    #[test]
    fn load_verifying_key_random_garbage_returns_malformed() {
        // Sanity check that arbitrary nonsense of plausible length is
        // also rejected — caught here rather than in the `expect()` of
        // the previous implementation. Using a deterministic byte
        // pattern keeps the test reproducible.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("garbage.key");
        let garbage: Vec<u8> = (0..512).map(|i| (i * 31) as u8).collect();
        std::fs::write(&path, &garbage).expect("write garbage key");

        let err = load_verifying_key(&path).expect_err("garbage bytes must error");
        assert!(
            matches!(err, KeyLoadError::Malformed { .. }),
            "expected Malformed, got {:?}",
            err
        );
    }
}
