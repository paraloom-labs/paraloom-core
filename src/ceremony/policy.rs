//! Fail-closed policy gate for ceremony finalization.
//!
//! The cryptographic verifiers ([`verify_phase2_transcript`],
//! [`verify_final_pk`], [`verify_final_pk_consistency`]) prove that a
//! transcript's contribution chain is internally honest and that the
//! promoted key is the one the chain culminates in. What they do not
//! decide is whether the transcript is *sufficient* to promote at all:
//! an empty transcript verifies vacuously, and for an empty transcript
//! the final-key binding accepts the initial single-party key itself —
//! so a finalize run against the wrong (or never-contributed) files
//! would happily promote a key whose trapdoor one party still holds.
//!
//! This module is the promotion-boundary policy that closes that gap.
//! Finalize refuses to write production keys unless:
//!
//! 1. the transcript is non-empty and carries at least the operator's
//!    required minimum number of contributions;
//! 2. the operator-pinned SHA-512 of the initial proving key matches
//!    both the hash recorded in the transcript and the initial-key
//!    file actually read from disk — binding the run to the exact SRS
//!    the contributors started from;
//! 3. the final key's delta actually differs from the initial key's —
//!    a ceremony that leaves delta unchanged contributed nothing;
//! 4. optionally, the chain tip is the exact contribution the
//!    coordinator last verified (a pinned tail hash), so a transcript
//!    with extra or substituted contributions is refused even when it
//!    is internally consistent.
//!
//! Contributor signature enforcement is deliberately not part of this
//! policy: the contribute CLI does not yet populate signatures, and
//! requiring them retroactively would invalidate honest transcripts.
//! It remains a mainnet-ceremony gate (issue #64).
//!
//! [`verify_phase2_transcript`]: super::verifier::verify_phase2_transcript
//! [`verify_final_pk`]: super::verifier::verify_final_pk
//! [`verify_final_pk_consistency`]: super::verifier::verify_final_pk_consistency

use ark_bn254::Bn254;
use ark_groth16::ProvingKey;

use super::transcript::{hash_contribution, Phase2Transcript, TranscriptHash};

/// Operator-supplied requirements a transcript must meet before
/// finalize will promote it to production keys.
pub struct FinalizePolicy {
    /// Minimum number of contributions. A floor of 1 is enforced
    /// regardless — an empty transcript is never promotable — so
    /// passing 0 does not open the empty-transcript path back up.
    pub min_contributions: usize,

    /// SHA-512 of the initial single-source proving key. Must equal
    /// both the transcript's recorded `initial_srs_hash` and the
    /// digest of the initial-key file finalize actually read.
    pub initial_srs_hash: TranscriptHash,

    /// If set, the hash of the transcript's last contribution must
    /// equal this value — the coordinator pins the chain tip they
    /// verified so finalize cannot run on a longer or altered chain.
    pub final_contribution_hash: Option<TranscriptHash>,
}

/// Errors surfaced by [`enforce_finalize_policy`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("transcript has no contributions; an empty ceremony must not be finalized")]
    EmptyTranscript,

    #[error("transcript has {got} contribution(s) but the policy requires at least {min}")]
    TooFewContributions { got: usize, min: usize },

    #[error(
        "the transcript's recorded initial SRS hash does not match the pinned hash; \
         this transcript was not started from the pinned initial key"
    )]
    TranscriptSrsHashMismatch,

    #[error(
        "the initial proving key file on disk does not hash to the pinned initial \
         SRS hash; finalize was pointed at the wrong initial key"
    )]
    InitialKeyHashMismatch,

    #[error(
        "the final key's delta is unchanged from the initial key; the ceremony \
         applied no effective contribution"
    )]
    FinalKeyUnchanged,

    #[error(
        "the transcript's last contribution does not match the pinned chain-tip \
         hash; the chain differs from the one the coordinator verified"
    )]
    FinalContributionMismatch,
}

/// Enforce a [`FinalizePolicy`] against the files a finalize run read.
///
/// `initial_pk_file_hash` is the SHA-512 of the raw initial-key file
/// bytes as read from disk — hashed by the caller so this check stays
/// IO-free. Run this *before* the cryptographic verifiers: every check
/// here is cheap, and a policy refusal should not spend minutes on
/// pairings first.
pub fn enforce_finalize_policy(
    policy: &FinalizePolicy,
    initial_pk_file_hash: &TranscriptHash,
    initial_pk: &ProvingKey<Bn254>,
    final_pk: &ProvingKey<Bn254>,
    transcript: &Phase2Transcript,
) -> Result<(), PolicyError> {
    if transcript.is_empty() {
        return Err(PolicyError::EmptyTranscript);
    }
    let min = policy.min_contributions.max(1);
    if transcript.len() < min {
        return Err(PolicyError::TooFewContributions {
            got: transcript.len(),
            min,
        });
    }

    if transcript.initial_srs_hash != policy.initial_srs_hash {
        return Err(PolicyError::TranscriptSrsHashMismatch);
    }
    if *initial_pk_file_hash != policy.initial_srs_hash {
        return Err(PolicyError::InitialKeyHashMismatch);
    }

    if final_pk.delta_g1 == initial_pk.delta_g1 && final_pk.vk.delta_g2 == initial_pk.vk.delta_g2 {
        return Err(PolicyError::FinalKeyUnchanged);
    }

    if let Some(pinned_tail) = &policy.final_contribution_hash {
        let tip = transcript
            .contributions
            .last()
            .expect("non-empty checked above");
        if hash_contribution(tip) != *pinned_tail {
            return Err(PolicyError::FinalContributionMismatch);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::transcript::{CircuitId, Contribution};
    use crate::types::NodeId;
    use ark_bn254::Fr;
    use ark_groth16::Groth16;
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_snark::SNARK;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Trivial circuit so circuit_specific_setup yields real
    /// ProvingKey<Bn254> values with distinct deltas per rng seed.
    #[derive(Clone)]
    struct TrivialCircuit;

    impl ConstraintSynthesizer<Fr> for TrivialCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| Ok(Fr::from(3u32)))?;
            let b = cs.new_witness_variable(|| Ok(Fr::from(5u32)))?;
            let c = cs.new_input_variable(|| Ok(Fr::from(15u32)))?;
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            Ok(())
        }
    }

    fn pk_from_seed(seed: u64) -> ProvingKey<Bn254> {
        let mut rng = StdRng::seed_from_u64(seed);
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(TrivialCircuit, &mut rng).unwrap();
        pk
    }

    /// Policy checks never touch the DLEQ proofs, so dummy
    /// contribution bytes are sufficient — only the hash chain
    /// linkage has to be genuine for `append` to accept them.
    fn dummy_transcript(initial_hash: TranscriptHash, n: usize) -> Phase2Transcript {
        let mut t = Phase2Transcript::new(CircuitId::Withdraw, initial_hash);
        for i in 0..n {
            let prior_hash = match t.contributions.last() {
                Some(prev) => hash_contribution(prev),
                None => initial_hash,
            };
            t.append(Contribution {
                prior_hash,
                contributor: NodeId(vec![i as u8]),
                delta_after_g1: vec![0xAA; 48],
                delta_after_g2: vec![0xBB; 96],
                dleq_proof: vec![0xCC; 96],
                contributor_pubkey: Vec::new(),
                signature: Vec::new(),
                attestation: format!("policy test contributor {}", i),
            })
            .unwrap();
        }
        t
    }

    const PINNED: TranscriptHash = [0x42u8; 64];

    fn policy(min: usize, tail: Option<TranscriptHash>) -> FinalizePolicy {
        FinalizePolicy {
            min_contributions: min,
            initial_srs_hash: PINNED,
            final_contribution_hash: tail,
        }
    }

    #[test]
    fn empty_transcript_is_rejected_even_with_min_zero() {
        let initial = pk_from_seed(1);
        let final_pk = pk_from_seed(2);
        let t = dummy_transcript(PINNED, 0);
        match enforce_finalize_policy(&policy(0, None), &PINNED, &initial, &final_pk, &t) {
            Err(PolicyError::EmptyTranscript) => {}
            other => panic!("expected EmptyTranscript, got {:?}", other),
        }
    }

    #[test]
    fn below_minimum_contribution_count_is_rejected() {
        let initial = pk_from_seed(1);
        let final_pk = pk_from_seed(2);
        let t = dummy_transcript(PINNED, 1);
        match enforce_finalize_policy(&policy(2, None), &PINNED, &initial, &final_pk, &t) {
            Err(PolicyError::TooFewContributions { got: 1, min: 2 }) => {}
            other => panic!("expected TooFewContributions(1,2), got {:?}", other),
        }
    }

    #[test]
    fn transcript_started_from_a_different_srs_is_rejected() {
        let initial = pk_from_seed(1);
        let final_pk = pk_from_seed(2);
        let t = dummy_transcript([0x99u8; 64], 2);
        match enforce_finalize_policy(&policy(2, None), &PINNED, &initial, &final_pk, &t) {
            Err(PolicyError::TranscriptSrsHashMismatch) => {}
            other => panic!("expected TranscriptSrsHashMismatch, got {:?}", other),
        }
    }

    #[test]
    fn wrong_initial_key_file_is_rejected() {
        let initial = pk_from_seed(1);
        let final_pk = pk_from_seed(2);
        let t = dummy_transcript(PINNED, 2);
        let wrong_file_hash: TranscriptHash = [0x13u8; 64];
        match enforce_finalize_policy(&policy(2, None), &wrong_file_hash, &initial, &final_pk, &t) {
            Err(PolicyError::InitialKeyHashMismatch) => {}
            other => panic!("expected InitialKeyHashMismatch, got {:?}", other),
        }
    }

    #[test]
    fn final_key_equal_to_initial_key_is_rejected() {
        let initial = pk_from_seed(1);
        let final_pk = initial.clone();
        let t = dummy_transcript(PINNED, 2);
        match enforce_finalize_policy(&policy(2, None), &PINNED, &initial, &final_pk, &t) {
            Err(PolicyError::FinalKeyUnchanged) => {}
            other => panic!("expected FinalKeyUnchanged, got {:?}", other),
        }
    }

    #[test]
    fn mismatched_chain_tip_is_rejected() {
        let initial = pk_from_seed(1);
        let final_pk = pk_from_seed(2);
        let t = dummy_transcript(PINNED, 2);
        let wrong_tail: TranscriptHash = [0x77u8; 64];
        match enforce_finalize_policy(
            &policy(2, Some(wrong_tail)),
            &PINNED,
            &initial,
            &final_pk,
            &t,
        ) {
            Err(PolicyError::FinalContributionMismatch) => {}
            other => panic!("expected FinalContributionMismatch, got {:?}", other),
        }
    }

    #[test]
    fn compliant_transcript_passes_with_and_without_tail_pin() {
        let initial = pk_from_seed(1);
        let final_pk = pk_from_seed(2);
        let t = dummy_transcript(PINNED, 4);

        enforce_finalize_policy(&policy(2, None), &PINNED, &initial, &final_pk, &t)
            .expect("4-contribution transcript passes a min-2 policy");

        let tail = hash_contribution(t.contributions.last().unwrap());
        enforce_finalize_policy(&policy(4, Some(tail)), &PINNED, &initial, &final_pk, &t)
            .expect("exact-count policy with the true tail pin passes");
    }
}
