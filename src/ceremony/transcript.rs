//! Phase 2 ceremony transcript: data layer.
//!
//! This module is the persistent record of the multi-party
//! computation: the chain of contributions, each contributor's
//! proof that they applied their `δ_i` consistently, and the hash
//! chain that pins the order. The actual BGM17 contribution math
//! and the discrete-log-equality (DLEQ) verifier live in sibling
//! modules; this file is intentionally crypto-free so the data
//! schema can evolve without touching protocol-critical code.
//!
//! ## Wire format and stability
//!
//! The transcript is serialised with `bincode` for on-disk
//! storage and over-the-wire transfer between contributors. Every
//! field is `Serialize + Deserialize`. Adding a new field to
//! `Contribution` or `Phase2Transcript` requires bumping
//! `TRANSCRIPT_VERSION` so verifiers can refuse a transcript
//! produced by a future code revision they do not understand.
//!
//! ## Hash chain
//!
//! Each `Contribution` records `prior_hash`: the SHA-512 hash of
//! the previous contribution's serialised bytes (or the
//! initial-state hash for the first contribution). Tampering with
//! any contribution breaks the chain at that point, so a verifier
//! detects the modification by recomputing the chain end-to-end.
//!
//! See `docs/mpc-ceremony.md` (locally; not committed per project
//! convention) and issue #64 for the surrounding protocol design.

use crate::types::NodeId;
use serde::{Deserialize, Serialize};

/// Wire-format version stamped on every transcript. A verifier
/// reading a transcript with a higher version refuses to validate
/// rather than silently mis-interpret unknown fields.
pub const TRANSCRIPT_VERSION: u32 = 1;

/// 64-byte SHA-512 digest. Stored as a fixed-size byte array
/// rather than a hex-encoded string so the chain check stays a
/// pure-byte comparison.
pub type TranscriptHash = [u8; 64];

/// Serde helper for `[u8; 64]` fields. Derive expansion does not
/// support arrays larger than 32 elements, so transcript fields
/// of type `TranscriptHash` are annotated `#[serde(with =
/// "serde_hash")]` to delegate to this module.
mod serde_hash {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(h: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_bytes(h)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let bytes = Vec::<u8>::deserialize(de)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"64 bytes for a TranscriptHash",
            ));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Identifier of the circuit a transcript was produced against.
///
/// A Groth16 phase-2 SRS is bound to a specific R1CS, so a single
/// transcript is meaningful only for one circuit. The label
/// disambiguates the three privacy circuits paraloom ceremonies
/// against (`DepositCircuit`, `TransferCircuit`,
/// `WithdrawCircuit`); other circuits remain explicitly out of
/// scope for v0.5.0 per issue #64.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CircuitId {
    Deposit,
    Transfer,
    Withdraw,
}

impl CircuitId {
    /// Stable string label for logging and transcript display.
    pub fn label(&self) -> &'static str {
        match self {
            CircuitId::Deposit => "deposit",
            CircuitId::Transfer => "transfer",
            CircuitId::Withdraw => "withdraw",
        }
    }
}

/// A single contributor's record on the transcript.
///
/// The cryptographic content (DLEQ proof, contributor's public
/// key, signature) lives here verbatim; the `prior_hash` field
/// pins this contribution to its position in the chain. The
/// contribution operation that produces these fields lives in a
/// sibling module under #64; this struct is the wire shape only.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contribution {
    /// Hash of the previous contribution's serialised bytes, or
    /// the initial-state hash if this is the first contribution.
    #[serde(with = "serde_hash")]
    pub prior_hash: TranscriptHash,

    /// Contributor's identity. NodeId is reused so the ceremony
    /// audit log can be cross-referenced with the validator
    /// registry; this does not require the contributor to be a
    /// running validator at the time of contribution.
    pub contributor: NodeId,

    /// Updated `delta` in `G1` after applying this contribution's
    /// `δ_i` to the previous primary's value. Stored as opaque
    /// bytes here; deserialisation into an arkworks `G1Affine`
    /// happens in the protocol module, keeping this file free of
    /// curve-specific imports.
    pub delta_after_g1: Vec<u8>,

    /// Updated `delta` in `G2` after this contribution. Same
    /// opaque-bytes rationale as `delta_after_g1`.
    pub delta_after_g2: Vec<u8>,

    /// Discrete-log-equality proof showing the contributor
    /// applied the same `δ_i` to both `delta_g1` and `delta_g2`.
    /// Schnorr-style `(R_g1, R_g2, s)` triple, serialised as
    /// opaque bytes.
    pub dleq_proof: Vec<u8>,

    /// Contributor's public key. The signature on this
    /// contribution must verify under this key. Stored as opaque
    /// bytes so the signing scheme can be upgraded without
    /// breaking the transcript schema.
    pub contributor_pubkey: Vec<u8>,

    /// Signature over the contribution body (every field above
    /// concatenated in declaration order, plus the new SRS hash).
    /// A verifier rejects the contribution if this fails.
    pub signature: Vec<u8>,

    /// Free-form attestation describing what the contributor did
    /// (hardware, OS, air-gap status). Public, audit-only;
    /// cryptographically meaningless. See issue #64 for the
    /// rationale on attestations as auditable claims rather than
    /// enforced rules.
    pub attestation: String,
}

/// The full ceremony transcript for one circuit.
///
/// A finished transcript records every contribution from the
/// initial state to the final SRS, including the version stamp,
/// the circuit identity, and the SRS hashes at the boundaries.
/// Verifiers re-run the chain end-to-end before accepting the
/// final SRS as canonical.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase2Transcript {
    /// Wire-format version. See `TRANSCRIPT_VERSION`.
    pub version: u32,

    /// Which of the three privacy circuits this transcript
    /// ceremonies. The verifier cross-checks this against the
    /// R1CS hash recorded in `initial_srs_hash`.
    pub circuit: CircuitId,

    /// Hash of the initial single-source SRS (produced by the
    /// existing `setup_*_ceremony` binaries). The first
    /// contribution's `prior_hash` must equal this value.
    #[serde(with = "serde_hash")]
    pub initial_srs_hash: TranscriptHash,

    /// Ordered list of contributions. The chain is canonical:
    /// reordering or deletion breaks the hash chain at the
    /// affected position.
    pub contributions: Vec<Contribution>,

    /// Hash of the final SRS after all contributions. The
    /// verifier recomputes this from the final ProvingKey and
    /// compares against this stored value as a defence against
    /// a corrupted ProvingKey file accompanying an otherwise-
    /// valid transcript.
    #[serde(with = "serde_hash")]
    pub final_srs_hash: TranscriptHash,
}

impl Phase2Transcript {
    /// Construct an empty transcript bound to a circuit and an
    /// initial SRS. The first contribution applied to this
    /// transcript must have `prior_hash == initial_srs_hash`.
    pub fn new(circuit: CircuitId, initial_srs_hash: TranscriptHash) -> Self {
        Self {
            version: TRANSCRIPT_VERSION,
            circuit,
            initial_srs_hash,
            contributions: Vec::new(),
            final_srs_hash: [0u8; 64],
        }
    }

    /// Number of contributions on the chain. Useful for the
    /// social-trust signal recorded on the public dashboard.
    pub fn len(&self) -> usize {
        self.contributions.len()
    }

    /// Whether the transcript has no contributions yet.
    pub fn is_empty(&self) -> bool {
        self.contributions.is_empty()
    }

    /// Append a contribution to the chain. Does **not** verify
    /// the contribution's cryptographic validity — that is the
    /// verifier module's responsibility. Append is the data-layer
    /// operation: it checks only that the `prior_hash` matches
    /// what the chain currently expects, which is the cheapest
    /// defence against a contributor stamping a contribution at
    /// the wrong position by mistake.
    pub fn append(&mut self, contribution: Contribution) -> Result<(), TranscriptError> {
        let expected_prior = match self.contributions.last() {
            Some(prev) => hash_contribution(prev),
            None => self.initial_srs_hash,
        };
        if contribution.prior_hash != expected_prior {
            return Err(TranscriptError::ChainBroken {
                position: self.contributions.len(),
            });
        }
        self.contributions.push(contribution);
        Ok(())
    }

    /// Walk the chain end-to-end and confirm every link's
    /// `prior_hash` matches the previous contribution's serialised
    /// hash. Returns the position of the first broken link, if
    /// any. Cryptographic verification of each contribution's
    /// DLEQ proof and signature is the verifier module's job; this
    /// method only checks the data-layer chain integrity.
    pub fn verify_chain(&self) -> Result<(), TranscriptError> {
        let mut expected = self.initial_srs_hash;
        for (i, contribution) in self.contributions.iter().enumerate() {
            if contribution.prior_hash != expected {
                return Err(TranscriptError::ChainBroken { position: i });
            }
            expected = hash_contribution(contribution);
        }
        Ok(())
    }
}

/// Compute the hash of a contribution's serialised bytes. This
/// hash is what the next contribution's `prior_hash` must equal.
///
/// Uses SHA-512 (64-byte output) because `sha2` is already in our
/// dependency tree and the digest size is large enough that any
/// preimage attack against the chain is infeasible. A verifier
/// with a 30-contributor transcript spends negligible time on
/// hashing — the cost is dominated by the per-contribution DLEQ
/// proof verification done elsewhere.
pub fn hash_contribution(contribution: &Contribution) -> TranscriptHash {
    let bytes = bincode::serialize(contribution).expect("Contribution always serialises");
    let digest = sha2::Sha512::digest(&bytes);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest[..]);
    out
}

/// Errors surfaced by the data-layer transcript operations.
#[derive(Debug, thiserror::Error)]
pub enum TranscriptError {
    #[error("transcript chain broken at position {position}: prior_hash does not match the previous contribution")]
    ChainBroken { position: usize },
}

// Bring the digest trait into scope locally so the public API
// does not leak the underlying crate's traits.
use sha2::Digest;

#[cfg(test)]
mod tests {
    use super::*;

    fn nodeid(byte: u8) -> NodeId {
        NodeId(vec![byte])
    }

    fn dummy_contribution(prior_hash: TranscriptHash, contributor_byte: u8) -> Contribution {
        Contribution {
            prior_hash,
            contributor: nodeid(contributor_byte),
            delta_after_g1: vec![0xAA; 96],
            delta_after_g2: vec![0xBB; 192],
            dleq_proof: vec![0xCC; 32 * 3],
            contributor_pubkey: vec![0xDD; 32],
            signature: vec![0xEE; 64],
            attestation: format!("contributor {}: air-gapped Pi 4", contributor_byte),
        }
    }

    #[test]
    fn empty_transcript_has_zero_contributions() {
        let t = Phase2Transcript::new(CircuitId::Deposit, [0u8; 64]);
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert_eq!(t.version, TRANSCRIPT_VERSION);
        assert!(t.verify_chain().is_ok());
    }

    #[test]
    fn append_chains_consecutive_contributions() {
        let initial: TranscriptHash = [0x42u8; 64];
        let mut t = Phase2Transcript::new(CircuitId::Transfer, initial);

        let c1 = dummy_contribution(initial, 1);
        t.append(c1)
            .expect("first contribution links to initial hash");
        assert_eq!(t.len(), 1);

        let c1_hash = hash_contribution(&t.contributions[0]);
        let c2 = dummy_contribution(c1_hash, 2);
        t.append(c2).expect("second contribution links to first");
        assert_eq!(t.len(), 2);

        t.verify_chain().expect("chain end-to-end is consistent");
    }

    #[test]
    fn append_rejects_wrong_prior_hash() {
        let initial: TranscriptHash = [0x42u8; 64];
        let mut t = Phase2Transcript::new(CircuitId::Withdraw, initial);

        // A contribution whose prior_hash does not equal the
        // initial state's hash must be rejected — otherwise an
        // attacker could splice in a contribution from a
        // different chain.
        let bogus = dummy_contribution([0u8; 64], 1);
        match t.append(bogus) {
            Err(TranscriptError::ChainBroken { position }) => assert_eq!(position, 0),
            other => panic!("expected ChainBroken at 0, got {:?}", other),
        }
    }

    #[test]
    fn verify_chain_detects_tampering_after_the_fact() {
        let initial: TranscriptHash = [0x42u8; 64];
        let mut t = Phase2Transcript::new(CircuitId::Deposit, initial);
        let c1 = dummy_contribution(initial, 1);
        t.append(c1).unwrap();
        let c1_hash = hash_contribution(&t.contributions[0]);
        let c2 = dummy_contribution(c1_hash, 2);
        t.append(c2).unwrap();

        // Mutate a field on the first contribution (without
        // recomputing the chain). verify_chain must surface the
        // break at position 1 because c2's prior_hash no longer
        // matches the recomputed hash of the tampered c1.
        t.contributions[0].attestation = "tampered".to_string();
        match t.verify_chain() {
            Err(TranscriptError::ChainBroken { position }) => assert_eq!(position, 1),
            other => panic!("expected ChainBroken at 1, got {:?}", other),
        }
    }

    #[test]
    fn transcript_round_trips_through_bincode() {
        let initial: TranscriptHash = [0x77u8; 64];
        let mut t = Phase2Transcript::new(CircuitId::Transfer, initial);
        t.append(dummy_contribution(initial, 1)).unwrap();
        let c1_hash = hash_contribution(&t.contributions[0]);
        t.append(dummy_contribution(c1_hash, 2)).unwrap();
        t.final_srs_hash = [0x99u8; 64];

        let encoded = bincode::serialize(&t).expect("serialise");
        let decoded: Phase2Transcript = bincode::deserialize(&encoded).expect("deserialise");

        assert_eq!(decoded.version, t.version);
        assert_eq!(decoded.circuit, t.circuit);
        assert_eq!(decoded.initial_srs_hash, t.initial_srs_hash);
        assert_eq!(decoded.final_srs_hash, t.final_srs_hash);
        assert_eq!(decoded.contributions.len(), t.contributions.len());
        decoded
            .verify_chain()
            .expect("decoded chain is still consistent");
    }

    #[test]
    fn circuit_id_label_matches_documentation() {
        assert_eq!(CircuitId::Deposit.label(), "deposit");
        assert_eq!(CircuitId::Transfer.label(), "transfer");
        assert_eq!(CircuitId::Withdraw.label(), "withdraw");
    }
}
