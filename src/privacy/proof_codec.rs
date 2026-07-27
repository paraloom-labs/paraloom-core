//! Proof serialization and deserialization for network transmission

use crate::privacy::Result;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::io::Cursor;

pub type Groth16Proof = Proof<Bn254>;
pub type Groth16VerifyingKey = VerifyingKey<Bn254>;

/// Serialize a Groth16 proof to bytes for network transmission
pub fn serialize_proof(proof: &Groth16Proof) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|e| crate::privacy::PrivacyError::SerializationError(e.to_string()))?;
    Ok(bytes)
}

/// Deserialize a Groth16 proof from bytes
pub fn deserialize_proof(bytes: &[u8]) -> Result<Groth16Proof> {
    let mut cursor = Cursor::new(bytes);
    Proof::<Bn254>::deserialize_compressed(&mut cursor)
        .map_err(|e| crate::privacy::PrivacyError::SerializationError(e.to_string()))
}

/// Serialize a verifying key to bytes
pub fn serialize_vk(vk: &Groth16VerifyingKey) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)
        .map_err(|e| crate::privacy::PrivacyError::SerializationError(e.to_string()))?;
    Ok(bytes)
}

/// Deserialize a verifying key from bytes
pub fn deserialize_vk(bytes: &[u8]) -> Result<Groth16VerifyingKey> {
    let mut cursor = Cursor::new(bytes);
    VerifyingKey::<Bn254>::deserialize_compressed(&mut cursor)
        .map_err(|e| crate::privacy::PrivacyError::SerializationError(e.to_string()))
}

/// Convert field element to bytes (32 bytes, big-endian)
pub fn field_to_bytes(field: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let mut buf = Vec::new();
    field
        .serialize_compressed(&mut buf)
        .expect("Field serialization failed");

    let len = buf.len().min(32);
    bytes[32 - len..].copy_from_slice(&buf[..len]);
    bytes
}

/// Convert bytes to field element
pub fn bytes_to_field(bytes: &[u8]) -> Result<Fr> {
    let mut cursor = Cursor::new(bytes);
    Fr::deserialize_compressed(&mut cursor)
        .map_err(|e| crate::privacy::PrivacyError::SerializationError(e.to_string()))
}

// ──────────────────────────────────────────────────────────────────────────
// Proof-suite envelope
// ──────────────────────────────────────────────────────────────────────────

/// Length of an arkworks-compressed BN254 Groth16 proof: G1(32) + G2(64) +
/// G1(32). The untagged legacy encoding is exactly this long, so a tagged blob
/// (one byte longer) can never be mistaken for one, or vice versa.
pub const GROTH16_BN254_COMPRESSED_LEN: usize = 128;

/// Which proof system a settlement proof was produced under.
///
/// The L2 carries proofs as opaque `Vec<u8>` through the ingress, the gossip
/// codec and the consensus round; nothing in that path is self-describing, so
/// today a proof's system is implied purely by "whatever the single embedded
/// verifying key happens to be". That is fine while there is exactly one, and
/// unrecoverable the moment there are two: two suites' blobs are just byte
/// strings, and a migration window needs both accepted at once and
/// distinguished without guessing.
///
/// Adding the discriminant is only possible before wallets pin the format, so
/// it is done now even though there is still just one suite. The tag is
/// deliberately **not** zero-based: an all-zero or truncated buffer must not
/// parse as a valid suite.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProofSuite {
    /// Groth16 over BN254 (`alt_bn128`) for `TransactCircuitV3`, proof body in
    /// arkworks-compressed form. The only suite the on-chain program can
    /// verify.
    Groth16Bn254TransactV3 = 1,
}

impl ProofSuite {
    /// The on-the-wire tag byte.
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Parse a tag byte. An unrecognised tag is an error, never a fallback to
    /// the current suite: a node that cannot verify a suite must reject the
    /// proof, not verify it under different rules than the prover used.
    pub fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(ProofSuite::Groth16Bn254TransactV3),
            other => Err(crate::privacy::PrivacyError::SerializationError(format!(
                "unknown proof suite tag {other}"
            ))),
        }
    }

    /// Expected body length for this suite, if it is fixed.
    pub const fn body_len(self) -> usize {
        match self {
            ProofSuite::Groth16Bn254TransactV3 => GROTH16_BN254_COMPRESSED_LEN,
        }
    }
}

/// Prepend the suite tag to a proof body, producing the L2 wire encoding
/// `tag(1) || body`.
pub fn tag_proof(suite: ProofSuite, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(suite.tag());
    out.extend_from_slice(body);
    out
}

/// Split an L2 wire proof into its suite and body.
///
/// Rejects an empty buffer, an unknown tag, and a body whose length does not
/// match the suite. The length check is what stops a legacy untagged
/// 128-byte proof from being read as a tagged one whose first byte happens to
/// be `0x01`: it would leave a 127-byte body.
pub fn split_tagged_proof(wire: &[u8]) -> Result<(ProofSuite, &[u8])> {
    let (tag, body) = wire.split_first().ok_or_else(|| {
        crate::privacy::PrivacyError::SerializationError("empty proof blob".to_string())
    })?;
    let suite = ProofSuite::from_tag(*tag)?;
    if body.len() != suite.body_len() {
        return Err(crate::privacy::PrivacyError::SerializationError(format!(
            "proof suite {:?} expects a {}-byte body, got {}",
            suite,
            suite.body_len(),
            body.len()
        )));
    }
    Ok((suite, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{RngCore, SeedableRng};
    use ark_std::UniformRand;

    #[test]
    fn test_field_roundtrip() {
        let mut rng = ark_std::test_rng();
        let field = Fr::rand(&mut rng);

        let bytes = field_to_bytes(&field);
        let recovered = bytes_to_field(&bytes).unwrap();

        assert_eq!(field, recovered);
    }

    /// Many random field elements round-trip cleanly. Adds confidence
    /// that a single-element round-trip wasn't a fluke.
    #[test]
    fn field_roundtrip_many_random_elements() {
        let mut rng = ark_std::test_rng();
        for _ in 0..256 {
            let field = Fr::rand(&mut rng);
            let bytes = field_to_bytes(&field);
            let recovered = bytes_to_field(&bytes).expect("round-trip");
            assert_eq!(field, recovered);
        }
    }

    // ── Negative paths: never panic on adversarial input ──────────────
    //
    // The audit (#71) asked for fuzz coverage of \`proof_codec\`'s
    // deserialise path because a malicious peer can hand the L2 any
    // byte sequence they like through the network codec. The tests
    // below stand in for the dedicated \`cargo-fuzz\` target that
    // tracker covers separately: deterministic seed + 1024 random
    // shapes + a curated set of edge buffers. Every attempt must
    // surface as a typed \`Err\`, never as a panic.

    #[test]
    fn deserialize_proof_empty_buffer_errors() {
        assert!(deserialize_proof(&[]).is_err());
    }

    #[test]
    fn deserialize_proof_short_buffer_errors() {
        for len in 0..64 {
            let buf = vec![0u8; len];
            assert!(
                deserialize_proof(&buf).is_err(),
                "short buffer of length {} must fail to deserialise as a proof",
                len
            );
        }
    }

    #[test]
    fn deserialize_proof_random_bytes_never_panic() {
        // Seeded so the corpus is reproducible. 1024 random buffers of
        // varying sizes exercises the code paths through the
        // ark-serialize state machine without depending on a fuzzer.
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xDEAD_BEEFu64);
        for size in [1usize, 31, 32, 96, 192, 200, 1024, 4096] {
            for _ in 0..128 {
                let mut buf = vec![0u8; size];
                rng.fill_bytes(&mut buf);
                // We do not care whether deserialise returns Ok or
                // Err — only that it does not panic. (Random bytes
                // *can* in principle decode to a valid \`Proof\`
                // structure; if they do, that's fine.)
                let _ = deserialize_proof(&buf);
            }
        }
    }

    #[test]
    fn deserialize_vk_empty_and_short_buffers_error() {
        assert!(deserialize_vk(&[]).is_err());
        for len in [1usize, 8, 32, 64, 128] {
            let buf = vec![0u8; len];
            assert!(
                deserialize_vk(&buf).is_err(),
                "VK deserialise must reject {}-byte buffer",
                len
            );
        }
    }

    #[test]
    fn deserialize_vk_random_bytes_never_panic() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xCAFE_BABEu64);
        for size in [1usize, 31, 32, 96, 256, 1024] {
            for _ in 0..64 {
                let mut buf = vec![0u8; size];
                rng.fill_bytes(&mut buf);
                let _ = deserialize_vk(&buf);
            }
        }
    }

    #[test]
    fn bytes_to_field_empty_and_short_buffers_error() {
        assert!(bytes_to_field(&[]).is_err());
        // \`Fr\` requires 32 bytes for compressed serialisation;
        // anything shorter is structurally invalid.
        for len in 0..32 {
            let buf = vec![0u8; len];
            assert!(
                bytes_to_field(&buf).is_err(),
                "Fr deserialise must reject {}-byte buffer",
                len
            );
        }
    }

    /// A buffer whose top bytes encode a value larger than the BN254
    /// scalar prime must be rejected — \`Fr\` cannot represent such a
    /// value canonically.
    #[test]
    fn bytes_to_field_above_modulus_errors() {
        let buf = [0xFFu8; 32];
        assert!(bytes_to_field(&buf).is_err());
    }

    // ── Proof-suite envelope ──────────────────────────────────────────

    #[test]
    fn tagged_proof_round_trips() {
        let body = vec![7u8; GROTH16_BN254_COMPRESSED_LEN];
        let wire = tag_proof(ProofSuite::Groth16Bn254TransactV3, &body);
        assert_eq!(wire.len(), GROTH16_BN254_COMPRESSED_LEN + 1);

        let (suite, got) = split_tagged_proof(&wire).expect("split");
        assert_eq!(suite, ProofSuite::Groth16Bn254TransactV3);
        assert_eq!(got, &body[..]);
    }

    /// An unknown suite must be an error and never silently fall back to the
    /// one suite this build knows how to verify. This is the whole point of
    /// the discriminant: a node that cannot check a proof rejects it.
    #[test]
    fn unknown_suite_tag_is_rejected_not_defaulted() {
        for tag in [0u8, 2, 3, 0x80, 0xff] {
            let mut wire = vec![tag];
            wire.extend_from_slice(&[0u8; GROTH16_BN254_COMPRESSED_LEN]);
            assert!(
                split_tagged_proof(&wire).is_err(),
                "tag {tag} must not parse"
            );
        }
    }

    /// A legacy untagged 128-byte proof cannot be misread as a tagged one,
    /// even when its first byte collides with a valid tag: the remaining body
    /// is then one byte short.
    #[test]
    fn untagged_legacy_proof_cannot_be_misread() {
        let mut legacy = vec![0u8; GROTH16_BN254_COMPRESSED_LEN];
        legacy[0] = ProofSuite::Groth16Bn254TransactV3.tag();
        assert!(split_tagged_proof(&legacy).is_err());
    }

    #[test]
    fn empty_and_tag_only_blobs_are_rejected() {
        assert!(split_tagged_proof(&[]).is_err());
        assert!(split_tagged_proof(&[ProofSuite::Groth16Bn254TransactV3.tag()]).is_err());
    }

    /// A body of the wrong length is rejected even under a known tag, so a
    /// suite whose proofs are a different size can never be settled by a build
    /// that only knows this one.
    #[test]
    fn body_length_is_enforced_under_a_known_tag() {
        for body_len in [0usize, 1, 127, 129, 256] {
            let mut wire = vec![0u8; 1 + body_len];
            wire[0] = ProofSuite::Groth16Bn254TransactV3.tag();
            assert!(
                split_tagged_proof(&wire).is_err(),
                "a {body_len}-byte body must not parse"
            );
        }
    }

    /// Any byte string is either rejected or split into a suite and a body of
    /// that suite's length — never a panic and never a short read.
    #[test]
    fn split_tagged_proof_never_panics_on_random_input() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xC0FFEE);
        for _ in 0..1024 {
            let len = (rng.next_u32() % 300) as usize;
            let mut buf = vec![0u8; len];
            rng.fill_bytes(&mut buf);
            if let Ok((suite, body)) = split_tagged_proof(&buf) {
                assert_eq!(body.len(), suite.body_len());
            }
        }
    }
}
