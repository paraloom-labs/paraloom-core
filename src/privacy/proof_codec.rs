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
}
