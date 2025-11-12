//! Proof serialization and deserialization for network transmission

use crate::privacy::Result;
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::io::Cursor;

pub type Groth16Proof = Proof<Bls12_381>;
pub type Groth16VerifyingKey = VerifyingKey<Bls12_381>;

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
    Proof::<Bls12_381>::deserialize_compressed(&mut cursor)
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
    VerifyingKey::<Bls12_381>::deserialize_compressed(&mut cursor)
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
    use ark_std::UniformRand;

    #[test]
    fn test_field_roundtrip() {
        let mut rng = ark_std::test_rng();
        let field = Fr::rand(&mut rng);

        let bytes = field_to_bytes(&field);
        let recovered = bytes_to_field(&bytes).unwrap();

        assert_eq!(field, recovered);
    }
}
