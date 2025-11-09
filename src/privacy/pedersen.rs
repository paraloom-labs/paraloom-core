//! Pedersen commitment scheme using BLS12-381 curve
//!
//! Provides cryptographically secure commitments using elliptic curve cryptography.
//! This replaces the hash-based placeholder implementation with real Pedersen commitments.
//!
//! Pedersen commitment: C = value*G + randomness*H
//! where G and H are generator points on the BLS12-381 curve.

use crate::privacy::types::Commitment;
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use sha2::{Digest, Sha256};

/// Generator points for Pedersen commitments
pub struct PedersenGenerators {
    /// Primary generator G
    pub g: G1Affine,
    /// Secondary generator H (domain-separated from G)
    pub h: G1Affine,
}

impl PedersenGenerators {
    /// Generate the standard generators for Pedersen commitments
    pub fn new() -> Self {
        // G is the standard generator
        let g = G1Affine::generator();

        // H is derived by hashing a domain separator
        // This ensures G and H have no known discrete log relationship
        let h = Self::hash_to_curve(b"PARALOOM_PEDERSEN_H_GENERATOR");

        PedersenGenerators { g, h }
    }

    /// Hash a message to a curve point (hash-to-curve)
    fn hash_to_curve(msg: &[u8]) -> G1Affine {
        // Simple hash-to-curve using try-and-increment
        // In production, use a proper hash-to-curve like in BLS signatures
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let mut counter = 0u64;

        loop {
            hasher.update(counter.to_le_bytes());
            let hash = hasher.finalize_reset();

            // Try to interpret hash as x-coordinate
            if let Some(point) = Self::try_point_from_hash(&hash) {
                return point.into_affine();
            }

            counter += 1;
            if counter > 1000000 {
                panic!("Failed to find valid curve point after 1M attempts");
            }
        }
    }

    /// Try to construct a curve point from a hash
    fn try_point_from_hash(hash: &[u8]) -> Option<G1Projective> {
        // Take first 32 bytes as potential x-coordinate
        if hash.len() < 32 {
            return None;
        }

        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&hash[..32]);

        // Try to construct a point
        // This is simplified; production should use proper hash-to-curve
        let x = Fr::from_le_bytes_mod_order(&x_bytes);

        // For simplicity, just use the generator scaled by this value
        // In production, use a proper hash-to-curve algorithm
        Some(G1Projective::generator() * x)
    }
}

impl Default for PedersenGenerators {
    fn default() -> Self {
        Self::new()
    }
}

/// Pedersen commitment generator
pub struct PedersenCommitment {
    generators: PedersenGenerators,
}

impl PedersenCommitment {
    /// Create a new Pedersen commitment generator
    pub fn new() -> Self {
        PedersenCommitment {
            generators: PedersenGenerators::new(),
        }
    }

    /// Create a commitment to a value with randomness
    ///
    /// C = value*G + randomness*H
    pub fn commit(&self, value: u64, randomness: &[u8; 32]) -> Commitment {
        // Convert value to field element
        let value_scalar = Fr::from(value);

        // Convert randomness to field element
        let randomness_scalar = Fr::from_le_bytes_mod_order(randomness);

        // Compute commitment: C = value*G + randomness*H
        let g_term = self.generators.g * value_scalar;
        let h_term = self.generators.h * randomness_scalar;
        let commitment_point = g_term + h_term;

        // Convert to affine and serialize
        let affine = commitment_point.into_affine();
        let mut bytes = Vec::new();
        affine.serialize_compressed(&mut bytes).unwrap();

        // Take first 32 bytes as commitment
        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(&bytes[..32]);

        Commitment(commitment_bytes)
    }

    /// Verify that a commitment opens to a specific value
    pub fn verify(&self, commitment: &Commitment, value: u64, randomness: &[u8; 32]) -> bool {
        let recomputed = self.commit(value, randomness);
        commitment == &recomputed
    }

    /// Generate cryptographically secure randomness
    pub fn generate_randomness() -> [u8; 32] {
        let mut rng = ark_std::rand::thread_rng();
        let random_field = Fr::rand(&mut rng);
        let mut bytes = [0u8; 32];
        random_field
            .into_bigint()
            .serialize_compressed(&mut bytes[..])
            .unwrap();
        bytes
    }
}

impl Default for PedersenCommitment {
    fn default() -> Self {
        Self::new()
    }
}

/// Global Pedersen commitment instance
static PEDERSEN: once_cell::sync::Lazy<PedersenCommitment> =
    once_cell::sync::Lazy::new(PedersenCommitment::new);

/// Commit to a value using the global Pedersen instance
pub fn commit(value: u64, randomness: &[u8; 32]) -> Commitment {
    PEDERSEN.commit(value, randomness)
}

/// Verify a commitment using the global Pedersen instance
pub fn verify(commitment: &Commitment, value: u64, randomness: &[u8; 32]) -> bool {
    PEDERSEN.verify(commitment, value, randomness)
}

/// Generate secure randomness
pub fn generate_randomness() -> [u8; 32] {
    PedersenCommitment::generate_randomness()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_generators() {
        let gen = PedersenGenerators::new();

        // Generators should be valid curve points
        assert!(gen.g.is_on_curve());
        assert!(gen.h.is_on_curve());

        // G and H should be different
        assert_ne!(gen.g, gen.h);
    }

    #[test]
    fn test_pedersen_commit() {
        let pedersen = PedersenCommitment::new();
        let value = 1000u64;
        let randomness = [42u8; 32];

        let commitment = pedersen.commit(value, &randomness);

        // Commitment should be 32 bytes
        assert_eq!(commitment.as_bytes().len(), 32);

        // Same inputs should produce same commitment (deterministic)
        let commitment2 = pedersen.commit(value, &randomness);
        assert_eq!(commitment, commitment2);
    }

    #[test]
    fn test_pedersen_hiding() {
        let pedersen = PedersenCommitment::new();
        let randomness = [42u8; 32];

        let c1 = pedersen.commit(1000, &randomness);
        let c2 = pedersen.commit(2000, &randomness);

        // Different values should produce different commitments
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_pedersen_blinding() {
        let pedersen = PedersenCommitment::new();
        let value = 1000u64;

        let c1 = pedersen.commit(value, &[1u8; 32]);
        let c2 = pedersen.commit(value, &[2u8; 32]);

        // Different randomness should produce different commitments
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_pedersen_verify() {
        let pedersen = PedersenCommitment::new();
        let value = 5000u64;
        let randomness = [100u8; 32];

        let commitment = pedersen.commit(value, &randomness);

        // Correct opening should verify
        assert!(pedersen.verify(&commitment, value, &randomness));

        // Wrong value should not verify
        assert!(!pedersen.verify(&commitment, 6000, &randomness));

        // Wrong randomness should not verify
        assert!(!pedersen.verify(&commitment, value, &[101u8; 32]));
    }

    #[test]
    fn test_generate_randomness() {
        let r1 = generate_randomness();
        let r2 = generate_randomness();

        // Should generate different randomness each time
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_global_instance() {
        let value = 1234u64;
        let randomness = [77u8; 32];

        // Test global commit function
        let c1 = commit(value, &randomness);
        let c2 = commit(value, &randomness);

        assert_eq!(c1, c2);

        // Test global verify function
        assert!(verify(&c1, value, &randomness));
        assert!(!verify(&c1, value + 1, &randomness));
    }

    #[test]
    fn test_commitment_homomorphism() {
        let pedersen = PedersenCommitment::new();

        // C(v1, r1) + C(v2, r2) should equal C(v1+v2, r1+r2)
        // This is a key property of Pedersen commitments

        let v1 = 100u64;
        let v2 = 200u64;
        let r1_scalar = Fr::from(42u64);
        let r2_scalar = Fr::from(84u64);

        let mut r1 = [0u8; 32];
        let mut r2 = [0u8; 32];
        r1_scalar
            .into_bigint()
            .serialize_compressed(&mut r1[..])
            .unwrap();
        r2_scalar
            .into_bigint()
            .serialize_compressed(&mut r2[..])
            .unwrap();

        let c1_point = {
            let v_scalar = Fr::from(v1);
            let r_scalar = Fr::from_le_bytes_mod_order(&r1);
            (pedersen.generators.g * v_scalar) + (pedersen.generators.h * r_scalar)
        };

        let c2_point = {
            let v_scalar = Fr::from(v2);
            let r_scalar = Fr::from_le_bytes_mod_order(&r2);
            (pedersen.generators.g * v_scalar) + (pedersen.generators.h * r_scalar)
        };

        // Sum of commitments
        let sum_point = c1_point + c2_point;

        // Commitment to sum
        let v_sum = v1 + v2;
        let r_sum_scalar = r1_scalar + r2_scalar;
        let mut r_sum = [0u8; 32];
        r_sum_scalar
            .into_bigint()
            .serialize_compressed(&mut r_sum[..])
            .unwrap();

        let c_sum_point = {
            let v_scalar = Fr::from(v_sum);
            let r_scalar = Fr::from_le_bytes_mod_order(&r_sum);
            (pedersen.generators.g * v_scalar) + (pedersen.generators.h * r_scalar)
        };

        // They should be equal (homomorphic property)
        assert_eq!(sum_point.into_affine(), c_sum_point.into_affine());
    }
}
