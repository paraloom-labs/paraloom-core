//! Vendored Groth16 (BN254) verifier over Solana's `alt_bn128` syscalls.
//!
//! Source: <https://github.com/Lightprotocol/groth16-solana> (MIT), trimmed to
//! the verify path. Proofs are produced off-chain by the workspace prover in
//! the `alt_bn128` wire form (big-endian coordinates, G2 `c1`/`c0` ordering,
//! negated `proof_a`); this only checks them.
#![allow(dead_code)]

use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use solana_bn254::prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing};

#[derive(Debug, PartialEq, Eq)]
pub enum Groth16Error {
    InvalidPublicInputsLength,
    PublicInputGreaterThanFieldSize,
    PreparingInputsG1MulFailed,
    PreparingInputsG1AdditionFailed,
    ProofVerificationFailed,
}

pub struct Groth16Verifyingkey<'a> {
    pub nr_pubinputs: usize,
    pub vk_alpha_g1: [u8; 64],
    pub vk_beta_g2: [u8; 128],
    pub vk_gamme_g2: [u8; 128],
    pub vk_delta_g2: [u8; 128],
    pub vk_ic: &'a [[u8; 64]],
}

pub struct Groth16Verifier<'a, const NR_INPUTS: usize> {
    proof_a: &'a [u8; 64],
    proof_b: &'a [u8; 128],
    proof_c: &'a [u8; 64],
    public_inputs: &'a [[u8; 32]; NR_INPUTS],
    prepared_public_inputs: [u8; 64],
    verifyingkey: &'a Groth16Verifyingkey<'a>,
}

impl<const NR_INPUTS: usize> Groth16Verifier<'_, NR_INPUTS> {
    pub fn new<'a>(
        proof_a: &'a [u8; 64],
        proof_b: &'a [u8; 128],
        proof_c: &'a [u8; 64],
        public_inputs: &'a [[u8; 32]; NR_INPUTS],
        verifyingkey: &'a Groth16Verifyingkey<'a>,
    ) -> Result<Groth16Verifier<'a, NR_INPUTS>, Groth16Error> {
        if public_inputs.len() + 1 != verifyingkey.vk_ic.len() {
            return Err(Groth16Error::InvalidPublicInputsLength);
        }
        Ok(Groth16Verifier {
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            prepared_public_inputs: [0u8; 64],
            verifyingkey,
        })
    }

    fn prepare_inputs(&mut self) -> Result<(), Groth16Error> {
        let mut prepared = self.verifyingkey.vk_ic[0];
        for (i, input) in self.public_inputs.iter().enumerate() {
            if !is_less_than_bn254_field_size_be(input) {
                return Err(Groth16Error::PublicInputGreaterThanFieldSize);
            }
            let mul_res = alt_bn128_multiplication(
                &[&self.verifyingkey.vk_ic[i + 1][..], &input[..]].concat(),
            )
            .map_err(|_| Groth16Error::PreparingInputsG1MulFailed)?;
            prepared = alt_bn128_addition(&[&mul_res[..], &prepared[..]].concat())
                .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?[..]
                .try_into()
                .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?;
        }
        self.prepared_public_inputs = prepared;
        Ok(())
    }

    pub fn verify(&mut self) -> Result<bool, Groth16Error> {
        if self.proof_a.iter().all(|&b| b == 0)
            || self.proof_b.iter().all(|&b| b == 0)
            || self.proof_c.iter().all(|&b| b == 0)
        {
            return Err(Groth16Error::ProofVerificationFailed);
        }
        self.prepare_inputs()?;
        let pairing_input = [
            self.proof_a.as_slice(),
            self.proof_b.as_slice(),
            self.prepared_public_inputs.as_slice(),
            self.verifyingkey.vk_gamme_g2.as_slice(),
            self.proof_c.as_slice(),
            self.verifyingkey.vk_delta_g2.as_slice(),
            self.verifyingkey.vk_alpha_g1.as_slice(),
            self.verifyingkey.vk_beta_g2.as_slice(),
        ]
        .concat();
        let res = alt_bn128_pairing(pairing_input.as_slice())
            .map_err(|_| Groth16Error::ProofVerificationFailed)?;
        if res[31] != 1 {
            return Err(Groth16Error::ProofVerificationFailed);
        }
        Ok(true)
    }
}

fn is_less_than_bn254_field_size_be(bytes: &[u8; 32]) -> bool {
    BigUint::from_bytes_be(bytes) < Fr::MODULUS.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transact_fixture_data as fx;
    use crate::transact_vk_data as vk;

    const VK_IC: [[u8; 64]; 9] = [
        vk::VK_IC_0,
        vk::VK_IC_1,
        vk::VK_IC_2,
        vk::VK_IC_3,
        vk::VK_IC_4,
        vk::VK_IC_5,
        vk::VK_IC_6,
        vk::VK_IC_7,
        vk::VK_IC_8,
    ];

    fn test_vk() -> Groth16Verifyingkey<'static> {
        Groth16Verifyingkey {
            nr_pubinputs: 8,
            vk_alpha_g1: vk::VK_ALPHA_G1,
            vk_beta_g2: vk::VK_BETA_G2,
            vk_gamme_g2: vk::VK_GAMMA_G2,
            vk_delta_g2: vk::VK_DELTA_G2,
            vk_ic: &VK_IC,
        }
    }

    #[test]
    fn verify_rejects_all_zero_proof_points_before_pairing() {
        let vk = test_vk();
        let inputs = [[0u8; 32]; 8];

        let zero_g1 = [0u8; 64];
        let zero_g2 = [0u8; 128];

        let mut v_a = Groth16Verifier::new(
            &zero_g1,
            &fx::FIXTURE_PROOF_B,
            &fx::FIXTURE_PROOF_C,
            &inputs,
            &vk,
        )
        .unwrap();
        assert_eq!(v_a.verify(), Err(Groth16Error::ProofVerificationFailed));

        let mut v_b = Groth16Verifier::new(
            &fx::FIXTURE_PROOF_A,
            &zero_g2,
            &fx::FIXTURE_PROOF_C,
            &inputs,
            &vk,
        )
        .unwrap();
        assert_eq!(v_b.verify(), Err(Groth16Error::ProofVerificationFailed));

        let mut v_c = Groth16Verifier::new(
            &fx::FIXTURE_PROOF_A,
            &fx::FIXTURE_PROOF_B,
            &zero_g1,
            &inputs,
            &vk,
        )
        .unwrap();
        assert_eq!(v_c.verify(), Err(Groth16Error::ProofVerificationFailed));
    }

    #[test]
    fn verify_rejects_public_input_at_or_above_modulus() {
        let vk = test_vk();
        let modulus: BigUint = Fr::MODULUS.into();
        let modulus_be_vec = modulus.to_bytes_be();
        let mut modulus_be = [0u8; 32];
        modulus_be[32 - modulus_be_vec.len()..].copy_from_slice(&modulus_be_vec);

        let mut inputs = [[0u8; 32]; 8];
        inputs[0] = modulus_be;

        let mut verifier = Groth16Verifier::new(
            &fx::FIXTURE_PROOF_A,
            &fx::FIXTURE_PROOF_B,
            &fx::FIXTURE_PROOF_C,
            &inputs,
            &vk,
        )
        .unwrap();
        assert_eq!(
            verifier.verify(),
            Err(Groth16Error::PublicInputGreaterThanFieldSize)
        );
    }
}
