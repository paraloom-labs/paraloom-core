//! Production [`Submitter`] for the private-swap relayer, settling over the v3
//! `transact` (withdraw-to-fresh) + `deposit_note` (re-shield) flow.
//!
//! The withdraw leg is a v3 `transact` with `ext_amount < 0` and
//! `recipient = fresh_address`: it is proved with the transact proving key,
//! POSTed to the public transact ingress, and settled by the 2-of-2 validator
//! co-sign quorum (see [`crate::relayer::transact_submit`]). The re-shield leg
//! is a permissionless `deposit_note` signed by the fresh ephemeral key. SPL
//! re-shielding is unavailable on the native-only v3 program.

use ark_bn254::Bn254;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalDeserialize;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::sync::Arc;

use crate::bridge::solana::{create_deposit_note_instruction, derive_bridge_vault};
use crate::privacy::poseidon_circom::v3_commit;
use crate::privacy::types::ShieldedAddress;
use crate::relayer::private_swap::{RelayerError, Result, SubmittedLeg, Submitter, WithdrawLeg};
use crate::relayer::transact_submit;

/// Default settlement poll timeout (matches the demo's 120s window).
const SETTLEMENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

fn is_canonical_le(b: &[u8; 32]) -> bool {
    let reduced = Fr::from_le_bytes_mod_order(b);
    let le = reduced.into_bigint().to_bytes_le();
    let mut canonical = [0u8; 32];
    let n = le.len().min(32);
    canonical[..n].copy_from_slice(&le[..n]);
    &canonical == b
}

/// Settles the relayer's on-chain legs against a live Solana RPC + transact
/// ingress. Cloneable config is moved into the blocking tasks that run the
/// (blocking) `transact_submit` helpers.
pub struct OnChainSubmitter {
    program_id: Pubkey,
    rpc_url: String,
    ingress_url: String,
    proving_key: Arc<ark_groth16::ProvingKey<Bn254>>,
}

impl OnChainSubmitter {
    /// Build a submitter over `rpc_url`, the deployed `program_id`, the transact
    /// `ingress_url`, and the v3 transact proving key at `proving_key_path`
    /// (e.g. `keys/transact_v3_proving.key`).
    pub fn new(
        rpc_url: impl Into<String>,
        program_id: Pubkey,
        ingress_url: impl Into<String>,
        proving_key_path: impl AsRef<std::path::Path>,
    ) -> Result<Self> {
        let bytes = std::fs::read(proving_key_path.as_ref())
            .map_err(|e| RelayerError::SubmissionFailed(format!("read proving key: {e}")))?;
        let mut cursor = &bytes[..];
        let pk = ark_groth16::ProvingKey::<Bn254>::deserialize_compressed(&mut cursor)
            .map_err(|e| RelayerError::SubmissionFailed(format!("decode proving key: {e}")))?;
        if !cursor.is_empty() {
            return Err(RelayerError::SubmissionFailed(
                "proving key has unconsumed trailing bytes".to_string(),
            ));
        }
        Ok(Self {
            program_id,
            rpc_url: rpc_url.into(),
            ingress_url: ingress_url.into(),
            proving_key: Arc::new(pk),
        })
    }

    fn client(&self) -> RpcClient {
        RpcClient::new_with_commitment(self.rpc_url.clone(), CommitmentConfig::confirmed())
    }
}

#[async_trait::async_trait]
impl Submitter for OnChainSubmitter {
    #[allow(clippy::too_many_arguments)]
    async fn submit_withdraw_to_fresh(
        &self,
        leg: WithdrawLeg,
        amount: u64,
        sk: [u8; 32],
        blinding: [u8; 32],
        note_pubkey: [u8; 32],
        leaf_index: u64,
        fresh_address: [u8; 32],
    ) -> Result<SubmittedLeg> {
        if !matches!(leg, WithdrawLeg::Native) {
            return Err(RelayerError::SubmissionFailed(
                "SPL withdraw is unavailable on the native-only v3 program".to_string(),
            ));
        }
        if amount == 0 {
            return Err(RelayerError::SubmissionFailed(
                "withdraw amount must be greater than zero".to_string(),
            ));
        }
        if fresh_address == [0u8; 32] {
            return Err(RelayerError::SubmissionFailed(
                "fresh address cannot be the all-zero address".to_string(),
            ));
        }
        let program_id = self.program_id;
        let rpc_url = self.rpc_url.clone();
        let ingress = self.ingress_url.clone();
        let pk = self.proving_key.clone();

        // The transact_submit helpers are blocking (blocking RpcClient + reqwest).
        let result = tokio::task::spawn_blocking(move || -> transact_submit::Result<String> {
            let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
            if !transact_submit::quorum_available(&client, &program_id) {
                return Err(transact_submit::TransactSubmitError::IngressRejected {
                    status: 503,
                    body: "no validator quorum (need >= 2 active validators)".to_string(),
                });
            }
            let sk_fr = Fr::from_le_bytes_mod_order(&sk);
            let blinding_fr = Fr::from_le_bytes_mod_order(&blinding);
            let note_pk_fr = Fr::from_le_bytes_mod_order(&note_pubkey);
            let commitment = v3_commit(Fr::from(amount), note_pk_fr, blinding_fr, Fr::from(0u64));
            let membership =
                transact_submit::read_membership(&client, &program_id, leaf_index, commitment)?;
            let w = transact_submit::prove_withdraw_to_fresh(
                &pk,
                sk_fr,
                blinding_fr,
                note_pk_fr,
                amount,
                &membership,
                &fresh_address,
            )?;
            // Two well-formed placeholder envelopes: the withdraw's output notes
            // are zero-value, but the ingress still requires valid ciphertexts.
            let demo_recipient = *crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng)
                .public_key()
                .as_bytes();
            let ct0 =
                crate::privacy::note_crypto::seal(&demo_recipient, b"withdraw out 0").to_bytes();
            let ct1 =
                crate::privacy::note_crypto::seal(&demo_recipient, b"withdraw out 1").to_bytes();
            transact_submit::post_transact(&ingress, &fresh_address, &w, [ct0, ct1])?;

            let recipient_pk = Pubkey::new_from_array(fresh_address);
            transact_submit::wait_for_settlement(
                &client,
                &program_id,
                &recipient_pk,
                &w.nullifiers[0],
                SETTLEMENT_TIMEOUT,
            )?;
            // Settlement lands via the quorum, not a single tx we hold — return
            // the fresh address as the leg's on-chain reference.
            Ok(recipient_pk.to_string())
        })
        .await
        .map_err(|e| RelayerError::SubmissionFailed(format!("withdraw task join: {e}")))?
        .map_err(|e| RelayerError::SubmissionFailed(e.to_string()))?;

        Ok(SubmittedLeg {
            leg,
            amount,
            fresh_address,
            signature: result,
        })
    }

    async fn submit_deposit_from_fresh(
        &self,
        leg: WithdrawLeg,
        amount: u64,
        signer: &Keypair,
        recipient: ShieldedAddress,
        randomness: [u8; 32],
    ) -> Result<SubmittedLeg> {
        if !matches!(leg, WithdrawLeg::Native) {
            return Err(RelayerError::SubmissionFailed(
                "SPL re-shield is unavailable on the native-only v3 program (needs a redeploy)"
                    .to_string(),
            ));
        }
        if amount == 0 {
            return Err(RelayerError::SubmissionFailed(
                "deposit amount must be greater than zero".to_string(),
            ));
        }
        if !is_canonical_le(&recipient.0) {
            return Err(RelayerError::SubmissionFailed(
                "recipient is not a canonical BN254 field element".to_string(),
            ));
        }
        if !is_canonical_le(&randomness) {
            return Err(RelayerError::SubmissionFailed(
                "randomness is not a canonical BN254 field element".to_string(),
            ));
        }
        let program_id = self.program_id;
        let fresh_address = signer.pubkey().to_bytes();
        let signer = signer.insecure_clone();
        let client = self.client();

        let sig = tokio::task::spawn_blocking(move || -> std::result::Result<String, String> {
            let (vault, _) = derive_bridge_vault(&program_id);
            let ix = create_deposit_note_instruction(
                &program_id,
                &signer.pubkey(),
                &vault,
                amount,
                recipient.0,
                randomness,
            )
            .map_err(|e| e.to_string())?;
            let bh = client.get_latest_blockhash().map_err(|e| e.to_string())?;
            let tx =
                Transaction::new_signed_with_payer(&[ix], Some(&signer.pubkey()), &[&signer], bh);
            client
                .send_and_confirm_transaction(&tx)
                .map(|s| s.to_string())
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| RelayerError::SubmissionFailed(format!("deposit task join: {e}")))?
        .map_err(RelayerError::SubmissionFailed)?;

        Ok(SubmittedLeg {
            leg,
            amount,
            fresh_address,
            signature: sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_groth16::Groth16;
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_serialize::CanonicalSerialize;
    use ark_snark::SNARK;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[derive(Clone)]
    struct DummyCircuit;

    impl ConstraintSynthesizer<Fr> for DummyCircuit {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<Fr>,
        ) -> std::result::Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| Ok(Fr::from(1u32)))?;
            let b = cs.new_input_variable(|| Ok(Fr::from(1u32)))?;
            cs.enforce_constraint(lc!() + a, lc!() + a, lc!() + b)?;
            Ok(())
        }
    }

    fn dummy_pk() -> ark_groth16::ProvingKey<Bn254> {
        let mut rng = StdRng::seed_from_u64(42);
        let (pk, _) = Groth16::<Bn254>::circuit_specific_setup(DummyCircuit, &mut rng).unwrap();
        pk
    }

    #[tokio::test]
    async fn submit_withdraw_rejects_zero_amount_and_zero_address() {
        let submitter = OnChainSubmitter {
            program_id: Pubkey::new_unique(),
            rpc_url: "http://127.0.0.1:8899".to_string(),
            ingress_url: "http://127.0.0.1:8898".to_string(),
            proving_key: Arc::new(dummy_pk()),
        };

        // Zero amount rejected
        let res = submitter
            .submit_withdraw_to_fresh(
                WithdrawLeg::Native,
                0,
                [1; 32],
                [2; 32],
                [3; 32],
                0,
                [4; 32],
            )
            .await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("greater than zero"));

        // All-zero fresh address rejected
        let res = submitter
            .submit_withdraw_to_fresh(
                WithdrawLeg::Native,
                100,
                [1; 32],
                [2; 32],
                [3; 32],
                0,
                [0; 32],
            )
            .await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("all-zero address"));
    }

    #[tokio::test]
    async fn submit_deposit_rejects_zero_amount_and_non_canonical() {
        let submitter = OnChainSubmitter {
            program_id: Pubkey::new_unique(),
            rpc_url: "http://127.0.0.1:8899".to_string(),
            ingress_url: "http://127.0.0.1:8898".to_string(),
            proving_key: Arc::new(dummy_pk()),
        };
        let signer = Keypair::new();

        // Zero amount rejected
        let res = submitter
            .submit_deposit_from_fresh(
                WithdrawLeg::Native,
                0,
                &signer,
                ShieldedAddress([1; 32]),
                [2; 32],
            )
            .await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("greater than zero"));

        // Compute non-canonical element: canonical + p
        let ple = <Fr as PrimeField>::MODULUS.to_bytes_le();
        let mut modulus = [0u8; 32];
        modulus[..ple.len().min(32)].copy_from_slice(&ple[..ple.len().min(32)]);
        let canonical = [1u8; 32];
        let mut non_canonical = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let s = canonical[i] as u16 + modulus[i] as u16 + carry;
            non_canonical[i] = (s & 0xff) as u8;
            carry = s >> 8;
        }

        // Non-canonical recipient rejected
        let res = submitter
            .submit_deposit_from_fresh(
                WithdrawLeg::Native,
                100,
                &signer,
                ShieldedAddress(non_canonical),
                [2; 32],
            )
            .await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("canonical"));

        // Non-canonical randomness rejected
        let res = submitter
            .submit_deposit_from_fresh(
                WithdrawLeg::Native,
                100,
                &signer,
                ShieldedAddress([1; 32]),
                non_canonical,
            )
            .await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("canonical"));
    }

    #[test]
    fn new_rejects_proving_key_with_trailing_bytes() {
        let pk = dummy_pk();
        let mut bytes = Vec::new();
        pk.serialize_compressed(&mut bytes).unwrap();
        bytes.extend_from_slice(b"extra garbage bytes");

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), bytes).unwrap();

        let res = OnChainSubmitter::new(
            "http://127.0.0.1:8899",
            Pubkey::new_unique(),
            "http://127.0.0.1:8898",
            tmp.path(),
        );
        match res {
            Err(e) => assert!(e.to_string().contains("trailing bytes")),
            Ok(_) => panic!("expected failure on trailing bytes"),
        }
    }
}
