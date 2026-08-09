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
use ark_ff::PrimeField;
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
        let pk = ark_groth16::ProvingKey::<Bn254>::deserialize_compressed(&bytes[..])
            .map_err(|e| RelayerError::SubmissionFailed(format!("decode proving key: {e}")))?;
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
