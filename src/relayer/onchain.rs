//! Production [`Submitter`] for the private-swap relayer (#240): settles the
//! withdraw-to-fresh and re-deposit-from-fresh legs as real on-chain
//! transactions, branching native vs. SPL on the [`WithdrawLeg`].
//!
//! # Who signs what
//!
//! The two legs are signed by different keys, and that split is the point:
//!
//! * **Withdraw leg** — signed by the bridge **authority** (the settlement
//!   key), exactly like [`crate::bin`]'s `demo_flow`. The on-chain `withdraw` /
//!   `withdraw_spl` are `has_one = authority` and credit the validator fee to
//!   the authority's validator account, so the authority must be a registered
//!   validator. Value lands at the fresh ephemeral address (native: its system
//!   account; SPL: its associated token account, created idempotently here).
//! * **Deposit-from-fresh leg** — signed by the per-swap **ephemeral** keypair,
//!   because on-chain `deposit` / `deposit_spl` require the depositor (the
//!   funds' owner) to sign, and after the swap that owner is the fresh address.
//!   The relayer threads that keypair in through
//!   [`Submitter::submit_deposit_from_fresh`].
//!
//! No key is shared between the user's original deposit and these legs, so the
//! on-chain trace never ties the user to the swap — the relayer-layer
//! expression of the withdrawal nullifier's link-severing.
//!
//! # Honest scope
//!
//! `RpcClient` is blocking, so every call is run on a blocking thread. This
//! submitter needs a live validator and a registered-validator authority key;
//! it is exercised end to end by the `private_swap_demo` binary against a
//! localnet (mainnet-fork for the swap leg), not in CI.

use crate::bridge::solana::{
    create_associated_token_account_idempotent_instruction, create_deposit_instruction,
    create_deposit_spl_instruction, create_withdraw_instruction, create_withdraw_spl_instruction,
    derive_associated_token_address, derive_bridge_vault,
};
use crate::privacy::types::{Nullifier, ShieldedAddress};
use crate::relayer::private_swap::{RelayerError, Result, SubmittedLeg, Submitter, WithdrawLeg};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::sync::Arc;

/// Settles the relayer's on-chain legs against a live Solana RPC.
///
/// Holds the program id, the bridge authority keypair (signs the withdraw
/// legs), the RPC URL, and the withdrawal expiration window. Cloneable handles
/// to the authority are shared into the blocking tasks.
pub struct OnChainSubmitter {
    program_id: Pubkey,
    authority: Arc<Keypair>,
    rpc_url: String,
    /// Slots added to the current slot to bound each withdrawal's validity.
    expiration_window_slots: u64,
}

impl OnChainSubmitter {
    /// Build a submitter over `rpc_url`, the deployed `program_id`, and the
    /// bridge `authority` (which must be a registered validator). The
    /// `expiration_window_slots` bounds each withdrawal's on-chain validity
    /// (`current_slot + window`).
    pub fn new(
        rpc_url: impl Into<String>,
        program_id: Pubkey,
        authority: Keypair,
        expiration_window_slots: u64,
    ) -> Self {
        Self {
            program_id,
            authority: Arc::new(authority),
            rpc_url: rpc_url.into(),
            expiration_window_slots,
        }
    }

    fn client(&self) -> RpcClient {
        RpcClient::new_with_commitment(self.rpc_url.clone(), CommitmentConfig::confirmed())
    }

    /// Sign `instructions` with `signers` (payer first) and send+confirm, off
    /// the async runtime. Returns the transaction signature string.
    async fn send(
        &self,
        instructions: Vec<Instruction>,
        signers: Vec<Arc<Keypair>>,
    ) -> Result<String> {
        let rpc_url = self.rpc_url.clone();
        tokio::task::spawn_blocking(move || {
            let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
            let payer = signers[0].pubkey();
            let blockhash = client
                .get_latest_blockhash()
                .map_err(|e| RelayerError::SubmissionFailed(e.to_string()))?;
            let signer_refs: Vec<&Keypair> = signers.iter().map(|s| s.as_ref()).collect();
            let tx = Transaction::new_signed_with_payer(
                &instructions,
                Some(&payer),
                &signer_refs,
                blockhash,
            );
            client
                .send_and_confirm_transaction(&tx)
                .map(|sig| sig.to_string())
                .map_err(|e| RelayerError::SubmissionFailed(e.to_string()))
        })
        .await
        .map_err(|e| RelayerError::SubmissionFailed(format!("join error: {e}")))?
    }

    /// Current slot + the configured window, the `expiration_slot` the on-chain
    /// withdraw enforces.
    async fn expiration_slot(&self) -> Result<u64> {
        let client = self.client();
        let window = self.expiration_window_slots;
        tokio::task::spawn_blocking(move || {
            client
                .get_slot()
                .map(|slot| slot + window)
                .map_err(|e| RelayerError::SubmissionFailed(e.to_string()))
        })
        .await
        .map_err(|e| RelayerError::SubmissionFailed(format!("join error: {e}")))?
    }
}

#[async_trait::async_trait]
impl Submitter for OnChainSubmitter {
    async fn submit_withdraw_to_fresh(
        &self,
        leg: WithdrawLeg,
        nullifier: Nullifier,
        amount: u64,
        fresh_address: [u8; 32],
        proof: Vec<u8>,
    ) -> Result<SubmittedLeg> {
        let expiration_slot = self.expiration_slot().await?;
        let fresh = Pubkey::new_from_array(fresh_address);
        let nullifier_bytes = *nullifier.as_bytes();

        // The prover hands us the arkworks-compressed proof; the on-chain
        // verifier expects the 256-byte alt_bn128 wire form. Convert at this
        // submission boundary (#249).
        let proof = crate::privacy::onchain_verifier::compressed_proof_to_onchain_bytes(&proof)
            .map_err(|e| RelayerError::SubmissionFailed(format!("proof encoding: {e}")))?
            .to_vec();

        let signature = match leg {
            WithdrawLeg::Native => {
                let (bridge_vault, _) = derive_bridge_vault(&self.program_id);
                let ix = create_withdraw_instruction(
                    &self.program_id,
                    &self.authority.pubkey(),
                    &bridge_vault,
                    fresh_address,
                    nullifier_bytes,
                    amount,
                    expiration_slot,
                    proof,
                    &[self.authority.pubkey()], // quorum co-signers (#260)
                )
                .map_err(|e| RelayerError::SubmissionFailed(e.to_string()))?;
                self.send(vec![ix], vec![self.authority.clone()]).await?
            }
            WithdrawLeg::Spl(mint_bytes) => {
                let mint = Pubkey::new_from_array(mint_bytes);
                // Ensure the fresh address has an ATA to receive into; the
                // authority pays the rent. Idempotent, so a pre-existing ATA is
                // fine.
                let create_ata = create_associated_token_account_idempotent_instruction(
                    &self.authority.pubkey(),
                    &fresh,
                    &mint,
                );
                let recipient_token = derive_associated_token_address(&fresh, &mint);
                let withdraw = create_withdraw_spl_instruction(
                    &self.program_id,
                    &self.authority.pubkey(),
                    &mint,
                    &recipient_token,
                    nullifier_bytes,
                    amount,
                    expiration_slot,
                    proof,
                    // Quorum co-signers (#260); the node-side round that gathers
                    // the full validator quorum into the tx is the next step.
                    &[self.authority.pubkey()],
                )
                .map_err(|e| RelayerError::SubmissionFailed(e.to_string()))?;
                self.send(vec![create_ata, withdraw], vec![self.authority.clone()])
                    .await?
            }
        };

        Ok(SubmittedLeg {
            leg,
            amount,
            fresh_address,
            signature,
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
        let fresh_address = signer.pubkey().to_bytes();
        // The ephemeral key signs (and pays) — it owns the post-swap funds.
        let ephemeral = Arc::new(signer.insecure_clone());
        let recipient_bytes = *recipient.as_bytes();

        let signature = match leg {
            WithdrawLeg::Native => {
                let (bridge_vault, _) = derive_bridge_vault(&self.program_id);
                let ix = create_deposit_instruction(
                    &self.program_id,
                    &signer.pubkey(),
                    &bridge_vault,
                    amount,
                    recipient_bytes,
                    randomness,
                )
                .map_err(|e| RelayerError::SubmissionFailed(e.to_string()))?;
                self.send(vec![ix], vec![ephemeral]).await?
            }
            WithdrawLeg::Spl(mint_bytes) => {
                let mint = Pubkey::new_from_array(mint_bytes);
                let depositor_token = derive_associated_token_address(&signer.pubkey(), &mint);
                let ix = create_deposit_spl_instruction(
                    &self.program_id,
                    &signer.pubkey(),
                    &mint,
                    &depositor_token,
                    amount,
                    recipient_bytes,
                    randomness,
                )
                .map_err(|e| RelayerError::SubmissionFailed(e.to_string()))?;
                self.send(vec![ix], vec![ephemeral]).await?
            }
        };

        Ok(SubmittedLeg {
            leg,
            amount,
            fresh_address,
            signature,
        })
    }
}
