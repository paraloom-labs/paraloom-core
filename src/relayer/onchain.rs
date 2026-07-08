//! Production [`Submitter`] for the private-swap relayer (#240).
//!
//! # Status: pending v3 rework
//!
//! This submitter previously settled the withdraw-to-fresh and
//! re-deposit-from-fresh legs through the legacy off-chain-root `withdraw` /
//! `withdraw_spl` / `deposit_spl` instructions. Those instructions were removed
//! with the off-chain-root shielded path — all shielded settlement now goes
//! through the program-owned-tree `transact` instruction (which requires a v3
//! Groth16 proof and a validator co-sign quorum), and SPL support was dropped
//! for now (native-only). Re-expressing the relayer's two legs over `transact`
//! + `deposit_note` is a follow-up; until then this submitter's on-chain legs
//! return a clear error rather than building instructions that no longer exist
//! on-chain. The struct and constructor are retained so the `private_swap_demo`
//! binary and the mock-tested orchestration layer keep compiling.

use crate::privacy::types::{Nullifier, ShieldedAddress};
use crate::relayer::private_swap::{RelayerError, Result, SubmittedLeg, Submitter, WithdrawLeg};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
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

    /// Error returned by both on-chain legs while the relayer awaits its v3
    /// rework. References the retained config so the fields are not dead.
    fn pending_v3(&self) -> RelayerError {
        RelayerError::SubmissionFailed(format!(
            "on-chain relayer legs were removed with the off-chain-root shielded path \
             (program {}, rpc {}, expiration window {} slots); the private-swap relayer \
             must be re-expressed over the v3 transact + deposit_note flow before it can \
             settle on-chain",
            self.program_id, self.rpc_url, self.expiration_window_slots
        ))
    }
}

#[async_trait::async_trait]
impl Submitter for OnChainSubmitter {
    async fn submit_withdraw_to_fresh(
        &self,
        _leg: WithdrawLeg,
        _nullifier: Nullifier,
        _amount: u64,
        _fresh_address: [u8; 32],
        _proof: Vec<u8>,
    ) -> Result<SubmittedLeg> {
        let _ = self.authority.pubkey();
        Err(self.pending_v3())
    }

    async fn submit_deposit_from_fresh(
        &self,
        _leg: WithdrawLeg,
        _amount: u64,
        _signer: &Keypair,
        _recipient: ShieldedAddress,
        _randomness: [u8; 32],
    ) -> Result<SubmittedLeg> {
        Err(self.pending_v3())
    }
}
