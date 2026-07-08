//! Mock `BridgeRpc` for in-tree unit tests. Each method takes its
//! response off a per-call slot — set the slot before driving the
//! code under test, the mock returns it once, then any further call
//! produces a typed error so a test asserting "exactly one RPC call"
//! catches an unexpected second call instead of returning a stale
//! cached value.

#![cfg(test)]

use crate::bridge::solana::instructions::{discriminators, DepositInstructionData};
use crate::bridge::solana::rpc::BridgeRpc;
use crate::bridge::{BridgeError, Result};
use async_trait::async_trait;
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
use solana_sdk::account::Account;
use solana_sdk::hash::Hash;
use solana_sdk::message::MessageHeader;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::Transaction;
use solana_transaction_status::{
    EncodedConfirmedTransactionWithStatusMeta, EncodedTransaction,
    EncodedTransactionWithStatusMeta, UiCompiledInstruction, UiMessage, UiRawMessage,
    UiTransaction, UiTransactionEncoding,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

#[derive(Default)]
pub struct MockBridgeRpc {
    pub next_get_account: Mutex<Option<Result<Account>>>,
    pub next_get_balance: Mutex<Option<Result<u64>>>,
    pub next_get_slot: Mutex<Option<Result<u64>>>,
    pub next_get_signatures: Mutex<Option<Result<Vec<RpcConfirmedTransactionStatusWithSignature>>>>,
    /// Successive `getSignaturesForAddress` pages, consumed front-first. When
    /// non-empty this takes precedence over `next_get_signatures`, letting a
    /// test drive the pagination loop across multiple calls.
    pub get_signatures_pages:
        Mutex<VecDeque<Result<Vec<RpcConfirmedTransactionStatusWithSignature>>>>,
    pub next_get_transaction: Mutex<Option<Result<EncodedConfirmedTransactionWithStatusMeta>>>,
    /// `getTransaction` responses keyed by signature, consumed once per
    /// signature (the value is not `Clone`). When it has no entry for the
    /// requested signature the mock falls back to `next_get_transaction`.
    pub get_transactions: Mutex<HashMap<Signature, EncodedConfirmedTransactionWithStatusMeta>>,
    pub next_get_latest_blockhash: Mutex<Option<Result<Hash>>>,
    pub next_send_and_confirm: Mutex<Option<Result<Signature>>>,
}

impl MockBridgeRpc {
    pub fn new() -> Self {
        Self::default()
    }
}

fn take<T>(slot: &Mutex<Option<Result<T>>>, label: &'static str) -> Result<T> {
    slot.lock().unwrap().take().unwrap_or_else(|| {
        Err(BridgeError::SolanaRpc(format!(
            "mock {} not configured",
            label
        )))
    })
}

/// Build a synthetic `EncodedConfirmedTransactionWithStatusMeta`
/// shaped like what `getTransaction` returns for a real Paraloom
/// deposit. Used by listener tests that need to drive
/// `extract_deposit_events` end to end without booting a validator.
/// Account ordering matches the legacy deposit instruction's account
/// metas: `[bridge_state, bridge_vault, depositor, system_program,
/// program]` (program is at index 4 so the program-id-index in the
/// instruction lands there, with `depositor` at index 2 to match
/// `DEPOSITOR_ACCOUNT_INDEX` in the decoder).
pub fn synth_deposit_tx(
    signature: Signature,
    slot: u64,
    program_id: &Pubkey,
    depositor: &Pubkey,
    amount: u64,
    recipient: [u8; 32],
    randomness: [u8; 32],
) -> EncodedConfirmedTransactionWithStatusMeta {
    let payload = DepositInstructionData {
        amount,
        recipient,
        randomness,
    };
    let mut data = discriminators::DEPOSIT.to_vec();
    data.extend_from_slice(&borsh::to_vec(&payload).expect("borsh serialise"));
    let instruction = UiCompiledInstruction {
        program_id_index: 4,
        accounts: vec![0, 1, 2, 3],
        data: bs58::encode(data).into_string(),
        stack_height: None,
    };
    let dummy = Pubkey::default();
    let account_keys = vec![
        dummy.to_string(),
        dummy.to_string(),
        depositor.to_string(),
        solana_sdk::system_program::ID.to_string(),
        program_id.to_string(),
    ];
    let raw = UiRawMessage {
        header: MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 2,
        },
        account_keys,
        recent_blockhash: Hash::default().to_string(),
        instructions: vec![instruction],
        address_table_lookups: None,
    };
    EncodedConfirmedTransactionWithStatusMeta {
        slot,
        transaction: EncodedTransactionWithStatusMeta {
            transaction: EncodedTransaction::Json(UiTransaction {
                signatures: vec![signature.to_string()],
                message: UiMessage::Raw(raw),
            }),
            meta: None,
            version: None,
        },
        block_time: None,
    }
}

#[async_trait]
impl BridgeRpc for MockBridgeRpc {
    async fn get_signatures_for_address_with_config(
        &self,
        _address: &Pubkey,
        _config: GetConfirmedSignaturesForAddress2Config,
    ) -> Result<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        if let Some(page) = self.get_signatures_pages.lock().unwrap().pop_front() {
            return page;
        }
        take(&self.next_get_signatures, "get_signatures_for_address")
    }

    async fn get_transaction(
        &self,
        signature: &Signature,
        _encoding: UiTransactionEncoding,
    ) -> Result<EncodedConfirmedTransactionWithStatusMeta> {
        if let Some(tx) = self.get_transactions.lock().unwrap().remove(signature) {
            return Ok(tx);
        }
        take(&self.next_get_transaction, "get_transaction")
    }

    async fn get_account(&self, _pubkey: &Pubkey) -> Result<Account> {
        take(&self.next_get_account, "get_account")
    }

    async fn send_and_confirm_transaction(&self, _tx: &Transaction) -> Result<Signature> {
        take(&self.next_send_and_confirm, "send_and_confirm_transaction")
    }

    async fn get_latest_blockhash(&self) -> Result<Hash> {
        take(&self.next_get_latest_blockhash, "get_latest_blockhash")
    }

    async fn get_balance(&self, _pubkey: &Pubkey) -> Result<u64> {
        take(&self.next_get_balance, "get_balance")
    }

    async fn get_slot(&self) -> Result<u64> {
        take(&self.next_get_slot, "get_slot")
    }
}
