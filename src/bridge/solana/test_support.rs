//! Mock `BridgeRpc` for in-tree unit tests. Each method takes its
//! response off a per-call slot — set the slot before driving the
//! code under test, the mock returns it once, then any further call
//! produces a typed error so a test asserting "exactly one RPC call"
//! catches an unexpected second call instead of returning a stale
//! cached value.

#![cfg(test)]

use crate::bridge::solana::rpc::BridgeRpc;
use crate::bridge::{BridgeError, Result};
use async_trait::async_trait;
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
use solana_sdk::account::Account;
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::Transaction;
use solana_transaction_status::{EncodedConfirmedTransactionWithStatusMeta, UiTransactionEncoding};
use std::sync::Mutex;

#[derive(Default)]
pub struct MockBridgeRpc {
    pub next_get_account: Mutex<Option<Result<Account>>>,
    pub next_get_balance: Mutex<Option<Result<u64>>>,
    pub next_get_slot: Mutex<Option<Result<u64>>>,
    pub next_get_signatures: Mutex<Option<Result<Vec<RpcConfirmedTransactionStatusWithSignature>>>>,
    pub next_get_transaction: Mutex<Option<Result<EncodedConfirmedTransactionWithStatusMeta>>>,
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

#[async_trait]
impl BridgeRpc for MockBridgeRpc {
    async fn get_signatures_for_address_with_config(
        &self,
        _address: &Pubkey,
        _config: GetConfirmedSignaturesForAddress2Config,
    ) -> Result<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        take(&self.next_get_signatures, "get_signatures_for_address")
    }

    async fn get_transaction(
        &self,
        _signature: &Signature,
        _encoding: UiTransactionEncoding,
    ) -> Result<EncodedConfirmedTransactionWithStatusMeta> {
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
