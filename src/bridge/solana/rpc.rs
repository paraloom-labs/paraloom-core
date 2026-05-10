//! Trait abstraction over `solana_client::RpcClient` so the bridge
//! can be unit-tested with a mock instead of a live RPC. Production
//! code depends on `Arc<dyn BridgeRpc>`; `RealBridgeRpc` wraps a
//! real client.

use crate::bridge::{BridgeError, Result};
use async_trait::async_trait;
use solana_client::client_error::ClientError;
use solana_client::rpc_client::{GetConfirmedSignaturesForAddress2Config, RpcClient};
use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
use solana_sdk::account::Account;
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::Transaction;
use solana_transaction_status::{EncodedConfirmedTransactionWithStatusMeta, UiTransactionEncoding};
use std::sync::Arc;

#[async_trait]
pub trait BridgeRpc: Send + Sync {
    async fn get_signatures_for_address_with_config(
        &self,
        address: &Pubkey,
        config: GetConfirmedSignaturesForAddress2Config,
    ) -> Result<Vec<RpcConfirmedTransactionStatusWithSignature>>;

    async fn get_transaction(
        &self,
        signature: &Signature,
        encoding: UiTransactionEncoding,
    ) -> Result<EncodedConfirmedTransactionWithStatusMeta>;

    async fn get_account(&self, pubkey: &Pubkey) -> Result<Account>;

    async fn send_and_confirm_transaction(&self, tx: &Transaction) -> Result<Signature>;

    async fn get_latest_blockhash(&self) -> Result<Hash>;

    async fn get_balance(&self, pubkey: &Pubkey) -> Result<u64>;

    async fn get_slot(&self) -> Result<u64>;
}

pub struct RealBridgeRpc {
    client: Arc<RpcClient>,
}

impl RealBridgeRpc {
    pub fn new(client: Arc<RpcClient>) -> Self {
        Self { client }
    }
}

/// Map a `ClientError` (large) to a `BridgeError::SolanaRpc` (small)
/// at the call site so closures crossing `spawn_blocking` never carry
/// the large variant — `clippy::result_large_err` flags the un-mapped
/// shape.
fn rpc_err<T>(label: &'static str, r: std::result::Result<T, ClientError>) -> Result<T> {
    r.map_err(|e| BridgeError::SolanaRpc(format!("{}: {}", label, e)))
}

async fn blocking<T, F>(label: &'static str, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| BridgeError::SolanaRpc(format!("{} task panicked: {}", label, e)))?
}

#[async_trait]
impl BridgeRpc for RealBridgeRpc {
    async fn get_signatures_for_address_with_config(
        &self,
        address: &Pubkey,
        config: GetConfirmedSignaturesForAddress2Config,
    ) -> Result<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        let rpc = Arc::clone(&self.client);
        let addr = *address;
        blocking("getSignaturesForAddress", move || {
            rpc_err(
                "getSignaturesForAddress",
                rpc.get_signatures_for_address_with_config(&addr, config),
            )
        })
        .await
    }

    async fn get_transaction(
        &self,
        signature: &Signature,
        encoding: UiTransactionEncoding,
    ) -> Result<EncodedConfirmedTransactionWithStatusMeta> {
        let rpc = Arc::clone(&self.client);
        let sig = *signature;
        blocking("getTransaction", move || {
            rpc_err("getTransaction", rpc.get_transaction(&sig, encoding))
        })
        .await
    }

    async fn get_account(&self, pubkey: &Pubkey) -> Result<Account> {
        let rpc = Arc::clone(&self.client);
        let key = *pubkey;
        blocking("getAccount", move || {
            rpc_err("getAccount", rpc.get_account(&key))
        })
        .await
    }

    async fn send_and_confirm_transaction(&self, tx: &Transaction) -> Result<Signature> {
        let rpc = Arc::clone(&self.client);
        let tx = tx.clone();
        blocking("sendAndConfirmTransaction", move || {
            rpc_err(
                "sendAndConfirmTransaction",
                rpc.send_and_confirm_transaction(&tx),
            )
        })
        .await
    }

    async fn get_latest_blockhash(&self) -> Result<Hash> {
        let rpc = Arc::clone(&self.client);
        blocking("getLatestBlockhash", move || {
            rpc_err("getLatestBlockhash", rpc.get_latest_blockhash())
        })
        .await
    }

    async fn get_balance(&self, pubkey: &Pubkey) -> Result<u64> {
        let rpc = Arc::clone(&self.client);
        let key = *pubkey;
        blocking("getBalance", move || {
            rpc_err("getBalance", rpc.get_balance(&key))
        })
        .await
    }

    async fn get_slot(&self) -> Result<u64> {
        let rpc = Arc::clone(&self.client);
        blocking("getSlot", move || rpc_err("getSlot", rpc.get_slot())).await
    }
}
