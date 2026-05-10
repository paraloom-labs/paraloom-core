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
}

pub struct RealBridgeRpc {
    client: Arc<RpcClient>,
}

impl RealBridgeRpc {
    pub fn new(client: Arc<RpcClient>) -> Self {
        Self { client }
    }
}

async fn blocking<T, F>(label: &'static str, f: F) -> Result<T>
where
    F: FnOnce() -> std::result::Result<T, ClientError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        f().map_err(|e| BridgeError::SolanaRpc(format!("{}: {}", label, e)))
    })
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
            rpc.get_signatures_for_address_with_config(&addr, config)
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
            rpc.get_transaction(&sig, encoding)
        })
        .await
    }

    async fn get_account(&self, pubkey: &Pubkey) -> Result<Account> {
        let rpc = Arc::clone(&self.client);
        let key = *pubkey;
        blocking("getAccount", move || rpc.get_account(&key)).await
    }

    async fn send_and_confirm_transaction(&self, tx: &Transaction) -> Result<Signature> {
        let rpc = Arc::clone(&self.client);
        let tx = tx.clone();
        blocking("sendAndConfirmTransaction", move || {
            rpc.send_and_confirm_transaction(&tx)
        })
        .await
    }
}
