//! Solana bridge implementation

mod cosign_assembly;
mod cosign_message;
mod decoder;
mod instructions;
mod keypair;
mod listener;
mod program;
pub mod rpc;
#[cfg(test)]
mod test_support;

pub use cosign_assembly::{assemble_transaction, gather_signatures};
pub use cosign_message::{build_settlement_message, CoSignPayload, SettlementParams};
pub use instructions::{
    create_deactivate_validator_instruction, create_deposit_note_instruction,
    create_initialize_instruction, create_initialize_merkle_tree_instruction,
    create_initialize_validator_registry_instruction, create_register_validator_instruction,
    create_reset_validator_registry_instruction, create_set_bridge_authority_instruction,
    create_transact_instruction, derive_asset_vault, derive_asset_vault_authority,
    derive_associated_token_address, derive_bridge_state, derive_bridge_vault,
    derive_nullifier_account, derive_program_data, derive_validator_account,
    derive_validator_registry, DepositInstructionData, SPL_ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID,
    SPL_TOKEN_PROGRAM_ID,
};
pub use keypair::{load_keypair_from_file, pubkey_from_file};
pub use listener::EventListener;
pub use program::ProgramInterface;
pub use rpc::{BridgeRpc, RealBridgeRpc};

use crate::bridge::{BridgeConfig, BridgeStats, Result};
use crate::privacy::ShieldedPool;
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Solana bridge managing deposits and settlement submission.
pub struct SolanaBridge {
    /// Event listener for deposits
    listener: EventListener,

    /// Program interface
    program: ProgramInterface,

    /// Bridge statistics
    #[allow(dead_code)]
    stats: Arc<RwLock<BridgeStats>>,
}

impl SolanaBridge {
    /// Create a new Solana bridge
    pub fn new(
        config: BridgeConfig,
        pool: Arc<ShieldedPool>,
        stats: Arc<RwLock<BridgeStats>>,
    ) -> Result<Self> {
        // One RpcClient instance shared across listener / program /
        // submitter via the BridgeRpc trait.
        let rpc: Arc<dyn BridgeRpc> = Arc::new(RealBridgeRpc::new(Arc::new(
            RpcClient::new_with_commitment(
                config.solana_rpc_url.clone(),
                CommitmentConfig::confirmed(),
            ),
        )));
        let program = ProgramInterface::new(config.clone(), Arc::clone(&rpc))?;
        let listener =
            EventListener::new(config.clone(), Arc::clone(&rpc), pool, Arc::clone(&stats));

        Ok(Self {
            listener,
            program,
            stats,
        })
    }

    /// Start bridge services
    pub async fn start(&mut self) -> Result<()> {
        log::info!("Starting Solana bridge event listener...");
        self.listener.start().await?;

        log::info!("Solana bridge ready");
        Ok(())
    }

    /// Stop bridge services
    pub async fn stop(&mut self) -> Result<()> {
        log::info!("Stopping Solana bridge...");
        self.listener.stop().await?;

        Ok(())
    }

    /// Latest blockhash for a node-assembled co-signed settlement tx (#260).
    pub async fn latest_blockhash(&self) -> Result<[u8; 32]> {
        self.program.latest_blockhash().await
    }

    /// Current slot, for deriving a settlement's expiration window.
    pub async fn current_slot(&self) -> Result<u64> {
        self.program.get_slot().await
    }

    /// Submit a pre-assembled, co-signed settlement transaction (#260).
    pub async fn submit_signed_transaction(
        &self,
        transaction: &solana_sdk::transaction::Transaction,
    ) -> Result<String> {
        self.program.submit_signed_transaction(transaction).await
    }

    /// Get program interface
    pub fn program(&self) -> &ProgramInterface {
        &self.program
    }
}
