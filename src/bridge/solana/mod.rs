//! Solana bridge implementation

mod decoder;
mod instructions;
mod keypair;
mod listener;
mod program;
pub mod rpc;
mod submitter;
#[cfg(test)]
mod test_support;

pub use instructions::{
    create_deposit_instruction, create_initialize_instruction,
    create_initialize_validator_registry_instruction, create_register_validator_instruction,
    create_shielded_transfer_instruction, create_update_merkle_root_instruction,
    create_withdraw_instruction, derive_bridge_state, derive_bridge_vault,
    derive_nullifier_account, derive_program_data, derive_validator_account,
    derive_validator_registry, DepositInstructionData, ShieldedTransferInstructionData,
};
pub use keypair::load_keypair_from_file;
pub use listener::EventListener;
pub use program::ProgramInterface;
pub use rpc::{BridgeRpc, RealBridgeRpc};
pub use submitter::ResultSubmitter;

use crate::bridge::{BridgeConfig, BridgeStats, Result, WithdrawalRequest};
use crate::consensus::ApprovedWithdrawal;
use crate::privacy::ShieldedPool;
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Solana bridge managing deposits and withdrawals
pub struct SolanaBridge {
    /// Event listener for deposits
    listener: EventListener,

    /// Result submitter for withdrawals
    submitter: ResultSubmitter,

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
        let listener = EventListener::new(
            config.clone(),
            Arc::clone(&rpc),
            pool.clone(),
            Arc::clone(&stats),
        );
        let submitter = ResultSubmitter::new(config, rpc, pool, Arc::clone(&stats))?;

        Ok(Self {
            listener,
            submitter,
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

    /// Submit a withdrawal to Solana
    pub async fn submit_withdrawal(&self, request: WithdrawalRequest) -> Result<String> {
        self.submitter.submit(request).await
    }

    /// Settle a consensus-approved withdrawal on-chain (#164).
    pub async fn submit_approved(&self, approved: ApprovedWithdrawal) -> Result<String> {
        self.submitter.submit_approved(approved).await
    }

    /// Settle a consensus-approved shielded transfer on-chain (#194).
    pub async fn submit_approved_transfer(
        &self,
        approved: crate::consensus::ApprovedTransfer,
    ) -> Result<String> {
        self.submitter.submit_approved_transfer(approved).await
    }

    /// Get program interface
    pub fn program(&self) -> &ProgramInterface {
        &self.program
    }
}
