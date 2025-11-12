//! Solana bridge implementation

mod instructions;
mod keypair;
mod listener;
mod program;
mod submitter;

pub use instructions::{
    create_deposit_instruction, create_initialize_instruction,
    create_update_merkle_root_instruction, create_withdraw_instruction, derive_bridge_state,
    derive_bridge_vault, derive_nullifier_account,
};
pub use keypair::load_keypair_from_file;
pub use listener::EventListener;
pub use program::ProgramInterface;
pub use submitter::ResultSubmitter;

use crate::bridge::{BridgeConfig, BridgeStats, Result, WithdrawalRequest};
use crate::privacy::ShieldedPool;
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
        let program = ProgramInterface::new(config.clone())?;
        let listener = EventListener::new(config.clone(), pool.clone(), Arc::clone(&stats));
        let submitter = ResultSubmitter::new(config, pool, Arc::clone(&stats))?;

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

    /// Get program interface
    pub fn program(&self) -> &ProgramInterface {
        &self.program
    }
}
