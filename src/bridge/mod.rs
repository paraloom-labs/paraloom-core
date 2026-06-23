//! Bridge module for cross-chain integration
//!
//! Connects Paraloom privacy layer with external blockchains (currently Solana).
//! Handles deposits from blockchain to privacy pool and withdrawals back.

pub mod error;
pub mod solana;
pub mod types;

pub use error::{BridgeError, Result};
pub use types::{BridgeConfig, BridgeStats, DepositEvent, SolanaAddress, WithdrawalRequest};

/// Semver-encoded program version this L2 binary was compiled against:
/// `major(8) | minor(8) | patch(8) | reserved(8)`. v0.4.0 → 0x00040000.
/// The L2 reads `BridgeState.program_version` from the deployed
/// program at startup and refuses to talk to a program at a
/// different version (#69, audit #9). Bump in lockstep with every
/// breaking on-chain change so a missed redeploy fails loudly
/// instead of silently sending incompatible instructions.
pub const EXPECTED_PROGRAM_VERSION: u32 = 0x0004_0000;

use crate::privacy::ShieldedPool;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Bridge manager coordinating all bridge operations
pub struct Bridge {
    /// Solana bridge instance
    solana_bridge: Option<solana::SolanaBridge>,

    /// Bridge configuration
    config: BridgeConfig,

    /// Bridge statistics
    stats: Arc<RwLock<BridgeStats>>,
}

impl Bridge {
    /// Create a new bridge instance
    pub fn new(config: BridgeConfig) -> Self {
        Self {
            solana_bridge: None,
            config,
            stats: Arc::new(RwLock::new(BridgeStats::default())),
        }
    }

    /// Initialize bridge with privacy pool
    pub async fn init(&mut self, pool: Arc<ShieldedPool>) -> Result<()> {
        if !self.config.enabled {
            log::info!("Bridge disabled in configuration");
            return Ok(());
        }

        log::info!("Initializing Solana bridge...");
        self.solana_bridge = Some(solana::SolanaBridge::new(
            self.config.clone(),
            pool,
            Arc::clone(&self.stats),
        )?);

        Ok(())
    }

    /// Start bridge services (event listener, etc.)
    pub async fn start(&mut self) -> Result<()> {
        if let Some(ref mut bridge) = self.solana_bridge {
            log::info!("Starting Solana bridge services...");
            bridge.start().await?;
        }

        Ok(())
    }

    /// Stop bridge services
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(ref mut bridge) = self.solana_bridge {
            log::info!("Stopping Solana bridge services...");
            bridge.stop().await?;
        }

        Ok(())
    }

    /// Get bridge statistics
    pub async fn stats(&self) -> BridgeStats {
        self.stats.read().await.clone()
    }

    /// Submit a withdrawal to Solana
    pub async fn submit_withdrawal(&self, request: WithdrawalRequest) -> Result<String> {
        if let Some(ref bridge) = self.solana_bridge {
            bridge.submit_withdrawal(request).await
        } else {
            Err(BridgeError::ConfigError(
                "Solana bridge not initialized".to_string(),
            ))
        }
    }

    /// Settle a consensus-approved withdrawal on-chain (#164). Called by
    /// the node's submitter task when the validator quorum approves a
    /// withdrawal; the expiration slot is derived inside the submitter.
    pub async fn submit_approved(
        &self,
        approved: crate::consensus::ApprovedWithdrawal,
    ) -> Result<String> {
        if let Some(ref bridge) = self.solana_bridge {
            bridge.submit_approved(approved).await
        } else {
            Err(BridgeError::ConfigError(
                "Solana bridge not initialized".to_string(),
            ))
        }
    }

    /// Settle a consensus-approved shielded transfer on-chain (#194). Called
    /// by the node's transfer submitter task when the validator quorum
    /// approves a transfer.
    pub async fn submit_approved_transfer(
        &self,
        approved: crate::consensus::ApprovedTransfer,
    ) -> Result<String> {
        if let Some(ref bridge) = self.solana_bridge {
            bridge.submit_approved_transfer(approved).await
        } else {
            Err(BridgeError::ConfigError(
                "Solana bridge not initialized".to_string(),
            ))
        }
    }

    /// Latest blockhash for a node-assembled co-signed settlement tx (#260).
    pub async fn latest_blockhash(&self) -> Result<[u8; 32]> {
        if let Some(ref bridge) = self.solana_bridge {
            bridge.latest_blockhash().await
        } else {
            Err(BridgeError::ConfigError(
                "Solana bridge not initialized".to_string(),
            ))
        }
    }

    /// Current slot, for deriving a settlement's expiration window.
    pub async fn current_slot(&self) -> Result<u64> {
        if let Some(ref bridge) = self.solana_bridge {
            bridge.current_slot().await
        } else {
            Err(BridgeError::ConfigError(
                "Solana bridge not initialized".to_string(),
            ))
        }
    }

    /// Submit a pre-assembled, co-signed settlement transaction (#260) — the
    /// multi-sig withdrawal the node gathered from the approving validators.
    pub async fn submit_signed_transaction(
        &self,
        transaction: &solana_sdk::transaction::Transaction,
    ) -> Result<String> {
        if let Some(ref bridge) = self.solana_bridge {
            bridge.submit_signed_transaction(transaction).await
        } else {
            Err(BridgeError::ConfigError(
                "Solana bridge not initialized".to_string(),
            ))
        }
    }

    /// Publish the live shielded-pool root on-chain via the quorum-gated
    /// `update_merkle_root` instruction (#260), so the on-chain `withdraw`
    /// verifies proofs against the same root the wallet proved against (the
    /// deposit listener never advances `bridge_state.merkle_root`).
    pub async fn update_merkle_root(
        &self,
        new_root: [u8; 32],
        quorum_validators: &[solana_sdk::pubkey::Pubkey],
    ) -> Result<String> {
        if let Some(ref bridge) = self.solana_bridge {
            bridge
                .program()
                .update_merkle_root(new_root, quorum_validators)
                .await
        } else {
            Err(BridgeError::ConfigError(
                "Solana bridge not initialized".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bridge_creation() {
        let config = BridgeConfig::default();
        let bridge = Bridge::new(config);
        assert!(bridge.solana_bridge.is_none());
    }

    #[tokio::test]
    async fn test_bridge_stats() {
        let config = BridgeConfig::default();
        let bridge = Bridge::new(config);
        let stats = bridge.stats().await;
        assert_eq!(stats.total_deposits, 0);
        assert_eq!(stats.total_withdrawals, 0);
    }
}
