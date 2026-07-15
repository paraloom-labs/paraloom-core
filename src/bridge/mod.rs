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

    /// Validate that a withdrawal request has not expired (#532).
    ///
    /// Returns `Ok(())` if the request is still valid, or an error if the
    /// current slot exceeds the request's `expiration_slot`. Requests with
    /// `expiration_slot == 0` are treated as having no expiry.
    pub async fn validate_withdrawal_expiry(
        &self,
        request: &crate::bridge::types::WithdrawalRequest,
    ) -> Result<()> {
        if request.expiration_slot == 0 {
            return Ok(());
        }
        let current = self.current_slot().await?;
        if current > request.expiration_slot {
            return Err(anyhow::anyhow!(
                "Withdrawal request expired: current slot {} > expiration_slot {} (#532)",
                current,
                request.expiration_slot
            ));
        }
        Ok(())
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
