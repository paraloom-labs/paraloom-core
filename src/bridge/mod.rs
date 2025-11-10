//! Bridge module for cross-chain integration
//!
//! Connects Paraloom privacy layer with external blockchains (currently Solana).
//! Handles deposits from blockchain to privacy pool and withdrawals back.

pub mod error;
pub mod solana;
pub mod types;

pub use error::{BridgeError, Result};
pub use types::{BridgeConfig, BridgeStats, DepositEvent, SolanaAddress, WithdrawalRequest};

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
