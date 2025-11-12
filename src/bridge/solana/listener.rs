//! Event listener for Solana deposits
//!
//! Monitors Solana blockchain for deposit events and processes them
//! into the privacy pool

use crate::bridge::{BridgeConfig, BridgeError, BridgeStats, DepositEvent, Result};
use crate::privacy::{DepositTx, ShieldedAddress, ShieldedPool};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

/// Event listener for deposit events
pub struct EventListener {
    /// Bridge configuration
    config: BridgeConfig,

    /// Privacy pool to process deposits into
    pool: Arc<ShieldedPool>,

    /// Bridge statistics
    stats: Arc<RwLock<BridgeStats>>,

    /// Running flag
    running: Arc<RwLock<bool>>,

    /// Last processed block
    last_block: Arc<RwLock<u64>>,
}

impl EventListener {
    /// Create a new event listener
    pub fn new(
        config: BridgeConfig,
        pool: Arc<ShieldedPool>,
        stats: Arc<RwLock<BridgeStats>>,
    ) -> Self {
        let start_block = config.start_block.unwrap_or(0);

        Self {
            config,
            pool,
            stats,
            running: Arc::new(RwLock::new(false)),
            last_block: Arc::new(RwLock::new(start_block)),
        }
    }

    /// Start listening for events
    pub async fn start(&mut self) -> Result<()> {
        *self.running.write().await = true;

        let running = Arc::clone(&self.running);
        let pool = Arc::clone(&self.pool);
        let stats = Arc::clone(&self.stats);
        let last_block = Arc::clone(&self.last_block);
        let poll_interval = self.config.poll_interval_secs;

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(poll_interval));

            while *running.read().await {
                ticker.tick().await;

                match Self::poll_events(&pool, &stats, &last_block).await {
                    Ok(count) => {
                        if count > 0 {
                            log::info!("Processed {} deposit events", count);
                        }
                    }
                    Err(e) => {
                        log::error!("Error polling events: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop listening
    pub async fn stop(&mut self) -> Result<()> {
        *self.running.write().await = false;
        Ok(())
    }

    /// Poll for new deposit events
    async fn poll_events(
        pool: &Arc<ShieldedPool>,
        stats: &Arc<RwLock<BridgeStats>>,
        last_block: &Arc<RwLock<u64>>,
    ) -> Result<usize> {
        let current_block = *last_block.read().await;
        let events = Self::fetch_events(current_block).await?;

        let mut processed = 0;
        for event in events {
            let amount = event.amount;
            match Self::process_deposit(pool, event).await {
                Ok(_) => {
                    processed += 1;
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_deposits += 1;
                    stats_guard.volume_deposited += amount;
                }
                Err(e) => {
                    log::error!("Failed to process deposit: {}", e);
                }
            }
        }

        if processed > 0 {
            let mut block = last_block.write().await;
            *block += 1;

            let mut stats_guard = stats.write().await;
            stats_guard.last_block = *block;
        }

        Ok(processed)
    }

    /// Fetch deposit events from Solana
    async fn fetch_events(_from_block: u64) -> Result<Vec<DepositEvent>> {
        Ok(Vec::new())
    }

    /// Process a single deposit event
    async fn process_deposit(pool: &Arc<ShieldedPool>, event: DepositEvent) -> Result<()> {
        log::info!(
            "Processing deposit: {} lamports from {:?}",
            event.amount,
            &event.from[..8]
        );

        // Create shielded address from recipient
        let recipient = ShieldedAddress(event.recipient);

        // Create deposit transaction
        let deposit_tx = DepositTx::new(
            event.from.to_vec(),
            event.amount,
            recipient,
            event.randomness,
            event.fee,
        );

        // Verify deposit transaction
        if !deposit_tx.verify() {
            return Err(BridgeError::InvalidTransaction(
                "Deposit verification failed".to_string(),
            ));
        }

        // Process deposit into pool
        let net_amount = event.amount.saturating_sub(event.fee);
        pool.deposit(deposit_tx.output_note, net_amount)
            .await
            .map_err(|e| BridgeError::DepositFailed(e.to_string()))?;

        log::info!("Deposit processed successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::pedersen;

    #[test]
    fn test_listener_creation() {
        let config = BridgeConfig::default();
        let pool = Arc::new(ShieldedPool::new());
        let stats = Arc::new(RwLock::new(BridgeStats::default()));

        let listener = EventListener::new(config, pool, stats);
        assert_eq!(*listener.last_block.blocking_read(), 0);
    }

    #[tokio::test]
    async fn test_process_deposit() {
        let pool = Arc::new(ShieldedPool::new());
        let randomness = pedersen::generate_randomness();

        let event = DepositEvent {
            signature: "test_sig".to_string(),
            from: [1u8; 32],
            amount: 1000,
            recipient: [2u8; 32],
            randomness,
            fee: 10,
            block: 100,
            timestamp: 0,
        };

        let result = EventListener::process_deposit(&pool, event).await;
        assert!(result.is_ok());

        // Verify deposit was added to pool
        assert_eq!(pool.total_supply().await, 990); // 1000 - 10 fee
        assert_eq!(pool.commitment_count().await, 1);
    }
}
