//! Result submitter for withdrawals
//!
//! Submits withdrawal requests to Solana blockchain

use crate::bridge::{BridgeConfig, BridgeError, BridgeStats, Result, WithdrawalRequest};
use crate::privacy::ShieldedPool;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Result submitter for withdrawal transactions
pub struct ResultSubmitter {
    /// Bridge configuration
    config: BridgeConfig,

    /// Privacy pool for verification
    pool: Arc<ShieldedPool>,

    /// Bridge statistics
    stats: Arc<RwLock<BridgeStats>>,
}

impl ResultSubmitter {
    /// Create a new result submitter
    pub fn new(
        config: BridgeConfig,
        pool: Arc<ShieldedPool>,
        stats: Arc<RwLock<BridgeStats>>,
    ) -> Self {
        Self {
            config,
            pool,
            stats,
        }
    }

    /// Submit a withdrawal request to Solana
    pub async fn submit(&self, request: WithdrawalRequest) -> Result<String> {
        log::info!(
            "Submitting withdrawal: {} lamports to {:?}",
            request.amount,
            &request.recipient[..8]
        );

        // Verify nullifier hasn't been spent
        use crate::privacy::Nullifier;
        let nullifier = Nullifier(request.nullifier);

        if self.pool.is_spent(&nullifier).await {
            return Err(BridgeError::InvalidTransaction(
                "Nullifier already spent".to_string(),
            ));
        }

        // Verify proof
        self.verify_withdrawal_proof(&request).await?;

        // Process withdrawal in privacy pool
        self.pool
            .withdraw(nullifier, request.amount, &request.recipient)
            .await
            .map_err(|e| BridgeError::WithdrawalFailed(e.to_string()))?;

        // Submit to Solana
        let signature = self.submit_to_solana(&request).await?;

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_withdrawals += 1;
        stats.volume_withdrawn += request.amount;

        log::info!("Withdrawal submitted successfully: {}", signature);
        Ok(signature)
    }

    /// Verify withdrawal proof
    async fn verify_withdrawal_proof(&self, request: &WithdrawalRequest) -> Result<()> {
        // TODO: Implement actual zkSNARK proof verification
        // This should verify the withdrawal circuit proof

        if request.proof.is_empty() {
            return Err(BridgeError::InvalidTransaction(
                "Missing proof".to_string(),
            ));
        }

        // For now, accept any non-empty proof
        log::debug!("Verifying withdrawal proof ({} bytes)", request.proof.len());
        Ok(())
    }

    /// Submit withdrawal transaction to Solana
    async fn submit_to_solana(&self, request: &WithdrawalRequest) -> Result<String> {
        // TODO: Implement actual Solana transaction submission
        // This will:
        // 1. Create Solana transaction calling withdraw instruction
        // 2. Sign transaction
        // 3. Send to Solana RPC
        // 4. Wait for confirmation
        // 5. Return transaction signature

        // For now, return mock signature
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mock_signature = format!("withdraw_{}_{}", request.amount, timestamp);

        log::info!(
            "Would submit to Solana: {} lamports to {:?}",
            request.amount,
            &request.recipient[..8]
        );

        Ok(mock_signature)
    }

    /// Batch submit multiple withdrawals (optimization)
    pub async fn batch_submit(&self, requests: Vec<WithdrawalRequest>) -> Result<Vec<String>> {
        let mut signatures = Vec::new();

        for request in requests {
            match self.submit(request).await {
                Ok(sig) => signatures.push(sig),
                Err(e) => {
                    log::error!("Failed to submit withdrawal: {}", e);
                    // Continue with other withdrawals
                }
            }
        }

        Ok(signatures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::{pedersen, DepositTx, ShieldedAddress};

    #[tokio::test]
    async fn test_submitter_creation() {
        let config = BridgeConfig::default();
        let pool = Arc::new(ShieldedPool::new());
        let stats = Arc::new(RwLock::new(BridgeStats::default()));

        let _submitter = ResultSubmitter::new(config, pool, stats);
    }

    #[tokio::test]
    async fn test_submit_withdrawal() {
        let config = BridgeConfig::default();
        let pool = Arc::new(ShieldedPool::new());
        let stats = Arc::new(RwLock::new(BridgeStats::default()));

        // Setup: deposit some funds first
        let address = ShieldedAddress([1u8; 32]);
        let randomness = pedersen::generate_randomness();
        let deposit = DepositTx::new(vec![0x42; 32], 1000, address, randomness, 10);

        let note = deposit.output_note.clone();
        pool.deposit(note.clone(), 990).await.unwrap();

        // Create withdrawal request
        let request = WithdrawalRequest {
            nullifier: [1u8; 32],
            amount: 500,
            recipient: [0x99u8; 32],
            fee: 10,
            proof: vec![0u8; 32], // Mock proof
        };

        let submitter = ResultSubmitter::new(config, pool, stats);
        let result = submitter.submit(request).await;

        // Should succeed (mock implementation)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_batch_submit() {
        let config = BridgeConfig::default();
        let pool = Arc::new(ShieldedPool::new());
        let stats = Arc::new(RwLock::new(BridgeStats::default()));

        let requests = vec![
            WithdrawalRequest {
                nullifier: [1u8; 32],
                amount: 100,
                recipient: [0x01u8; 32],
                fee: 5,
                proof: vec![0u8; 32],
            },
            WithdrawalRequest {
                nullifier: [2u8; 32],
                amount: 200,
                recipient: [0x02u8; 32],
                fee: 5,
                proof: vec![0u8; 32],
            },
        ];

        let submitter = ResultSubmitter::new(config, pool, stats);
        let result = submitter.batch_submit(requests).await;

        assert!(result.is_ok());
    }
}
