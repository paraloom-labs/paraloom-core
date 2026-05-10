//! Result submitter for withdrawals
//!
//! Submits withdrawal requests to Solana blockchain

use crate::bridge::solana::rpc::BridgeRpc;
use crate::bridge::{BridgeConfig, BridgeError, BridgeStats, Result, WithdrawalRequest};
use crate::consensus::WithdrawalVerificationCoordinator;
use crate::privacy::ShieldedPool;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::ProgramInterface;

/// Result submitter for withdrawal transactions
pub struct ResultSubmitter {
    /// Privacy pool for verification
    pool: Arc<ShieldedPool>,

    /// Bridge statistics
    stats: Arc<RwLock<BridgeStats>>,

    /// Program interface for Solana interactions
    program: ProgramInterface,

    /// Distributed verification coordinator (optional)
    verification_coordinator: Option<Arc<WithdrawalVerificationCoordinator>>,

    /// Enable distributed consensus
    enable_consensus: bool,
}

impl ResultSubmitter {
    /// Create a new result submitter
    pub fn new(
        config: BridgeConfig,
        rpc: Arc<dyn BridgeRpc>,
        pool: Arc<ShieldedPool>,
        stats: Arc<RwLock<BridgeStats>>,
    ) -> Result<Self> {
        let program = ProgramInterface::new(config, rpc)?;
        Ok(Self {
            pool,
            stats,
            program,
            verification_coordinator: None,
            enable_consensus: false,
        })
    }

    /// Create a new result submitter with distributed consensus
    pub fn with_consensus(
        config: BridgeConfig,
        rpc: Arc<dyn BridgeRpc>,
        pool: Arc<ShieldedPool>,
        stats: Arc<RwLock<BridgeStats>>,
        verification_coordinator: Arc<WithdrawalVerificationCoordinator>,
    ) -> Result<Self> {
        let program = ProgramInterface::new(config, rpc)?;
        Ok(Self {
            pool,
            stats,
            program,
            verification_coordinator: Some(verification_coordinator),
            enable_consensus: true,
        })
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

    /// Verify withdrawal proof with real zkSNARK verification
    async fn verify_withdrawal_proof(&self, request: &WithdrawalRequest) -> Result<()> {
        if request.proof.is_empty() {
            return Err(BridgeError::InvalidTransaction("Missing proof".to_string()));
        }

        log::debug!("Verifying withdrawal proof ({} bytes)", request.proof.len());

        // Use distributed consensus if enabled
        if self.enable_consensus {
            self.verify_with_consensus(request).await
        } else {
            self.verify_single_node(request).await
        }
    }

    /// Verify withdrawal proof with distributed consensus
    async fn verify_with_consensus(&self, request: &WithdrawalRequest) -> Result<()> {
        use crate::consensus::WithdrawalVerificationRequest;

        let coordinator = self.verification_coordinator.as_ref().ok_or_else(|| {
            BridgeError::InvalidTransaction("No verification coordinator available".to_string())
        })?;

        log::info!("Starting distributed verification for withdrawal");

        // Create verification request
        let verification_request = WithdrawalVerificationRequest::from_withdrawal(request);

        // Start verification (broadcasts to all validators)
        let request_id = coordinator
            .start_verification(verification_request)
            .await
            .map_err(|e| {
                BridgeError::InvalidTransaction(format!("Failed to start verification: {}", e))
            })?;

        log::info!("Verification request started: {}", request_id);

        // Wait for consensus (7/10 validators)
        let result = coordinator
            .wait_for_consensus(&request_id)
            .await
            .map_err(|e| BridgeError::InvalidTransaction(format!("Consensus failed: {}", e)))?;

        // Check result
        if !result.is_valid() {
            return Err(BridgeError::InvalidTransaction(
                "Consensus rejected withdrawal".to_string(),
            ));
        }

        // Cleanup
        coordinator
            .cleanup(&request_id)
            .await
            .map_err(|e| BridgeError::InvalidTransaction(format!("Cleanup failed: {}", e)))?;

        log::info!("Withdrawal proof verified by consensus");
        Ok(())
    }

    /// Verify withdrawal proof on single node (no consensus)
    async fn verify_single_node(&self, request: &WithdrawalRequest) -> Result<()> {
        use crate::privacy::proof::ProofVerifier;
        use crate::privacy::transaction::WithdrawTx;
        use crate::privacy::Nullifier;

        // Get current Merkle root from pool
        let merkle_root = self.pool.root().await;

        // Create WithdrawTx for verification
        let withdraw_tx = WithdrawTx {
            tx_id: uuid::Uuid::new_v4().to_string(),
            input_nullifier: Nullifier(request.nullifier),
            amount: request.amount,
            to_public: request.recipient.to_vec(),
            zk_proof: request.proof.clone(),
            merkle_root,
            fee: request.fee,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Verify using ProofVerifier
        let result = ProofVerifier::verify_withdraw(&withdraw_tx);

        if !result.is_valid() {
            return Err(BridgeError::InvalidTransaction(format!(
                "Withdrawal proof verification failed: {:?}",
                result
            )));
        }

        log::info!("Withdrawal proof verified successfully (single node)");
        Ok(())
    }

    /// Submit withdrawal transaction to Solana.
    ///
    /// Performs a local pre-submit check against `request.expiration_slot`
    /// before paying RPC fees. The on-chain program will reject an
    /// expired request anyway (#61), but the local check turns a
    /// late-arriving request into a typed `BridgeError::InvalidTransaction`
    /// instead of a Solana RPC failure with a less-actionable message.
    async fn submit_to_solana(&self, request: &WithdrawalRequest) -> Result<String> {
        log::debug!(
            "Submitting to Solana: {} lamports to {:?} (expires at slot {})",
            request.amount,
            &request.recipient[..8],
            request.expiration_slot
        );

        match self.program.get_slot().await {
            Ok(current_slot) if current_slot > request.expiration_slot => {
                return Err(BridgeError::InvalidTransaction(format!(
                    "withdrawal request expired: current slot {} > expiration slot {}",
                    current_slot, request.expiration_slot
                )));
            }
            Ok(_) => {}
            Err(e) => {
                // If we cannot reach the RPC for `getSlot`, fall through
                // to submission and let the on-chain check decide. The
                // alternative — failing here — would mean a transient
                // RPC blip blocks otherwise-honest withdrawals.
                log::warn!(
                    target: "paraloom::bridge::solana",
                    "skipping local expiration check — getSlot failed: {}",
                    e
                );
            }
        }

        // Submit via program interface
        let signature = self
            .program
            .submit_withdrawal(
                request.recipient,
                request.amount,
                request.nullifier,
                request.expiration_slot,
                &request.proof,
            )
            .await?;

        log::info!("Transaction submitted to Solana: {}", signature);
        Ok(signature)
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
    use crate::bridge::solana::rpc::RealBridgeRpc;
    use crate::privacy::{pedersen, DepositTx, ShieldedAddress};
    use solana_client::rpc_client::RpcClient;

    fn dummy_rpc() -> Arc<dyn BridgeRpc> {
        Arc::new(RealBridgeRpc::new(Arc::new(RpcClient::new(
            "http://localhost:8899".to_string(),
        ))))
    }

    #[tokio::test]
    async fn test_submitter_creation() {
        let config = BridgeConfig {
            program_id: "11111111111111111111111111111111".to_string(),
            ..Default::default()
        };
        let pool = Arc::new(ShieldedPool::new());
        let stats = Arc::new(RwLock::new(BridgeStats::default()));

        let result = ResultSubmitter::new(config, dummy_rpc(), pool, stats);
        // Will succeed even without keypair, just won't be able to submit
        assert!(result.is_ok());
    }

    fn submitter_for(pool: Arc<ShieldedPool>) -> ResultSubmitter {
        let config = BridgeConfig {
            program_id: "11111111111111111111111111111111".to_string(),
            ..Default::default()
        };
        let stats = Arc::new(RwLock::new(BridgeStats::default()));
        ResultSubmitter::new(config, dummy_rpc(), pool, stats).unwrap()
    }

    /// `submit` rejects a withdrawal whose nullifier is already in the
    /// pool's spent set before it ever reaches proof verification or
    /// the chain. Pins the first defence layer of the replay
    /// protection (#71) — without it a leaked withdrawal could be
    /// re-submitted while the on-chain nullifier PDA still let it
    /// through some race window.
    #[tokio::test]
    async fn submit_rejects_already_spent_nullifier() {
        use crate::privacy::Nullifier;
        let pool = Arc::new(ShieldedPool::new());
        let randomness = pedersen::generate_randomness();
        let deposit = DepositTx::new(
            vec![0x42; 32],
            1000,
            ShieldedAddress([1u8; 32]),
            randomness,
            10,
        );
        pool.deposit(deposit.output_note.clone(), 990)
            .await
            .unwrap();
        let nullifier = Nullifier::derive(&deposit.output_note.commitment(), &randomness);
        pool.withdraw(nullifier.clone(), 990, &[0u8; 32])
            .await
            .unwrap();

        let request = WithdrawalRequest {
            nullifier: nullifier.0,
            amount: 100,
            recipient: [0u8; 32],
            fee: 1,
            expiration_slot: u64::MAX,
            proof: vec![1u8; 32],
        };
        let err = submitter_for(pool)
            .submit(request)
            .await
            .expect_err("replay");
        assert!(matches!(err, BridgeError::InvalidTransaction(_)));
    }

    /// An empty proof is rejected before any consensus / chain work.
    /// The on-chain handler also checks `!proof.is_empty()` — we
    /// catch the same shape locally so a malformed request fails
    /// fast rather than wasting validator time.
    #[tokio::test]
    async fn submit_rejects_empty_proof() {
        let pool = Arc::new(ShieldedPool::new());
        let request = WithdrawalRequest {
            nullifier: [9u8; 32],
            amount: 100,
            recipient: [0u8; 32],
            fee: 1,
            expiration_slot: u64::MAX,
            proof: vec![],
        };
        let err = submitter_for(pool)
            .submit(request)
            .await
            .expect_err("empty proof");
        assert!(matches!(err, BridgeError::InvalidTransaction(_)));
    }

    /// `batch_submit` must continue past individual failures rather
    /// than aborting on the first error. Contract is best-effort:
    /// collect successful signatures, log the rest, return
    /// `Ok(successes)`. With three deliberately-malformed requests
    /// (all empty-proof) none succeed; the call must still resolve
    /// to `Ok(empty Vec)`, and the pool's nullifier set must stay
    /// untouched.
    #[tokio::test]
    async fn batch_submit_continues_past_individual_failures() {
        let pool = Arc::new(ShieldedPool::new());
        let bad = |n: u8| WithdrawalRequest {
            nullifier: [n; 32],
            amount: 1,
            recipient: [0u8; 32],
            fee: 0,
            expiration_slot: u64::MAX,
            proof: vec![],
        };
        let signatures = submitter_for(Arc::clone(&pool))
            .batch_submit(vec![bad(1), bad(2), bad(3)])
            .await
            .expect("batch_submit must not propagate per-item errors");
        assert!(signatures.is_empty());
        assert_eq!(pool.spent_count().await, 0);
    }

    #[tokio::test]
    #[ignore] // Requires zkSNARK keys, run with: cargo test -- --ignored
    async fn test_submit_withdrawal() {
        let config = BridgeConfig {
            program_id: "11111111111111111111111111111111".to_string(),
            ..Default::default()
        };
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
            expiration_slot: u64::MAX,
            proof: vec![0u8; 32], // Mock proof
        };

        let submitter = ResultSubmitter::new(config, dummy_rpc(), pool, stats).unwrap();
        let result = submitter.submit(request).await;

        // Will fail without keypair configured
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore] // Requires zkSNARK keys, run with: cargo test -- --ignored
    async fn test_batch_submit() {
        let config = BridgeConfig {
            program_id: "11111111111111111111111111111111".to_string(),
            ..Default::default()
        };
        let pool = Arc::new(ShieldedPool::new());
        let stats = Arc::new(RwLock::new(BridgeStats::default()));

        let requests = vec![
            WithdrawalRequest {
                nullifier: [1u8; 32],
                amount: 100,
                recipient: [0x01u8; 32],
                fee: 5,
                expiration_slot: u64::MAX,
                proof: vec![0u8; 32],
            },
            WithdrawalRequest {
                nullifier: [2u8; 32],
                amount: 200,
                recipient: [0x02u8; 32],
                fee: 5,
                expiration_slot: u64::MAX,
                proof: vec![0u8; 32],
            },
        ];

        let submitter = ResultSubmitter::new(config, dummy_rpc(), pool, stats).unwrap();
        let result = submitter.batch_submit(requests).await;

        // Will succeed but return empty vec (all fail without keypair)
        assert!(result.is_ok());
    }
}
