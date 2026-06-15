//! Result submitter for withdrawals
//!
//! Submits withdrawal requests to Solana blockchain

use crate::bridge::solana::rpc::BridgeRpc;
use crate::bridge::{BridgeConfig, BridgeError, BridgeStats, Result, WithdrawalRequest};
use crate::consensus::{ApprovedTransfer, ApprovedWithdrawal, WithdrawalVerificationCoordinator};
use crate::privacy::{Commitment, Nullifier, ShieldedPool};
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

    /// Slots past the current chain slot at which a request built from a
    /// consensus approval expires. Copied from
    /// `BridgeConfig::withdrawal_expiration_window_slots` so `submit_approved`
    /// can set the expiration without re-reading the config.
    expiration_window_slots: u64,

    /// Test seam: skip Groth16 proof verification so a unit test can drive
    /// `submit` past the proof check to exercise the submit/mark-spent ordering.
    /// Always `false` in production.
    skip_proof_verification: bool,
}

impl ResultSubmitter {
    /// Create a new result submitter
    pub fn new(
        config: BridgeConfig,
        rpc: Arc<dyn BridgeRpc>,
        pool: Arc<ShieldedPool>,
        stats: Arc<RwLock<BridgeStats>>,
    ) -> Result<Self> {
        let expiration_window_slots = config.withdrawal_expiration_window_slots;
        let program = ProgramInterface::new(config, rpc)?;
        Ok(Self {
            pool,
            stats,
            program,
            verification_coordinator: None,
            enable_consensus: false,
            expiration_window_slots,
            skip_proof_verification: false,
        })
    }

    /// Test seam: skip Groth16 proof verification (see field docs).
    #[cfg(test)]
    fn skipping_proof_verification(mut self) -> Self {
        self.skip_proof_verification = true;
        self
    }

    /// Create a new result submitter with distributed consensus
    pub fn with_consensus(
        config: BridgeConfig,
        rpc: Arc<dyn BridgeRpc>,
        pool: Arc<ShieldedPool>,
        stats: Arc<RwLock<BridgeStats>>,
        verification_coordinator: Arc<WithdrawalVerificationCoordinator>,
    ) -> Result<Self> {
        let expiration_window_slots = config.withdrawal_expiration_window_slots;
        let program = ProgramInterface::new(config, rpc)?;
        Ok(Self {
            pool,
            stats,
            program,
            verification_coordinator: Some(verification_coordinator),
            enable_consensus: true,
            expiration_window_slots,
            skip_proof_verification: false,
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

        // Submit on-chain FIRST. The note is marked spent in the local pool
        // only after the chain accepts the settlement (audit), so a transient
        // submit failure — RPC error, blockhash expiry, a momentary
        // QuorumNotMet — leaves the note spendable for a retry instead of
        // freezing it with funds still sitting in the vault. (If the chain did
        // settle but this call still returned an error, a later attempt is
        // rejected on-chain by the nullifier PDA and skipped as a replay — the
        // double-spend defence lives on-chain, not in this local flag.)
        let signature = self.submit_to_solana(&request).await?;

        // Settled on-chain → record the spend in the local pool. A failure here
        // does not undo the settlement, so log and continue; the on-chain
        // nullifier PDA remains the source of truth for double-spend.
        if let Err(e) = self
            .pool
            .withdraw(nullifier, request.amount, &request.recipient)
            .await
        {
            log::error!(
                target: "paraloom::bridge::solana",
                "settled on-chain ({}) but failed to mark the note spent locally: {}",
                signature,
                e
            );
        }

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_withdrawals += 1;
        stats.volume_withdrawn += request.amount;

        log::info!("Withdrawal submitted successfully: {}", signature);
        Ok(signature)
    }

    /// Settle a consensus-approved withdrawal (#164).
    ///
    /// Builds the on-chain [`WithdrawalRequest`] from the approval,
    /// deriving the expiration slot from the live chain slot plus the
    /// configured window (falling back to the window alone if `getSlot`
    /// is unavailable), then submits it via [`submit`](Self::submit).
    /// Separated from `submit` so the consensus pipeline does not have to
    /// know how the expiration slot is derived.
    pub async fn submit_approved(&self, approved: ApprovedWithdrawal) -> Result<String> {
        let current_slot = self.program.get_slot().await.unwrap_or(0);
        let request = WithdrawalRequest {
            nullifier: approved.nullifier,
            amount: approved.amount,
            recipient: approved.recipient,
            fee: approved.fee,
            expiration_slot: current_slot + self.expiration_window_slots,
            proof: approved.proof,
        };
        self.submit(request).await
    }

    /// Settle a consensus-approved shielded transfer (#194).
    ///
    /// Applies the transfer to the local pool from its public parts (mark the
    /// input nullifiers spent, append the output commitments — the settling
    /// node does not hold the private output notes), then submits the on-chain
    /// `shielded_transfer` instruction. Unlike `submit_approved`, no funds move
    /// and there is no expiration slot.
    pub async fn submit_approved_transfer(&self, approved: ApprovedTransfer) -> Result<String> {
        let nullifiers: Vec<Nullifier> =
            approved.nullifiers.iter().copied().map(Nullifier).collect();
        let output_commitments: Vec<Commitment> = approved
            .output_commitments
            .iter()
            .copied()
            .map(Commitment)
            .collect();

        // Local pool state first; a double-spend here surfaces before we pay
        // RPC fees. The on-chain nullifier PDAs are the authoritative replay
        // guard, but this keeps the node's own view consistent.
        self.pool
            .apply_transfer(nullifiers, output_commitments)
            .await
            .map_err(|e| BridgeError::WithdrawalFailed(e.to_string()))?;

        let signature = self
            .program
            .submit_shielded_transfer(
                approved.nullifiers,
                approved.output_commitments,
                approved.new_merkle_root,
                &approved.proof,
            )
            .await?;

        log::info!("Shielded transfer settled: {}", signature);
        Ok(signature)
    }

    /// Verify withdrawal proof with real zkSNARK verification
    async fn verify_withdrawal_proof(&self, request: &WithdrawalRequest) -> Result<()> {
        if self.skip_proof_verification {
            return Ok(());
        }
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

    /// Audit: a withdrawal whose on-chain submit fails must NOT be marked spent
    /// locally, or the note is frozen — funds still in the vault but every
    /// retry rejected as "already spent". The fix submits on-chain first and
    /// records the spend only on success.
    #[tokio::test]
    async fn a_failed_submit_leaves_the_note_spendable() {
        use crate::privacy::Nullifier;
        let pool = Arc::new(ShieldedPool::new());
        let randomness = pedersen::generate_randomness();
        let deposit = DepositTx::new(
            vec![0x77; 32],
            1000,
            ShieldedAddress([2u8; 32]),
            randomness,
            10,
        );
        pool.deposit(deposit.output_note.clone(), 990)
            .await
            .unwrap();
        let nullifier = Nullifier::derive(&deposit.output_note.commitment(), &randomness);

        let request = WithdrawalRequest {
            nullifier: nullifier.0,
            amount: 100,
            recipient: [0u8; 32],
            fee: 1,
            expiration_slot: u64::MAX,
            proof: vec![1u8; 32],
        };

        // No authority keypair and no reachable RPC, so the on-chain submit
        // fails. (Proof verification is skipped so we reach the submit step.)
        let submitter = submitter_for(pool.clone()).skipping_proof_verification();
        assert!(
            submitter.submit(request).await.is_err(),
            "submit must fail when the chain does not accept it"
        );
        assert!(
            !pool.is_spent(&nullifier).await,
            "a failed on-chain submit must leave the note spendable, not frozen"
        );
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
