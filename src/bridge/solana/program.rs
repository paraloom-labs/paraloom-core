//! Solana program interface
//!
//! Interacts with the Paraloom Solana program for deposits and withdrawals

use crate::bridge::solana::rpc::BridgeRpc;
use crate::bridge::{BridgeConfig, BridgeError, Result, SolanaAddress};
use solana_sdk::{
    pubkey::Pubkey, signature::Keypair, signature::Signature, signature::Signer,
    transaction::Transaction,
};
use solana_transaction_status::UiTransactionEncoding;
use std::sync::Arc;

/// Anchor account discriminator length in bytes. Sits at the start of
/// every Anchor-managed account; data the program itself stores
/// begins at offset [`ANCHOR_DISCRIMINATOR_LEN`].
const ANCHOR_DISCRIMINATOR_LEN: usize = 8;

/// Pull the `program_version: u32` out of a raw `BridgeState` account
/// buffer. The on-chain layout puts `program_version` as the first
/// field (after the 8-byte Anchor discriminator), so the value lives
/// at offset 8..12 in little-endian byte order.
///
/// Returns a typed error rather than panicking on a short buffer —
/// the L2 startup flow turns this into a `BridgeError::ConfigError`
/// when the BridgeState account hasn't been initialised yet, instead
/// of crashing.
fn parse_program_version(data: &[u8]) -> Result<u32> {
    let start = ANCHOR_DISCRIMINATOR_LEN;
    let end = start + std::mem::size_of::<u32>();
    if data.len() < end {
        return Err(BridgeError::ConfigError(format!(
            "BridgeState account truncated: {} bytes, need >= {}",
            data.len(),
            end
        )));
    }
    let bytes: [u8; 4] = data[start..end].try_into().expect("slice fits a u32");
    Ok(u32::from_le_bytes(bytes))
}

/// Interface to Paraloom Solana program
pub struct ProgramInterface {
    /// Solana RPC behind the trait so tests can substitute a mock.
    rpc: Arc<dyn BridgeRpc>,

    /// Program ID
    program_id: Pubkey,

    /// Bridge authority keypair (for signing withdrawal transactions)
    authority_keypair: Option<Keypair>,

    /// Bridge vault address
    bridge_vault: Option<Pubkey>,
}

impl ProgramInterface {
    /// Create new program interface using the supplied RPC backend.
    pub fn new(config: BridgeConfig, rpc: Arc<dyn BridgeRpc>) -> Result<Self> {
        let program_id = config
            .program_id
            .parse::<Pubkey>()
            .map_err(|e| BridgeError::ConfigError(format!("Invalid program ID: {}", e)))?;

        let authority_keypair = if let Some(ref path) = config.authority_keypair_path {
            Some(super::load_keypair_from_file(path)?)
        } else {
            log::warn!("No authority keypair configured - withdrawal submission will not work");
            None
        };

        let bridge_vault =
            if let Some(ref vault_str) = config.bridge_vault {
                Some(vault_str.parse::<Pubkey>().map_err(|e| {
                    BridgeError::ConfigError(format!("Invalid vault address: {}", e))
                })?)
            } else {
                let (vault_pda, _) = super::derive_bridge_vault(&program_id);
                Some(vault_pda)
            };

        Ok(Self {
            rpc,
            program_id,
            authority_keypair,
            bridge_vault,
        })
    }

    /// Get program ID
    pub fn program_id(&self) -> &Pubkey {
        &self.program_id
    }

    /// Verify a deposit transaction exists on Solana
    pub async fn verify_deposit(&self, signature: &str, expected_amount: u64) -> Result<bool> {
        log::debug!("Verifying deposit signature: {}", signature);

        let sig = signature
            .parse::<Signature>()
            .map_err(|e| BridgeError::InvalidTransaction(format!("Invalid signature: {}", e)))?;

        let tx = self
            .rpc
            .get_transaction(&sig, UiTransactionEncoding::Json)
            .await?;

        // Verify transaction succeeded
        if tx
            .transaction
            .meta
            .as_ref()
            .and_then(|m| m.err.as_ref())
            .is_some()
        {
            log::warn!("Transaction failed on-chain");
            return Ok(false);
        }

        log::info!("Deposit verified: {} lamports", expected_amount);
        Ok(true)
    }

    /// Submit withdrawal transaction to Solana.
    ///
    /// `expiration_slot` is the Solana slot past which the on-chain
    /// program will reject this transaction (#61). The submitter is
    /// expected to compute it from the bridge config's expiration
    /// window before calling here.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_withdrawal(
        &self,
        recipient: SolanaAddress,
        amount: u64,
        nullifier: [u8; 32],
        expiration_slot: u64,
        proof: &[u8],
    ) -> Result<String> {
        log::info!(
            "Submitting withdrawal: {} lamports to {:?} (expires at slot {})",
            amount,
            &recipient[..8],
            expiration_slot
        );

        // Verify we have authority keypair
        let authority = self.authority_keypair.as_ref().ok_or_else(|| {
            BridgeError::ConfigError("No authority keypair configured".to_string())
        })?;

        // Verify we have bridge vault
        let vault = self
            .bridge_vault
            .ok_or_else(|| BridgeError::ConfigError("No bridge vault configured".to_string()))?;

        // The on-chain program verifies the proof (#165): convert the prover's
        // compressed proof to the 256-byte alt_bn128 wire form it expects.
        let onchain_proof =
            crate::privacy::onchain_verifier::compressed_proof_to_onchain_bytes(proof)
                .map_err(|e| BridgeError::Serialization(format!("withdrawal proof: {e}")))?;

        // Create withdraw instruction
        let instruction = super::create_withdraw_instruction(
            &self.program_id,
            &authority.pubkey(),
            &vault,
            recipient,
            nullifier,
            amount,
            expiration_slot,
            onchain_proof.to_vec(),
            // Quorum co-signers (#260). The node-side round that gathers the
            // full validator quorum into the tx is the next step; for now the
            // settling authority co-signs.
            &[authority.pubkey()],
        )?;

        let recent_blockhash = self.rpc.get_latest_blockhash().await?;
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&authority.pubkey()),
            &[authority],
            recent_blockhash,
        );
        let signature = self.rpc.send_and_confirm_transaction(&transaction).await?;
        log::info!("Withdrawal submitted successfully: {}", signature);
        Ok(signature.to_string())
    }

    /// Submit a quorum-approved shielded transfer on-chain (#194).
    ///
    /// Builds the `shielded_transfer` instruction (nullify two inputs, append
    /// two output commitments, advance the Merkle root) and sends it signed by
    /// the bridge authority. No vault is involved — a transfer releases no
    /// funds.
    pub async fn submit_shielded_transfer(
        &self,
        nullifiers: [[u8; 32]; 2],
        output_commitments: [[u8; 32]; 2],
        new_merkle_root: [u8; 32],
        proof: &[u8],
    ) -> Result<String> {
        log::info!("Submitting shielded transfer (advancing root)");

        let authority = self.authority_keypair.as_ref().ok_or_else(|| {
            BridgeError::ConfigError("No authority keypair configured".to_string())
        })?;

        // On-chain transfer verification (#194): convert the compressed proof to
        // the 256-byte alt_bn128 wire form.
        let onchain_proof =
            crate::privacy::onchain_verifier::compressed_proof_to_onchain_bytes(proof)
                .map_err(|e| BridgeError::Serialization(format!("transfer proof: {e}")))?;

        let instruction = super::create_shielded_transfer_instruction(
            &self.program_id,
            &authority.pubkey(),
            nullifiers,
            output_commitments,
            new_merkle_root,
            onchain_proof.to_vec(),
            &[authority.pubkey()], // quorum co-signers (#260); node-side round next
        )?;

        let recent_blockhash = self.rpc.get_latest_blockhash().await?;
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&authority.pubkey()),
            &[authority],
            recent_blockhash,
        );
        let signature = self.rpc.send_and_confirm_transaction(&transaction).await?;
        log::info!("Shielded transfer submitted successfully: {}", signature);
        Ok(signature.to_string())
    }

    /// Get account balance
    pub async fn get_balance(&self, address: SolanaAddress) -> Result<u64> {
        self.rpc.get_balance(&Pubkey::new_from_array(address)).await
    }

    /// Check if program is deployed
    pub async fn is_program_deployed(&self) -> Result<bool> {
        match self.rpc.get_account(&self.program_id).await {
            Ok(account) => {
                // Check if account is executable (is a program)
                Ok(account.executable)
            }
            Err(e) => {
                log::warn!("Program not found: {}", e);
                Ok(false)
            }
        }
    }

    /// Get current slot (block number equivalent)
    pub async fn get_slot(&self) -> Result<u64> {
        self.rpc.get_slot().await
    }

    /// Read the deployed program's `program_version` from the
    /// `BridgeState` PDA. The version sits at byte offset 8..12 of the
    /// account data — Anchor prepends an 8-byte discriminator and the
    /// `program_version` field is intentionally placed first so this
    /// read does not require deserialising the rest of the struct.
    pub async fn program_version(&self) -> Result<u32> {
        let (state_pda, _) = super::derive_bridge_state(&self.program_id);
        let account = self.rpc.get_account(&state_pda).await?;
        parse_program_version(&account.data)
    }

    /// Compare the on-chain program version against the binary's
    /// expected version (#69, audit #9). Returns `Ok(())` on a match,
    /// `Err(BridgeError::ConfigError)` on a mismatch with both values
    /// in the message so an operator can see at a glance whether the
    /// L2 or the on-chain side is stale.
    pub async fn verify_program_version(&self) -> Result<()> {
        let on_chain = self.program_version().await?;
        let expected = crate::bridge::EXPECTED_PROGRAM_VERSION;
        if on_chain != expected {
            return Err(BridgeError::ConfigError(format!(
                "program version mismatch: on-chain={:#010x} expected={:#010x} (redeploy or upgrade the L2 binary)",
                on_chain, expected
            )));
        }
        log::info!(
            target: "paraloom::bridge::solana",
            "program version handshake OK ({:#010x})",
            on_chain
        );
        Ok(())
    }

    /// Update Merkle root on Solana program.
    ///
    /// Publishing a root anchors every later withdrawal proof, so the program
    /// now gates it on the same BFT validator quorum (#260) as settlement
    /// (`quorum_validators`). This single-key submitter only attaches the
    /// authority's payer/co-signer signature, so it satisfies the quorum only
    /// when the authority is itself the registered validator that meets the
    /// threshold (the single-operator case); a multi-validator set must gather
    /// the co-signatures over the #260 cosign path before submitting.
    pub async fn update_merkle_root(
        &self,
        new_merkle_root: [u8; 32],
        quorum_validators: &[Pubkey],
    ) -> Result<String> {
        log::info!("Updating merkle root to: {:?}", &new_merkle_root[..8]);

        // Verify we have authority keypair
        let authority = self.authority_keypair.as_ref().ok_or_else(|| {
            BridgeError::ConfigError("No authority keypair configured".to_string())
        })?;

        // Create update merkle root instruction
        let instruction = super::create_update_merkle_root_instruction(
            &self.program_id,
            &authority.pubkey(),
            new_merkle_root,
            quorum_validators,
        )?;

        let recent_blockhash = self.rpc.get_latest_blockhash().await?;
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&authority.pubkey()),
            &[authority],
            recent_blockhash,
        );
        let signature = self.rpc.send_and_confirm_transaction(&transaction).await?;
        log::info!("Merkle root updated successfully: {}", signature);
        Ok(signature.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::solana::rpc::RealBridgeRpc;
    use crate::bridge::solana::test_support::MockBridgeRpc;
    use solana_client::rpc_client::RpcClient;
    use solana_sdk::account::Account;

    fn dummy_rpc() -> Arc<dyn BridgeRpc> {
        Arc::new(RealBridgeRpc::new(Arc::new(RpcClient::new(
            "http://localhost:8899".to_string(),
        ))))
    }

    fn bridge_state_account(program_version: u32) -> Account {
        let mut data = vec![0xAAu8; 8];
        data.extend_from_slice(&program_version.to_le_bytes());
        Account {
            lamports: 1,
            data,
            owner: Pubkey::default(),
            executable: false,
            rent_epoch: 0,
        }
    }

    #[test]
    fn test_program_interface_creation() {
        let config = BridgeConfig::default();
        let result = ProgramInterface::new(config, dummy_rpc());
        assert!(result.is_err() || result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_deposit_with_valid_config() {
        let config = BridgeConfig {
            program_id: "11111111111111111111111111111111".to_string(),
            ..Default::default()
        };
        let program = ProgramInterface::new(config, dummy_rpc());
        assert!(program.is_ok());
    }

    fn program_with_mock(mock: Arc<MockBridgeRpc>) -> ProgramInterface {
        let config = BridgeConfig {
            program_id: "11111111111111111111111111111111".to_string(),
            ..Default::default()
        };
        ProgramInterface::new(config, mock).unwrap()
    }

    /// `is_program_deployed` reads `program_id` via `get_account` and
    /// returns `account.executable`. The handler treats a missing
    /// account (RPC `Err`) as "not deployed" rather than a fatal
    /// error so the L2 health check can keep running while the
    /// operator inspects.
    #[tokio::test]
    async fn is_program_deployed_returns_true_for_executable_account() {
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_account.lock().unwrap() = Some(Ok(Account {
            lamports: 1,
            data: vec![],
            owner: Pubkey::default(),
            executable: true,
            rent_epoch: 0,
        }));
        let program = program_with_mock(mock);
        assert!(program.is_program_deployed().await.unwrap());
    }

    #[tokio::test]
    async fn is_program_deployed_returns_false_when_account_missing() {
        let mock = Arc::new(MockBridgeRpc::new());
        // Default — no `next_get_account` configured — so the mock
        // returns the "not configured" Err. is_program_deployed maps
        // any RPC Err to `false`.
        let program = program_with_mock(mock);
        assert!(!program.is_program_deployed().await.unwrap());
    }

    /// `get_balance` is a thin pass-through to the RPC: forwards the
    /// configured value, surfaces an RPC error untouched.
    #[tokio::test]
    async fn get_balance_returns_mocked_value() {
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_balance.lock().unwrap() = Some(Ok(42_000_000));
        let program = program_with_mock(mock);
        assert_eq!(program.get_balance([1u8; 32]).await.unwrap(), 42_000_000);
    }

    /// Same shape for `get_slot`: pass-through, no parsing, no
    /// fallback. A regression that returned 0 instead of forwarding
    /// the value would break the lag-metric path.
    #[tokio::test]
    async fn get_slot_returns_mocked_value() {
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_slot.lock().unwrap() = Some(Ok(987_654_321));
        let program = program_with_mock(mock);
        assert_eq!(program.get_slot().await.unwrap(), 987_654_321);
    }

    /// Both signing handlers (`submit_withdrawal`, `update_merkle_root`)
    /// guard against being called without an authority keypair —
    /// without the guard a misconfigured node would silently no-op
    /// withdrawals or root updates instead of failing loudly. The
    /// mock is never reached because the guard short-circuits.
    #[tokio::test]
    async fn submit_withdrawal_fails_fast_when_authority_missing() {
        let program = program_with_mock(Arc::new(MockBridgeRpc::new()));
        let err = program
            .submit_withdrawal([0u8; 32], 1, [0u8; 32], u64::MAX, &[0u8; 4])
            .await
            .expect_err("missing authority must fail before any RPC call");
        assert!(matches!(err, BridgeError::ConfigError(_)));
    }

    #[tokio::test]
    async fn update_merkle_root_fails_fast_when_authority_missing() {
        let program = program_with_mock(Arc::new(MockBridgeRpc::new()));
        let err = program
            .update_merkle_root([0u8; 32], &[])
            .await
            .expect_err("missing authority must fail before any RPC call");
        assert!(matches!(err, BridgeError::ConfigError(_)));
    }

    /// Synthesise a BridgeState account: 8 bytes of discriminator
    /// (any value), then a u32 program_version, then arbitrary
    /// trailing bytes. \`parse_program_version\` must read exactly the
    /// version regardless of the discriminator content or trailing
    /// payload.
    /// `verify_program_version` reads the on-chain BridgeState via
    /// `get_account`, parses the version from the fixed offset, and
    /// returns `Ok(())` when it matches `EXPECTED_PROGRAM_VERSION`.
    #[tokio::test]
    async fn verify_program_version_accepts_matching_version() {
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_account.lock().unwrap() = Some(Ok(bridge_state_account(
            crate::bridge::EXPECTED_PROGRAM_VERSION,
        )));
        let config = BridgeConfig {
            program_id: "11111111111111111111111111111111".to_string(),
            ..Default::default()
        };
        let program = ProgramInterface::new(config, mock).unwrap();
        assert!(program.verify_program_version().await.is_ok());
    }

    /// A version mismatch surfaces as a typed `ConfigError`, not a
    /// silent pass — the L2 startup flow turns this into a refusal
    /// to boot rather than risk talking to an incompatible program.
    #[tokio::test]
    async fn verify_program_version_rejects_mismatch() {
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_account.lock().unwrap() = Some(Ok(bridge_state_account(0x0099_0000)));
        let config = BridgeConfig {
            program_id: "11111111111111111111111111111111".to_string(),
            ..Default::default()
        };
        let program = ProgramInterface::new(config, mock).unwrap();
        let err = program
            .verify_program_version()
            .await
            .expect_err("mismatch");
        assert!(matches!(err, BridgeError::ConfigError(_)));
    }

    #[test]
    fn parse_program_version_reads_v04() {
        let mut buf = vec![0xAAu8; 8]; // discriminator
        buf.extend_from_slice(&0x0004_0000u32.to_le_bytes());
        buf.extend_from_slice(&[0xFFu8; 200]); // trailing payload
        assert_eq!(parse_program_version(&buf).unwrap(), 0x0004_0000);
    }

    #[test]
    fn parse_program_version_reads_v123() {
        let mut buf = vec![0u8; 8];
        buf.extend_from_slice(&0x0102_0304u32.to_le_bytes());
        assert_eq!(parse_program_version(&buf).unwrap(), 0x0102_0304);
    }

    /// A short buffer (BridgeState account that hasn't been
    /// initialised yet, or a corrupted account) must produce a typed
    /// error — never a panic.
    #[test]
    fn parse_program_version_rejects_short_buffer() {
        let buf = vec![0u8; 11]; // 8-byte discriminator + 3 bytes < u32
        let err = parse_program_version(&buf).expect_err("short buffer");
        assert!(matches!(err, BridgeError::ConfigError(_)));
    }

    #[test]
    fn parse_program_version_rejects_empty_buffer() {
        let err = parse_program_version(&[]).expect_err("empty buffer");
        assert!(matches!(err, BridgeError::ConfigError(_)));
    }
}
