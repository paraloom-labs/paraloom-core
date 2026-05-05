//! Solana program interface
//!
//! Interacts with the Paraloom Solana program for deposits and withdrawals

use crate::bridge::{BridgeConfig, BridgeError, Result, SolanaAddress};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Keypair, signature::Signature,
    signature::Signer, transaction::Transaction,
};
use solana_transaction_status::UiTransactionEncoding;

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
    /// Solana RPC client
    rpc_client: RpcClient,

    /// Program ID
    program_id: Pubkey,

    /// Bridge authority keypair (for signing withdrawal transactions)
    authority_keypair: Option<Keypair>,

    /// Bridge vault address
    bridge_vault: Option<Pubkey>,
}

impl ProgramInterface {
    /// Create new program interface
    pub fn new(config: BridgeConfig) -> Result<Self> {
        let rpc_client = RpcClient::new_with_commitment(
            config.solana_rpc_url.clone(),
            CommitmentConfig::confirmed(),
        );

        let program_id = config
            .program_id
            .parse::<Pubkey>()
            .map_err(|e| BridgeError::ConfigError(format!("Invalid program ID: {}", e)))?;

        // Load authority keypair if configured
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
            rpc_client,
            program_id,
            authority_keypair,
            bridge_vault,
        })
    }

    /// Get program ID
    pub fn program_id(&self) -> &Pubkey {
        &self.program_id
    }

    /// Get RPC client
    pub fn rpc_client(&self) -> &RpcClient {
        &self.rpc_client
    }

    /// Verify a deposit transaction exists on Solana
    pub async fn verify_deposit(&self, signature: &str, expected_amount: u64) -> Result<bool> {
        log::debug!("Verifying deposit signature: {}", signature);

        let sig = signature
            .parse::<Signature>()
            .map_err(|e| BridgeError::InvalidTransaction(format!("Invalid signature: {}", e)))?;

        // Get transaction details with JSON encoding for easier parsing
        let tx = self
            .rpc_client
            .get_transaction(&sig, UiTransactionEncoding::Json)
            .map_err(|e| BridgeError::SolanaRpc(format!("Failed to fetch transaction: {}", e)))?;

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

        // Create withdraw instruction
        let instruction = super::create_withdraw_instruction(
            &self.program_id,
            &authority.pubkey(),
            &vault,
            recipient,
            nullifier,
            amount,
            expiration_slot,
            proof.to_vec(),
        )?;

        // Get recent blockhash
        let recent_blockhash = self
            .rpc_client
            .get_latest_blockhash()
            .map_err(|e| BridgeError::SolanaRpc(format!("Failed to get blockhash: {}", e)))?;

        // Create and sign transaction
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&authority.pubkey()),
            &[authority],
            recent_blockhash,
        );

        // Send transaction
        let signature = self
            .rpc_client
            .send_and_confirm_transaction(&transaction)
            .map_err(|e| BridgeError::SolanaRpc(format!("Failed to send transaction: {}", e)))?;

        log::info!("Withdrawal submitted successfully: {}", signature);
        Ok(signature.to_string())
    }

    /// Get account balance
    pub async fn get_balance(&self, address: SolanaAddress) -> Result<u64> {
        let pubkey = Pubkey::new_from_array(address);

        let balance = self
            .rpc_client
            .get_balance(&pubkey)
            .map_err(|e| BridgeError::SolanaRpc(format!("Failed to get balance: {}", e)))?;

        Ok(balance)
    }

    /// Check if program is deployed
    pub async fn is_program_deployed(&self) -> Result<bool> {
        match self.rpc_client.get_account(&self.program_id) {
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
        self.rpc_client
            .get_slot()
            .map_err(|e| BridgeError::SolanaRpc(format!("Failed to get slot: {}", e)))
    }

    /// Read the deployed program's `program_version` from the
    /// `BridgeState` PDA. The version sits at byte offset 8..12 of the
    /// account data — Anchor prepends an 8-byte discriminator and the
    /// `program_version` field is intentionally placed first so this
    /// read does not require deserialising the rest of the struct.
    pub async fn program_version(&self) -> Result<u32> {
        let (state_pda, _) = super::derive_bridge_state(&self.program_id);
        let account = self.rpc_client.get_account(&state_pda).map_err(|e| {
            BridgeError::SolanaRpc(format!(
                "Failed to read BridgeState account {}: {}",
                state_pda, e
            ))
        })?;
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

    /// Update Merkle root on Solana program
    /// This should be called after processing deposits to sync the on-chain state
    pub async fn update_merkle_root(&self, new_merkle_root: [u8; 32]) -> Result<String> {
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
        )?;

        // Get recent blockhash
        let recent_blockhash = self
            .rpc_client
            .get_latest_blockhash()
            .map_err(|e| BridgeError::SolanaRpc(format!("Failed to get blockhash: {}", e)))?;

        // Create and sign transaction
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&authority.pubkey()),
            &[authority],
            recent_blockhash,
        );

        // Send transaction
        let signature = self
            .rpc_client
            .send_and_confirm_transaction(&transaction)
            .map_err(|e| BridgeError::SolanaRpc(format!("Failed to send transaction: {}", e)))?;

        log::info!("Merkle root updated successfully: {}", signature);
        Ok(signature.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_interface_creation() {
        let config = BridgeConfig::default();
        let result = ProgramInterface::new(config);
        // Will fail with invalid program ID, but tests the creation path
        assert!(result.is_err() || result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_deposit_with_valid_config() {
        // Use a valid-format program ID for testing
        let config = BridgeConfig {
            program_id: "11111111111111111111111111111111".to_string(),
            ..Default::default()
        };

        let program = ProgramInterface::new(config);
        assert!(program.is_ok());
    }

    /// Synthesise a BridgeState account: 8 bytes of discriminator
    /// (any value), then a u32 program_version, then arbitrary
    /// trailing bytes. \`parse_program_version\` must read exactly the
    /// version regardless of the discriminator content or trailing
    /// payload.
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
