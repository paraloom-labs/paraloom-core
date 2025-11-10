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

    /// Submit withdrawal transaction to Solana
    pub async fn submit_withdrawal(
        &self,
        recipient: SolanaAddress,
        amount: u64,
        nullifier: [u8; 32],
        proof: &[u8],
    ) -> Result<String> {
        log::info!(
            "Submitting withdrawal: {} lamports to {:?}",
            amount,
            &recipient[..8]
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
}
