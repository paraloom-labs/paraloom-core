//! Solana program interface
//!
//! Interacts with the Paraloom Solana program for deposits and withdrawals

use crate::bridge::{BridgeConfig, Result, SolanaAddress};

/// Interface to Paraloom Solana program
pub struct ProgramInterface {
    /// Solana RPC URL
    rpc_url: String,

    /// Program ID
    program_id: String,
}

impl ProgramInterface {
    /// Create new program interface
    pub fn new(config: BridgeConfig) -> Self {
        Self {
            rpc_url: config.solana_rpc_url,
            program_id: config.program_id,
        }
    }

    /// Get program ID
    pub fn program_id(&self) -> &str {
        &self.program_id
    }

    /// Get RPC URL
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// Verify a deposit transaction exists on Solana
    pub async fn verify_deposit(
        &self,
        signature: &str,
        _expected_amount: u64,
    ) -> Result<bool> {
        // TODO: Implement actual Solana RPC call
        // For now, return Ok for testing
        log::debug!("Verifying deposit signature: {}", signature);
        Ok(true)
    }

    /// Submit withdrawal transaction to Solana
    pub async fn submit_withdrawal(
        &self,
        _recipient: SolanaAddress,
        _amount: u64,
        _proof: &[u8],
    ) -> Result<String> {
        // TODO: Implement actual Solana transaction submission
        // For now, return mock signature
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mock_signature = format!("mock_sig_{}", timestamp);
        log::info!("Submitted withdrawal (mock): {}", mock_signature);
        Ok(mock_signature)
    }

    /// Get account balance
    pub async fn get_balance(&self, _address: SolanaAddress) -> Result<u64> {
        // TODO: Implement actual balance query
        Ok(0)
    }

    /// Check if program is deployed
    pub async fn is_program_deployed(&self) -> Result<bool> {
        // TODO: Implement actual program check
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_interface_creation() {
        let config = BridgeConfig::default();
        let program = ProgramInterface::new(config);
        assert!(!program.rpc_url.is_empty());
    }

    #[tokio::test]
    async fn test_verify_deposit() {
        let config = BridgeConfig::default();
        let program = ProgramInterface::new(config);
        let result = program.verify_deposit("test_sig", 1000).await;
        assert!(result.is_ok());
    }
}
