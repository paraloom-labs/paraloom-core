//! Solana program interface
//!
//! Interacts with the Paraloom Solana program for deposits and withdrawals

use crate::bridge::solana::rpc::BridgeRpc;
use crate::bridge::{BridgeConfig, BridgeError, Result, SolanaAddress};
use solana_account_decoder::UiAccountEncoding;
use solana_client::rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig};
use solana_client::rpc_filter::{Memcmp, RpcFilterType};
use solana_sdk::{pubkey::Pubkey, signature::Signature, transaction::Transaction};
use solana_transaction_status::UiTransactionEncoding;
use std::collections::HashSet;
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
}

impl ProgramInterface {
    /// Create new program interface using the supplied RPC backend.
    pub fn new(config: BridgeConfig, rpc: Arc<dyn BridgeRpc>) -> Result<Self> {
        let program_id = config
            .program_id
            .parse::<Pubkey>()
            .map_err(|e| BridgeError::ConfigError(format!("Invalid program ID: {}", e)))?;

        Ok(Self { rpc, program_id })
    }

    /// Get program ID
    pub fn program_id(&self) -> &Pubkey {
        &self.program_id
    }

    /// Read every on-chain `ValidatorAccount` in one `getProgramAccounts` call
    /// and return `(validator_wallet, stake_amount)` for the ACTIVE ones. The
    /// validator-stake reconciler weights the consensus set by this real
    /// on-chain stake instead of a placeholder, so the stake-weighted quorum
    /// reflects actual at-risk capital.
    ///
    /// Base64 encoding is requested because a current `ValidatorAccount` is 145
    /// bytes. The layout after the 8-byte discriminator is `wallet[8..40]`,
    /// `stake_amount[40..48]`, and the `is_active` flag at byte 88 (active=1).
    pub async fn list_validator_stakes(&self) -> Result<Vec<(Pubkey, u64)>> {
        // sha256("account:ValidatorAccount")[..8].
        const VALIDATOR_DISC: [u8; 8] = [32, 144, 229, 203, 9, 154, 158, 255];
        const VALIDATOR_LEN: usize = 145;
        let config = RpcProgramAccountsConfig {
            filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
                0,
                VALIDATOR_DISC.to_vec(),
            ))]),
            account_config: RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64),
                ..Default::default()
            },
            ..Default::default()
        };
        let accounts = self
            .rpc
            .get_program_accounts(&self.program_id, config)
            .await?;
        let mut stakes = Vec::with_capacity(accounts.len());
        let mut seen_wallets = HashSet::new();
        for (pda, acc) in accounts {
            if acc.owner != self.program_id || acc.data.len() != VALIDATOR_LEN || acc.data[0..8] != VALIDATOR_DISC {
                continue;
            }
            let wallet = Pubkey::new_from_array(acc.data[8..40].try_into().expect("32-byte wallet"));
            let (expected_pda, _) = Pubkey::find_program_address(&[b"validator", wallet.as_ref()], &self.program_id);
            if pda != expected_pda || acc.data[88] != 1 {
                continue;
            }
            let stake = u64::from_le_bytes(acc.data[40..48].try_into().expect("8-byte stake"));
            if stake > 0 && seen_wallets.insert(wallet) {
                stakes.push((wallet, stake));
            }
        }
        Ok(stakes)
    }

    /// Read `ValidatorRegistry.total_active_stake` — the DENOMINATOR the on-chain
    /// stake-weighted quorum uses.
    ///
    /// Layout after the 8-byte Anchor discriminator: `authority[8..40]`,
    /// `total_validators[40..48]`, `active_validators[48..56]`,
    /// `minimum_stake[56..64]`, `total_active_stake[64..72]`.
    pub async fn registry_total_active_stake(&self) -> Result<u64> {
        // sha256("account:ValidatorRegistry")[..8]
        const REGISTRY_DISC: [u8; 8] = [168, 113, 195, 186, 62, 121, 163, 230];
        const REGISTRY_LEN: usize = 112;
        let (registry_pda, _) =
            Pubkey::find_program_address(&[b"validator_registry"], &self.program_id);
        let account = self.rpc.get_account(&registry_pda).await?;
        if account.owner != self.program_id || account.data.len() < REGISTRY_LEN || account.data[0..8] != REGISTRY_DISC {
            return Err(BridgeError::Serialization("Invalid ValidatorRegistry account".into()));
        }
        Ok(u64::from_le_bytes(
            account.data[64..72].try_into().expect("8-byte total_active_stake"),
        ))
    }

    /// Verify a deposit transaction exists on Solana
    pub async fn verify_deposit(&self, signature: &str) -> Result<bool> {
        log::debug!("Checking deposit transaction: {}", signature);

        let sig = signature
            .parse::<Signature>()
            .map_err(|e| BridgeError::InvalidTransaction(format!("Invalid signature: {}", e)))?;

        let tx = self
            .rpc
            .get_transaction(&sig, UiTransactionEncoding::Json)
            .await?;

        let failed = tx
            .transaction
            .meta
            .as_ref()
            .and_then(|m| m.err.as_ref())
            .is_some();
        if failed {
            log::warn!("Deposit transaction failed on-chain: {}", signature);
        }
        Ok(!failed)
    }

    /// Get account balance
    pub async fn get_balance(&self, address: SolanaAddress) -> Result<u64> {
        self.rpc.get_balance(&Pubkey::new_from_array(address)).await
    }

    /// Check if program is deployed
    pub async fn is_program_deployed(&self) -> Result<bool> {
        match self.rpc.get_account(&self.program_id).await {
            Ok(account) => {
                Ok(account.executable)
            }
            Err(e) => {
                log::warn!("Program not found: {}", e);
                Ok(false)
            }
        }
    }

    /// Whether a nullifier has already been spent on chain
    pub async fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        let (pda, _) = Pubkey::find_program_address(&[b"nullifier", nullifier], &self.program_id);
        match self.rpc.get_account(&pda).await {
            Ok(account) => account.owner == self.program_id,
            Err(_) => false,
        }
    }

    /// Get current slot
    pub async fn get_slot(&self) -> Result<u64> {
        self.rpc.get_slot().await
    }

    /// Latest blockhash as raw bytes.
    pub async fn latest_blockhash(&self) -> Result<[u8; 32]> {
        Ok(self.rpc.get_latest_blockhash().await?.to_bytes())
    }

    /// Submit a transaction the caller already assembled and signed.
    pub async fn submit_signed_transaction(&self, transaction: &Transaction) -> Result<String> {
        let signature = self.rpc.send_and_confirm_transaction(transaction).await?;
        Ok(signature.to_string())
    }

    /// Read the deployed program's `program_version` from the
    /// `BridgeState` PDA.
    pub async fn program_version(&self) -> Result<u32> {
        let (state_pda, _) = super::derive_bridge_state(&self.program_id);
        let account = self.rpc.get_account(&state_pda).await?;
        if account.owner != self.program_id {
            return Err(BridgeError::ConfigError("BridgeState has wrong owner".into()));
        }
        parse_program_version(&account.data)
    }

    /// Compare the on-chain program version against the binary's
    /// expected version.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::solana::test_support::MockBridgeRpc;
    use solana_sdk::account::Account;

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

    #[tokio::test]
    async fn verify_deposit_distinguishes_a_succeeded_from_a_failed_transaction() {
        use crate::bridge::solana::test_support::synth_deposit_tx;

        let sig = Signature::new_unique();
        let program_id = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();

        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_transaction.lock().unwrap() = Some(Ok(synth_deposit_tx(
            sig,
            7,
            &program_id,
            &depositor,
            1_000,
            [9u8; 32],
            [11u8; 32],
        )));
        assert!(
            program_with_mock(mock)
                .verify_deposit(&sig.to_string())
                .await
                .expect("rpc ok"),
            "a transaction without meta.err must verify"
        );

        let mock = Arc::new(MockBridgeRpc::new());
        let failed = crate::bridge::solana::test_support::with_tx_error(
            synth_deposit_tx(
                sig,
                7,
                &program_id,
                &depositor,
                1_000,
                [9u8; 32],
                [11u8; 32],
            ),
            solana_sdk::transaction::TransactionError::AccountNotFound,
        );
        *mock.next_get_transaction.lock().unwrap() = Some(Ok(failed));
        assert!(
            !program_with_mock(mock)
                .verify_deposit(&sig.to_string())
                .await
                .expect("rpc ok"),
            "a transaction whose meta carries an error must not verify"
        );
    }

    #[tokio::test]
    async fn verify_deposit_rejects_a_malformed_signature() {
        let program = program_with_mock(Arc::new(MockBridgeRpc::new()));
        assert!(matches!(
            program.verify_deposit("not-a-signature").await,
            Err(BridgeError::InvalidTransaction(_))
        ));
    }

    fn program_with_mock(mock: Arc<MockBridgeRpc>) -> ProgramInterface {
        let config = BridgeConfig {
            program_id: "11111111111111111111111111111111".to_string(),
            ..Default::default()
        };
        ProgramInterface::new(config, mock).unwrap()
    }

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
        let program = program_with_mock(mock);
        assert!(!program.is_program_deployed().await.unwrap());
    }

    #[tokio::test]
    async fn get_balance_returns_mocked_value() {
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_balance.lock().unwrap() = Some(Ok(42_000_000));
        let program = program_with_mock(mock);
        assert_eq!(program.get_balance([1u8; 32]).await.unwrap(), 42_000_000);
    }

    #[tokio::test]
    async fn get_slot_returns_mocked_value() {
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_slot.lock().unwrap() = Some(Ok(987_654_321));
        let program = program_with_mock(mock);
        assert_eq!(program.get_slot().await.unwrap(), 987_654_321);
    }

    #[tokio::test]
    async fn verify_program_version_accepts_matching_version() {
        let mock = Arc::new(MockBridgeRpc::new());
        let account = bridge_state_account(crate::bridge::EXPECTED_PROGRAM_VERSION);
        *mock.next_get_account.lock().unwrap() = Some(Ok(Account {
            owner: "11111111111111111111111111111111".parse().unwrap(),
            ..account
        }));
        let config = BridgeConfig {
            program_id: "11111111111111111111111111111111".to_string(),
            ..Default::default()
        };
        let program = ProgramInterface::new(config, mock).unwrap();
        assert!(program.verify_program_version().await.is_ok());
    }

    #[tokio::test]
    async fn verify_program_version_rejects_mismatch() {
        let mock = Arc::new(MockBridgeRpc::new());
        let account = bridge_state_account(0x0099_0000);
        *mock.next_get_account.lock().unwrap() = Some(Ok(Account {
            owner: "11111111111111111111111111111111".parse().unwrap(),
            ..account
        }));
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
        let mut buf = vec![0xAAu8; 8];
        buf.extend_from_slice(&0x0004_0000u32.to_le_bytes());
        buf.extend_from_slice(&[0xFFu8; 200]);
        assert_eq!(parse_program_version(&buf).unwrap(), 0x0004_0000);
    }

    #[test]
    fn parse_program_version_reads_v123() {
        let mut buf = vec![0u8; 8];
        buf.extend_from_slice(&0x0102_0304u32.to_le_bytes());
        assert_eq!(parse_program_version(&buf).unwrap(), 0x0102_0304);
    }

    #[test]
    fn parse_program_version_rejects_short_buffer() {
        let buf = vec![0u8; 11];
        let err = parse_program_version(&buf).expect_err("short buffer");
        assert!(matches!(err, BridgeError::ConfigError(_)));
    }

    #[test]
    fn parse_program_version_rejects_empty_buffer() {
        let err = parse_program_version(&[]).expect_err("empty buffer");
        assert!(matches!(err, BridgeError::ConfigError(_)));
    }
}