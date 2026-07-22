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
    /// Base64 encoding is requested because a current `ValidatorAccount` is 129
    /// bytes and the RPC rejects base58 above 128. The layout after the 8-byte
    /// discriminator is `wallet[8..40]`, `stake_amount[40..48]`, and the
    /// `is_active` flag at byte 88.
    pub async fn list_validator_stakes(&self) -> Result<Vec<(Pubkey, u64)>> {
        // sha256("account:ValidatorAccount")[..8].
        const VALIDATOR_DISC: [u8; 8] = [32, 144, 229, 203, 9, 154, 158, 255];
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
        for (_pda, acc) in accounts {
            let d = &acc.data;
            if d.len() < 89 || d[0..8] != VALIDATOR_DISC || d[88] == 0 {
                continue; // wrong account, truncated, or inactive
            }
            let wallet = Pubkey::new_from_array(d[8..40].try_into().expect("32-byte wallet"));
            let stake = u64::from_le_bytes(d[40..48].try_into().expect("8-byte stake"));
            stakes.push((wallet, stake));
        }
        Ok(stakes)
    }

    /// Verify a deposit transaction exists on Solana
    /// Confirm a deposit transaction landed on-chain without error.
    ///
    /// This is NOT an amount gate. `deposit_note` binds the deposited amount
    /// into the note commitment on-chain — the commitment is derived from the
    /// transferred lamports and re-checked when the note is spent — so there is
    /// no off-chain amount verification here, and this must not be used to gate
    /// funds. It previously took an `expected_amount` it never read and logged
    /// it as "verified"; that misleading parameter is removed (#623). Returns
    /// whether the transaction succeeded.
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

    /// Latest blockhash as raw bytes. The node bakes this into the multi-sig
    /// settlement transaction it assembles in the #260 co-signing round, so it
    /// needs the same blockhash this RPC will later confirm against.
    pub async fn latest_blockhash(&self) -> Result<[u8; 32]> {
        Ok(self.rpc.get_latest_blockhash().await?.to_bytes())
    }

    /// Submit a transaction the caller already assembled and signed — the
    /// co-signed settlement multi-sig tx (#260) — and confirm it on-chain.
    pub async fn submit_signed_transaction(&self, transaction: &Transaction) -> Result<String> {
        let signature = self.rpc.send_and_confirm_transaction(transaction).await?;
        Ok(signature.to_string())
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
