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

/// `sha256("account:ValidatorAccount")[..8]`.
const VALIDATOR_ACCOUNT_DISC: [u8; 8] = [32, 144, 229, 203, 9, 154, 158, 255];

/// Current on-chain `ValidatorAccount` size: 8-byte Anchor discriminator +
/// 137-byte `INIT_SPACE` (post-dual-stake layout with `token_stake_amount` and
/// `token_unbonding_amount`). Pre-migration 113-byte and 129-byte accounts are
/// rejected by `ValidatorAccount::try_deserialize` in `verify_validator_quorum`
/// and by `Account<'info, ValidatorAccount>` in `transact` / `transact_spl`.
const VALIDATOR_ACCOUNT_LEN: usize = 145;

/// `sha256("account:ValidatorRegistry")[..8]`.
const VALIDATOR_REGISTRY_DISC: [u8; 8] = [168, 113, 195, 186, 62, 121, 163, 230];

/// Current on-chain `ValidatorRegistry` size: 8-byte Anchor discriminator +
/// `authority` (32) + 4×`u64` counters (32) + `stake_mint` (32) +
/// `min_token_stake` (8) = 112 bytes.
const VALIDATOR_REGISTRY_LEN: usize = 112;

/// Decode and validate a raw on-chain `ValidatorAccount` PDA, returning
/// `(validator_wallet, stake_amount)` only if the account satisfies every
/// invariant required by on-chain `quorum::verify_validator_quorum` and
/// `transact`:
/// - owned by `program_id`,
/// - migrated to the current 145-byte dual-stake layout with the
///   `ValidatorAccount` Anchor discriminator,
/// - canonical Borsh `is_active == true` (`1u8`) and `stake_amount > 0`,
/// - located at the canonical `[b"validator", wallet]` PDA for `program_id`.
fn decode_active_validator_stake(
    program_id: &Pubkey,
    pda: &Pubkey,
    acc: &solana_sdk::account::Account,
) -> Option<(Pubkey, u64)> {
    if acc.owner != *program_id {
        return None;
    }
    let d = &acc.data;
    if d.len() < VALIDATOR_ACCOUNT_LEN || d[0..8] != VALIDATOR_ACCOUNT_DISC || d[88] != 1 {
        return None;
    }
    let wallet = Pubkey::new_from_array(d[8..40].try_into().ok()?);
    let (expected_pda, _) = super::derive_validator_account(program_id, &wallet);
    if *pda != expected_pda {
        return None;
    }
    let stake = u64::from_le_bytes(d[40..48].try_into().ok()?);
    if stake == 0 {
        return None;
    }
    Some((wallet, stake))
}

/// Extract `total_active_stake` from a raw `ValidatorRegistry` account after
/// verifying program ownership, the `ValidatorRegistry` Anchor discriminator,
/// and the post-dual-stake 112-byte layout size.
fn parse_registry_total_active_stake(
    program_id: &Pubkey,
    account: &solana_sdk::account::Account,
) -> Result<u64> {
    if account.owner != *program_id {
        return Err(BridgeError::Serialization(format!(
            "ValidatorRegistry account owner mismatch: expected {}, got {}",
            program_id, account.owner
        )));
    }
    let d = &account.data;
    if d.len() < VALIDATOR_REGISTRY_LEN {
        return Err(BridgeError::Serialization(format!(
            "ValidatorRegistry account too short: {} bytes (need >= {})",
            d.len(),
            VALIDATOR_REGISTRY_LEN
        )));
    }
    if d[0..8] != VALIDATOR_REGISTRY_DISC {
        return Err(BridgeError::Serialization(
            "ValidatorRegistry account discriminator mismatch".to_string(),
        ));
    }
    Ok(u64::from_le_bytes(
        d[64..72].try_into().expect("8-byte total_active_stake"),
    ))
}

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
    /// bytes and the RPC rejects base58 above 128. The layout after the 8-byte
    /// discriminator is `wallet[8..40]`, `stake_amount[40..48]`, and the
    /// `is_active` flag at byte 88.
    pub async fn list_validator_stakes(&self) -> Result<Vec<(Pubkey, u64)>> {
        let config = RpcProgramAccountsConfig {
            filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
                0,
                VALIDATOR_ACCOUNT_DISC.to_vec(),
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
        let mut seen = std::collections::HashSet::with_capacity(accounts.len());
        for (pda, acc) in accounts {
            if let Some((wallet, stake)) =
                decode_active_validator_stake(&self.program_id, &pda, &acc)
            {
                if seen.insert(wallet) {
                    stakes.push((wallet, stake));
                }
            }
        }
        Ok(stakes)
    }

    /// Read `ValidatorRegistry.total_active_stake` — the DENOMINATOR the on-chain
    /// stake-weighted quorum uses (`programs/paraloom/src/quorum.rs`). The
    /// off-chain gate mirrors this exact value instead of summing
    /// `list_validator_stakes`, so a lagging `getProgramAccounts` scan can never
    /// lower the threshold below what the program enforces.
    ///
    /// Layout after the 8-byte Anchor discriminator: `authority[8..40]`,
    /// `total_validators[40..48]`, `active_validators[48..56]`,
    /// `minimum_stake[56..64]`, `total_active_stake[64..72]`,
    /// `stake_mint[72..104]`, `min_token_stake[104..112]`.
    pub async fn registry_total_active_stake(&self) -> Result<u64> {
        let (registry_pda, _) =
            Pubkey::find_program_address(&[b"validator_registry"], &self.program_id);
        let account = self.rpc.get_account(&registry_pda).await?;
        parse_registry_total_active_stake(&self.program_id, &account)
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

    /// Whether a nullifier has already been spent on chain, i.e. whether its
    /// PDA exists (#703).
    ///
    /// This is how a losing submitter learns that the settlement it raced for
    /// actually landed. Asking the chain is the only reliable way: the submit
    /// failure surfaces from Anchor's `init` on an existing account, and its
    /// text belongs to the runtime rather than to this program, so classifying
    /// it by message means guessing at a string somebody else owns.
    ///
    /// A `get_account` failure is reported as "not spent" rather than as an
    /// error: the caller uses this to decide whether a retry is pointless, and
    /// an unreachable RPC is exactly when a retry is worth attempting.
    pub async fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        let (pda, _) = Pubkey::find_program_address(&[b"nullifier", nullifier], &self.program_id);
        match self.rpc.get_account(&pda).await {
            Ok(account) => account.owner == self.program_id,
            Err(_) => false,
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
        if account.owner != self.program_id {
            return Err(BridgeError::ConfigError(format!(
                "BridgeState account owner mismatch: expected {}, got {}",
                self.program_id, account.owner
            )));
        }
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

    // `test_program_interface_creation` used to sit here asserting
    // `result.is_err() || result.is_ok()`, which is a logical constant. Its
    // real property — construction succeeds for a well-formed program id — is
    // exercised by every test below through `program_with_mock`, which
    // `unwrap`s it.

    /// `verify_deposit` reports whether the transaction succeeded on chain.
    ///
    /// Both arms, because the previous test with this name never called it: it
    /// constructed a `ProgramInterface` and asserted that construction worked,
    /// leaving `verify_deposit` at zero executed lines behind a green test
    /// bearing its name. That matters here more than most — this is the helper
    /// whose own doc records #623, where it took an `expected_amount` it never
    /// read and logged it as "verified".
    #[tokio::test]
    async fn verify_deposit_distinguishes_a_succeeded_from_a_failed_transaction() {
        use crate::bridge::solana::test_support::synth_deposit_tx;

        let sig = Signature::new_unique();
        let program_id = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();

        // A transaction with no `meta.err` is a landed deposit.
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

        // The same transaction carrying an on-chain error must not.
        // `synth_deposit_tx` leaves `meta: None`, so the error has to be
        // attached deliberately — the first version of this test mutated a meta
        // that was never there and panicked, which is how it should fail, but it
        // meant the branch went unexercised until this landed.
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

    /// An unparsable signature is rejected before any RPC call.
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

    #[tokio::test]
    async fn verify_program_version_rejects_wrong_owner() {
        let mock = Arc::new(MockBridgeRpc::new());
        let mut acc = bridge_state_account(crate::bridge::EXPECTED_PROGRAM_VERSION);
        acc.owner = Pubkey::new_unique();
        *mock.next_get_account.lock().unwrap() = Some(Ok(acc));
        let program = program_with_mock(mock);
        let err = program
            .verify_program_version()
            .await
            .expect_err("wrong owner");
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

    fn synth_validator_account(
        program_id: &Pubkey,
        wallet: &Pubkey,
        stake: u64,
        is_active: u8,
        len: usize,
    ) -> (Pubkey, Account) {
        let (pda, _) = crate::bridge::solana::derive_validator_account(program_id, wallet);
        let mut data = vec![0u8; len.max(89)];
        data[0..8].copy_from_slice(&VALIDATOR_ACCOUNT_DISC);
        data[8..40].copy_from_slice(wallet.as_ref());
        data[40..48].copy_from_slice(&stake.to_le_bytes());
        data[88] = is_active;
        data.truncate(len);
        (
            pda,
            Account {
                lamports: 1_000_000,
                data,
                owner: *program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
    }

    #[test]
    fn decode_active_validator_stake_enforces_migrated_canonical_active_pda() {
        let program_id = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();

        // 1. Canonical 145-byte active ValidatorAccount with non-zero stake succeeds.
        let (pda, acc) = synth_validator_account(
            &program_id,
            &wallet,
            5_000_000_000,
            1,
            VALIDATOR_ACCOUNT_LEN,
        );
        assert_eq!(
            decode_active_validator_stake(&program_id, &pda, &acc),
            Some((wallet, 5_000_000_000))
        );

        // 2. Unmigrated 113-byte (pre-#375) and 129-byte (pre-dual-stake) accounts must
        // be rejected so off-chain quorum never counts a validator that fails
        // `ValidatorAccount::try_deserialize` on-chain.
        let (pda_113, acc_113) =
            synth_validator_account(&program_id, &wallet, 5_000_000_000, 1, 113);
        assert_eq!(
            decode_active_validator_stake(&program_id, &pda_113, &acc_113),
            None
        );
        let (pda_129, acc_129) =
            synth_validator_account(&program_id, &wallet, 5_000_000_000, 1, 129);
        assert_eq!(
            decode_active_validator_stake(&program_id, &pda_129, &acc_129),
            None
        );

        // 3. Non-canonical PDA address (even with valid data & owner) must be rejected.
        let wrong_pda = Pubkey::new_unique();
        assert_eq!(
            decode_active_validator_stake(&program_id, &wrong_pda, &acc),
            None
        );

        // 4. Wrong account owner must be rejected.
        let mut wrong_owner_acc = acc.clone();
        wrong_owner_acc.owner = Pubkey::new_unique();
        assert_eq!(
            decode_active_validator_stake(&program_id, &pda, &wrong_owner_acc),
            None
        );

        // 5. Non-canonical boolean byte (e.g. 2) and inactive (0) must be rejected.
        let (_, acc_inactive) = synth_validator_account(
            &program_id,
            &wallet,
            5_000_000_000,
            0,
            VALIDATOR_ACCOUNT_LEN,
        );
        assert_eq!(
            decode_active_validator_stake(&program_id, &pda, &acc_inactive),
            None
        );
        let (_, acc_bad_bool) = synth_validator_account(
            &program_id,
            &wallet,
            5_000_000_000,
            2,
            VALIDATOR_ACCOUNT_LEN,
        );
        assert_eq!(
            decode_active_validator_stake(&program_id, &pda, &acc_bad_bool),
            None
        );

        // 6. Zero stake must be rejected.
        let (_, acc_zero_stake) =
            synth_validator_account(&program_id, &wallet, 0, 1, VALIDATOR_ACCOUNT_LEN);
        assert_eq!(
            decode_active_validator_stake(&program_id, &pda, &acc_zero_stake),
            None
        );
    }

    #[tokio::test]
    async fn registry_total_active_stake_validates_owner_discriminator_and_length() {
        let program_id = Pubkey::default();
        let mut data = vec![0u8; VALIDATOR_REGISTRY_LEN];
        data[0..8].copy_from_slice(&VALIDATOR_REGISTRY_DISC);
        data[64..72].copy_from_slice(&15_000_000_000u64.to_le_bytes());

        let valid_acc = Account {
            lamports: 1_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        };

        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_account.lock().unwrap() = Some(Ok(valid_acc.clone()));
        let program = program_with_mock(mock);
        assert_eq!(
            program.registry_total_active_stake().await.unwrap(),
            15_000_000_000
        );

        // Unmigrated 72-byte pre-dual-stake registry must be rejected.
        let mut short_acc = valid_acc.clone();
        short_acc.data.truncate(72);
        assert!(parse_registry_total_active_stake(&program_id, &short_acc).is_err());

        // Wrong discriminator must be rejected.
        let mut bad_disc_acc = valid_acc.clone();
        bad_disc_acc.data[0] ^= 0xFF;
        assert!(parse_registry_total_active_stake(&program_id, &bad_disc_acc).is_err());

        // Wrong owner must be rejected.
        let mut bad_owner_acc = valid_acc;
        bad_owner_acc.owner = Pubkey::new_unique();
        assert!(parse_registry_total_active_stake(&program_id, &bad_owner_acc).is_err());
    }
}
