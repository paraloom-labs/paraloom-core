//! Decoder for Paraloom deposit instructions found in Solana transactions.
//!
//! The event listener pulls confirmed transactions from the Solana RPC,
//! and for each one this module pulls out any instructions that match
//! the Paraloom deposit discriminator and renders them as the bridge's
//! [`DepositEvent`] type. Keeping the decoder pure and free of RPC I/O
//! makes it directly unit-testable against synthetic instruction data.

use crate::bridge::solana::instructions::{discriminators, DepositInstructionData};
use crate::bridge::DepositEvent;
use borsh::BorshDeserialize;
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::{
    EncodedConfirmedTransactionWithStatusMeta, EncodedTransaction, UiInstruction, UiMessage,
    UiTransactionEncoding,
};

/// Account-index position of the depositor (signer) in a legacy deposit
/// instruction's account list `[bridge_state, bridge_vault, depositor,
/// system_program]`. The legacy off-chain-root `deposit` builder was removed,
/// but this decoder still reads historical deposits from that layout.
const DEPOSITOR_ACCOUNT_INDEX: usize = 2;

/// Recommended encoding to request from `getTransaction` for the
/// listener. JSON encoding produces a `UiMessage::Raw` variant for
/// unparsed programs (paraloom is unparsed), which exposes raw
/// base58-encoded instruction data — exactly what
/// [`extract_deposit_events`] consumes.
pub const LISTENER_TX_ENCODING: UiTransactionEncoding = UiTransactionEncoding::Json;

/// Pull every Paraloom deposit instruction out of a confirmed Solana
/// transaction and turn it into a [`DepositEvent`].
///
/// Returns an empty vector if the transaction does not target the
/// Paraloom program, the encoding is not the expected raw JSON form,
/// or no instruction matches the deposit discriminator. Address-table-
/// lookup transactions are skipped with a warning — none of the deposit
/// flows in v0.3 are expected to use LUTs.
pub fn extract_deposit_events(
    signature: &str,
    confirmed: &EncodedConfirmedTransactionWithStatusMeta,
    program_id: &Pubkey,
) -> Vec<DepositEvent> {
    // Skip on-chain failures: a transaction whose execution errored out
    // didn't actually transfer funds, so no deposit should be emitted.
    if let Some(meta) = &confirmed.transaction.meta {
        if meta.err.is_some() {
            log::debug!(
                target: "paraloom::bridge::solana",
                "skipping failed transaction {}",
                signature
            );
            return Vec::new();
        }
    }

    let ui_tx = match &confirmed.transaction.transaction {
        EncodedTransaction::Json(t) => t,
        _ => {
            log::warn!(
                target: "paraloom::bridge::solana",
                "tx {} not in JSON encoding; skipping",
                signature
            );
            return Vec::new();
        }
    };

    let raw = match &ui_tx.message {
        UiMessage::Raw(r) => r,
        UiMessage::Parsed(_) => {
            log::warn!(
                target: "paraloom::bridge::solana",
                "tx {} returned parsed message instead of raw; the program should be unrecognised by the RPC, skipping",
                signature
            );
            return Vec::new();
        }
    };

    let account_keys = match parse_account_keys(&raw.account_keys) {
        Ok(keys) => keys,
        Err(bad) => {
            log::warn!(
                target: "paraloom::bridge::solana",
                "tx {} has unparsable account key '{}'; skipping",
                signature,
                bad
            );
            return Vec::new();
        }
    };

    let mut events = Vec::new();

    // Top-level instructions are already compiled — JSON encoding for
    // an unparsed program drops the `UiInstruction` wrapper.
    for compiled in &raw.instructions {
        if let Some(decoded) = decode_compiled_deposit(compiled, &account_keys, program_id) {
            events.push(build_event(signature, confirmed, decoded));
        }
    }

    // Inner instructions (CPI from another program into ours) come back
    // through the meta field as `UiInstruction`, which needs the match
    // because parsed instructions can also appear there.
    if let Some(meta) = &confirmed.transaction.meta {
        if let solana_transaction_status::option_serializer::OptionSerializer::Some(inner) =
            &meta.inner_instructions
        {
            for inner_set in inner {
                for instruction in &inner_set.instructions {
                    if let UiInstruction::Compiled(compiled) = instruction {
                        if let Some(decoded) =
                            decode_compiled_deposit(compiled, &account_keys, program_id)
                        {
                            events.push(build_event(signature, confirmed, decoded));
                        }
                    }
                }
            }
        }
    }

    events
}

/// Decoded result of a single deposit instruction. Kept private so the
/// public surface is just `extract_deposit_events`.
struct DecodedDeposit {
    data: DepositInstructionData,
    depositor: Pubkey,
    /// The deposited asset (#237): the SPL mint's bytes, or `NATIVE_SOL_ASSET`.
    asset_id: [u8; 32],
}

/// `deposit_spl` account layout: bridge_state(0), mint(1), …, depositor(5).
const SPL_MINT_ACCOUNT_INDEX: usize = 1;
const SPL_DEPOSITOR_ACCOUNT_INDEX: usize = 5;

/// Try to interpret a single compiled instruction as a Paraloom
/// deposit. Returns `None` if the instruction targets a different
/// program, the discriminator does not match, the borsh payload is
/// malformed, or the depositor account index is out of range.
fn decode_compiled_deposit(
    compiled: &solana_transaction_status::UiCompiledInstruction,
    account_keys: &[Pubkey],
    program_id: &Pubkey,
) -> Option<DecodedDeposit> {
    let program_index = compiled.program_id_index as usize;
    let invoked_program = account_keys.get(program_index)?;
    if invoked_program != program_id {
        return None;
    }

    let raw_data = bs58::decode(&compiled.data).into_vec().ok()?;
    if raw_data.len() < discriminators::DEPOSIT.len() {
        return None;
    }

    // Native `deposit` and `deposit_spl` share the same borsh payload
    // (amount, recipient, randomness) but differ in discriminator, account
    // layout, and asset. The SPL deposit's asset id is the mint account; the
    // native deposit's is NATIVE_SOL.
    let (depositor_index, asset_id) = if raw_data[..8] == discriminators::DEPOSIT {
        (
            DEPOSITOR_ACCOUNT_INDEX,
            crate::privacy::types::NATIVE_SOL_ASSET,
        )
    } else if raw_data[..8] == discriminators::DEPOSIT_SPL {
        let mint_index = *compiled.accounts.get(SPL_MINT_ACCOUNT_INDEX)? as usize;
        let mint = account_keys.get(mint_index)?;
        (SPL_DEPOSITOR_ACCOUNT_INDEX, mint.to_bytes())
    } else {
        return None;
    };

    let payload = &raw_data[8..];
    let data = DepositInstructionData::try_from_slice(payload).ok()?;

    let depositor_index = *compiled.accounts.get(depositor_index)? as usize;
    let depositor = account_keys.get(depositor_index)?;

    Some(DecodedDeposit {
        data,
        depositor: *depositor,
        asset_id,
    })
}

fn build_event(
    signature: &str,
    confirmed: &EncodedConfirmedTransactionWithStatusMeta,
    decoded: DecodedDeposit,
) -> DepositEvent {
    DepositEvent {
        signature: signature.to_string(),
        from: decoded.depositor.to_bytes(),
        amount: decoded.data.amount,
        recipient: decoded.data.recipient,
        randomness: decoded.data.randomness,
        asset_id: decoded.asset_id,
        // Fees are charged inside the on-chain program rather than
        // being part of the deposit instruction payload. Until the
        // program emits an explicit fee component, we report 0 and let
        // the L2 net it from the volume-deposited metric. Tracked as a
        // follow-up on the bridge side.
        fee: 0,
        block: confirmed.slot,
        timestamp: confirmed.block_time.unwrap_or_default(),
    }
}

fn parse_account_keys(keys: &[String]) -> std::result::Result<Vec<Pubkey>, String> {
    keys.iter()
        .map(|k| k.parse::<Pubkey>().map_err(|_| k.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_transaction_status::UiCompiledInstruction;

    fn encode_deposit_data(amount: u64, recipient: [u8; 32], randomness: [u8; 32]) -> String {
        let payload = DepositInstructionData {
            amount,
            recipient,
            randomness,
        };
        let mut bytes = discriminators::DEPOSIT.to_vec();
        bytes.extend_from_slice(&borsh::to_vec(&payload).unwrap());
        bs58::encode(bytes).into_string()
    }

    fn make_compiled_ix(
        program_index: u8,
        depositor_index: u8,
        data_b58: String,
    ) -> UiCompiledInstruction {
        UiCompiledInstruction {
            program_id_index: program_index,
            // bridge_state, bridge_vault, depositor, system_program
            accounts: vec![0, 1, depositor_index, 0],
            data: data_b58,
            stack_height: None,
        }
    }

    #[test]
    fn decodes_a_well_formed_deposit() {
        let program_id = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let extra = Pubkey::new_unique();

        let account_keys = vec![extra, extra, depositor, program_id];

        let amount = 1_000_000u64;
        let recipient = [7u8; 32];
        let randomness = [9u8; 32];
        let ix = make_compiled_ix(3, 2, encode_deposit_data(amount, recipient, randomness));

        let decoded = decode_compiled_deposit(&ix, &account_keys, &program_id)
            .expect("well-formed deposit must decode");
        assert_eq!(decoded.data.amount, amount);
        assert_eq!(decoded.data.recipient, recipient);
        assert_eq!(decoded.data.randomness, randomness);
        assert_eq!(decoded.depositor, depositor);
        assert_eq!(decoded.asset_id, crate::privacy::types::NATIVE_SOL_ASSET);
    }

    #[test]
    fn decodes_a_well_formed_spl_deposit() {
        // deposit_spl shares the payload but uses the SPL account layout
        // (mint @ index 1, depositor @ index 5) and binds the mint as asset_id.
        let program_id = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        // account_keys: program@0, mint@2, depositor@7.
        let account_keys = vec![
            program_id, other, mint, other, other, other, other, depositor,
        ];

        let amount = 5_000u64;
        let recipient = [3u8; 32];
        let randomness = [4u8; 32];
        let payload = DepositInstructionData {
            amount,
            recipient,
            randomness,
        };
        let mut bytes = discriminators::DEPOSIT_SPL.to_vec();
        bytes.extend_from_slice(&borsh::to_vec(&payload).unwrap());
        let ix = UiCompiledInstruction {
            program_id_index: 0,
            // deposit_spl ix accounts: position 1 = mint(key 2), position 5 = depositor(key 7).
            accounts: vec![1, 2, 3, 4, 5, 7, 1, 1, 1],
            data: bs58::encode(bytes).into_string(),
            stack_height: None,
        };

        let decoded = decode_compiled_deposit(&ix, &account_keys, &program_id)
            .expect("well-formed SPL deposit must decode");
        assert_eq!(decoded.data.amount, amount);
        assert_eq!(decoded.depositor, depositor);
        assert_eq!(decoded.asset_id, mint.to_bytes());
    }

    #[test]
    fn ignores_instructions_for_other_programs() {
        let program_id = Pubkey::new_unique();
        let other_program = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();

        // program_index points at a different program; even with valid
        // deposit-shaped data we must not pick it up.
        let account_keys = vec![other_program, other_program, depositor, other_program];
        let ix = make_compiled_ix(3, 2, encode_deposit_data(1, [0u8; 32], [0u8; 32]));

        assert!(decode_compiled_deposit(&ix, &account_keys, &program_id).is_none());
    }

    #[test]
    fn ignores_wrong_discriminator() {
        let program_id = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let account_keys = vec![program_id, program_id, depositor, program_id];

        // Build a buffer that targets the program but starts with a
        // non-deposit discriminator instead.
        let mut bytes = discriminators::SET_BRIDGE_AUTHORITY.to_vec();
        bytes.extend_from_slice(&[0u8; 16]);
        let ix = make_compiled_ix(3, 2, bs58::encode(bytes).into_string());

        assert!(decode_compiled_deposit(&ix, &account_keys, &program_id).is_none());
    }

    #[test]
    fn ignores_truncated_payload() {
        let program_id = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let account_keys = vec![program_id, program_id, depositor, program_id];

        // Discriminator only — borsh deserialize must fail and the
        // decoder must report None rather than panicking.
        let bytes = discriminators::DEPOSIT.to_vec();
        let ix = make_compiled_ix(3, 2, bs58::encode(bytes).into_string());

        assert!(decode_compiled_deposit(&ix, &account_keys, &program_id).is_none());
    }

    #[test]
    fn ignores_garbage_base58() {
        let program_id = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let account_keys = vec![program_id, program_id, depositor, program_id];

        // '0OIl' are explicitly excluded from the bitcoin base58
        // alphabet, so this string fails to decode at the bs58 layer.
        let ix = make_compiled_ix(3, 2, "0OIl".to_string());

        assert!(decode_compiled_deposit(&ix, &account_keys, &program_id).is_none());
    }

    #[test]
    fn ignores_out_of_range_account_indices() {
        let program_id = Pubkey::new_unique();
        let account_keys = vec![program_id, program_id, program_id, program_id];

        // depositor index 99 is out of range; decoder must return None
        // rather than indexing past the end of `accounts`.
        let ix = UiCompiledInstruction {
            program_id_index: 3,
            accounts: vec![0, 1, 99],
            data: encode_deposit_data(1, [0u8; 32], [0u8; 32]),
            stack_height: None,
        };

        assert!(decode_compiled_deposit(&ix, &account_keys, &program_id).is_none());
    }
}
