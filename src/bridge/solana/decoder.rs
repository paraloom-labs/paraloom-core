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
/// or no instruction matches the deposit discriminator. For v0 transactions
/// that route accounts through address lookup tables, static keys are extended
/// with `loaded_addresses.writable` then `loaded_addresses.readonly` in Solana's
/// canonical resolution order, so LUT-referenced mints and depositors resolve
/// instead of being silently dropped.
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

    let static_keys = match parse_account_keys(&raw.account_keys) {
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

    // v0 LUT extension: compiled instruction indexes address static keys,
    // then loaded writable, then loaded readonly. Without this, any mint or
    // depositor referenced through a lookup table is out of bounds for the
    // static array, `.get()` returns `None`, and the deposit is silently
    // dropped — confirmed on-chain but never indexed.
    let mut loaded: Option<(&[String], &[String])> = None;
    if let Some(m) = confirmed.transaction.meta.as_ref() {
        if let solana_transaction_status::option_serializer::OptionSerializer::Some(l) =
            &m.loaded_addresses
        {
            loaded = Some((l.writable.as_slice(), l.readonly.as_slice()));
        }
    }
    let account_keys = resolve_account_keys(signature, static_keys, loaded);

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
    /// The deposited asset: `NATIVE_SOL_ASSET`, `mint_to_asset(mint)` for a
    /// `deposit_note_spl` (#779), or the legacy `deposit_spl`'s raw mint bytes
    /// (#237). The v3 arms must use whatever the program hashed into the leaf.
    asset_id: [u8; 32],
}

/// `deposit_spl` account layout: bridge_state(0), mint(1), …, depositor(5).
const SPL_MINT_ACCOUNT_INDEX: usize = 1;
const SPL_DEPOSITOR_ACCOUNT_INDEX: usize = 5;

/// `deposit_note` account layout: bridge_state(0), bridge_vault(1),
/// merkle_tree(2), depositor(3), … — the tree account is what pushes the
/// depositor one further along than the legacy `deposit`.
const DEPOSIT_NOTE_DEPOSITOR_ACCOUNT_INDEX: usize = 3;

/// `deposit_note_spl` account layout: bridge_state(0), asset_config(1),
/// mint(2), asset_vault(3), depositor_token_account(4), merkle_tree(5),
/// depositor(6), token_program(7). Both the per-asset config and the vault sit
/// ahead of the mint, so neither the legacy `deposit_spl` positions nor the
/// native `deposit_note` ones carry over.
const DEPOSIT_NOTE_SPL_MINT_ACCOUNT_INDEX: usize = 2;
const DEPOSIT_NOTE_SPL_DEPOSITOR_ACCOUNT_INDEX: usize = 6;

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

    // All four deposit instructions share one borsh payload — a u64 amount and
    // two 32-byte fields — and differ in discriminator, account layout and
    // asset. `deposit_note` and `deposit_note_spl` are the two the program
    // still exposes; the two legacy arms stay so historical deposits made
    // before `8830226` removed them still decode.
    let (depositor_index, asset_id) = if raw_data[..8] == discriminators::DEPOSIT_NOTE {
        (
            DEPOSIT_NOTE_DEPOSITOR_ACCOUNT_INDEX,
            crate::privacy::types::NATIVE_SOL_ASSET,
        )
    } else if raw_data[..8] == discriminators::DEPOSIT_NOTE_SPL {
        let mint_index = *compiled.accounts.get(DEPOSIT_NOTE_SPL_MINT_ACCOUNT_INDEX)? as usize;
        let mint = account_keys.get(mint_index)?;
        // `mint_to_asset`, not the raw mint bytes the legacy arm below uses:
        // `deposit_note_spl` hashes `Poseidon(2)` over the mint's halves into
        // the leaf, and `process_deposit` reduces this field into the same
        // `v3_commit` the program computed. Feeding it raw bytes would credit a
        // commitment the chain never appended — blind is recoverable, a wrong
        // leaf in the pool is not.
        (
            DEPOSIT_NOTE_SPL_DEPOSITOR_ACCOUNT_INDEX,
            crate::privacy::poseidon_circom::mint_to_asset(&mint.to_bytes()),
        )
    } else if raw_data[..8] == discriminators::DEPOSIT {
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

/// Resolve the full account-key table used for compiled-instruction index
/// resolution: static keys plus, for v0 LUT transactions, loaded writable
/// then loaded readonly addresses in Solana's canonical order.
///
/// Safety invariants (each exists so a malformed LUT table can only cause a
/// safe skip, never a wrong credit):
/// - Missing LUT data (legacy transaction, or RPC without LUT info) returns
///   the static table unchanged.
/// - An unparsable *writable* key falls back to the static table and does NOT
///   append readonly: readonly indexes are offset by the writable run, so
///   appending readonly without writable would shift every readonly index
///   onto the wrong account.
/// - An unparsable *readonly* key keeps static+writable: writable indexes are
///   unaffected by the missing tail, while readonly-dependent instructions go
///   out of bounds (\`.get()\` → \`None\` → skip) instead of resolving wrongly.
/// - Every skip path logs the signature and the bad key, replacing the old
///   silent drop with an attributable warning.
fn resolve_account_keys(
    signature: &str,
    mut keys: Vec<Pubkey>,
    loaded: Option<(&[String], &[String])>,
) -> Vec<Pubkey> {
    let Some((writable, readonly)) = loaded else {
        return keys;
    };
    if writable.is_empty() && readonly.is_empty() {
        return keys;
    }
    match parse_account_keys(writable) {
        Ok(mut w) => keys.append(&mut w),
        Err(bad) => {
            log::warn!(
                target: "paraloom::bridge::solana",
                "tx {} has unparsable loaded writable key '{}'; continuing with static keys",
                signature,
                bad
            );
            return keys;
        }
    }
    match parse_account_keys(readonly) {
        Ok(mut r) => keys.append(&mut r),
        Err(bad) => {
            log::warn!(
                target: "paraloom::bridge::solana",
                "tx {} has unparsable loaded readonly key '{}'; continuing with static+writable keys",
                signature,
                bad
            );
        }
    }
    keys
}

fn parse_account_keys(keys: &[String]) -> std::result::Result<Vec<Pubkey>, String> {
    keys.iter()
        .map(|k| k.parse::<Pubkey>().map_err(|_| k.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::solana::instructions::DepositNoteInstructionData;
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

    /// `deposit_note` is the only deposit instruction the program still
    /// exposes — `8830226` removed the other two — so a decoder that cannot
    /// read it cannot see any deposit at all. It went unread for nineteen
    /// days; this is the test that would have caught it.
    #[test]
    fn decodes_a_deposit_note() {
        let program_id = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let other = Pubkey::new_unique();

        // deposit_note accounts: bridge_state(0), bridge_vault(1),
        // merkle_tree(2), depositor(3) — one further along than the legacy
        // layout, because of the tree account.
        let account_keys = vec![other, other, other, depositor, program_id];

        let amount = 2_500_000u64;
        let pubkey = [11u8; 32];
        let blinding = [13u8; 32];
        let payload = DepositNoteInstructionData {
            amount,
            pubkey,
            blinding,
        };
        let mut bytes = discriminators::DEPOSIT_NOTE.to_vec();
        bytes.extend_from_slice(&borsh::to_vec(&payload).unwrap());

        let ix = UiCompiledInstruction {
            program_id_index: 4,
            accounts: vec![0, 1, 2, 3],
            data: bs58::encode(bytes).into_string(),
            stack_height: None,
        };

        let decoded = decode_compiled_deposit(&ix, &account_keys, &program_id)
            .expect("deposit_note must decode");
        assert_eq!(decoded.data.amount, amount);
        // The payloads share a layout; `pubkey`/`blinding` arrive in the
        // fields v1 called `recipient`/`randomness`.
        assert_eq!(decoded.data.recipient, pubkey);
        assert_eq!(decoded.data.randomness, blinding);
        assert_eq!(decoded.depositor, depositor);
        assert_eq!(decoded.asset_id, crate::privacy::types::NATIVE_SOL_ASSET);
    }

    /// `deposit_note_spl` is the SPL half of the v3 deposit surface, and it
    /// went unread the same way `deposit_note` did (#689): the discriminator
    /// simply had no arm, so every SPL deposit fell out of
    /// `extract_deposit_events` and the pool never saw the leaf.
    ///
    /// The assert that matters is the last one. The legacy `deposit_spl` arm
    /// keys the asset as the raw mint bytes, and reusing that here would decode
    /// fine, credit a commitment, and be wrong — so this pins the asset to
    /// `mint_to_asset` *and* to not being the raw bytes.
    #[test]
    fn decodes_a_deposit_note_spl() {
        let program_id = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let other = Pubkey::new_unique();

        // deposit_note_spl accounts: bridge_state(0), asset_config(1), mint(2),
        // asset_vault(3), depositor_token_account(4), merkle_tree(5),
        // depositor(6), token_program(7).
        let account_keys = vec![
            other, other, mint, other, other, other, depositor, other, program_id,
        ];

        let amount = 5_000_000u64;
        let pubkey = [11u8; 32];
        let blinding = [13u8; 32];
        let payload = DepositNoteInstructionData {
            amount,
            pubkey,
            blinding,
        };
        let mut bytes = discriminators::DEPOSIT_NOTE_SPL.to_vec();
        bytes.extend_from_slice(&borsh::to_vec(&payload).unwrap());

        let ix = UiCompiledInstruction {
            program_id_index: 8,
            accounts: vec![0, 1, 2, 3, 4, 5, 6, 7],
            data: bs58::encode(bytes).into_string(),
            stack_height: None,
        };

        let decoded = decode_compiled_deposit(&ix, &account_keys, &program_id)
            .expect("deposit_note_spl must decode");
        assert_eq!(decoded.data.amount, amount);
        assert_eq!(decoded.data.recipient, pubkey);
        assert_eq!(decoded.data.randomness, blinding);
        assert_eq!(decoded.depositor, depositor);
        assert_eq!(
            decoded.asset_id,
            crate::privacy::poseidon_circom::mint_to_asset(&mint.to_bytes())
        );
        assert_ne!(
            decoded.asset_id,
            mint.to_bytes(),
            "the v3 SPL arm must not reuse the legacy raw-mint asset"
        );
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
    fn lut_keys_append_in_canonical_order() {
        let s0 = Pubkey::new_unique();
        let s1 = Pubkey::new_unique();
        let w0 = Pubkey::new_unique();
        let r0 = Pubkey::new_unique();
        let combined = resolve_account_keys(
            "sig",
            vec![s0, s1],
            Some((&[w0.to_string()], &[r0.to_string()])),
        );
        assert_eq!(combined, vec![s0, s1, w0, r0]);
    }

    #[test]
    fn lut_missing_returns_static_unchanged() {
        let s0 = Pubkey::new_unique();
        let combined = resolve_account_keys("sig", vec![s0], None);
        assert_eq!(combined, vec![s0]);
    }

    #[test]
    fn lut_bad_writable_falls_back_to_static_without_readonly() {
        // Readonly must NOT be appended when writable fails: readonly indexes
        // are offset by the writable run, so appending them alone would shift
        // every readonly index onto the wrong account.
        let s0 = Pubkey::new_unique();
        let r0 = Pubkey::new_unique();
        let combined = resolve_account_keys(
            "sig",
            vec![s0],
            Some((&["not-a-key".to_string()], &[r0.to_string()])),
        );
        assert_eq!(combined, vec![s0]);
    }

    #[test]
    fn lut_bad_readonly_keeps_static_plus_writable() {
        let s0 = Pubkey::new_unique();
        let w0 = Pubkey::new_unique();
        let combined = resolve_account_keys(
            "sig",
            vec![s0],
            Some((&[w0.to_string()], &["bad-key".to_string()])),
        );
        assert_eq!(combined, vec![s0, w0]);
    }

    #[test]
    fn lut_loaded_depositor_resolves() {
        // deposit_note layout: depositor at position 3. Static table holds 3
        // entries, so index 3 lives in the loaded run — exactly the reported bug.
        let program_id = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let combined = resolve_account_keys(
            "sig",
            vec![other, other, other],
            Some((&[depositor.to_string()], &[])),
        );
        assert_eq!(combined.len(), 4);
        let amount = 500_000u64;
        let pubkey = [21u8; 32];
        let blinding = [23u8; 32];
        let payload = DepositNoteInstructionData {
            amount,
            pubkey,
            blinding,
        };
        let mut bytes = discriminators::DEPOSIT_NOTE.to_vec();
        bytes.extend_from_slice(&borsh::to_vec(&payload).unwrap());
        let ix = UiCompiledInstruction {
            program_id_index: 4,
            accounts: vec![0, 1, 2, 3],
            data: bs58::encode(bytes).into_string(),
            stack_height: None,
        };
        // Without the LUT extension this is out of bounds (None → silent drop);
        // with it, the loaded depositor resolves.
        assert!(decode_compiled_deposit(&ix, &combined[..3], &program_id).is_none());
        let decoded = decode_compiled_deposit(&ix, &combined, &program_id)
            .expect("LUT-loaded depositor must resolve");
        assert_eq!(decoded.depositor, depositor);
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
