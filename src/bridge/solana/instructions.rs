//! Solana program instruction builders
//!
//! Creates instructions for interacting with the Paraloom Solana program

use crate::bridge::{BridgeError, Result, SolanaAddress};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

/// Solana system program id. The newer `solana_system_interface::program`
/// crate is the migration target, but going through `solana-sdk` 2.0 the
/// constant is the all-zeros 32-byte pubkey, which is stable across the
/// crate split. Defined as a `const` here so the loader cannot panic
/// at runtime.
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

/// Instruction data for deposit (Solana → paraloom L2).
///
/// Layout matches the on-chain Anchor program: the eight-byte
/// discriminator [`discriminators::DEPOSIT`] is prepended on the wire,
/// followed by this struct's borsh encoding.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct DepositInstructionData {
    pub amount: u64,
    pub recipient: [u8; 32],
    pub randomness: [u8; 32],
}

/// Instruction data for withdraw.
///
/// Layout matches the on-chain `withdraw` function exactly:
/// `(nullifier, amount, expiration_slot, proof)`. The
/// `expiration_slot` was added in #61 as the time-bound replay-
/// protection layer; the on-chain program rejects calls where
/// `Clock::slot > expiration_slot`.
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct WithdrawInstructionData {
    pub nullifier: [u8; 32],
    pub amount: u64,
    pub expiration_slot: u64,
    pub proof: Vec<u8>,
}

/// Instruction data for `shielded_transfer` (shielded → shielded, #193).
///
/// Layout matches the on-chain `shielded_transfer` function: fixed
/// 2-in/2-out (`nullifiers`, `output_commitments`), the leader-computed
/// `new_merkle_root`, and the `TransferCircuit` proof blob (recorded but
/// not verified on-chain — verification is the L2 quorum's job, #194).
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ShieldedTransferInstructionData {
    pub nullifiers: [[u8; 32]; 2],
    pub output_commitments: [[u8; 32]; 2],
    pub new_merkle_root: [u8; 32],
    pub proof: Vec<u8>,
}

/// Instruction discriminators (matching Anchor's generated discriminators)
pub mod discriminators {
    pub const INITIALIZE: [u8; 8] = [175, 175, 109, 31, 13, 152, 155, 237];
    pub const DEPOSIT: [u8; 8] = [242, 35, 198, 137, 82, 225, 242, 182];
    pub const WITHDRAW: [u8; 8] = [183, 18, 70, 156, 148, 109, 161, 34];
    /// `sha256("global:shielded_transfer")[..8]` (#193). Verified against the
    /// generated IDL by `anchor build`.
    pub const SHIELDED_TRANSFER: [u8; 8] = [191, 130, 5, 127, 124, 187, 238, 188];
    pub const UPDATE_MERKLE_ROOT: [u8; 8] = [240, 174, 252, 99, 208, 105, 45, 104];
    #[allow(dead_code)]
    pub const PAUSE: [u8; 8] = [139, 98, 119, 98, 22, 6, 120, 33];
    #[allow(dead_code)]
    pub const UNPAUSE: [u8; 8] = [111, 51, 238, 100, 208, 146, 57, 103];
    /// `sha256("global:set_bridge_authority")[..8]`. Rotates the bridge
    /// settlement authority (admin op, current-authority-signed).
    pub const SET_BRIDGE_AUTHORITY: [u8; 8] = [158, 241, 140, 64, 226, 16, 99, 251];
    /// `sha256("global:initialize_validator_registry")[..8]`.
    pub const INITIALIZE_VALIDATOR_REGISTRY: [u8; 8] = [168, 49, 128, 236, 25, 7, 168, 85];
    /// `sha256("global:register_validator")[..8]`.
    pub const REGISTER_VALIDATOR: [u8; 8] = [118, 98, 251, 58, 81, 30, 13, 240];
    /// `sha256("global:deposit_spl")[..8]` (#237). Asset-aware deposit of an
    /// SPL token into a per-asset vault keyed by the mint.
    pub const DEPOSIT_SPL: [u8; 8] = [224, 0, 198, 175, 198, 47, 105, 204];
    /// `sha256("global:withdraw_spl")[..8]` (#237). Asset-aware withdrawal of an
    /// SPL token from its per-asset vault.
    pub const WITHDRAW_SPL: [u8; 8] = [181, 154, 94, 86, 62, 115, 6, 186];
}

/// SPL Token program id (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`), the
/// classic v1 token program the on-chain `anchor_spl::token::Token` resolves
/// to. Defined here as a constant so the off-chain SPL builders need no
/// `spl-token` dependency.
pub const SPL_TOKEN_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
]);

/// Associated Token Account program id
/// (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`). Used to derive the
/// canonical ATA for an owner + mint without a `spl-associated-token-account`
/// dependency.
pub const SPL_ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218,
    255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
]);

/// Instruction data for `deposit_spl` (#237). Wire-identical to the native
/// [`DepositInstructionData`] — the on-chain `deposit_spl` takes the same
/// `(amount, recipient, randomness)` tuple; only the value-movement differs.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct DepositSplInstructionData {
    pub amount: u64,
    pub recipient: [u8; 32],
    pub randomness: [u8; 32],
}

/// Instruction data for `withdraw_spl` (#237). Wire-identical to the native
/// [`WithdrawInstructionData`]; the mint is passed as an account, not in the
/// payload.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct WithdrawSplInstructionData {
    pub nullifier: [u8; 32],
    pub amount: u64,
    pub expiration_slot: u64,
    pub proof: Vec<u8>,
}

/// Create initialize instruction.
///
/// `program_version` is the semver-encoded version the deployed
/// program should record in `BridgeState` (#69, audit #9). The L2
/// later reads it back via [`crate::bridge::ProgramInterface::program_version`]
/// and refuses to start if it does not match the binary's
/// [`crate::bridge::EXPECTED_PROGRAM_VERSION`].
pub fn create_initialize_instruction(
    program_id: &Pubkey,
    authority: &Pubkey,
    program_version: u32,
    initial_merkle_root: [u8; 32],
) -> Result<Instruction> {
    let (bridge_state_pda, _bump) = Pubkey::find_program_address(&[b"bridge_state"], program_id);

    #[derive(BorshSerialize)]
    struct InitializeData {
        program_version: u32,
        initial_merkle_root: [u8; 32],
    }

    let data = InitializeData {
        program_version,
        initial_merkle_root,
    };

    let mut instruction_data = discriminators::INITIALIZE.to_vec();
    instruction_data.extend_from_slice(
        &borsh::to_vec(&data).map_err(|e| BridgeError::Serialization(e.to_string()))?,
    );

    let system_program_id = SYSTEM_PROGRAM_ID;
    // #204: `initialize` is gated to the program's upgrade authority via the
    // BPFLoaderUpgradeable ProgramData account. The on-chain `Initialize`
    // accounts struct requires it (seeds = [program_id], program =
    // bpf_loader_upgradeable), so it must be passed here.
    let (program_data_pda, _) = derive_program_data(program_id);

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(bridge_state_pda, false),
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(program_data_pda, false),
            AccountMeta::new_readonly(system_program_id, false),
        ],
        data: instruction_data,
    })
}

/// Create an `initialize_validator_registry` instruction (#204-gated to the
/// program's upgrade authority, same as `initialize`).
pub fn create_initialize_validator_registry_instruction(
    program_id: &Pubkey,
    authority: &Pubkey,
) -> Result<Instruction> {
    let (registry_pda, _) = derive_validator_registry(program_id);
    let (program_data_pda, _) = derive_program_data(program_id);

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(registry_pda, false),
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(program_data_pda, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: discriminators::INITIALIZE_VALIDATOR_REGISTRY.to_vec(),
    })
}

/// Create a `register_validator` instruction. Permissionless: the validator
/// signs for itself and stakes `stake_amount` lamports (>= MIN_VALIDATOR_STAKE).
pub fn create_register_validator_instruction(
    program_id: &Pubkey,
    validator: &Pubkey,
    stake_amount: u64,
) -> Result<Instruction> {
    let (validator_pda, _) = derive_validator_account(program_id, validator);
    let (registry_pda, _) = derive_validator_registry(program_id);

    let mut instruction_data = discriminators::REGISTER_VALIDATOR.to_vec();
    instruction_data.extend_from_slice(
        &borsh::to_vec(&stake_amount).map_err(|e| BridgeError::Serialization(e.to_string()))?,
    );

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(validator_pda, false),
            AccountMeta::new(registry_pda, false),
            AccountMeta::new(*validator, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: instruction_data,
    })
}

/// Create deposit instruction
pub fn create_deposit_instruction(
    program_id: &Pubkey,
    depositor: &Pubkey,
    bridge_vault: &Pubkey,
    amount: u64,
    recipient: [u8; 32],
    randomness: [u8; 32],
) -> Result<Instruction> {
    let (bridge_state_pda, _bump) = Pubkey::find_program_address(&[b"bridge_state"], program_id);

    let data = DepositInstructionData {
        amount,
        recipient,
        randomness,
    };

    let mut instruction_data = discriminators::DEPOSIT.to_vec();
    instruction_data.extend_from_slice(
        &borsh::to_vec(&data).map_err(|e| BridgeError::Serialization(e.to_string()))?,
    );

    let system_program_id = SYSTEM_PROGRAM_ID;

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(bridge_state_pda, false),
            AccountMeta::new(*bridge_vault, false),
            AccountMeta::new(*depositor, true),
            AccountMeta::new_readonly(system_program_id, false),
        ],
        data: instruction_data,
    })
}

/// Create withdraw instruction.
///
/// `expiration_slot` is bound at construction time and forwarded to the
/// on-chain program as part of [`WithdrawInstructionData`]. Callers
/// typically compute it as `current_slot + withdrawal_expiration_window_slots`
/// (see [`crate::bridge::BridgeConfig`]). A value in the past is not
/// rejected here — the program does that — but doing so locally would
/// be cheaper, and the submitter performs that check before this builder
/// is reached.
#[allow(clippy::too_many_arguments)]
pub fn create_withdraw_instruction(
    program_id: &Pubkey,
    authority: &Pubkey,
    bridge_vault: &Pubkey,
    recipient: SolanaAddress,
    nullifier: [u8; 32],
    amount: u64,
    expiration_slot: u64,
    proof: Vec<u8>,
) -> Result<Instruction> {
    let (bridge_state_pda, _bump) = Pubkey::find_program_address(&[b"bridge_state"], program_id);
    let (nullifier_pda, _nullifier_bump) = derive_nullifier_account(program_id, &nullifier);
    // The settling validator's account, bound to the `authority` signer.
    // The on-chain program credits the withdrawal fee here, so settlement
    // requires the submitter to be a registered validator.
    let (validator_pda, _validator_bump) = derive_validator_account(program_id, authority);
    let recipient_pubkey = Pubkey::new_from_array(recipient);

    let data = WithdrawInstructionData {
        nullifier,
        amount,
        expiration_slot,
        proof,
    };

    let mut instruction_data = discriminators::WITHDRAW.to_vec();
    instruction_data.extend_from_slice(
        &borsh::to_vec(&data).map_err(|e| BridgeError::Serialization(e.to_string()))?,
    );

    let system_program_id = SYSTEM_PROGRAM_ID;

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(bridge_state_pda, false),
            AccountMeta::new(*bridge_vault, false),
            AccountMeta::new(nullifier_pda, false), // Nullifier account (will be created)
            AccountMeta::new(recipient_pubkey, false),
            AccountMeta::new(validator_pda, false), // Settling validator (fee credited here)
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(system_program_id, false),
        ],
        data: instruction_data,
    })
}

/// Create `shielded_transfer` instruction (#193).
///
/// Settles a shielded → shielded transfer: records both input nullifiers
/// (their PDAs are `init`'d, so a replay fails on-chain) and advances the
/// Merkle root to `new_merkle_root`, without moving any lamports. Mirrors
/// [`create_withdraw_instruction`]; both nullifier PDAs are derived through
/// the shared [`derive_nullifier_account`] helper, so the account order here
/// must match the `ShieldedTransfer` accounts struct in the program.
pub fn create_shielded_transfer_instruction(
    program_id: &Pubkey,
    authority: &Pubkey,
    nullifiers: [[u8; 32]; 2],
    output_commitments: [[u8; 32]; 2],
    new_merkle_root: [u8; 32],
    proof: Vec<u8>,
) -> Result<Instruction> {
    let (bridge_state_pda, _bump) = Pubkey::find_program_address(&[b"bridge_state"], program_id);
    let (nullifier_pda_0, _) = derive_nullifier_account(program_id, &nullifiers[0]);
    let (nullifier_pda_1, _) = derive_nullifier_account(program_id, &nullifiers[1]);

    let data = ShieldedTransferInstructionData {
        nullifiers,
        output_commitments,
        new_merkle_root,
        proof,
    };

    let mut instruction_data = discriminators::SHIELDED_TRANSFER.to_vec();
    instruction_data.extend_from_slice(
        &borsh::to_vec(&data).map_err(|e| BridgeError::Serialization(e.to_string()))?,
    );

    let system_program_id = SYSTEM_PROGRAM_ID;

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(bridge_state_pda, false),
            AccountMeta::new(nullifier_pda_0, false), // Nullifier account 0 (will be created)
            AccountMeta::new(nullifier_pda_1, false), // Nullifier account 1 (will be created)
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(system_program_id, false),
        ],
        data: instruction_data,
    })
}

/// Create update merkle root instruction
pub fn create_update_merkle_root_instruction(
    program_id: &Pubkey,
    authority: &Pubkey,
    new_merkle_root: [u8; 32],
) -> Result<Instruction> {
    let (bridge_state_pda, _bump) = Pubkey::find_program_address(&[b"bridge_state"], program_id);

    #[derive(BorshSerialize)]
    struct UpdateMerkleRootData {
        new_merkle_root: [u8; 32],
    }

    let data = UpdateMerkleRootData { new_merkle_root };

    let mut instruction_data = discriminators::UPDATE_MERKLE_ROOT.to_vec();
    instruction_data.extend_from_slice(
        &borsh::to_vec(&data).map_err(|e| BridgeError::Serialization(e.to_string()))?,
    );

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(bridge_state_pda, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data: instruction_data,
    })
}

/// Create a `set_bridge_authority` instruction (admin: rotate the bridge
/// settlement authority). Signed by the CURRENT authority; sets
/// `bridge_state.authority = new_authority`. Used to hand settlement control
/// from the genesis (upgrade) authority to the node-resident validator key,
/// keeping the upgrade authority offline.
pub fn create_set_bridge_authority_instruction(
    program_id: &Pubkey,
    authority: &Pubkey,
    new_authority: &Pubkey,
) -> Result<Instruction> {
    let (bridge_state_pda, _bump) = Pubkey::find_program_address(&[b"bridge_state"], program_id);

    #[derive(BorshSerialize)]
    struct SetBridgeAuthorityData {
        // Serialized as 32 bytes — wire-identical to the on-chain `Pubkey`
        // borsh layout the program decodes.
        new_authority: [u8; 32],
    }

    let data = SetBridgeAuthorityData {
        new_authority: new_authority.to_bytes(),
    };

    let mut instruction_data = discriminators::SET_BRIDGE_AUTHORITY.to_vec();
    instruction_data.extend_from_slice(
        &borsh::to_vec(&data).map_err(|e| BridgeError::Serialization(e.to_string()))?,
    );

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(bridge_state_pda, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data: instruction_data,
    })
}

/// Derive bridge vault PDA
pub fn derive_bridge_vault(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"bridge_vault"], program_id)
}

/// Derive bridge state PDA
pub fn derive_bridge_state(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"bridge_state"], program_id)
}

/// Derive a validator account PDA from the validator's pubkey.
pub fn derive_validator_account(program_id: &Pubkey, validator: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"validator", validator.as_ref()], program_id)
}

/// Derive the validator registry PDA.
pub fn derive_validator_registry(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"validator_registry"], program_id)
}

/// Derive the BPFLoaderUpgradeable `ProgramData` PDA for `program_id` — the
/// account the #204 upgrade-authority gate reads on `initialize` /
/// `initialize_validator_registry`.
pub fn derive_program_data(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[program_id.as_ref()],
        &solana_sdk::bpf_loader_upgradeable::id(),
    )
}

/// Derive nullifier account PDA
pub fn derive_nullifier_account(program_id: &Pubkey, nullifier: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"nullifier", nullifier.as_ref()], program_id)
}

/// Derive the program PDA that owns every per-asset vault
/// (`seeds = [b"asset_vault_authority"]`). One authority signs releases from
/// all asset vaults on the SPL withdraw path.
pub fn derive_asset_vault_authority(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"asset_vault_authority"], program_id)
}

/// Derive the per-asset vault token account PDA for `mint`
/// (`seeds = [b"asset_vault", mint]`). Custody for one SPL asset.
pub fn derive_asset_vault(program_id: &Pubkey, mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"asset_vault", mint.as_ref()], program_id)
}

/// Derive the canonical Associated Token Account address for `owner` + `mint`,
/// mirroring `spl_associated_token_account::get_associated_token_address`
/// without the dependency: it is the PDA of
/// `[owner, SPL_TOKEN_PROGRAM_ID, mint]` under the ATA program.
pub fn derive_associated_token_address(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), SPL_TOKEN_PROGRAM_ID.as_ref(), mint.as_ref()],
        &SPL_ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID,
    )
    .0
}

/// Build an idempotent "create associated token account" instruction (the
/// ATA program's `CreateIdempotent`, discriminator byte `1`). `payer` funds the
/// new account; `owner` will own it; it holds `mint`. Idempotent so re-running
/// against an existing ATA is a no-op rather than an error — handy in a demo
/// that may re-create the fresh address's token account.
pub fn create_associated_token_account_idempotent_instruction(
    payer: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
) -> Instruction {
    let ata = derive_associated_token_address(owner, mint);
    Instruction {
        program_id: SPL_ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata, false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(SPL_TOKEN_PROGRAM_ID, false),
        ],
        // `1` = CreateIdempotent (vs. `0` = Create).
        data: vec![1],
    }
}

/// Create a `deposit_spl` instruction (#237): move `amount` of `mint` from the
/// depositor's `depositor_token` account into the program's per-asset vault,
/// emitting a shielded note for `recipient`/`randomness`. The account order
/// matches the on-chain `DepositSpl` accounts struct exactly: bridge_state,
/// mint, asset_vault_authority, asset_vault, depositor_token, depositor
/// (signer), token_program, system_program, rent.
pub fn create_deposit_spl_instruction(
    program_id: &Pubkey,
    depositor: &Pubkey,
    mint: &Pubkey,
    depositor_token: &Pubkey,
    amount: u64,
    recipient: [u8; 32],
    randomness: [u8; 32],
) -> Result<Instruction> {
    let (bridge_state_pda, _) = derive_bridge_state(program_id);
    let (asset_vault_authority, _) = derive_asset_vault_authority(program_id);
    let (asset_vault, _) = derive_asset_vault(program_id, mint);

    let data = DepositSplInstructionData {
        amount,
        recipient,
        randomness,
    };
    let mut instruction_data = discriminators::DEPOSIT_SPL.to_vec();
    instruction_data.extend_from_slice(
        &borsh::to_vec(&data).map_err(|e| BridgeError::Serialization(e.to_string()))?,
    );

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(bridge_state_pda, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(asset_vault_authority, false),
            AccountMeta::new(asset_vault, false),
            AccountMeta::new(*depositor_token, false),
            AccountMeta::new(*depositor, true),
            AccountMeta::new_readonly(SPL_TOKEN_PROGRAM_ID, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        ],
        data: instruction_data,
    })
}

/// Create a `withdraw_spl` instruction (#237): release `amount` of `mint` from
/// its per-asset vault to `recipient_token`, spending `nullifier`. The account
/// order matches the on-chain `WithdrawSpl` accounts struct exactly:
/// bridge_state, mint, asset_vault_authority, asset_vault, nullifier_account,
/// recipient_token, validator_account, authority (signer), token_program,
/// system_program.
#[allow(clippy::too_many_arguments)]
pub fn create_withdraw_spl_instruction(
    program_id: &Pubkey,
    authority: &Pubkey,
    mint: &Pubkey,
    recipient_token: &Pubkey,
    nullifier: [u8; 32],
    amount: u64,
    expiration_slot: u64,
    proof: Vec<u8>,
) -> Result<Instruction> {
    let (bridge_state_pda, _) = derive_bridge_state(program_id);
    let (asset_vault_authority, _) = derive_asset_vault_authority(program_id);
    let (asset_vault, _) = derive_asset_vault(program_id, mint);
    let (nullifier_pda, _) = derive_nullifier_account(program_id, &nullifier);
    let (validator_pda, _) = derive_validator_account(program_id, authority);

    let data = WithdrawSplInstructionData {
        nullifier,
        amount,
        expiration_slot,
        proof,
    };
    let mut instruction_data = discriminators::WITHDRAW_SPL.to_vec();
    instruction_data.extend_from_slice(
        &borsh::to_vec(&data).map_err(|e| BridgeError::Serialization(e.to_string()))?,
    );

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(bridge_state_pda, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(asset_vault_authority, false),
            AccountMeta::new(asset_vault, false),
            AccountMeta::new(nullifier_pda, false),
            AccountMeta::new(*recipient_token, false),
            AccountMeta::new(validator_pda, false),
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(SPL_TOKEN_PROGRAM_ID, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: instruction_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_pdas() {
        let program_id = Pubkey::new_unique();
        let (state, _) = derive_bridge_state(&program_id);
        let (vault, _) = derive_bridge_vault(&program_id);

        // PDAs should be deterministic
        let (state2, _) = derive_bridge_state(&program_id);
        let (vault2, _) = derive_bridge_vault(&program_id);

        assert_eq!(state, state2);
        assert_eq!(vault, vault2);
    }

    #[test]
    fn test_create_withdraw_instruction() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let bridge_vault = Pubkey::new_unique();
        let recipient = [0u8; 32];
        let nullifier = [1u8; 32];
        let proof = vec![0u8; 100];

        let ix = create_withdraw_instruction(
            &program_id,
            &authority,
            &bridge_vault,
            recipient,
            nullifier,
            1000,
            // expiration_slot — picked far enough in the future that
            // the test does not depend on a real `Clock`.
            u64::MAX,
            proof,
        );

        assert!(ix.is_ok());
        let instruction = ix.unwrap();
        assert_eq!(instruction.program_id, program_id);
        // bridge_state, bridge_vault, nullifier, recipient, validator_account,
        // authority (signer), system_program.
        assert_eq!(instruction.accounts.len(), 7);

        // The settling validator's account is bound to the authority signer
        // and sits between the recipient and the signer.
        let (validator_pda, _) = derive_validator_account(&program_id, &authority);
        assert_eq!(instruction.accounts[4].pubkey, validator_pda);
        assert!(instruction.accounts[4].is_writable);
        assert!(!instruction.accounts[4].is_signer);
        assert_eq!(instruction.accounts[5].pubkey, authority);
        assert!(instruction.accounts[5].is_signer);
    }

    #[test]
    fn test_derive_nullifier_account() {
        let program_id = Pubkey::new_unique();
        let nullifier = [1u8; 32];

        let (pda1, _) = derive_nullifier_account(&program_id, &nullifier);
        let (pda2, _) = derive_nullifier_account(&program_id, &nullifier);

        // Same nullifier should produce same PDA
        assert_eq!(pda1, pda2);

        // Different nullifier should produce different PDA
        let different_nullifier = [2u8; 32];
        let (pda3, _) = derive_nullifier_account(&program_id, &different_nullifier);
        assert_ne!(pda1, pda3);
    }

    /// Round-trip the new \`expiration_slot\` field through borsh to
    /// catch any drift between the L2 wire format and the on-chain
    /// \`withdraw\` function signature. Belt-and-suspenders: the
    /// on-chain decoder is anchor-derived from the same struct shape,
    /// so a mismatch in field order or width here would surface as a
    /// failed instruction at runtime — this test catches it at unit
    /// time instead.
    #[test]
    fn test_withdraw_instruction_data_round_trip() {
        let original = WithdrawInstructionData {
            nullifier: [0xAB; 32],
            amount: 12_345_678,
            expiration_slot: 9_876_543,
            proof: vec![0xCD; 64],
        };

        let bytes = borsh::to_vec(&original).expect("borsh serialize");
        let decoded = WithdrawInstructionData::try_from_slice(&bytes).expect("borsh deserialize");

        assert_eq!(decoded.nullifier, original.nullifier);
        assert_eq!(decoded.amount, original.amount);
        assert_eq!(decoded.expiration_slot, original.expiration_slot);
        assert_eq!(decoded.proof, original.proof);
    }

    /// Field ordering is observable on the wire — Anchor's discriminator
    /// is followed by borsh fields in declaration order. A regression
    /// where someone swaps \`amount\` and \`expiration_slot\` (both
    /// \`u64\`, indistinguishable to the type system) would deploy
    /// silently and cause every withdrawal to either fail expiration
    /// or transfer a nonsensical amount. The byte-prefix check below
    /// pins the layout: \`[nullifier (32) | amount (8) | expiration (8) | proof_len (4) | proof…]\`.
    #[test]
    fn test_withdraw_instruction_data_field_order() {
        let payload = WithdrawInstructionData {
            nullifier: [0u8; 32],
            amount: 0x0807_0605_0403_0201,
            expiration_slot: 0x1716_1514_1312_1110,
            proof: vec![],
        };
        let bytes = borsh::to_vec(&payload).expect("borsh serialize");
        // Skip the 32-byte nullifier; assert the next 16 bytes are
        // amount-then-expiration_slot in little-endian order.
        assert_eq!(
            &bytes[32..32 + 8],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(
            &bytes[32 + 8..32 + 16],
            &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]
        );
    }

    #[test]
    fn test_create_shielded_transfer_instruction() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let nullifiers = [[1u8; 32], [2u8; 32]];
        let output_commitments = [[3u8; 32], [4u8; 32]];
        let new_merkle_root = [5u8; 32];
        let proof = vec![0u8; 192];

        let ix = create_shielded_transfer_instruction(
            &program_id,
            &authority,
            nullifiers,
            output_commitments,
            new_merkle_root,
            proof,
        )
        .expect("builder");

        assert_eq!(ix.program_id, program_id);
        // bridge_state, nullifier_0, nullifier_1, authority, system_program.
        assert_eq!(ix.accounts.len(), 5);
        // The two nullifier PDAs must match the shared derivation helper and
        // sit in slots 1 and 2 (after bridge_state).
        let (n0, _) = derive_nullifier_account(&program_id, &nullifiers[0]);
        let (n1, _) = derive_nullifier_account(&program_id, &nullifiers[1]);
        assert_eq!(ix.accounts[1].pubkey, n0);
        assert_eq!(ix.accounts[2].pubkey, n1);
        // The wire payload is prefixed with the Anchor discriminator.
        assert_eq!(&ix.data[..8], &discriminators::SHIELDED_TRANSFER);
    }

    #[test]
    fn test_create_deposit_spl_instruction() {
        let program_id = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let depositor_token = Pubkey::new_unique();

        let ix = create_deposit_spl_instruction(
            &program_id,
            &depositor,
            &mint,
            &depositor_token,
            500,
            [7u8; 32],
            [9u8; 32],
        )
        .expect("builder");

        assert_eq!(ix.program_id, program_id);
        // bridge_state, mint, asset_vault_authority, asset_vault,
        // depositor_token, depositor (signer), token_program, system_program,
        // rent — exactly the on-chain `DepositSpl` order.
        assert_eq!(ix.accounts.len(), 9);
        assert_eq!(ix.accounts[0].pubkey, derive_bridge_state(&program_id).0);
        assert_eq!(ix.accounts[1].pubkey, mint);
        assert_eq!(
            ix.accounts[2].pubkey,
            derive_asset_vault_authority(&program_id).0
        );
        assert_eq!(
            ix.accounts[3].pubkey,
            derive_asset_vault(&program_id, &mint).0
        );
        assert_eq!(ix.accounts[4].pubkey, depositor_token);
        assert!(ix.accounts[5].is_signer);
        assert_eq!(ix.accounts[6].pubkey, SPL_TOKEN_PROGRAM_ID);
        assert_eq!(&ix.data[..8], &discriminators::DEPOSIT_SPL);
    }

    #[test]
    fn test_create_withdraw_spl_instruction() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let recipient_token = Pubkey::new_unique();
        let nullifier = [1u8; 32];

        let ix = create_withdraw_spl_instruction(
            &program_id,
            &authority,
            &mint,
            &recipient_token,
            nullifier,
            1000,
            u64::MAX,
            vec![0u8; 100],
        )
        .expect("builder");

        assert_eq!(ix.program_id, program_id);
        // bridge_state, mint, asset_vault_authority, asset_vault,
        // nullifier_account, recipient_token, validator_account, authority
        // (signer), token_program, system_program.
        assert_eq!(ix.accounts.len(), 10);
        assert_eq!(ix.accounts[1].pubkey, mint);
        assert_eq!(
            ix.accounts[3].pubkey,
            derive_asset_vault(&program_id, &mint).0
        );
        assert_eq!(
            ix.accounts[4].pubkey,
            derive_nullifier_account(&program_id, &nullifier).0
        );
        assert_eq!(ix.accounts[5].pubkey, recipient_token);
        assert_eq!(
            ix.accounts[6].pubkey,
            derive_validator_account(&program_id, &authority).0
        );
        assert!(ix.accounts[7].is_signer);
        assert_eq!(&ix.data[..8], &discriminators::WITHDRAW_SPL);
    }

    #[test]
    fn test_associated_token_address_is_deterministic() {
        let owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let a = derive_associated_token_address(&owner, &mint);
        let b = derive_associated_token_address(&owner, &mint);
        assert_eq!(a, b);
        // Different owners yield different ATAs.
        assert_ne!(
            a,
            derive_associated_token_address(&Pubkey::new_unique(), &mint)
        );
    }

    /// Round-trip the transfer payload through borsh to pin the wire format
    /// against the on-chain `shielded_transfer` signature (#193).
    #[test]
    fn test_shielded_transfer_instruction_data_round_trip() {
        let original = ShieldedTransferInstructionData {
            nullifiers: [[0xAB; 32], [0xCD; 32]],
            output_commitments: [[0x11; 32], [0x22; 32]],
            new_merkle_root: [0x33; 32],
            proof: vec![0xEF; 192],
        };

        let bytes = borsh::to_vec(&original).expect("borsh serialize");
        let decoded =
            ShieldedTransferInstructionData::try_from_slice(&bytes).expect("borsh deserialize");

        assert_eq!(decoded, original);
        // Layout: [nullifiers (64) | output_commitments (64) | root (32) | proof_len (4) | proof…].
        assert_eq!(&bytes[..32], &[0xAB; 32]);
        assert_eq!(&bytes[32..64], &[0xCD; 32]);
        assert_eq!(&bytes[64..96], &[0x11; 32]);
        assert_eq!(&bytes[96..128], &[0x22; 32]);
        assert_eq!(&bytes[128..160], &[0x33; 32]);
    }
}
