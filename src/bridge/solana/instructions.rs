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

/// Instruction discriminators (matching Anchor's generated discriminators)
pub mod discriminators {
    pub const INITIALIZE: [u8; 8] = [175, 175, 109, 31, 13, 152, 155, 237];
    pub const DEPOSIT: [u8; 8] = [242, 35, 198, 137, 82, 225, 242, 182];
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
    /// `sha256("global:reset_validator_registry")[..8]`. Ceremony-redeploy
    /// registry migration: grows the registry PDA to the current layout and
    /// rebuilds its counters from the co-signer validator PDAs in
    /// `remaining_accounts`.
    pub const RESET_VALIDATOR_REGISTRY: [u8; 8] = [101, 188, 0, 99, 248, 198, 207, 7];
    /// `sha256("global:transact")[..8]` (#350). Unified v3 settlement against
    /// the on-chain incremental tree.
    pub const TRANSACT: [u8; 8] = [217, 149, 130, 143, 221, 52, 252, 119];
    /// `sha256("global:deposit_note")[..8]` (#350). v3 deposit that appends the
    /// note commitment to the on-chain tree.
    #[allow(dead_code)]
    pub const DEPOSIT_NOTE: [u8; 8] = [75, 212, 96, 185, 178, 167, 29, 57];
    /// `sha256("global:initialize_merkle_tree")[..8]` (#350). One-time,
    /// upgrade-authority-gated tree account creation.
    #[allow(dead_code)]
    pub const INITIALIZE_MERKLE_TREE: [u8; 8] = [67, 143, 80, 157, 177, 227, 11, 238];
}

/// Instruction data for `transact` (circuit v3, #350).
///
/// Layout matches the on-chain `transact` function exactly:
/// `(nullifiers, output_commitments, root, ext_amount, proof)`. `root` is a
/// root from the program's on-chain history the proof proves membership
/// against; `ext_amount` is the signed external flow (`< 0` withdraws
/// `|ext_amount|`, `== 0` is a pure shielded transfer; deposits go through
/// `deposit_note` and `> 0` is rejected on-chain).
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransactInstructionData {
    pub nullifiers: [[u8; 32]; 2],
    pub output_commitments: [[u8; 32]; 2],
    pub root: [u8; 32],
    pub ext_amount: i64,
    pub proof: Vec<u8>,
}

/// Instruction data for `deposit_note` (circuit v3, #350).
///
/// Layout matches the on-chain `deposit_note` function:
/// `(amount, pubkey, blinding)`. The program computes the note commitment
/// `Poseidon(amount, pubkey, blinding, asset)` itself and appends it to the
/// on-chain tree, so the leaf is bound to the lamports actually deposited.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct DepositNoteInstructionData {
    pub amount: u64,
    pub pubkey: [u8; 32],
    pub blinding: [u8; 32],
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

/// Create a `reset_validator_registry` instruction (#204-gated to the program's
/// upgrade authority). Grows the registry PDA to the current layout and rebuilds
/// its counters from `co_signers` — the validator wallets whose PDAs are passed
/// as `remaining_accounts`. Only these are counted, so stale registrations are
/// dropped from the stake-weighted quorum denominator. Used once at the
/// ceremony-key redeploy.
pub fn create_reset_validator_registry_instruction(
    program_id: &Pubkey,
    authority: &Pubkey,
    co_signers: &[Pubkey],
) -> Result<Instruction> {
    let (registry_pda, _) = derive_validator_registry(program_id);
    let (program_data_pda, _) = derive_program_data(program_id);

    let mut accounts = vec![
        AccountMeta::new(registry_pda, false),
        AccountMeta::new(*authority, true),
        AccountMeta::new_readonly(program_data_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];
    // Each co-signer's validator PDA, read-only, as remaining_accounts.
    for wallet in co_signers {
        let (validator_pda, _) = derive_validator_account(program_id, wallet);
        accounts.push(AccountMeta::new_readonly(validator_pda, false));
    }

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data: discriminators::RESET_VALIDATOR_REGISTRY.to_vec(),
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

/// Append the quorum co-signers as remaining accounts (#260): each validator's
/// wallet (a signer) followed by its `ValidatorAccount` PDA. The program
/// verifies on-chain that a supermajority of registered validators signed.
fn append_quorum_accounts(
    program_id: &Pubkey,
    quorum_validators: &[Pubkey],
    accounts: &mut Vec<AccountMeta>,
) {
    for v in quorum_validators {
        let (vpda, _) = derive_validator_account(program_id, v);
        accounts.push(AccountMeta::new_readonly(*v, true));
        accounts.push(AccountMeta::new_readonly(vpda, false));
    }
}

/// Create the `transact` instruction (circuit v3, #350).
///
/// Unified 2-in/2-out settlement against the program's own on-chain tree:
/// the proof is verified against `root` (which must be in the on-chain root
/// history), both nullifier PDAs are `init`'d, and the program appends both
/// output commitments itself. The account order must match the `Transact`
/// accounts struct in the program. Quorum-gated by a supermajority of
/// registered validators appended via [`append_quorum_accounts`] (#260).
#[allow(clippy::too_many_arguments)]
pub fn create_transact_instruction(
    program_id: &Pubkey,
    authority: &Pubkey,
    bridge_vault: &Pubkey,
    recipient: SolanaAddress,
    nullifiers: [[u8; 32]; 2],
    output_commitments: [[u8; 32]; 2],
    root: [u8; 32],
    ext_amount: i64,
    proof: Vec<u8>,
    quorum_validators: &[Pubkey],
) -> Result<Instruction> {
    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], program_id);
    let (merkle_tree_pda, _) = derive_merkle_tree(program_id);
    let (validator_registry_pda, _) =
        Pubkey::find_program_address(&[b"validator_registry"], program_id);
    let (nullifier_pda_0, _) = derive_nullifier_account(program_id, &nullifiers[0]);
    let (nullifier_pda_1, _) = derive_nullifier_account(program_id, &nullifiers[1]);
    let (validator_pda, _) = derive_validator_account(program_id, authority);
    let recipient_pubkey = Pubkey::new_from_array(recipient);

    let data = TransactInstructionData {
        nullifiers,
        output_commitments,
        root,
        ext_amount,
        proof,
    };

    let mut instruction_data = discriminators::TRANSACT.to_vec();
    instruction_data.extend_from_slice(
        &borsh::to_vec(&data).map_err(|e| BridgeError::Serialization(e.to_string()))?,
    );

    let mut accounts = vec![
        AccountMeta::new(bridge_state_pda, false),
        AccountMeta::new(merkle_tree_pda, false),
        AccountMeta::new(*bridge_vault, false),
        AccountMeta::new(nullifier_pda_0, false), // Nullifier account 0 (will be created)
        AccountMeta::new(nullifier_pda_1, false), // Nullifier account 1 (will be created)
        AccountMeta::new(recipient_pubkey, false),
        AccountMeta::new(validator_pda, false), // Settling validator (fee credited here)
        AccountMeta::new_readonly(validator_registry_pda, false),
        AccountMeta::new(*authority, true),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];
    append_quorum_accounts(program_id, quorum_validators, &mut accounts);

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data: instruction_data,
    })
}

/// Create the `deposit_note` instruction (circuit v3, #350).
///
/// Permissionless: the depositor moves their own lamports into the vault and
/// the program computes + appends the note commitment on-chain. The account
/// order must match the `DepositNote` accounts struct in the program.
pub fn create_deposit_note_instruction(
    program_id: &Pubkey,
    depositor: &Pubkey,
    bridge_vault: &Pubkey,
    amount: u64,
    pubkey: [u8; 32],
    blinding: [u8; 32],
) -> Result<Instruction> {
    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], program_id);
    let (merkle_tree_pda, _) = derive_merkle_tree(program_id);

    let data = DepositNoteInstructionData {
        amount,
        pubkey,
        blinding,
    };

    let mut instruction_data = discriminators::DEPOSIT_NOTE.to_vec();
    instruction_data.extend_from_slice(
        &borsh::to_vec(&data).map_err(|e| BridgeError::Serialization(e.to_string()))?,
    );

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(bridge_state_pda, false),
            AccountMeta::new(*bridge_vault, false),
            AccountMeta::new(merkle_tree_pda, false),
            AccountMeta::new(*depositor, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: instruction_data,
    })
}

/// Create the `initialize_merkle_tree` instruction (circuit v3, #350).
///
/// One-time creation of the on-chain incremental tree, gated to the program
/// upgrade authority like the other `initialize_*` instructions (#204).
pub fn create_initialize_merkle_tree_instruction(
    program_id: &Pubkey,
    authority: &Pubkey,
) -> Instruction {
    let (merkle_tree_pda, _) = derive_merkle_tree(program_id);
    let (program_data_pda, _) = derive_program_data(program_id);

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(merkle_tree_pda, false),
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(program_data_pda, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: discriminators::INITIALIZE_MERKLE_TREE.to_vec(),
    }
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

/// Derive the on-chain incremental Merkle tree PDA (circuit v3, #350).
pub fn derive_merkle_tree(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"merkle_tree"], program_id)
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

    #[test]
    fn test_create_transact_instruction() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let bridge_vault = Pubkey::new_unique();
        let cosigner = Pubkey::new_unique();

        let ix = create_transact_instruction(
            &program_id,
            &authority,
            &bridge_vault,
            [9u8; 32],
            [[1u8; 32], [2u8; 32]],
            [[3u8; 32], [4u8; 32]],
            [5u8; 32],
            -500,
            vec![0u8; 256],
            &[authority, cosigner],
        )
        .expect("build transact instruction");

        assert_eq!(ix.program_id, program_id);
        // bridge_state, merkle_tree, bridge_vault, nullifier_0, nullifier_1,
        // recipient, validator_account, validator_registry, authority (signer),
        // system_program — then 2 quorum (wallet, PDA) pairs (#260).
        assert_eq!(ix.accounts.len(), 10 + 4);
        assert_eq!(ix.accounts[1].pubkey, derive_merkle_tree(&program_id).0);
        assert!(ix.accounts[1].is_writable);
        assert_eq!(
            ix.accounts[3].pubkey,
            derive_nullifier_account(&program_id, &[1u8; 32]).0
        );
        assert_eq!(
            ix.accounts[4].pubkey,
            derive_nullifier_account(&program_id, &[2u8; 32]).0
        );
        assert_eq!(ix.accounts[5].pubkey, Pubkey::new_from_array([9u8; 32]));
        // The settling validator's account is bound to the authority signer.
        assert_eq!(
            ix.accounts[6].pubkey,
            derive_validator_account(&program_id, &authority).0
        );
        assert_eq!(ix.accounts[8].pubkey, authority);
        assert!(ix.accounts[8].is_signer);
        // Quorum pairs: each wallet signs, its PDA does not.
        assert_eq!(ix.accounts[10].pubkey, authority);
        assert!(ix.accounts[10].is_signer);
        assert_eq!(ix.accounts[12].pubkey, cosigner);
        assert!(ix.accounts[12].is_signer);
        assert!(!ix.accounts[13].is_signer);

        assert_eq!(&ix.data[..8], &discriminators::TRANSACT);
    }

    /// Field ordering is observable on the wire — Anchor decodes borsh fields
    /// in declaration order. Pins the layout
    /// `[nullifiers (64) | output_commitments (64) | root (32) | ext_amount (8, i64 LE) | proof_len (4) | proof…]`
    /// including the two's-complement encoding of a negative `ext_amount`
    /// (a withdrawal), which a `u64` mix-up would corrupt silently.
    #[test]
    fn test_transact_instruction_data_field_order() {
        let payload = TransactInstructionData {
            nullifiers: [[0xAB; 32], [0xCD; 32]],
            output_commitments: [[0x11; 32], [0x22; 32]],
            root: [0x33; 32],
            ext_amount: -2,
            proof: vec![0xEF; 3],
        };
        let bytes = borsh::to_vec(&payload).expect("borsh serialize");
        let decoded = TransactInstructionData::try_from_slice(&bytes).expect("borsh deserialize");
        assert_eq!(decoded, payload);

        assert_eq!(&bytes[..32], &[0xAB; 32]);
        assert_eq!(&bytes[32..64], &[0xCD; 32]);
        assert_eq!(&bytes[64..96], &[0x11; 32]);
        assert_eq!(&bytes[96..128], &[0x22; 32]);
        assert_eq!(&bytes[128..160], &[0x33; 32]);
        // ext_amount = -2 as little-endian two's complement.
        assert_eq!(
            &bytes[160..168],
            &[0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        // proof: u32 length prefix then the bytes.
        assert_eq!(&bytes[168..172], &[3, 0, 0, 0]);
        assert_eq!(&bytes[172..], &[0xEF; 3]);
    }

    #[test]
    fn test_create_deposit_note_instruction() {
        let program_id = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let bridge_vault = Pubkey::new_unique();

        let ix = create_deposit_note_instruction(
            &program_id,
            &depositor,
            &bridge_vault,
            1_000_000,
            [7u8; 32],
            [8u8; 32],
        )
        .expect("build deposit_note instruction");

        // bridge_state, bridge_vault, merkle_tree, depositor (signer),
        // system_program.
        assert_eq!(ix.accounts.len(), 5);
        assert_eq!(ix.accounts[2].pubkey, derive_merkle_tree(&program_id).0);
        assert!(ix.accounts[2].is_writable);
        assert_eq!(ix.accounts[3].pubkey, depositor);
        assert!(ix.accounts[3].is_signer);

        assert_eq!(&ix.data[..8], &discriminators::DEPOSIT_NOTE);
        // amount immediately follows the discriminator (borsh u64 LE).
        assert_eq!(&ix.data[8..16], &1_000_000u64.to_le_bytes());
    }

    #[test]
    fn test_create_initialize_merkle_tree_instruction() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();

        let ix = create_initialize_merkle_tree_instruction(&program_id, &authority);

        // merkle_tree, authority (signer), program_data, system_program.
        assert_eq!(ix.accounts.len(), 4);
        assert_eq!(ix.accounts[0].pubkey, derive_merkle_tree(&program_id).0);
        assert_eq!(ix.accounts[1].pubkey, authority);
        assert!(ix.accounts[1].is_signer);
        assert_eq!(ix.accounts[2].pubkey, derive_program_data(&program_id).0);
        assert_eq!(ix.data, discriminators::INITIALIZE_MERKLE_TREE.to_vec());
    }
}
