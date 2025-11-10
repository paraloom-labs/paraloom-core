//! Solana program instruction builders
//!
//! Creates instructions for interacting with the Paraloom Solana program

use crate::bridge::{BridgeError, Result, SolanaAddress};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

// System program ID
const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

/// Instruction data for withdraw
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct WithdrawInstructionData {
    pub nullifier: [u8; 32],
    pub amount: u64,
    pub proof: Vec<u8>,
}

/// Instruction discriminators (matching Anchor's generated discriminators)
pub mod discriminators {
    pub const INITIALIZE: [u8; 8] = [175, 175, 109, 31, 13, 152, 155, 237];
    pub const DEPOSIT: [u8; 8] = [242, 35, 198, 137, 82, 225, 242, 182];
    pub const WITHDRAW: [u8; 8] = [183, 18, 70, 156, 148, 109, 161, 34];
    pub const UPDATE_MERKLE_ROOT: [u8; 8] = [240, 174, 252, 99, 208, 105, 45, 104];
    #[allow(dead_code)]
    pub const PAUSE: [u8; 8] = [139, 98, 119, 98, 22, 6, 120, 33];
    #[allow(dead_code)]
    pub const UNPAUSE: [u8; 8] = [111, 51, 238, 100, 208, 146, 57, 103];
}

/// Create initialize instruction
pub fn create_initialize_instruction(
    program_id: &Pubkey,
    authority: &Pubkey,
    initial_merkle_root: [u8; 32],
) -> Result<Instruction> {
    let (bridge_state_pda, _bump) = Pubkey::find_program_address(&[b"bridge_state"], program_id);

    #[derive(BorshSerialize)]
    struct InitializeData {
        initial_merkle_root: [u8; 32],
    }

    let data = InitializeData {
        initial_merkle_root,
    };

    let mut instruction_data = discriminators::INITIALIZE.to_vec();
    instruction_data.extend_from_slice(
        &borsh::to_vec(&data).map_err(|e| BridgeError::Serialization(e.to_string()))?,
    );

    let system_program_id = SYSTEM_PROGRAM_ID.parse().unwrap();

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(bridge_state_pda, false),
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(system_program_id, false),
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

    #[derive(BorshSerialize)]
    struct DepositData {
        amount: u64,
        recipient: [u8; 32],
        randomness: [u8; 32],
    }

    let data = DepositData {
        amount,
        recipient,
        randomness,
    };

    let mut instruction_data = discriminators::DEPOSIT.to_vec();
    instruction_data.extend_from_slice(
        &borsh::to_vec(&data).map_err(|e| BridgeError::Serialization(e.to_string()))?,
    );

    let system_program_id = SYSTEM_PROGRAM_ID.parse().unwrap();

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

/// Create withdraw instruction
pub fn create_withdraw_instruction(
    program_id: &Pubkey,
    authority: &Pubkey,
    bridge_vault: &Pubkey,
    recipient: SolanaAddress,
    nullifier: [u8; 32],
    amount: u64,
    proof: Vec<u8>,
) -> Result<Instruction> {
    let (bridge_state_pda, _bump) = Pubkey::find_program_address(&[b"bridge_state"], program_id);
    let (nullifier_pda, _nullifier_bump) = derive_nullifier_account(program_id, &nullifier);
    let recipient_pubkey = Pubkey::new_from_array(recipient);

    let data = WithdrawInstructionData {
        nullifier,
        amount,
        proof,
    };

    let mut instruction_data = discriminators::WITHDRAW.to_vec();
    instruction_data.extend_from_slice(
        &borsh::to_vec(&data).map_err(|e| BridgeError::Serialization(e.to_string()))?,
    );

    let system_program_id = SYSTEM_PROGRAM_ID.parse().unwrap();

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(bridge_state_pda, false),
            AccountMeta::new(*bridge_vault, false),
            AccountMeta::new(nullifier_pda, false), // Nullifier account (will be created)
            AccountMeta::new(recipient_pubkey, false),
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

/// Derive bridge vault PDA
pub fn derive_bridge_vault(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"bridge_vault"], program_id)
}

/// Derive bridge state PDA
pub fn derive_bridge_state(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"bridge_state"], program_id)
}

/// Derive nullifier account PDA
pub fn derive_nullifier_account(program_id: &Pubkey, nullifier: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"nullifier", nullifier.as_ref()], program_id)
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
            proof,
        );

        assert!(ix.is_ok());
        let instruction = ix.unwrap();
        assert_eq!(instruction.program_id, program_id);
        assert_eq!(instruction.accounts.len(), 6); // Updated: now includes nullifier account
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
}
