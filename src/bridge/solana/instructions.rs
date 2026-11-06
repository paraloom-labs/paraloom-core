use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

/// Instruction discriminators derived from Anchor `sha256("global:<fn_name>")[..8]`
pub const SLASH_VALIDATOR_DISCRIMINATOR: [u8; 8] = [238, 57, 244, 40, 132, 82, 78, 5];
pub const UPDATE_REPUTATION_DISCRIMINATOR: [u8; 8] = [194, 220, 43, 201, 54, 209, 49, 178];

/// Creates a `slash_validator` instruction adhering to Anchor positional account deserialization.
///
/// Positional layout matching Anchor `SlashValidator` struct:
/// 0. `validator_account` (writable)
/// 1. `slashed_funds_vault` (writable)
/// 2. `validator_registry` (writable)
/// 3. `stake_mint` (writable)
/// 4. `stake_token_vault` (writable)
/// 5. `stake_vault_authority` (readonly)
/// 6. `token_program` (readonly)
/// 7. `authority` (signer, writable)
pub fn create_slash_validator_instruction(
    program_id: &Pubkey,
    validator_account: &Pubkey,
    slashed_funds_vault: &Pubkey,
    validator_registry: &Pubkey,
    stake_mint: &Pubkey,
    stake_token_vault: &Pubkey,
    stake_vault_authority: &Pubkey,
    token_program: &Pubkey,
    authority: &Pubkey,
    validator: Pubkey,
    slash_percentage: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 32 + 1);
    data.extend_from_slice(&SLASH_VALIDATOR_DISCRIMINATOR);
    data.extend_from_slice(validator.as_ref());
    data.push(slash_percentage);

    let accounts = vec![
        AccountMeta::new(*validator_account, false),
        AccountMeta::new(*slashed_funds_vault, false),
        AccountMeta::new(*validator_registry, false),
        AccountMeta::new(*stake_mint, false),
        AccountMeta::new(*stake_token_vault, false),
        AccountMeta::new_readonly(*stake_vault_authority, false),
        AccountMeta::new_readonly(*token_program, false),
        AccountMeta::new(*authority, true),
    ];

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

/// Creates an `update_reputation` instruction adhering to Anchor positional account deserialization.
///
/// Positional layout matching Anchor `UpdateReputation` struct:
/// 0. `validator_account` (writable)
/// 1. `validator_registry` (writable)
/// 2. `authority` (signer, writable)
pub fn create_update_reputation_instruction(
    program_id: &Pubkey,
    validator_account: &Pubkey,
    validator_registry: &Pubkey,
    authority: &Pubkey,
    validator: Pubkey,
    new_reputation: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 32 + 8);
    data.extend_from_slice(&UPDATE_REPUTATION_DISCRIMINATOR);
    data.extend_from_slice(validator.as_ref());
    data.extend_from_slice(&new_reputation.to_le_bytes());

    let accounts = vec![
        AccountMeta::new(*validator_account, false),
        AccountMeta::new(*validator_registry, false),
        AccountMeta::new(*authority, true),
    ];

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slash_validator_instruction_accounts_and_discriminator() {
        let program_id = Pubkey::new_unique();
        let validator_account = Pubkey::new_unique();
        let slashed_funds_vault = Pubkey::new_unique();
        let validator_registry = Pubkey::new_unique();
        let stake_mint = Pubkey::new_unique();
        let stake_token_vault = Pubkey::new_unique();
        let stake_vault_authority = Pubkey::new_unique();
        let token_program = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let target_validator = Pubkey::new_unique();

        let ix = create_slash_validator_instruction(
            &program_id,
            &validator_account,
            &slashed_funds_vault,
            &validator_registry,
            &stake_mint,
            &stake_token_vault,
            &stake_vault_authority,
            &token_program,
            &authority,
            target_validator,
            50,
        );

        assert_eq!(&ix.data[..8], &SLASH_VALIDATOR_DISCRIMINATOR);
        assert_eq!(ix.data.len(), 8 + 32 + 1);
        assert_eq!(ix.data[8..40], target_validator.to_bytes());
        assert_eq!(ix.data[40], 50);

        assert_eq!(ix.accounts.len(), 8);
        assert_eq!(ix.accounts[0], AccountMeta::new(validator_account, false));
        assert_eq!(ix.accounts[1], AccountMeta::new(slashed_funds_vault, false));
        assert_eq!(ix.accounts[2], AccountMeta::new(validator_registry, false));
        assert_eq!(ix.accounts[3], AccountMeta::new(stake_mint, false));
        assert_eq!(ix.accounts[4], AccountMeta::new(stake_token_vault, false));
        assert_eq!(ix.accounts[5], AccountMeta::new_readonly(stake_vault_authority, false));
        assert_eq!(ix.accounts[6], AccountMeta::new_readonly(token_program, false));
        assert_eq!(ix.accounts[7], AccountMeta::new(authority, true));
    }

    #[test]
    fn test_update_reputation_instruction_accounts_and_discriminator() {
        let program_id = Pubkey::new_unique();
        let validator_account = Pubkey::new_unique();
        let validator_registry = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let target_validator = Pubkey::new_unique();

        let ix = create_update_reputation_instruction(
            &program_id,
            &validator_account,
            &validator_registry,
            &authority,
            target_validator,
            1000,
        );

        assert_eq!(&ix.data[..8], &UPDATE_REPUTATION_DISCRIMINATOR);
        assert_eq!(ix.data.len(), 8 + 32 + 8);
        assert_eq!(ix.data[8..40], target_validator.to_bytes());
        assert_eq!(&ix.data[40..48], &1000u64.to_le_bytes());

        assert_eq!(ix.accounts.len(), 3);
        assert_eq!(ix.accounts[0], AccountMeta::new(validator_account, false));
        assert_eq!(ix.accounts[1], AccountMeta::new(validator_registry, false));
        assert_eq!(ix.accounts[2], AccountMeta::new(authority, true));
    }
}
