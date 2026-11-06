use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::pubkey::Pubkey;
use solana_program::sysvar;

/// Anchor instruction discriminators derived via `sha256("global:<name>")[..8]`
pub const INIT_ASSET_VAULT_DISCRIMINATOR: [u8; 8] = [178, 96, 79, 76, 25, 81, 167, 109];
pub const SET_ASSET_DEPOSIT_CAP_DISCRIMINATOR: [u8; 8] = [209, 129, 220, 235, 236, 193, 22, 135];
pub const SET_MIN_TOKEN_STAKE_DISCRIMINATOR: [u8; 8] = [13, 125, 2, 121, 78, 212, 10, 46];

/// Instruction builder for `init_asset_vault`.
/// Account layout matching Anchor struct `InitAssetVault`:
/// 1. authority (signer, writable)
/// 2. mint (readonly)
/// 3. asset_vault (writable)
/// 4. asset_vault_authority (readonly)
/// 5. asset_config (writable)
/// 6. program_data (readonly)
/// 7. token_program (readonly)
/// 8. system_program (readonly)
/// 9. rent (readonly)
pub fn create_init_asset_vault_instruction(
    program_id: Pubkey,
    authority: Pubkey,
    mint: Pubkey,
    asset_vault: Pubkey,
    asset_vault_authority: Pubkey,
    asset_config: Pubkey,
    program_data: Pubkey,
    token_program: Pubkey,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(authority, true),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new(asset_vault, false),
        AccountMeta::new_readonly(asset_vault_authority, false),
        AccountMeta::new(asset_config, false),
        AccountMeta::new_readonly(program_data, false),
        AccountMeta::new_readonly(token_program, false),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
    ];

    Instruction {
        program_id,
        accounts,
        data: INIT_ASSET_VAULT_DISCRIMINATOR.to_vec(),
    }
}

/// Instruction builder for `set_asset_deposit_cap`.
/// Account layout matching Anchor struct `SetAssetDepositCap`:
/// 1. asset_config (writable)
/// 2. authority (signer, writable)
/// 3. program_data (readonly)
pub fn create_set_asset_deposit_cap_instruction(
    program_id: Pubkey,
    asset_config: Pubkey,
    authority: Pubkey,
    program_data: Pubkey,
    new_cap: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&SET_ASSET_DEPOSIT_CAP_DISCRIMINATOR);
    data.extend_from_slice(&new_cap.to_le_bytes());

    let accounts = vec![
        AccountMeta::new(asset_config, false),
        AccountMeta::new(authority, true),
        AccountMeta::new_readonly(program_data, false),
    ];

    Instruction {
        program_id,
        accounts,
        data,
    }
}

/// Instruction builder for `set_min_token_stake`.
/// Account layout matching Anchor struct `SetMinTokenStake`:
/// 1. validator_registry (writable)
/// 2. authority (signer, writable)
pub fn create_set_min_token_stake_instruction(
    program_id: Pubkey,
    validator_registry: Pubkey,
    authority: Pubkey,
    min_stake: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&SET_MIN_TOKEN_STAKE_DISCRIMINATOR);
    data.extend_from_slice(&min_stake.to_le_bytes());

    let accounts = vec![
        AccountMeta::new(validator_registry, false),
        AccountMeta::new(authority, true),
    ];

    Instruction {
        program_id,
        accounts,
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn compute_anchor_discriminator(name: &str) -> [u8; 8] {
        let preimage = format!("global:{}", name);
        let mut hasher = Sha256::new();
        hasher.update(preimage.as_bytes());
        let result = hasher.finalize();
        let mut disc = [0u8; 8];
        disc.copy_from_slice(&result[..8]);
        disc
    }

    #[test]
    fn test_discriminators_match_anchor() {
        assert_eq!(
            SET_MIN_TOKEN_STAKE_DISCRIMINATOR,
            compute_anchor_discriminator("set_min_token_stake"),
            "SET_MIN_TOKEN_STAKE discriminator mismatch"
        );
        assert_eq!(
            INIT_ASSET_VAULT_DISCRIMINATOR,
            compute_anchor_discriminator("init_asset_vault"),
            "INIT_ASSET_VAULT discriminator mismatch"
        );
        assert_eq!(
            SET_ASSET_DEPOSIT_CAP_DISCRIMINATOR,
            compute_anchor_discriminator("set_asset_deposit_cap"),
            "SET_ASSET_DEPOSIT_CAP discriminator mismatch"
        );
    }

    #[test]
    fn test_init_asset_vault_account_layout() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let asset_vault = Pubkey::new_unique();
        let asset_vault_authority = Pubkey::new_unique();
        let asset_config = Pubkey::new_unique();
        let program_data = Pubkey::new_unique();
        let token_program = Pubkey::new_unique();

        let ix = create_init_asset_vault_instruction(
            program_id,
            authority,
            mint,
            asset_vault,
            asset_vault_authority,
            asset_config,
            program_data,
            token_program,
        );

        assert_eq!(ix.data[..8], compute_anchor_discriminator("init_asset_vault"));
        assert_eq!(ix.accounts.len(), 9);
        assert_eq!(ix.accounts[0], AccountMeta::new(authority, true));
        assert_eq!(ix.accounts[1], AccountMeta::new_readonly(mint, false));
        assert_eq!(ix.accounts[2], AccountMeta::new(asset_vault, false));
        assert_eq!(ix.accounts[3], AccountMeta::new_readonly(asset_vault_authority, false));
        assert_eq!(ix.accounts[4], AccountMeta::new(asset_config, false));
        assert_eq!(ix.accounts[5], AccountMeta::new_readonly(program_data, false));
        assert_eq!(ix.accounts[6], AccountMeta::new_readonly(token_program, false));
        assert_eq!(ix.accounts[7], AccountMeta::new_readonly(solana_program::system_program::id(), false));
        assert_eq!(ix.accounts[8], AccountMeta::new_readonly(sysvar::rent::id(), false));
    }

    #[test]
    fn test_set_asset_deposit_cap_account_layout() {
        let program_id = Pubkey::new_unique();
        let asset_config = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let program_data = Pubkey::new_unique();
        let cap = 5_000_000u64;

        let ix = create_set_asset_deposit_cap_instruction(
            program_id,
            asset_config,
            authority,
            program_data,
            cap,
        );

        assert_eq!(ix.data[..8], compute_anchor_discriminator("set_asset_deposit_cap"));
        assert_eq!(u64::from_le_bytes(ix.data[8..16].try_into().unwrap()), cap);
        assert_eq!(ix.accounts.len(), 3);
        assert_eq!(ix.accounts[0], AccountMeta::new(asset_config, false));
        assert_eq!(ix.accounts[1], AccountMeta::new(authority, true));
        assert_eq!(ix.accounts[2], AccountMeta::new_readonly(program_data, false));
    }

    #[test]
    fn test_set_min_token_stake_account_layout() {
        let program_id = Pubkey::new_unique();
        let validator_registry = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let stake = 10_000_000u64;

        let ix = create_set_min_token_stake_instruction(
            program_id,
            validator_registry,
            authority,
            stake,
        );

        assert_eq!(ix.data[..8], compute_anchor_discriminator("set_min_token_stake"));
        assert_eq!(u64::from_le_bytes(ix.data[8..16].try_into().unwrap()), stake);
        assert_eq!(ix.accounts.len(), 2);
        assert_eq!(ix.accounts[0], AccountMeta::new(validator_registry, false));
        assert_eq!(ix.accounts[1], AccountMeta::new(authority, true));
    }
}
