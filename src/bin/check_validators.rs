use solana_client::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use std::str::FromStr;

/// `sha256("account:ValidatorRegistry")[..8]`.
const VALIDATOR_REGISTRY_DISC: [u8; 8] = [135, 198, 225, 159, 60, 129, 98, 43];
/// `sha256("account:ValidatorAccount")[..8]`.
const VALIDATOR_ACCOUNT_DISC: [u8; 8] = [32, 144, 229, 203, 9, 154, 158, 255];

fn is_valid_registry_account(owner: &Pubkey, data: &[u8], program_id: &Pubkey) -> bool {
    owner == program_id && data.len() >= 72 && data[0..8] == VALIDATOR_REGISTRY_DISC
}

fn decode_validator_summary(owner: &Pubkey, data: &[u8], program_id: &Pubkey) -> Option<(u64, bool)> {
    if owner != program_id || data.len() < 89 || data[0..8] != VALIDATOR_ACCOUNT_DISC {
        return None;
    }
    let stake = u64::from_le_bytes(data[40..48].try_into().ok()?);
    let is_active = data[88] != 0;
    Some((stake, is_active))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Checking Registered Validators on Devnet ===\n");

    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id_str = std::env::var("SOLANA_PROGRAM_ID")?;

    println!("RPC URL: {}", rpc_url);
    println!("Program ID: {}\n", program_id_str);

    let program_id = Pubkey::from_str(&program_id_str)?;
    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let (validator_registry_pda, _bump) =
        Pubkey::find_program_address(&[b"validator_registry"], &program_id);

    println!("Validator Registry PDA: {}\n", validator_registry_pda);

    let registry_account = client.get_account(&validator_registry_pda)?;
    if !is_valid_registry_account(&registry_account.owner, &registry_account.data, &program_id) {
        return Err(format!(
            "ValidatorRegistry PDA {} is not a valid initialized ValidatorRegistry (owner={}, len={})",
            validator_registry_pda,
            registry_account.owner,
            registry_account.data.len()
        )
        .into());
    }
    println!(
        "Registry Account Data Size: {} bytes",
        registry_account.data.len()
    );
    println!("Registry Account Owner: {}\n", registry_account.owner);

    let validator_addresses = [
        "ESL4rMBsmn3YcBu9GPRPiDoqFaRhuKvTKkbtJCiQxYr2",
        "4Q23Jt7ahSh9tsLUGQv8WaV7vxvjvb4WCuzfvSB1qRoJ",
        "TwujWZFm6KbP9PYiiY4Crv6AndtY3zyLdP5ZUDd8hdC",
    ];

    for (i, addr_str) in validator_addresses.iter().enumerate() {
        println!("Validator {} ({}):", i + 1, addr_str);
        let validator_pubkey = Pubkey::from_str(addr_str)?;

        let (validator_account_pda, _bump) =
            Pubkey::find_program_address(&[b"validator", validator_pubkey.as_ref()], &program_id);

        println!("  Validator Account PDA: {}", validator_account_pda);

        match client.get_account(&validator_account_pda) {
            Ok(account) => {
                let summary = decode_validator_summary(&account.owner, &account.data, &program_id);
                println!("  Account exists: Yes (initialized ValidatorAccount: {})", summary.is_some());
                println!("  Account data size: {} bytes", account.data.len());
                println!("  Account owner: {}", account.owner);
                println!("  Account balance: {} lamports", account.lamports);
                if let Some((stake, is_active)) = summary {
                    println!("  Validator stake: {} lamports (active: {})", stake, is_active);
                }
            }
            Err(e) => {
                println!("  Account exists: No");
                println!("  Error: {}", e);
            }
        }
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_validators_helpers_validate_owner_discriminator_and_length() {
        let program_id = Pubkey::new_unique();
        let other_owner = Pubkey::new_unique();

        let mut reg_data = vec![0u8; 72];
        reg_data[0..8].copy_from_slice(&VALIDATOR_REGISTRY_DISC);
        assert!(is_valid_registry_account(&program_id, &reg_data, &program_id));
        assert!(!is_valid_registry_account(&other_owner, &reg_data, &program_id));
        assert!(!is_valid_registry_account(&program_id, &reg_data[..71], &program_id));

        let mut val_data = vec![0u8; 89];
        val_data[0..8].copy_from_slice(&VALIDATOR_ACCOUNT_DISC);
        val_data[40..48].copy_from_slice(&2_000_000_000u64.to_le_bytes());
        val_data[88] = 1;
        assert_eq!(
            decode_validator_summary(&program_id, &val_data, &program_id),
            Some((2_000_000_000, true))
        );
        assert_eq!(decode_validator_summary(&other_owner, &val_data, &program_id), None);
        assert_eq!(decode_validator_summary(&program_id, &[], &program_id), None);
    }
}
