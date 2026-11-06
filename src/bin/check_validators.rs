use solana_client::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use std::str::FromStr;

const VALIDATOR_REGISTRY_DISC: [u8; 8] = [135, 198, 225, 159, 60, 129, 98, 43];
const VALIDATOR_ACCOUNT_DISC: [u8; 8] = [32, 144, 229, 203, 9, 154, 158, 255];

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

    match client.get_account(&validator_registry_pda) {
        Ok(registry_account) => {
            println!(
                "Registry Account Data Size: {} bytes",
                registry_account.data.len()
            );
            println!("Registry Account Owner: {}", registry_account.owner);

            if registry_account.owner != program_id {
                println!(
                    "⚠️  Warning: Registry account owner ({}) does not match program ID ({})!",
                    registry_account.owner, program_id
                );
            } else if registry_account.data.len() < 72
                || registry_account.data[0..8] != VALIDATOR_REGISTRY_DISC
            {
                println!(
                    "⚠️  Warning: Registry account is not a valid ValidatorRegistry PDA (invalid length or discriminator)!"
                );
            } else {
                let total_validators =
                    u64::from_le_bytes(registry_account.data[40..48].try_into()?);
                let active_validators =
                    u64::from_le_bytes(registry_account.data[48..56].try_into()?);
                let minimum_stake = u64::from_le_bytes(registry_account.data[56..64].try_into()?);
                let total_active_stake =
                    u64::from_le_bytes(registry_account.data[64..72].try_into()?);
                println!("  Total Validators: {}", total_validators);
                println!("  Active Validators: {}", active_validators);
                println!("  Minimum Stake: {} lamports", minimum_stake);
                println!("  Total Active Stake: {} lamports", total_active_stake);
            }
        }
        Err(e) => {
            println!("Failed to load Validator Registry: {}", e);
        }
    }
    println!();

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
                println!("  Account exists: Yes");
                println!("  Account data size: {} bytes", account.data.len());
                println!("  Account owner: {}", account.owner);
                println!("  Account balance: {} lamports", account.lamports);

                if account.owner != program_id {
                    println!(
                        "  Status: Uninitialized (owned by {}, not program)",
                        account.owner
                    );
                } else if account.data.len() < 89 || account.data[0..8] != VALIDATOR_ACCOUNT_DISC {
                    println!("  Status: Invalid (bad discriminator or length < 89)");
                } else {
                    let stake_amount = u64::from_le_bytes(account.data[40..48].try_into()?);
                    let reputation_score = u64::from_le_bytes(account.data[48..56].try_into()?);
                    let is_active = account.data[88] != 0;
                    println!("  Registered: Yes");
                    println!("  Is Active: {}", is_active);
                    println!("  Stake Amount: {} lamports", stake_amount);
                    println!("  Reputation Score: {}", reputation_score);
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
