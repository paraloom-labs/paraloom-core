use solana_client::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use std::str::FromStr;

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
                println!("  Account exists: Yes");
                println!("  Account data size: {} bytes", account.data.len());
                println!("  Account owner: {}", account.owner);
                println!("  Account balance: {} lamports", account.lamports);
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
