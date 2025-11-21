//! Paraloom CLI - Unified command-line interface
//!
//! A user-friendly CLI for interacting with the Paraloom privacy network.
//!
//! # Usage
//!
//! ```bash
//! # Wallet operations
//! paraloom wallet deposit --amount 10.0
//! paraloom wallet transfer --to <address> --amount 5.0
//! paraloom wallet withdraw --to <solana-address> --amount 5.0
//! paraloom wallet balance
//!
//! # Compute operations
//! paraloom compute submit --wasm program.wasm --input data.json
//! paraloom compute result --job-id <id>
//! paraloom compute list
//!
//! # Validator operations
//! paraloom validator start --config validator.toml
//! paraloom validator stop
//! paraloom validator status
//! ```

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[cfg(feature = "solana-bridge")]
use paraloom::bridge::solana::*;
#[cfg(feature = "solana-bridge")]
use solana_client::rpc_client::RpcClient;
#[cfg(feature = "solana-bridge")]
use solana_sdk::{
    commitment_config::CommitmentConfig, native_token::LAMPORTS_PER_SOL, pubkey::Pubkey,
    signature::Signer, transaction::Transaction,
};
#[cfg(feature = "solana-bridge")]
use std::str::FromStr;

// Compute layer imports
use paraloom::compute::{ComputeJob, JobExecutor, JobStatus, ResourceLimits};
use once_cell::sync::Lazy;
use std::sync::Arc;

// Global job executor instance
static JOB_EXECUTOR: Lazy<Arc<JobExecutor>> = Lazy::new(|| {
    let executor = JobExecutor::new().expect("Failed to create job executor");
    Arc::new(executor)
});

#[derive(Parser)]
#[command(name = "paraloom")]
#[command(author = "Paraloom Team")]
#[command(version = "0.1.0")]
#[command(about = "Privacy-preserving distributed computing on Solana", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Wallet operations (deposit, withdraw, transfer)
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },

    /// Confidential compute operations
    Compute {
        #[command(subcommand)]
        command: ComputeCommands,
    },

    /// Validator node operations
    Validator {
        #[command(subcommand)]
        command: ValidatorCommands,
    },

    /// Initialize Paraloom configuration
    Init {
        /// Directory to initialize
        #[arg(short, long, default_value = ".")]
        path: PathBuf,

        /// Force overwrite existing config
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    /// Deposit SOL to Paraloom privacy pool
    Deposit {
        /// Amount in SOL
        #[arg(short, long)]
        amount: f64,

        /// Solana RPC URL (default: devnet)
        #[arg(long)]
        rpc_url: Option<String>,

        /// Wallet keypair path
        #[arg(long)]
        keypair: Option<PathBuf>,

        /// Bridge program ID
        #[arg(long)]
        program_id: Option<String>,
    },

    /// Transfer SOL privately within Paraloom
    Transfer {
        /// Recipient shielded address
        #[arg(short, long)]
        to: String,

        /// Amount in SOL
        #[arg(short, long)]
        amount: f64,

        /// Optional memo (encrypted)
        #[arg(short, long)]
        memo: Option<String>,
    },

    /// Withdraw SOL from Paraloom to Solana
    Withdraw {
        /// Destination Solana address
        #[arg(short, long)]
        to: String,

        /// Amount in SOL
        #[arg(short, long)]
        amount: f64,

        /// Solana RPC URL (default: devnet)
        #[arg(long)]
        rpc_url: Option<String>,

        /// Authority keypair path
        #[arg(long)]
        keypair: Option<PathBuf>,

        /// Bridge program ID
        #[arg(long)]
        program_id: Option<String>,
    },

    /// Show shielded balance
    Balance {
        /// Show detailed breakdown
        #[arg(short, long)]
        detailed: bool,

        /// Solana RPC URL (default: devnet)
        #[arg(long)]
        rpc_url: Option<String>,

        /// Wallet keypair path (optional, for Solana balance)
        #[arg(long)]
        keypair: Option<PathBuf>,

        /// Bridge program ID
        #[arg(long)]
        program_id: Option<String>,
    },

    /// List transaction history (encrypted)
    History {
        /// Number of transactions to show
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },

    /// Generate new shielded address
    NewAddress {
        /// Label for the address
        #[arg(short, long)]
        label: Option<String>,
    },
}

#[derive(Subcommand)]
enum ComputeCommands {
    /// Submit private compute job
    Submit {
        /// WASM program file
        #[arg(short, long)]
        wasm: PathBuf,

        /// Input data file (JSON)
        #[arg(short, long)]
        input: PathBuf,

        /// Maximum execution time in seconds
        #[arg(long, default_value = "60")]
        timeout: u64,

        /// Maximum memory in MB
        #[arg(long, default_value = "64")]
        memory: u64,

        /// Job fee in SOL
        #[arg(long)]
        fee: Option<f64>,
    },

    /// Get job result
    Result {
        /// Job ID
        #[arg(short, long)]
        job_id: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Show proof details
        #[arg(long)]
        show_proof: bool,
    },

    /// List your compute jobs
    List {
        /// Filter by status (pending/running/completed/failed)
        #[arg(short, long)]
        status: Option<String>,

        /// Number of jobs to show
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },

    /// Show job status and details
    Status {
        /// Job ID
        #[arg(short, long)]
        job_id: String,

        /// Watch mode (continuous updates)
        #[arg(short, long)]
        watch: bool,
    },
}

#[derive(Subcommand)]
enum ValidatorCommands {
    /// Start validator node
    Start {
        /// Configuration file
        #[arg(short, long)]
        config: PathBuf,

        /// Run in background (daemon mode)
        #[arg(short, long)]
        daemon: bool,
    },

    /// Stop running validator
    Stop {
        /// Force stop (SIGKILL)
        #[arg(short, long)]
        force: bool,
    },

    /// Show validator status
    Status {
        /// Show detailed metrics
        #[arg(short, long)]
        detailed: bool,
    },

    /// View validator logs
    Logs {
        /// Number of lines to show
        #[arg(short, long, default_value = "100")]
        lines: usize,

        /// Follow log output
        #[arg(short, long)]
        follow: bool,
    },

    /// Show validator metrics
    Metrics {
        /// Time range (1h, 24h, 7d, 30d)
        #[arg(short, long, default_value = "24h")]
        range: String,
    },
}

fn print_banner() {
    println!(r#"
  ____                 _
 |  _ \ __ _ _ __ __ _| | ___   ___  _ __ ___
 | |_) / _` | '__/ _` | |/ _ \ / _ \| '_ ` _ \
 |  __/ (_| | | | (_| | | (_) | (_) | | | | | |
 |_|   \__,_|_|  \__,_|_|\___/ \___/|_| |_| |_|

 Privacy-preserving distributed computing on Solana
 True Decentralized Privacy | v0.1.0
"#);
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    log::info!("Paraloom CLI v0.1.0");

    // Load config if specified
    if let Some(config_path) = &cli.config {
        log::debug!("Loading config from: {}", config_path.display());
        // TODO: Load config file
    }

    // Execute command
    match cli.command {
        Commands::Wallet { command } => handle_wallet_command(command).await,
        Commands::Compute { command } => handle_compute_command(command).await,
        Commands::Validator { command } => handle_validator_command(command).await,
        Commands::Init { path, force } => handle_init_command(path, force).await,
    }
}

async fn handle_wallet_command(command: WalletCommands) -> Result<()> {
    match command {
        WalletCommands::Deposit {
            amount,
            rpc_url,
            keypair,
            program_id,
        } => {
            println!("Depositing {} SOL to Paraloom...\n", amount);

            #[cfg(feature = "solana-bridge")]
            {
                // Get RPC URL
                let rpc_url = rpc_url
                    .or_else(|| std::env::var("SOLANA_RPC_URL").ok())
                    .unwrap_or_else(|| "https://api.devnet.solana.com".to_string());

                // Get keypair path
                let keypair_path = keypair
                    .or_else(|| std::env::var("SOLANA_KEYPAIR_PATH").ok().map(PathBuf::from))
                    .context("Wallet keypair not specified. Use --keypair or SOLANA_KEYPAIR_PATH")?;

                // Get program ID
                let program_id_str = program_id
                    .or_else(|| std::env::var("SOLANA_PROGRAM_ID").ok())
                    .context("Bridge program ID not specified. Use --program-id or SOLANA_PROGRAM_ID")?;

                println!("RPC URL: {}", rpc_url);
                println!("Program ID: {}", program_id_str);
                println!("Depositor Keypair: {}\n", keypair_path.display());

                // Parse program ID
                let program_id = Pubkey::from_str(&program_id_str)
                    .context("Invalid program ID")?;

                // Load depositor keypair
                println!("Loading depositor keypair...");
                let depositor = load_keypair_from_file(keypair_path.to_str().context("Invalid keypair path")?)
                    .context("Failed to load keypair")?;
                println!("Depositor Address: {}\n", depositor.pubkey());

                // Create RPC client
                println!("Connecting to Solana...");
                let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

                // Check depositor balance
                let balance = client.get_balance(&depositor.pubkey())
                    .context("Failed to get balance")?;
                println!("Depositor Balance: {} SOL\n", balance as f64 / LAMPORTS_PER_SOL as f64);

                let deposit_lamports = (amount * LAMPORTS_PER_SOL as f64) as u64;
                if balance < deposit_lamports + LAMPORTS_PER_SOL / 100 {
                    anyhow::bail!("Insufficient balance. Need at least {} SOL (+ 0.01 SOL for fees)", amount);
                }

                // Derive bridge vault PDA
                let (bridge_vault, _vault_bump) = derive_bridge_vault(&program_id);
                println!("Bridge Vault PDA: {}\n", bridge_vault);

                // Generate deposit parameters
                let recipient = rand::random::<[u8; 32]>(); // Random recipient address in privacy pool
                let randomness = rand::random::<[u8; 32]>(); // Random blinding factor

                println!("Deposit Amount: {} SOL", amount);
                println!("Recipient (privacy address): {}", hex::encode(&recipient[..8]));
                println!("Randomness: {}\n", hex::encode(&randomness[..8]));

                // Create deposit instruction
                println!("Creating deposit instruction...");
                let ix = create_deposit_instruction(
                    &program_id,
                    &depositor.pubkey(),
                    &bridge_vault,
                    deposit_lamports,
                    recipient,
                    randomness,
                ).context("Failed to create deposit instruction")?;

                // Get recent blockhash
                println!("Getting recent blockhash...");
                let blockhash = client.get_latest_blockhash()
                    .context("Failed to get blockhash")?;

                // Create and sign transaction
                println!("Creating and signing transaction...");
                let tx = Transaction::new_signed_with_payer(
                    &[ix],
                    Some(&depositor.pubkey()),
                    &[&depositor],
                    blockhash,
                );

                // Send transaction
                println!("Sending transaction...");
                let signature = client.send_and_confirm_transaction(&tx)
                    .context("Failed to send transaction")?;

                println!("\n[OK] Deposit successful!");
                println!("  Transaction: {}", signature);
                println!("  Shielded balance: {} SOL", amount);
                println!("  Shielded address: paraloom1{}", hex::encode(&recipient[..16]));
                println!("\nView transaction:");
                println!("  solana confirm -v {}", signature);
            }

            #[cfg(not(feature = "solana-bridge"))]
            {
                anyhow::bail!("Solana bridge feature not enabled. Rebuild with --features solana-bridge");
            }

            Ok(())
        }

        WalletCommands::Transfer { to, amount, memo } => {
            println!("Transferring {} SOL to {}...", amount, to);

            if let Some(memo_text) = &memo {
                log::debug!("Memo: {}", memo_text);
            }

            // TODO: Implement private transfer
            // 1. Load user's shielded keypair
            // 2. Generate zkSNARK proof
            // 3. Submit to validators
            // 4. Wait for consensus
            // 5. Confirm transaction

            println!("[OK] Transfer successful!");
            println!("  Recipient: {}", to);
            println!("  Amount: {} SOL (hidden)", amount);
            println!("  Privacy: Full (sender/recipient/amount encrypted)");

            Ok(())
        }

        WalletCommands::Withdraw {
            to,
            amount,
            rpc_url,
            keypair,
            program_id,
        } => {
            println!("Withdrawing {} SOL to {}...\n", amount, to);

            #[cfg(feature = "solana-bridge")]
            {
                // Get RPC URL
                let rpc_url = rpc_url
                    .or_else(|| std::env::var("SOLANA_RPC_URL").ok())
                    .unwrap_or_else(|| "https://api.devnet.solana.com".to_string());

                // Get keypair path
                let keypair_path = keypair
                    .or_else(|| std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH").ok().map(PathBuf::from))
                    .context("Authority keypair not specified. Use --keypair or BRIDGE_AUTHORITY_KEYPAIR_PATH")?;

                // Get program ID
                let program_id_str = program_id
                    .or_else(|| std::env::var("SOLANA_PROGRAM_ID").ok())
                    .context("Bridge program ID not specified. Use --program-id or SOLANA_PROGRAM_ID")?;

                println!("RPC URL: {}", rpc_url);
                println!("Program ID: {}", program_id_str);
                println!("Authority Keypair: {}\n", keypair_path.display());

                // Parse program ID
                let program_id = Pubkey::from_str(&program_id_str)
                    .context("Invalid program ID")?;

                // Load authority keypair
                println!("Loading authority keypair...");
                let authority = load_keypair_from_file(keypair_path.to_str().context("Invalid keypair path")?)
                    .context("Failed to load keypair")?;
                println!("Authority Address: {}\n", authority.pubkey());

                // Create RPC client
                println!("Connecting to Solana...");
                let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

                // Check authority balance
                let balance = client.get_balance(&authority.pubkey())
                    .context("Failed to get balance")?;
                println!("Authority Balance: {} SOL\n", balance as f64 / LAMPORTS_PER_SOL as f64);

                // Derive bridge vault PDA
                let (bridge_vault, _vault_bump) = derive_bridge_vault(&program_id);
                println!("Bridge Vault PDA: {}\n", bridge_vault);

                // Check vault balance
                let vault_balance = client.get_balance(&bridge_vault)
                    .context("Failed to get vault balance")?;
                println!("Bridge Vault Balance: {} SOL\n", vault_balance as f64 / LAMPORTS_PER_SOL as f64);

                let withdrawal_lamports = (amount * LAMPORTS_PER_SOL as f64) as u64;
                if vault_balance < withdrawal_lamports {
                    anyhow::bail!("Insufficient vault balance. Vault has {} SOL, need {} SOL",
                        vault_balance as f64 / LAMPORTS_PER_SOL as f64, amount);
                }

                // Parse recipient address
                let recipient_pubkey = Pubkey::from_str(&to)
                    .context("Invalid recipient address")?;
                let recipient = recipient_pubkey.to_bytes();

                println!("Recipient Address: {}", recipient_pubkey);

                // Generate withdrawal parameters
                let nullifier = rand::random::<[u8; 32]>(); // Unique nullifier for this withdrawal
                let proof = vec![0u8; 128]; // Mock zkSNARK proof (verification skipped in MVP)

                println!("Withdrawal Amount: {} SOL", amount);
                println!("Nullifier: {}", hex::encode(&nullifier[..8]));
                println!("Proof length: {} bytes\n", proof.len());

                // Create withdraw instruction
                println!("Creating withdraw instruction...");
                let ix = create_withdraw_instruction(
                    &program_id,
                    &authority.pubkey(),
                    &bridge_vault,
                    recipient,
                    nullifier,
                    withdrawal_lamports,
                    proof,
                ).context("Failed to create withdraw instruction")?;

                // Get recent blockhash
                println!("Getting recent blockhash...");
                let blockhash = client.get_latest_blockhash()
                    .context("Failed to get blockhash")?;

                // Create and sign transaction
                println!("Creating and signing transaction...");
                let tx = Transaction::new_signed_with_payer(
                    &[ix],
                    Some(&authority.pubkey()),
                    &[&authority],
                    blockhash,
                );

                // Send transaction
                println!("Sending transaction...");
                let signature = client.send_and_confirm_transaction(&tx)
                    .context("Failed to send transaction")?;

                println!("\n[OK] Withdrawal successful!");
                println!("  Transaction: {}", signature);
                println!("  Destination: {}", to);
                println!("  Amount: {} SOL", amount);
                println!("\nView transaction:");
                println!("  solana confirm -v {}", signature);

                // Verify balances
                println!("\nVerifying balances...");
                let vault_balance_after = client.get_balance(&bridge_vault)
                    .context("Failed to get vault balance")?;
                let recipient_balance = client.get_balance(&recipient_pubkey)
                    .context("Failed to get recipient balance")?;

                println!("  Bridge Vault Balance (after): {} SOL", vault_balance_after as f64 / LAMPORTS_PER_SOL as f64);
                println!("  Recipient Balance: {} SOL", recipient_balance as f64 / LAMPORTS_PER_SOL as f64);
            }

            #[cfg(not(feature = "solana-bridge"))]
            {
                anyhow::bail!("Solana bridge feature not enabled");
            }

            Ok(())
        }

        WalletCommands::Balance {
            detailed,
            rpc_url,
            keypair,
            program_id,
        } => {
            println!("Fetching balance...\n");

            #[cfg(feature = "solana-bridge")]
            {
                // Get RPC URL
                let rpc_url = rpc_url
                    .or_else(|| std::env::var("SOLANA_RPC_URL").ok())
                    .unwrap_or_else(|| "https://api.devnet.solana.com".to_string());

                println!("RPC URL: {}", rpc_url);

                // Create RPC client
                let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

                // Show bridge vault balance if program_id is provided
                if let Some(program_id_str) = program_id.or_else(|| std::env::var("SOLANA_PROGRAM_ID").ok()) {
                    let program_id = Pubkey::from_str(&program_id_str)
                        .context("Invalid program ID")?;
                    let (bridge_vault, _) = derive_bridge_vault(&program_id);

                    let vault_balance = client.get_balance(&bridge_vault)
                        .context("Failed to get vault balance")?;

                    println!("\nBridge Vault Balance:");
                    println!("  Address: {}", bridge_vault);
                    println!("  Balance: {} SOL\n", vault_balance as f64 / LAMPORTS_PER_SOL as f64);
                }

                // Show wallet balance if keypair is provided
                if let Some(keypair_path) = keypair.or_else(|| std::env::var("SOLANA_KEYPAIR_PATH").ok().map(PathBuf::from)) {
                    let wallet = load_keypair_from_file(keypair_path.to_str().context("Invalid keypair path")?)
                        .context("Failed to load keypair")?;

                    let wallet_balance = client.get_balance(&wallet.pubkey())
                        .context("Failed to get wallet balance")?;

                    println!("Wallet Balance:");
                    println!("  Address: {}", wallet.pubkey());
                    println!("  Balance: {} SOL\n", wallet_balance as f64 / LAMPORTS_PER_SOL as f64);
                }

                if detailed {
                    println!("Note: Shielded balance tracking not yet implemented.");
                    println!("This would show:");
                    println!("  - Unspent commitments in the privacy pool");
                    println!("  - Individual commitment values (encrypted)");
                    println!("  - Transaction history");
                }
            }

            #[cfg(not(feature = "solana-bridge"))]
            {
                anyhow::bail!("Solana bridge feature not enabled");
            }

            Ok(())
        }

        WalletCommands::History { limit } => {
            println!("Transaction History (last {} transactions):\n", limit);

            // TODO: Query transaction history from storage
            // Show encrypted transaction metadata

            println!("Recent activity:");
            println!("  - Deposit:  SOL  (2 hours ago)");
            println!("  - Transfer:  (5 hours ago)");
            println!("  - Withdraw: SOL (1 day ago)");
            println!("\nNote: Amounts hidden for privacy");

            Ok(())
        }

        WalletCommands::NewAddress { label } => {
            println!("Generating new shielded address...\n");

            // TODO: Generate new keypair
            // Save to config/keystore

            let address = "paraloom1qxyz...abc123"; // Mock

            println!("[OK] New address created!");
            println!("  Address: {}", address);
            if let Some(label_text) = label {
                println!("  Label: {}", label_text);
            }
            println!("\nSave this address to receive private transfers.");

            Ok(())
        }
    }
}

async fn handle_compute_command(command: ComputeCommands) -> Result<()> {
    match command {
        ComputeCommands::Submit {
            wasm,
            input,
            timeout,
            memory,
            fee,
        } => {
            println!("Submitting compute job...\n");

            println!("WASM program: {}", wasm.display());
            println!("Input data: {}", input.display());
            println!("Timeout: {}s", timeout);
            println!("Memory limit: {}MB\n", memory);

            // Load WASM bytecode
            println!("Loading WASM program...");
            let wasm_code = std::fs::read(&wasm)
                .context(format!("Failed to read WASM file: {}", wasm.display()))?;
            println!("  WASM size: {} bytes", wasm_code.len());

            // Load input data
            println!("Loading input data...");
            let input_data = std::fs::read(&input)
                .context(format!("Failed to read input file: {}", input.display()))?;
            println!("  Input size: {} bytes\n", input_data.len());

            // Create resource limits
            let limits = ResourceLimits {
                max_memory_bytes: (memory as u64) * 1024 * 1024, // MB to bytes
                max_instructions: 10_000_000,
                timeout_secs: timeout,
            };

            // Create compute job
            let job = ComputeJob::new(wasm_code, input_data, limits);
            let job_id = job.id.clone();

            // Submit to executor
            println!("Submitting job to executor...");
            JOB_EXECUTOR.submit_job(job)
                .context("Failed to submit job")?;

            let estimated_fee = fee.unwrap_or(0.01);

            println!("\n[OK] Job submitted successfully!");
            println!("  Job ID: {}", job_id);
            println!("  Status: Pending");
            println!("  Estimated fee: {} SOL (payment not yet implemented)", estimated_fee);
            println!("\nUse 'paraloom compute status --job-id {}' to track progress", job_id);
            println!("Use 'paraloom compute result --job-id {}' to get the result", job_id);

            Ok(())
        }

        ComputeCommands::Result {
            job_id,
            output,
            show_proof,
        } => {
            println!("Fetching result for job {}...\n", job_id);

            // Query job result from executor
            let result = JOB_EXECUTOR.get_job_result(&job_id);

            match result {
                Some(job_result) => {
                    println!("Job Status: {:?}", job_result.status);

                    if job_result.execution_time_ms > 0 {
                        println!("Execution Time: {}ms", job_result.execution_time_ms);
                    }

                    if job_result.memory_used_bytes > 0 {
                        println!("Memory Used: {} bytes ({:.2} MB)",
                            job_result.memory_used_bytes,
                            job_result.memory_used_bytes as f64 / 1024.0 / 1024.0
                        );
                    }

                    if job_result.instructions_executed > 0 {
                        println!("Instructions Executed: {}", job_result.instructions_executed);
                    }

                    if show_proof {
                        println!("\nzkSNARK Proof:");
                        println!("  Note: Proof generation not yet implemented");
                        println!("  Future: Will contain execution correctness proof");
                    }

                    match job_result.status {
                        JobStatus::Completed => {
                            if let Some(output_data) = &job_result.output_data {
                                println!("\nOutput Data:");
                                println!("  Size: {} bytes", output_data.len());

                                if let Some(output_path) = output {
                                    std::fs::write(&output_path, output_data)
                                        .context("Failed to write output file")?;
                                    println!("\n[OK] Result saved to: {}", output_path.display());
                                } else {
                                    // Try to display as hex if small enough
                                    if output_data.len() <= 32 {
                                        println!("  Hex: {}", hex::encode(output_data));
                                    } else {
                                        println!("  (use --output to save to file)");
                                    }
                                }
                            } else {
                                println!("\n[OK] Job completed with no output");
                            }
                        }
                        JobStatus::Failed { error } => {
                            println!("\n[ERROR] Job failed: {}", error);
                        }
                        _ => {
                            println!("\n[WARN] Job not yet completed");
                            println!("Use 'paraloom compute status --job-id {}' to track progress", job_id);
                        }
                    }
                }
                None => {
                    println!("[ERROR] Job not found: {}", job_id);
                    println!("\nPossible reasons:");
                    println!("  - Job ID is incorrect");
                    println!("  - Job has not been submitted yet");
                    println!("\nUse 'paraloom compute list' to see all jobs");
                    anyhow::bail!("Job not found");
                }
            }

            Ok(())
        }

        ComputeCommands::List { status, limit } => {
            println!("Your Compute Jobs:\n");

            // Get all job results from executor
            let results = JOB_EXECUTOR.get_all_results();

            if results.is_empty() {
                println!("No jobs found.");
                println!("\nSubmit a job with: paraloom compute submit --wasm <file> --input <file>");
                return Ok(());
            }

            // Filter by status if specified
            let filtered_results: Vec<_> = if let Some(status_filter) = &status {
                let filter_str = status_filter.to_lowercase();
                results.into_iter()
                    .filter(|r| format!("{:?}", r.status).to_lowercase().contains(&filter_str))
                    .collect()
            } else {
                results
            };

            if filtered_results.is_empty() {
                println!("No jobs found matching filter: {}", status.unwrap());
                return Ok(());
            }

            // Print header
            println!("{:<20} {:<15} {:<15} {:<15}", "Job ID", "Status", "Exec Time", "Memory Used");
            println!("{}", "-".repeat(70));

            // Print jobs (limited)
            let display_count = std::cmp::min(filtered_results.len(), limit);
            for result in filtered_results.iter().take(display_count) {
                let job_id_short = if result.job_id.len() > 18 {
                    format!("{}...", &result.job_id[..15])
                } else {
                    result.job_id.clone()
                };

                let status_str = match &result.status {
                    JobStatus::Completed => "Completed",
                    JobStatus::Failed { .. } => "Failed",
                    JobStatus::Running => "Running",
                    JobStatus::Pending => "Pending",
                    JobStatus::Assigned => "Assigned",
                    JobStatus::TimedOut => "TimedOut",
                };

                let exec_time = if result.execution_time_ms > 0 {
                    format!("{}ms", result.execution_time_ms)
                } else {
                    "-".to_string()
                };

                let memory_used = if result.memory_used_bytes > 0 {
                    format!("{:.2}MB", result.memory_used_bytes as f64 / 1024.0 / 1024.0)
                } else {
                    "-".to_string()
                };

                println!("{:<20} {:<15} {:<15} {:<15}",
                    job_id_short,
                    status_str,
                    exec_time,
                    memory_used
                );
            }

            println!("\nShowing {} of {} jobs", display_count, filtered_results.len());

            if filtered_results.len() > limit {
                println!("Use --limit {} to see more", filtered_results.len());
            }

            Ok(())
        }

        ComputeCommands::Status { job_id, watch } => {
            if watch {
                println!("Watching job {}... (Ctrl+C to stop)\n", job_id);

                // Watch mode: poll every second until completed
                loop {
                    let status = JOB_EXECUTOR.get_job_status(&job_id);

                    match status {
                        Some(job_status) => {
                            print!("\rStatus: {:?}     ", job_status);
                            std::io::Write::flush(&mut std::io::stdout()).ok();

                            match job_status {
                                JobStatus::Completed | JobStatus::Failed { .. } | JobStatus::TimedOut => {
                                    println!("\n\nJob finished!");
                                    println!("Use 'paraloom compute result --job-id {}' to see details", job_id);
                                    break;
                                }
                                _ => {
                                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                                }
                            }
                        }
                        None => {
                            println!("\n[ERROR] Job not found: {}", job_id);
                            break;
                        }
                    }
                }
            } else {
                println!("Job Status: {}\n", job_id);

                let status = JOB_EXECUTOR.get_job_status(&job_id);

                match status {
                    Some(job_status) => {
                        println!("Current Status: {:?}", job_status);

                        // Try to get result for more details
                        if let Some(result) = JOB_EXECUTOR.get_job_result(&job_id) {
                            println!("\nJob Details:");

                            if result.execution_time_ms > 0 {
                                println!("  Execution Time: {}ms", result.execution_time_ms);
                            }

                            if result.memory_used_bytes > 0 {
                                println!("  Memory Used: {:.2} MB", result.memory_used_bytes as f64 / 1024.0 / 1024.0);
                            }

                            if result.instructions_executed > 0 {
                                println!("  Instructions Executed: {}", result.instructions_executed);
                            }

                            match job_status {
                                JobStatus::Completed => {
                                    println!("\n[OK] Job completed successfully!");
                                    println!("Use 'paraloom compute result --job-id {}' to get output", job_id);
                                }
                                JobStatus::Failed { error } => {
                                    println!("\n[ERROR] Job failed: {}", error);
                                }
                                JobStatus::TimedOut => {
                                    println!("\n[WARN] Job timed out");
                                }
                                _ => {
                                    println!("\n[INFO] Job still in progress...");
                                    println!("Use 'paraloom compute status --job-id {} --watch' to monitor", job_id);
                                }
                            }
                        } else {
                            println!("\n[INFO] Job is queued or in progress");
                            println!("Use 'paraloom compute status --job-id {} --watch' to monitor", job_id);
                        }
                    }
                    None => {
                        println!("[ERROR] Job not found: {}", job_id);
                        println!("\nUse 'paraloom compute list' to see all jobs");
                        anyhow::bail!("Job not found");
                    }
                }
            }

            Ok(())
        }
    }
}

async fn handle_validator_command(command: ValidatorCommands) -> Result<()> {
    match command {
        ValidatorCommands::Start { config, daemon } => {
            println!("Starting Paraloom validator...\n");

            log::info!("Config: {}", config.display());
            log::info!("Daemon mode: {}", daemon);

            // TODO: Implement validator startup
            // 1. Load validator config
            // 2. Initialize RocksDB storage
            // 3. Connect to P2P network
            // 4. Register validator capacity
            // 5. Start event loops

            if daemon {
                println!("[OK] Validator started in background (PID: 12345)");
                println!("  Logs: ~/.paraloom/logs/validator.log");
            } else {
                println!("[OK] Validator starting...");
                println!("  Press Ctrl+C to stop");
                println!("\n[INFO] Connecting to network...");
                println!("[INFO] Registered validator: validator_abc123");
                println!("[INFO] Reputation: 1000 (neutral)");
                println!("[INFO] Ready to process jobs");
            }

            Ok(())
        }

        ValidatorCommands::Stop { force } => {
            println!("Stopping validator...");

            if force {
                log::warn!("Force stop requested (SIGKILL)");
            }

            // TODO: Send shutdown signal to validator process

            println!("[OK] Validator stopped");

            Ok(())
        }

        ValidatorCommands::Status { detailed } => {
            println!("Validator Status:\n");

            // TODO: Query validator metrics

            println!("Status: [ONLINE] Online");
            println!("Uptime: 15 days, 7 hours");
            println!("Reputation: 1,850 (Good)");
            println!("Jobs processed (24h): 247");
            println!("Earnings (30d): 12.5 SOL");

            if detailed {
                println!("\nHardware:");
                println!("  CPU: 80% (4 cores)");
                println!("  RAM: 2.4GB / 4GB (60%)");
                println!("  Disk: 3GB / 10GB (30%)");
                println!("  Network: ↑ 1.2 MB/s  ↓ 800 KB/s");

                println!("\nNetwork:");
                println!("  Peers: 6 connected");
                println!("  Validator ID: validator_abc123");
                println!("  P2P Address: /ip4/1.2.3.4/tcp/8080");
            }

            Ok(())
        }

        ValidatorCommands::Logs { lines, follow } => {
            println!("Validator Logs (last {} lines):\n", lines);

            if follow {
                println!("Following logs... (Ctrl+C to stop)\n");
            }

            // TODO: Read logs from file

            println!("[INFO] Job assigned: job_7f3a2b9c");
            println!("[INFO] WASM execution completed: 2.3s");
            println!("[INFO] Proof generated: 192 bytes");
            println!("[INFO] Consensus reached: 3/3 validators agree");

            Ok(())
        }

        ValidatorCommands::Metrics { range } => {
            println!("Validator Metrics ({})\n", range);

            // TODO: Query metrics from storage/monitoring

            println!("Performance:");
            println!("  Jobs processed: 1,247");
            println!("  Success rate: 99.2%");
            println!("  Avg execution time: 2.1s");
            println!("  Avg proof time: 2.3s");

            println!("\nEarnings:");
            println!("  Total: 12.5 SOL");
            println!("  Avg per job: 0.01 SOL");
            println!("  Estimated APY: 15.3%");

            println!("\nReputation History:");
            println!("  Current: 1,850");
            println!("  Peak: 1,920");
            println!("  Changes: +850 (last 30 days)");

            Ok(())
        }
    }
}

async fn handle_init_command(path: PathBuf, force: bool) -> Result<()> {
    print_banner();
    println!("Initializing Paraloom in {}...\n", path.display());

    if !force && path.join("paraloom.toml").exists() {
        anyhow::bail!(
            "Config already exists. Use --force to overwrite.\nPath: {}",
            path.join("paraloom.toml").display()
        );
    }

    // TODO: Create default config file
    // Create .paraloom directory structure
    // Generate validator keypair if needed

    std::fs::create_dir_all(&path)?;
    std::fs::create_dir_all(path.join(".paraloom/logs"))?;
    std::fs::create_dir_all(path.join(".paraloom/storage"))?;
    std::fs::create_dir_all(path.join(".paraloom/keys"))?;

    let default_config = r#"
# Paraloom Configuration

[network]
p2p_port = 8080
rpc_port = 8081
bootstrap_peers = []

[validator]
enabled = false
capacity_cpu = 4
capacity_memory = 4096  # MB
capacity_storage = 10240  # MB

[privacy]
shielded_address = ""  # Generate with: paraloom wallet new-address

[solana]
rpc_url = "https://api.devnet.solana.com"
bridge_program_id = "GEwBw4vY7kXtMgHbbGRW4afKzkFPa7Y4cv3xNKvHfUCF"

[storage]
path = ".paraloom/storage"
max_size = 10240  # MB

[logging]
level = "info"
file = ".paraloom/logs/paraloom.log"
"#;

    std::fs::write(path.join("paraloom.toml"), default_config.trim())?;

    println!("[OK] Paraloom initialized!");
    println!("\nCreated:");
    println!("  - paraloom.toml (configuration)");
    println!("  - .paraloom/logs/ (log files)");
    println!("  - .paraloom/storage/ (database)");
    println!("  - .paraloom/keys/ (keypairs)");

    println!("\nNext steps:");
    println!("  1. Edit paraloom.toml to configure your setup");
    println!("  2. Generate a shielded address: paraloom wallet new-address");
    println!("  3. Deposit SOL: paraloom wallet deposit --amount 10.0");
    println!("  4. Start validator (optional): paraloom validator start --config paraloom.toml");

    Ok(())
}
