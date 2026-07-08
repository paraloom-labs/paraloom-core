//! RAII wrapper around a `solana-test-validator` subprocess for the
//! full bridge E2E tests. The wrapper kills the child on `Drop` so a
//! panicking test does not leave a stranded validator chewing the
//! RPC port. Tests using this harness are `#[ignore]`'d by default —
//! the validator binary is only available when the Solana CLI is
//! installed (CI runs with `--ignored` after installing the CLI).

use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::signature::Signer;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Paraloom on-chain program ID — declared in programs/paraloom/src/lib.rs.
/// Hardcoded here because programs/paraloom is not a dep of paraloom-core
/// (separate workspace, on-chain crate cannot pull the L2's heavy deps).
pub const PARALOOM_PROGRAM_ID: &str = "8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP";

pub struct SubprocessValidator {
    child: Child,
    rpc_port: u16,
    _ledger: tempfile::TempDir,
}

impl SubprocessValidator {
    /// Launch a fresh validator on `port` with no extra programs.
    pub fn launch(port: u16) -> Result<Self, String> {
        Self::launch_with_programs(port, &[])
    }

    /// Launch with a list of `(program_id, so_path)` pairs preloaded
    /// via `--bpf-program`. Each path must point at a built `.so`
    /// artefact — `cargo build-sbf` against programs/paraloom yields
    /// `programs/paraloom/target/deploy/paraloom_program.so`.
    pub fn launch_with_programs(port: u16, programs: &[(&str, PathBuf)]) -> Result<Self, String> {
        let ledger = tempfile::tempdir().map_err(|e| format!("tempdir: {}", e))?;
        let mut cmd = Command::new("solana-test-validator");
        cmd.args([
            "--ledger",
            ledger.path().to_str().expect("utf-8 ledger path"),
            "--reset",
            "--quiet",
            "--rpc-port",
            &port.to_string(),
        ]);
        for (id, so) in programs {
            if !so.exists() {
                return Err(format!(
                    "program .so not found at {:?} — run `cargo build-sbf` first",
                    so
                ));
            }
            cmd.arg("--bpf-program")
                .arg(id)
                .arg(so.to_str().expect("utf-8 so path"));
        }
        let child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn solana-test-validator: {}", e))?;

        let url = format!("http://127.0.0.1:{}", port);
        let rpc = RpcClient::new_with_commitment(url, CommitmentConfig::confirmed());
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if rpc.get_health().is_ok() {
                return Ok(Self {
                    child,
                    rpc_port: port,
                    _ledger: ledger,
                });
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err("validator did not become healthy within 60s".to_string())
    }

    /// Launch with a single program preloaded as an UPGRADEABLE program,
    /// i.e. with a BPFLoaderUpgradeable `ProgramData` account whose upgrade
    /// authority is `upgrade_authority`. The #204 init gate
    /// (`check_upgrade_authority`) reads that account, so the program must be
    /// loaded this way (not `--bpf-program`, which is non-upgradeable and has
    /// no ProgramData account) and the init signer must equal
    /// `upgrade_authority`.
    pub fn launch_with_upgradeable_program(
        port: u16,
        program_id: &str,
        so: PathBuf,
        upgrade_authority: &solana_sdk::pubkey::Pubkey,
    ) -> Result<Self, String> {
        if !so.exists() {
            return Err(format!(
                "program .so not found at {:?} — run `cargo build-sbf` first",
                so
            ));
        }
        let ledger = tempfile::tempdir().map_err(|e| format!("tempdir: {}", e))?;
        let mut cmd = Command::new("solana-test-validator");
        cmd.args([
            "--ledger",
            ledger.path().to_str().expect("utf-8 ledger path"),
            "--reset",
            "--quiet",
            "--rpc-port",
            &port.to_string(),
        ]);
        cmd.arg("--upgradeable-program")
            .arg(program_id)
            .arg(so.to_str().expect("utf-8 so path"))
            .arg(upgrade_authority.to_string());

        let child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn solana-test-validator: {}", e))?;

        let url = format!("http://127.0.0.1:{}", port);
        let rpc = RpcClient::new_with_commitment(url, CommitmentConfig::confirmed());
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if rpc.get_health().is_ok() {
                return Ok(Self {
                    child,
                    rpc_port: port,
                    _ledger: ledger,
                });
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err("validator did not become healthy within 60s".to_string())
    }

    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    pub fn rpc_client(&self) -> Arc<RpcClient> {
        Arc::new(RpcClient::new_with_commitment(
            self.rpc_url(),
            CommitmentConfig::confirmed(),
        ))
    }
}

impl Drop for SubprocessValidator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Canonical path to the Anchor-built `paraloom_program.so` artefact.
/// Resolved relative to `CARGO_MANIFEST_DIR` so tests work whether
/// they run from the workspace root or some other CWD.
pub fn paraloom_program_so() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("programs/paraloom/target/deploy/paraloom_program.so")
}

/// Airdrop `lamports` to an EXISTING keypair and poll until it lands. Used
/// when the keypair must be generated before the validator launches (e.g. it
/// is the upgrade authority passed to `launch_with_upgradeable_program`).
pub fn fund_keypair(
    rpc: &RpcClient,
    kp: &solana_sdk::signature::Keypair,
    lamports: u64,
) -> Result<(), String> {
    rpc.request_airdrop(&kp.pubkey(), lamports)
        .map_err(|e| format!("airdrop request: {}", e))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if rpc.get_balance(&kp.pubkey()).unwrap_or(0) >= lamports {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err("airdrop did not confirm within 30s".to_string())
}
