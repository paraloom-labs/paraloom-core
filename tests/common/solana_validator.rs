//! RAII wrapper around a `solana-test-validator` subprocess for the
//! full bridge E2E tests. The wrapper kills the child on `Drop` so a
//! panicking test does not leave a stranded validator chewing the
//! RPC port. Tests using this harness are `#[ignore]`'d by default —
//! the validator binary is only available when the Solana CLI is
//! installed (CI runs with `--ignored` after installing the CLI).

use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct SubprocessValidator {
    child: Child,
    rpc_port: u16,
    _ledger: tempfile::TempDir,
}

impl SubprocessValidator {
    /// Launch a fresh validator on `port`, wait up to 60s for the
    /// RPC to come up, then return the handle. `--reset` wipes any
    /// previous ledger state so each test starts from genesis.
    pub fn launch(port: u16) -> Result<Self, String> {
        let ledger = tempfile::tempdir().map_err(|e| format!("tempdir: {}", e))?;
        let child = Command::new("solana-test-validator")
            .args([
                "--ledger",
                ledger.path().to_str().expect("utf-8 ledger path"),
                "--reset",
                "--quiet",
                "--rpc-port",
                &port.to_string(),
            ])
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
