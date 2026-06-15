// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! An external Sui localnet, spawned as a sibling child process.
//!
//! The in-process `ika-test-cluster` uses `test_cluster::TestCluster` (Sui
//! linked in-process). That cannot back out-of-process ika validators — they
//! need a real RPC + faucet to publish against and read events from. So the
//! harness spawns the workspace-pinned `sui` binary directly, mirroring
//! `scripts/run_sui.sh`. One localnet is shared across binary swaps (realistic:
//! mainnet upgrades happen on a live chain). Torn down on `Drop`.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::process::{Child, Command};

/// Default localnet endpoints for `sui start` (Sui 1.x).
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:9000";
const DEFAULT_FAUCET_URL: &str = "http://127.0.0.1:9123/gas";

/// A running `sui start` localnet.
pub struct SuiLocalnet {
    rpc_url: String,
    faucet_url: String,
    log_path: PathBuf,
    child: Option<Child>,
}

impl SuiLocalnet {
    /// Spawn `sui start --with-faucet --force-regenesis` and block until the
    /// RPC answers. `sui_binary` is the path to a workspace-tag-matching `sui`.
    /// `sui_epoch_duration_ms` governs *Sui's* epochs (kept effectively
    /// infinite — ika epochs are driven separately at ika genesis); a large
    /// value avoids Sui reconfiguring underneath the test.
    pub async fn start(
        sui_binary: PathBuf,
        log_path: PathBuf,
        sui_epoch_duration_ms: u64,
    ) -> Result<Self> {
        let log = std::fs::File::create(&log_path)
            .with_context(|| format!("create sui log {}", log_path.display()))?;
        let stderr = log.try_clone()?;
        tracing::info!(binary = %sui_binary.display(), "spawning sui localnet");
        let child = Command::new(&sui_binary)
            .args([
                "start",
                "--with-faucet",
                "--force-regenesis",
                "--epoch-duration-ms",
            ])
            .arg(sui_epoch_duration_ms.to_string())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("spawn {}", sui_binary.display()))?;

        let localnet = Self {
            rpc_url: DEFAULT_RPC_URL.to_string(),
            faucet_url: DEFAULT_FAUCET_URL.to_string(),
            log_path,
            child: Some(child),
        };
        localnet.wait_until_ready(Duration::from_secs(120)).await?;
        Ok(localnet)
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    pub fn faucet_url(&self) -> &str {
        &self.faucet_url
    }

    async fn wait_until_ready(&self, timeout: Duration) -> Result<()> {
        let http = reqwest::Client::new();
        let deadline = tokio::time::Instant::now() + timeout;
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sui_getChainIdentifier",
            "params": [],
        });
        loop {
            let rpc_ok = http
                .post(&self.rpc_url)
                .json(&body)
                .send()
                .await
                .ok()
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            // The faucet (port 9123) comes up a beat after the RPC. `init_ika_on_sui`
            // hits it immediately, so wait for it too. The `/gas` endpoint is
            // POST-only; any HTTP response (even 405) means it is listening —
            // only a connection error means it is not up yet.
            let faucet_ok = rpc_ok
                && http
                    .get(&self.faucet_url)
                    .send()
                    .await
                    .map(|_| true)
                    .unwrap_or(false);
            if rpc_ok && faucet_ok {
                tracing::info!(rpc = %self.rpc_url, faucet = %self.faucet_url, "sui localnet ready");
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "sui localnet (rpc_ok={rpc_ok}, faucet_ok={faucet_ok}) not ready within {:?}; see {}",
                    timeout,
                    self.log_path.display(),
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

impl Drop for SuiLocalnet {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            // Best-effort synchronous kill on teardown; `kill_on_drop` also
            // arms a reaper, but we issue the signal eagerly so the port frees.
            let _ = child.start_kill();
        }
    }
}
