// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! A single `ika-validator` child process, controlled via its admin HTTP RPC.
//!
//! The harness never links `IkaNode`; it spawns the real binary with
//! `--config-path <yaml>` and talks to the admin server it brings up on
//! `127.0.0.1:<admin_interface_port>` (`ika-node/src/admin.rs`). The data dir
//! is persistent and survives `swap_binary`, which is what makes the on-disk
//! compatibility assertion real.

use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::process::{Child, Command};

/// Handle to one running (or stopped) validator process.
pub struct ValidatorProcess {
    /// Stable index in the cluster (0-based), for logs/labels.
    pub index: usize,
    /// Path to the `ika-validator` binary currently in use.
    binary: PathBuf,
    /// YAML node config passed via `--config-path`.
    config_path: PathBuf,
    /// Persistent data dir (RocksDB lives under here); survives binary swaps.
    #[allow(dead_code)]
    data_dir: PathBuf,
    /// `127.0.0.1:<admin_interface_port>` from the node config.
    admin_addr: SocketAddr,
    /// Per-validator log file (child stdout+stderr).
    log_path: PathBuf,
    child: Option<Child>,
    http: reqwest::Client,
}

impl ValidatorProcess {
    pub fn new(
        index: usize,
        binary: PathBuf,
        config_path: PathBuf,
        data_dir: PathBuf,
        admin_addr: SocketAddr,
        log_path: PathBuf,
    ) -> Self {
        Self {
            index,
            binary,
            config_path,
            data_dir,
            admin_addr,
            log_path,
            child: None,
            http: reqwest::Client::new(),
        }
    }

    /// Spawn the process and block until its admin server answers, i.e. the
    /// node has booted far enough to serve `GET /node-config`.
    pub async fn start(&mut self) -> Result<()> {
        if self.child.is_some() {
            bail!("validator {} already running", self.index);
        }
        let log = File::create(&self.log_path)
            .with_context(|| format!("create log file {}", self.log_path.display()))?;
        let stderr = log.try_clone()?;
        tracing::info!(
            index = self.index,
            binary = %self.binary.display(),
            admin = %self.admin_addr,
            "spawning ika-validator",
        );
        let child = Command::new(&self.binary)
            .arg("--config-path")
            .arg(&self.config_path)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("spawn {}", self.binary.display()))?;
        self.child = Some(child);
        self.wait_until_healthy(Duration::from_secs(120)).await?;
        Ok(())
    }

    /// SIGKILL the process and reap it. A hard kill models a validator crash,
    /// which the on-disk-compat path must survive anyway (RocksDB is
    /// crash-consistent via its WAL).
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            tracing::info!(index = self.index, "stopping ika-validator");
            child.start_kill().ok();
            let _ = child.wait().await;
        }
        Ok(())
    }

    /// Stop on the current binary, switch to `new_binary`, start again on the
    /// same data dir. This is the in-place upgrade primitive.
    pub async fn swap_binary(&mut self, new_binary: PathBuf) -> Result<()> {
        tracing::info!(
            index = self.index,
            from = %self.binary.display(),
            to = %new_binary.display(),
            "swapping validator binary",
        );
        self.stop().await?;
        self.binary = new_binary;
        self.start().await?;
        Ok(())
    }

    /// `GET /capabilities` — this node's view of received `AuthorityCapabilitiesV1`,
    /// as the admin server's debug text (one capability per line).
    pub async fn capabilities(&self) -> Result<String> {
        self.admin_get("capabilities").await
    }

    /// `GET /node-config` — masked current config snapshot (debug text).
    pub async fn node_config(&self) -> Result<String> {
        self.admin_get("node-config").await
    }

    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }

    pub fn log_path(&self) -> &PathBuf {
        &self.log_path
    }

    async fn wait_until_healthy(&self, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut backoff = Duration::from_millis(200);
        loop {
            if self.admin_get("node-config").await.is_ok() {
                tracing::info!(index = self.index, "validator healthy");
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "validator {} did not become healthy within {:?}; see {}",
                    self.index,
                    timeout,
                    self.log_path.display(),
                );
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(2));
        }
    }

    /// GET an admin endpoint, returning its body as text. The ika admin server
    /// returns `(StatusCode, String)` debug text, not JSON.
    async fn admin_get(&self, path: &str) -> Result<String> {
        let url = format!("http://{}/{path}", self.admin_addr);
        let resp = self.http.get(&url).send().await.context("admin GET")?;
        if !resp.status().is_success() {
            bail!("admin GET {url} -> {}", resp.status());
        }
        resp.text().await.context("read admin response")
    }
}
