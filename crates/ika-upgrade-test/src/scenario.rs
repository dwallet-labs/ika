// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Imperative scenario DSL — no declarative time-travel. Each step is an
//! explicit, ordered action the harness performs against the cluster.
//!
//! ```ignore
//! Scenario::new(4)
//!     .start_all(spec_old)
//!     .wait_for_epoch(1)
//!     .stop_and_swap(&[0, 1], spec_new)
//!     .wait_for_epoch(2)
//!     .stop_and_swap(&[2, 3], spec_new)
//!     .wait_for_epoch(3)
//!     .expect_protocol_version_at_least(4)
//!     .run().await?;
//! ```

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ika_protocol_config::ProtocolVersion;

use crate::DEFAULT_EPOCH_DURATION_MS;
use crate::binary::{BinaryResolver, BinarySpec};
use crate::cluster::{ClusterBuilder, ClusterOfProcesses};

/// One ordered step in a scenario.
#[derive(Clone, Debug)]
pub enum Step {
    StartAll(BinarySpec),
    WaitForEpoch(u64),
    StopAndSwap {
        validators: Vec<usize>,
        to: BinarySpec,
    },
    /// Override the protocol-upgrade buffer stake on every validator for the
    /// current epoch. `buffer_bps = 0` makes a quorum (not unanimity) enough to
    /// advance the protocol version.
    SetBufferStake {
        buffer_bps: u64,
    },
    ExpectProtocolVersionAtLeast(u64),
}

/// A scenario: a validator count, the binaries it can resolve, and an ordered
/// list of steps. Construction is pure; `run` does the work.
pub struct Scenario {
    pub num_validators: usize,
    pub steps: Vec<Step>,
    pub repo: PathBuf,
    pub sui_binary: PathBuf,
    pub notifier_binary: PathBuf,
    pub epoch_timeout: Duration,
    /// Genesis ika epoch duration. Long epochs avoid the known sui_executor
    /// gas-coin-contention wedge that short, rapid epoch transitions trigger
    /// (see project memory: epoch-13 wedge), and give a binary swap time to
    /// finish well before the mid-epoch reconfiguration MPC window.
    pub epoch_duration_ms: u64,
    /// Persistent data dir for the cluster. When `None` a temp dir is used
    /// (cleaned on drop — set this to keep node logs after a failure).
    pub base_dir: Option<PathBuf>,
}

impl Scenario {
    pub fn new(
        num_validators: usize,
        repo: PathBuf,
        sui_binary: PathBuf,
        notifier_binary: PathBuf,
    ) -> Self {
        Self {
            num_validators,
            steps: Vec::new(),
            repo,
            sui_binary,
            notifier_binary,
            epoch_timeout: Duration::from_secs(600),
            epoch_duration_ms: DEFAULT_EPOCH_DURATION_MS,
            base_dir: None,
        }
    }

    pub fn with_base_dir(mut self, dir: PathBuf) -> Self {
        self.base_dir = Some(dir);
        self
    }

    pub fn with_epoch_duration_ms(mut self, ms: u64) -> Self {
        self.epoch_duration_ms = ms;
        self
    }

    pub fn with_epoch_timeout(mut self, timeout: Duration) -> Self {
        self.epoch_timeout = timeout;
        self
    }

    pub fn start_all(mut self, spec: BinarySpec) -> Self {
        self.steps.push(Step::StartAll(spec));
        self
    }

    pub fn wait_for_epoch(mut self, epoch: u64) -> Self {
        self.steps.push(Step::WaitForEpoch(epoch));
        self
    }

    pub fn stop_and_swap(mut self, validators: &[usize], to: BinarySpec) -> Self {
        self.steps.push(Step::StopAndSwap {
            validators: validators.to_vec(),
            to,
        });
        self
    }

    /// Override the protocol-upgrade buffer stake on every validator for the
    /// epoch the cluster is currently in. Insert after a `stop_and_swap` and
    /// before the `wait_for_epoch` that crosses the upgrade boundary.
    pub fn set_buffer_stake(mut self, buffer_bps: u64) -> Self {
        self.steps.push(Step::SetBufferStake { buffer_bps });
        self
    }

    pub fn expect_protocol_version_at_least(mut self, version: u64) -> Self {
        self.steps.push(Step::ExpectProtocolVersionAtLeast(version));
        self
    }

    /// Resolve binaries, bring up the cluster, and execute the steps in order.
    /// Binary resolution (a `cargo build` for git refs) runs on a blocking
    /// thread so it doesn't stall the async runtime.
    pub async fn run(self) -> Result<()> {
        let resolver = BinaryResolver::new(self.repo.clone(), BinaryResolver::default_cache_root());
        let mut cluster: Option<ClusterOfProcesses> = None;

        for step in &self.steps {
            match step {
                Step::StartAll(spec) => {
                    let validator_binary = resolve(&resolver, spec).await?;
                    tracing::info!(spec = %spec.label(), "starting cluster on binary");
                    let mut builder = ClusterBuilder::new(
                        validator_binary,
                        self.notifier_binary.clone(),
                        self.sui_binary.clone(),
                    )
                    .with_num_validators(self.num_validators)
                    .with_epoch_duration_ms(self.epoch_duration_ms)
                    .with_genesis_protocol_version(ProtocolVersion::MIN);
                    if let Some(dir) = &self.base_dir {
                        builder = builder.with_base_dir(dir.clone());
                    }
                    let built = builder.build().await.context("bring up cluster")?;
                    cluster = Some(built);
                }
                Step::WaitForEpoch(epoch) => {
                    let c = cluster.as_ref().context("WaitForEpoch before StartAll")?;
                    c.wait_for_epoch(*epoch, self.epoch_timeout).await?;
                }
                Step::StopAndSwap { validators, to } => {
                    let new_binary = resolve(&resolver, to).await?;
                    let c = cluster.as_mut().context("StopAndSwap before StartAll")?;
                    for &idx in validators {
                        let proc = c
                            .validators
                            .get_mut(idx)
                            .with_context(|| format!("validator index {idx} out of range"))?;
                        proc.swap_binary(new_binary.clone()).await?;
                    }
                }
                Step::SetBufferStake { buffer_bps } => {
                    let c = cluster.as_ref().context("SetBufferStake before StartAll")?;
                    let epoch = c.current_epoch().await?;
                    for proc in &c.validators {
                        if proc.is_running() {
                            proc.set_buffer_stake(epoch, *buffer_bps)
                                .await
                                .with_context(|| {
                                    format!("set buffer stake on validator {}", proc.index)
                                })?;
                        }
                    }
                    tracing::info!(epoch, buffer_bps, "buffer stake override applied");
                }
                Step::ExpectProtocolVersionAtLeast(version) => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectProtocolVersion before StartAll")?;
                    let got = c.current_protocol_version().await?;
                    if got < *version {
                        bail!("protocol version {got} < expected {version}");
                    }
                    tracing::info!(
                        got,
                        expected = *version,
                        "protocol version assertion passed"
                    );
                }
            }
        }
        Ok(())
    }
}

/// Resolve a spec to a binary path on a blocking thread (a git-ref spec triggers
/// a `cargo build`, which must not block the async runtime).
async fn resolve(resolver: &BinaryResolver, spec: &BinarySpec) -> Result<PathBuf> {
    let resolver = resolver.clone();
    let spec = spec.clone();
    tokio::task::spawn_blocking(move || resolver.resolve(&spec))
        .await
        .context("binary resolver task panicked")?
}
