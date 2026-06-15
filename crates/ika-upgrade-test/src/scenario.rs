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
use ika_swarm_config::sui_client::GenesisGlobalPresignConfig;

use crate::DEFAULT_EPOCH_DURATION_MS;
use crate::binary::{BinaryResolver, BinarySpec};
use crate::cluster::{ClusterBuilder, ClusterOfProcesses};
use crate::mpc_timings::{self, TimingSnapshot};
use crate::workload::WorkloadDriver;

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
    /// Register a brand-new validator on chain (candidate → stake → join) and
    /// spawn its process on the given binary. It enters the active committee
    /// at the next epoch boundary.
    JoinValidator(BinarySpec),
    /// Submit on-chain removal for the validator at `index`. It leaves the
    /// committee at the next epoch boundary; its process keeps running until
    /// an explicit `StopValidator`.
    RemoveValidator {
        index: usize,
    },
    /// Stop the process of a validator that already left the committee.
    StopValidator {
        index: usize,
    },
    /// Assert the on-chain active committee has exactly this many members.
    ExpectCommitteeSize(usize),
    /// Write the production curve/algorithm set into the on-chain
    /// `GlobalPresignConfig`, routing those presigns to the validators'
    /// internal pool. Insert after the protocol-v4 upgrade is confirmed —
    /// the pool only fills with `internal_presign_sessions` on, so setting
    /// it earlier makes every routed presign unservable.
    SetGlobalPresignConfig,
    /// Scrape every running validator's MPC duration metrics into a labeled
    /// snapshot, printed immediately and compared against the other
    /// snapshots at the end of the run.
    RecordMpcTimings {
        label: String,
    },
    /// Drive a full DKG → Presign → Sign dWallet lifecycle through the `ika`
    /// CLI (requires `with_ika_cli`). Generates real dwallet MPC sessions so
    /// a following `RecordMpcTimings` has per-protocol numbers to report.
    RunWorkload {
        label: String,
    },
}

/// What a scenario run produced beyond pass/fail: the labeled MPC timing
/// snapshots, in recording order. The comparison between consecutive
/// snapshots is printed by `run` itself; tests can also inspect the raw
/// numbers here.
pub struct ScenarioReport {
    pub timing_snapshots: Vec<TimingSnapshot>,
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
    /// Genesis `min_validator_count` override (protocol default 4).
    pub min_validator_count: Option<u64>,
    /// Path to the `ika` CLI binary; required by `RunWorkload` steps.
    pub ika_cli: Option<PathBuf>,
    /// What genesis writes into the on-chain `GlobalPresignConfig`. Scenarios
    /// that run presigns before the v4 upgrade need `Empty` (the
    /// mainnet-v1.1.8 state) plus a [`Step::SetGlobalPresignConfig`] after
    /// the upgrade.
    pub genesis_global_presign_config: GenesisGlobalPresignConfig,
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
            min_validator_count: None,
            ika_cli: None,
            genesis_global_presign_config: GenesisGlobalPresignConfig::Full,
        }
    }

    /// Path to the `ika` CLI binary; required by `run_workload` steps.
    pub fn with_ika_cli(mut self, path: PathBuf) -> Self {
        self.ika_cli = Some(path);
        self
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

    pub fn join_validator(mut self, spec: BinarySpec) -> Self {
        self.steps.push(Step::JoinValidator(spec));
        self
    }

    pub fn remove_validator(mut self, index: usize) -> Self {
        self.steps.push(Step::RemoveValidator { index });
        self
    }

    pub fn stop_validator(mut self, index: usize) -> Self {
        self.steps.push(Step::StopValidator { index });
        self
    }

    pub fn expect_committee_size(mut self, n: usize) -> Self {
        self.steps.push(Step::ExpectCommitteeSize(n));
        self
    }

    pub fn record_mpc_timings(mut self, label: impl Into<String>) -> Self {
        self.steps.push(Step::RecordMpcTimings {
            label: label.into(),
        });
        self
    }

    pub fn run_workload(mut self, label: impl Into<String>) -> Self {
        self.steps.push(Step::RunWorkload {
            label: label.into(),
        });
        self
    }

    /// Genesis `min_validator_count` override, for scenarios that shrink the
    /// committee below the protocol default of 4.
    pub fn with_min_validator_count(mut self, n: u64) -> Self {
        self.min_validator_count = Some(n);
        self
    }

    /// Override what genesis writes into the on-chain `GlobalPresignConfig`
    /// (default `Full`). See [`Step::SetGlobalPresignConfig`].
    pub fn with_genesis_global_presign_config(
        mut self,
        config: GenesisGlobalPresignConfig,
    ) -> Self {
        self.genesis_global_presign_config = config;
        self
    }

    /// Apply the full production `GlobalPresignConfig` on chain. Only valid
    /// once the network runs protocol v4+.
    pub fn set_global_presign_config(mut self) -> Self {
        self.steps.push(Step::SetGlobalPresignConfig);
        self
    }

    /// Resolve binaries, bring up the cluster, and execute the steps in order.
    /// Binary resolution (a `cargo build` for git refs) runs on a blocking
    /// thread so it doesn't stall the async runtime.
    pub async fn run(self) -> Result<ScenarioReport> {
        let resolver = BinaryResolver::new(self.repo.clone(), BinaryResolver::default_cache_root());
        let mut cluster: Option<ClusterOfProcesses> = None;
        let mut timing_snapshots: Vec<TimingSnapshot> = Vec::new();

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
                    .with_genesis_protocol_version(ProtocolVersion::MIN)
                    .with_genesis_global_presign_config(self.genesis_global_presign_config);
                    if let Some(dir) = &self.base_dir {
                        builder = builder.with_base_dir(dir.clone());
                    }
                    if let Some(n) = self.min_validator_count {
                        builder = builder.with_min_validator_count(n);
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
                Step::JoinValidator(spec) => {
                    let binary = resolve(&resolver, spec).await?;
                    let c = cluster.as_mut().context("JoinValidator before StartAll")?;
                    let index = c.add_joiner_validator(binary).await?;
                    tracing::info!(index, spec = %spec.label(), "joiner validator spawned");
                }
                Step::RemoveValidator { index } => {
                    let c = cluster
                        .as_mut()
                        .context("RemoveValidator before StartAll")?;
                    c.remove_validator(*index).await?;
                }
                Step::StopValidator { index } => {
                    let c = cluster.as_mut().context("StopValidator before StartAll")?;
                    c.stop_validator(*index).await?;
                }
                Step::ExpectCommitteeSize(expected) => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectCommitteeSize before StartAll")?;
                    let got = c.active_committee_size().await?;
                    if got != *expected {
                        bail!("active committee size {got} != expected {expected}");
                    }
                    tracing::info!(got, "committee size assertion passed");
                }
                Step::SetGlobalPresignConfig => {
                    let c = cluster
                        .as_mut()
                        .context("SetGlobalPresignConfig before StartAll")?;
                    c.set_global_presign_config().await?;
                }
                Step::RecordMpcTimings { label } => {
                    let c = cluster
                        .as_ref()
                        .context("RecordMpcTimings before StartAll")?;
                    let snapshot = mpc_timings::record_snapshot(c, label.clone()).await?;
                    timing_snapshots.push(snapshot);
                }
                Step::RunWorkload { label } => {
                    let c = cluster.as_ref().context("RunWorkload before StartAll")?;
                    let ika_cli = self
                        .ika_cli
                        .as_ref()
                        .context("RunWorkload requires with_ika_cli")?;
                    // A fresh driver per step: its own user key + funding, so
                    // workloads in different epochs never contend on objects.
                    let driver = WorkloadDriver::new(
                        ika_cli.clone(),
                        c.rpc_url().to_string(),
                        c.faucet_url().to_string(),
                        c.network_config().clone(),
                        c.publisher_keypair().copy(),
                    )
                    .await
                    .context("build workload driver")?;
                    let outcome = driver
                        .run_dwallet_lifecycle()
                        .await
                        .with_context(|| format!("workload [{label}]"))?;
                    tracing::info!(label = %label, ?outcome, "workload lifecycle completed");
                }
            }
        }
        if timing_snapshots.len() >= 2 {
            println!("{}", mpc_timings::render_comparison(&timing_snapshots));
        }
        Ok(ScenarioReport { timing_snapshots })
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
