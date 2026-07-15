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

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use ika_protocol_config::ProtocolVersion;
use ika_swarm_config::sui_client::GenesisGlobalPresignConfig;
use tokio::time::sleep;

use crate::DEFAULT_EPOCH_DURATION_MS;
use crate::binary::{BinaryResolver, BinarySpec};
use crate::cluster::{ClusterBuilder, ClusterOfProcesses};
use crate::mpc_timings::{self, TimingSnapshot};
use crate::workload::WorkloadDriver;

const NETWORK_KEY_OUTPUT_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(60);

/// One ordered step in a scenario.
#[derive(Clone, Debug)]
pub enum Step {
    StartAll(BinarySpec),
    WaitForEpoch(u64),
    WaitForAllValidatorsLocalEpoch(u64),
    ExpectAllValidatorsHealthy,
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
    /// Instantaneous ceiling assertion: fails if the network already upgraded
    /// past `version`. Brackets a workload that must run in a pre-upgrade
    /// window — without the ceiling, timing drift silently erodes the window
    /// and the workload degrades into an ordinary post-upgrade test while the
    /// run stays green.
    ExpectProtocolVersionAtMost(u64),
    ExpectAllValidatorsProtocolVersionAtMost(u64),
    ExpectNetworkKeyReconfigurationNotStarted(u64),
    WaitForNetworkKeyReconfigurationStarted(u64),
    WaitForNetworkKeyReconfigurationCompleted(u64),
    /// Poll until every running validator reports a canonical network DKG
    /// output version `>= at_least` (via its `/metrics`), or time out. Confirms
    /// the off-chain handoff migrated the DKG output (e.g. 2 -> 3 after the v4
    /// reconfiguration); the on-chain copy stays V2, so this is metric-based.
    ExpectNetworkDkgOutputVersionAtLeast(u64),
    /// Register a brand-new validator on chain (candidate → stake → join) and
    /// spawn its process on the given binary. It enters the active committee
    /// at the next epoch boundary.
    JoinValidator(BinarySpec),
    /// Like [`Step::JoinValidator`], but the joiner boots peer-only
    /// `SuiStateMirrored`, reading verified Sui state through the scenario's
    /// `direct_validators` relay servers.
    JoinValidatorMirrored(BinarySpec),
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
    /// Assert that at least one explicitly selected validator's
    /// `ika_dwallet_mpc_malicious_actors_count` gauge is `>= min_total`.
    /// Every selected scrape and metric is required; there is no skip path.
    ExpectMaliciousActorsAtLeast {
        observer_indices: Vec<usize>,
        min_total: u64,
    },
    ExpectMaliciousActorsExactly {
        observer_indices: Vec<usize>,
        expected: u64,
    },
    ExpectNetworkKeyOutputConverged {
        observer_indices: Vec<usize>,
    },
    ExpectNoPendingNetworkKeyReconfiguration {
        epoch: u64,
        observer_indices: Vec<usize>,
    },
    /// Assert every expected validator's `node.log` does (`present: true`) or
    /// does not (`present: false`) contain `needle`. Logs are truncated on
    /// each (re)start, so after a swap this sees only the new binary's
    /// output. For invariants observable only in logs (e.g. the one-time
    /// committee-record migration at store open); prefer a metrics step
    /// where a gauge exists.
    ExpectLogLine {
        needle: String,
        present: bool,
    },
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Step::StartAll(spec) => write!(f, "start_all({})", spec.label()),
            Step::WaitForEpoch(e) => write!(f, "wait_for_epoch({e})"),
            Step::WaitForAllValidatorsLocalEpoch(e) => {
                write!(f, "wait_for_all_validators_local_epoch({e})")
            }
            Step::ExpectAllValidatorsHealthy => write!(f, "expect_all_validators_healthy"),
            Step::StopAndSwap { validators, to } => {
                write!(f, "stop_and_swap({validators:?} -> {})", to.label())
            }
            Step::SetBufferStake { buffer_bps } => write!(f, "set_buffer_stake({buffer_bps})"),
            Step::ExpectProtocolVersionAtLeast(v) => {
                write!(f, "expect_protocol_version_at_least({v})")
            }
            Step::ExpectProtocolVersionAtMost(v) => {
                write!(f, "expect_protocol_version_at_most({v})")
            }
            Step::ExpectAllValidatorsProtocolVersionAtMost(v) => {
                write!(f, "expect_all_validators_protocol_version_at_most({v})")
            }
            Step::ExpectNetworkKeyReconfigurationNotStarted(epoch) => {
                write!(f, "expect_network_key_reconfiguration_not_started({epoch})")
            }
            Step::WaitForNetworkKeyReconfigurationStarted(epoch) => {
                write!(f, "wait_for_network_key_reconfiguration_started({epoch})")
            }
            Step::WaitForNetworkKeyReconfigurationCompleted(epoch) => {
                write!(f, "wait_for_network_key_reconfiguration_completed({epoch})")
            }
            Step::ExpectNetworkDkgOutputVersionAtLeast(v) => {
                write!(f, "expect_network_dkg_output_version_at_least({v})")
            }
            Step::JoinValidator(spec) => write!(f, "join_validator({})", spec.label()),
            Step::JoinValidatorMirrored(spec) => {
                write!(f, "join_validator_mirrored({})", spec.label())
            }
            Step::RemoveValidator { index } => write!(f, "remove_validator({index})"),
            Step::StopValidator { index } => write!(f, "stop_validator({index})"),
            Step::ExpectCommitteeSize(n) => write!(f, "expect_committee_size({n})"),
            Step::SetGlobalPresignConfig => write!(f, "set_global_presign_config"),
            Step::RecordMpcTimings { label } => write!(f, "record_mpc_timings({label:?})"),
            Step::RunWorkload { label } => write!(f, "run_workload({label:?})"),
            Step::ExpectMaliciousActorsAtLeast {
                observer_indices,
                min_total,
            } => write!(
                f,
                "expect_malicious_actors_at_least({observer_indices:?}, {min_total})"
            ),
            Step::ExpectMaliciousActorsExactly {
                observer_indices,
                expected,
            } => write!(
                f,
                "expect_malicious_actors_exactly({observer_indices:?}, {expected})"
            ),
            Step::ExpectNetworkKeyOutputConverged { observer_indices } => write!(
                f,
                "expect_network_key_output_converged({observer_indices:?})"
            ),
            Step::ExpectNoPendingNetworkKeyReconfiguration {
                epoch,
                observer_indices,
            } => write!(
                f,
                "expect_no_pending_network_key_reconfiguration({epoch}, {observer_indices:?})"
            ),
            Step::ExpectLogLine { needle, present } => {
                let polarity = if *present { "present" } else { "absent" };
                write!(f, "expect_log_line_{polarity}({needle:?})")
            }
        }
    }
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
    /// Indices of validators kept on the DIRECT gRPC path (serving the
    /// `SuiStateMirror` relay). At a `stop_and_swap`, every OTHER swapped
    /// validator is flipped to peer-only `SuiStateMirrored` reading through
    /// these; joiners added via `join_validator_mirrored` mirror through them
    /// too. Empty (default) = every validator reads Sui directly.
    pub direct_validators: Vec<usize>,
    /// Boot the whole cluster (validators + notifier) from old-style
    /// (1.1.8-shape) configs: `sui-rpc-url` only, no `sui-data-source`, no
    /// trust anchor — the deprecated JSON-RPC transport every mainnet node
    /// runs on rollout day. Not compatible with `direct_validators` or
    /// mirrored joiners (those require `sui-data-source`).
    pub legacy_sui_config: bool,
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
            direct_validators: Vec::new(),
            legacy_sui_config: false,
        }
    }

    /// Boot the whole cluster from old-style (1.1.8-shape) configs — the
    /// legacy JSON-RPC path for every role. See the field doc.
    pub fn with_legacy_sui_config(mut self) -> Self {
        self.legacy_sui_config = true;
        self
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

    pub fn wait_for_all_validators_local_epoch(mut self, epoch: u64) -> Self {
        self.steps.push(Step::WaitForAllValidatorsLocalEpoch(epoch));
        self
    }

    pub fn expect_all_validators_healthy(mut self) -> Self {
        self.steps.push(Step::ExpectAllValidatorsHealthy);
        self
    }

    pub fn stop_and_swap(mut self, validators: &[usize], to: BinarySpec) -> Self {
        // Intentionally sequential: each validator is stopped, restarted, and
        // health-checked before the next index. Passing the full committee is
        // a coordinated full-committee rollout, not an atomic restart.
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

    /// Assert the network has NOT upgraded past `version` yet. Place around a
    /// workload that must run in a pre-upgrade window, so the window closing
    /// early fails loudly instead of silently voiding the workload's purpose.
    pub fn expect_protocol_version_at_most(mut self, version: u64) -> Self {
        self.steps.push(Step::ExpectProtocolVersionAtMost(version));
        self
    }

    pub fn expect_all_validators_protocol_version_at_most(mut self, version: u64) -> Self {
        self.steps
            .push(Step::ExpectAllValidatorsProtocolVersionAtMost(version));
        self
    }

    pub fn expect_network_key_reconfiguration_not_started(mut self, epoch: u64) -> Self {
        self.steps
            .push(Step::ExpectNetworkKeyReconfigurationNotStarted(epoch));
        self
    }

    pub fn wait_for_network_key_reconfiguration_started(mut self, epoch: u64) -> Self {
        self.steps
            .push(Step::WaitForNetworkKeyReconfigurationStarted(epoch));
        self
    }

    pub fn wait_for_network_key_reconfiguration_completed(mut self, epoch: u64) -> Self {
        self.steps
            .push(Step::WaitForNetworkKeyReconfigurationCompleted(epoch));
        self
    }

    /// Assert the off-chain handoff migrated the network DKG output to at least
    /// `version` (polled across all running validators' metrics).
    pub fn expect_network_dkg_output_version_at_least(mut self, version: u64) -> Self {
        self.steps
            .push(Step::ExpectNetworkDkgOutputVersionAtLeast(version));
        self
    }

    pub fn join_validator(mut self, spec: BinarySpec) -> Self {
        self.steps.push(Step::JoinValidator(spec));
        self
    }

    /// Join a brand-new validator that boots peer-only `SuiStateMirrored`,
    /// reading verified Sui state through the `direct_validators` relay servers
    /// (set via [`Self::with_direct_validators`]).
    pub fn join_validator_mirrored(mut self, spec: BinarySpec) -> Self {
        self.steps.push(Step::JoinValidatorMirrored(spec));
        self
    }

    /// Designate the relay-server (direct) validators by index; every other
    /// validator that runs v4 is flipped to peer-only `SuiStateMirrored`
    /// reading through them — at a [`Self::stop_and_swap`] (the split
    /// materializes at the upgrade swap) or when added via
    /// [`Self::join_validator_mirrored`]. The `SUI_STATE_DIRECT_COUNT` env var
    /// truncates this set (default: all of `indices`, clamped to >= 1), so one
    /// dispatch can test a single direct relay and another can test several.
    pub fn with_direct_validators(mut self, indices: &[usize]) -> Self {
        let count = std::env::var("SUI_STATE_DIRECT_COUNT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(indices.len())
            .clamp(1, indices.len().max(1));
        self.direct_validators = indices.iter().copied().take(count).collect();
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

    /// Assert at least one running validator recorded `>= min_total` malicious
    /// actors this epoch (scrapes the `ika_dwallet_mpc_malicious_actors_count`
    /// gauge).
    pub fn expect_malicious_actors_at_least(
        mut self,
        observer_indices: &[usize],
        min_total: u64,
    ) -> Self {
        self.steps.push(Step::ExpectMaliciousActorsAtLeast {
            observer_indices: observer_indices.to_vec(),
            min_total,
        });
        self
    }

    pub fn expect_malicious_actors_exactly(
        mut self,
        observer_indices: &[usize],
        expected: u64,
    ) -> Self {
        self.steps.push(Step::ExpectMaliciousActorsExactly {
            observer_indices: observer_indices.to_vec(),
            expected,
        });
        self
    }

    pub fn expect_network_key_output_converged(mut self, observer_indices: &[usize]) -> Self {
        self.steps.push(Step::ExpectNetworkKeyOutputConverged {
            observer_indices: observer_indices.to_vec(),
        });
        self
    }

    pub fn expect_no_pending_network_key_reconfiguration(
        mut self,
        epoch: u64,
        observer_indices: &[usize],
    ) -> Self {
        self.steps
            .push(Step::ExpectNoPendingNetworkKeyReconfiguration {
                epoch,
                observer_indices: observer_indices.to_vec(),
            });
        self
    }

    /// Assert every running validator's `node.log` contains `needle`.
    pub fn expect_log_line_present(mut self, needle: impl Into<String>) -> Self {
        self.steps.push(Step::ExpectLogLine {
            needle: needle.into(),
            present: true,
        });
        self
    }

    /// Assert no running validator's `node.log` contains `needle`.
    pub fn expect_log_line_absent(mut self, needle: impl Into<String>) -> Self {
        self.steps.push(Step::ExpectLogLine {
            needle: needle.into(),
            present: false,
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
        // Validators with an on-chain removal already submitted. They stay on
        // the direct path through a `stop_and_swap` (no point flipping a node
        // that's leaving) instead of being auto-mirrored.
        let mut removed_indices: HashSet<usize> = HashSet::new();

        let total = self.steps.len();
        for (index, step) in self.steps.iter().enumerate() {
            let step_number = index + 1;
            let step_started = std::time::Instant::now();
            tracing::info!("[flow {step_number}/{total}] >>> {step}");
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
                    if self.legacy_sui_config {
                        builder = builder.with_legacy_sui_config();
                    }
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
                Step::WaitForAllValidatorsLocalEpoch(epoch) => {
                    let c = cluster
                        .as_ref()
                        .context("WaitForAllValidatorsLocalEpoch before StartAll")?;
                    c.wait_for_all_validators_local_epoch(*epoch, self.epoch_timeout)
                        .await?;
                }
                Step::ExpectAllValidatorsHealthy => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectAllValidatorsHealthy before StartAll")?;
                    c.expect_all_validators_healthy().await?;
                }
                Step::StopAndSwap { validators, to } => {
                    let new_binary = resolve(&resolver, to).await?;
                    let split_configured = !self.direct_validators.is_empty();
                    // With a direct/mirror split configured, every swapped
                    // validator that is NOT a direct relay server and is NOT
                    // already leaving flips to peer-only SuiStateMirrored
                    // (reading through the direct validators) as it comes up on
                    // the new binary — the split materializes exactly at the
                    // upgrade swap. Partition so the relay servers swap FIRST:
                    // a mirrored validator must not restart before the servers
                    // it reads through are back up on the new binary.
                    let (to_mirror, to_direct): (Vec<usize>, Vec<usize>) =
                        validators.iter().copied().partition(|idx| {
                            split_configured
                                && !self.direct_validators.contains(idx)
                                && !removed_indices.contains(idx)
                        });
                    let c = cluster.as_mut().context("StopAndSwap before StartAll")?;
                    let mirror_peers = if split_configured {
                        c.peer_ids_of(&self.direct_validators)?
                    } else {
                        Vec::new()
                    };
                    for idx in to_direct {
                        c.validators
                            .get_mut(idx)
                            .with_context(|| format!("validator index {idx} out of range"))?
                            .swap_binary(new_binary.clone())
                            .await?;
                    }
                    for idx in to_mirror {
                        c.swap_and_mirror(idx, new_binary.clone(), mirror_peers.clone())
                            .await?;
                    }
                }
                Step::SetBufferStake { buffer_bps } => {
                    let c = cluster.as_ref().context("SetBufferStake before StartAll")?;
                    // `current_epoch` is the on-chain counter, which ticks before
                    // validators locally reconfigure; retry the override across
                    // that lag so it isn't rejected for a stale local epoch.
                    let epoch = c.current_epoch().await?;
                    for proc in &c.validators {
                        if proc.is_running() {
                            proc.set_buffer_stake_when_at_epoch(
                                epoch,
                                *buffer_bps,
                                Duration::from_secs(120),
                            )
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
                Step::ExpectProtocolVersionAtMost(version) => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectProtocolVersionAtMost before StartAll")?;
                    let got = c.current_protocol_version().await?;
                    if got > *version {
                        bail!(
                            "protocol version {got} > expected at most {version} — the \
                             pre-upgrade window closed before/during the bracketed workload, \
                             which therefore did not witness the pre-upgrade behavior"
                        );
                    }
                    tracing::info!(
                        got,
                        expected_at_most = *version,
                        "protocol version ceiling assertion passed"
                    );
                }
                Step::ExpectAllValidatorsProtocolVersionAtMost(version) => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectAllValidatorsProtocolVersionAtMost before StartAll")?;
                    c.expect_all_validators_protocol_version_at_most(*version)
                        .await?;
                }
                Step::ExpectNetworkKeyReconfigurationNotStarted(epoch) => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectNetworkKeyReconfigurationNotStarted before StartAll")?;
                    c.expect_network_key_reconfiguration_not_started(*epoch)
                        .await?;
                }
                Step::WaitForNetworkKeyReconfigurationStarted(epoch) => {
                    let c = cluster
                        .as_ref()
                        .context("WaitForNetworkKeyReconfigurationStarted before StartAll")?;
                    c.wait_for_network_key_reconfiguration_started(*epoch, self.epoch_timeout)
                        .await?;
                }
                Step::WaitForNetworkKeyReconfigurationCompleted(epoch) => {
                    let c = cluster
                        .as_ref()
                        .context("WaitForNetworkKeyReconfigurationCompleted before StartAll")?;
                    c.wait_for_network_key_reconfiguration_completed(*epoch, self.epoch_timeout)
                        .await?;
                }
                Step::ExpectNetworkDkgOutputVersionAtLeast(at_least) => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectNetworkDkgOutputVersionAtLeast before StartAll")?;
                    let deadline = tokio::time::Instant::now() + self.epoch_timeout;
                    loop {
                        let got = c.min_canonical_network_dkg_output_version().await;
                        if got >= *at_least {
                            tracing::info!(
                                got,
                                expected = *at_least,
                                "network DKG output version assertion passed \
                                 (off-chain handoff migrated)"
                            );
                            break;
                        }
                        if tokio::time::Instant::now() >= deadline {
                            bail!(
                                "min canonical network DKG output version {got} < expected \
                                 {at_least} after timeout — the off-chain handoff did not migrate"
                            );
                        }
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
                Step::JoinValidator(spec) => {
                    let binary = resolve(&resolver, spec).await?;
                    let c = cluster.as_mut().context("JoinValidator before StartAll")?;
                    let index = c.add_joiner_validator(binary).await?;
                    tracing::info!(index, spec = %spec.label(), "joiner validator spawned");
                }
                Step::JoinValidatorMirrored(spec) => {
                    let binary = resolve(&resolver, spec).await?;
                    let c = cluster
                        .as_mut()
                        .context("JoinValidatorMirrored before StartAll")?;
                    ensure!(
                        !self.direct_validators.is_empty(),
                        "join_validator_mirrored requires with_direct_validators(...) \
                         (a mirrored joiner needs at least one direct relay server)"
                    );
                    let index = c
                        .add_joiner_validator_mirrored(binary, &self.direct_validators)
                        .await?;
                    tracing::info!(index, spec = %spec.label(), "mirrored joiner validator spawned");
                }
                Step::RemoveValidator { index } => {
                    let c = cluster
                        .as_mut()
                        .context("RemoveValidator before StartAll")?;
                    c.remove_validator(*index).await?;
                    removed_indices.insert(*index);
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
                Step::ExpectMaliciousActorsAtLeast {
                    observer_indices,
                    min_total,
                } => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectMaliciousActorsAtLeast before StartAll")?;
                    c.expect_malicious_actors_at_least(observer_indices, *min_total)
                        .await?;
                }
                Step::ExpectMaliciousActorsExactly {
                    observer_indices,
                    expected,
                } => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectMaliciousActorsExactly before StartAll")?;
                    c.expect_malicious_actors_exactly(observer_indices, *expected)
                        .await?;
                }
                Step::ExpectNetworkKeyOutputConverged { observer_indices } => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectNetworkKeyOutputConverged before StartAll")?;
                    // The system session has already completed before normal
                    // scenarios reach this assertion. Allow metrics propagation
                    // some slack, but do not reuse a multi-minute epoch timeout:
                    // a missing authority output is itself release-blocking.
                    c.expect_network_key_output_converged(
                        observer_indices,
                        self.epoch_timeout
                            .min(NETWORK_KEY_OUTPUT_OBSERVATION_TIMEOUT),
                    )
                    .await?;
                }
                Step::ExpectNoPendingNetworkKeyReconfiguration {
                    epoch,
                    observer_indices,
                } => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectNoPendingNetworkKeyReconfiguration before StartAll")?;
                    c.expect_no_pending_network_key_reconfiguration(
                        *epoch,
                        observer_indices,
                        self.epoch_timeout,
                    )
                    .await?;
                }
                Step::ExpectLogLine { needle, present } => {
                    let c = cluster.as_ref().context("ExpectLogLine before StartAll")?;
                    for proc in &c.validators {
                        let log = std::fs::read_to_string(proc.log_path()).with_context(|| {
                            format!("read validator log {}", proc.log_path().display())
                        })?;
                        let found = log.contains(needle.as_str());
                        if found != *present {
                            bail!(
                                "expected {needle:?} to be {} in {}, but it was {}",
                                if *present { "present" } else { "absent" },
                                proc.log_path().display(),
                                if found { "present" } else { "absent" },
                            );
                        }
                    }
                    tracing::info!(
                        needle = needle.as_str(),
                        present = *present,
                        "log-line assertion passed on every expected validator"
                    );
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
                    // Debug aid: HOLD_CLUSTER holds the cluster up with the
                    // driver's config paths printed so `ika dwallet` can be
                    // driven by hand (fast iteration vs. ~6-min test cycles)
                    // instead of running the lifecycle.
                    if std::env::var("HOLD_CLUSTER").is_ok() {
                        eprintln!("HOLD_CLUSTER: cluster up at workload [{label}]. Run e.g.:");
                        eprintln!(
                            "  ika --json --client.config {} --ika-config {} dwallet create --curve secp256k1 --output-secret /tmp/s.bin",
                            driver.client_config_path().display(),
                            driver.ika_config_path().display(),
                        );
                        eprintln!("user_address={}", driver.user_address());
                        sleep(Duration::from_secs(3600)).await;
                    } else {
                        let outcome = driver
                            .run_dwallet_lifecycle()
                            .await
                            .with_context(|| format!("workload [{label}]"))?;
                        ensure!(
                            !outcome.sign_digest.is_empty(),
                            "workload [{label}]: lifecycle completed but produced no signature digest"
                        );
                        tracing::info!(label = %label, ?outcome, "workload lifecycle completed");
                    }
                }
            }
            tracing::info!(
                "[flow {step_number}/{total}] <<< {step} done in {:.1}s",
                step_started.elapsed().as_secs_f64()
            );
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
