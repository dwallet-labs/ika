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

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use ika_protocol_config::ProtocolVersion;
use ika_swarm_config::sui_client::GenesisGlobalPresignConfig;
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
use tokio::time::sleep;

use crate::DEFAULT_EPOCH_DURATION_MS;
use crate::binary::{BinaryResolver, BinarySpec};
use crate::cluster::{
    ClusterBuilder, ClusterOfProcesses, DrainWedgeSample, NetworkKeyBoundaryEvidence,
    evaluate_healthy_drain, evaluate_wedged_drain,
};
use crate::mpc_timings::{self, TimingSnapshot};
use crate::workload::WorkloadDriver;

const NETWORK_KEY_OUTPUT_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(60);

/// Arms the production binary's MPC-drain park hook. Mirrored from
/// `ika-core`'s `dwallet_mpc::park_drain_test_hook`, which this crate
/// deliberately does not link: the harness drives separately-compiled child
/// processes, so an env var is the whole interface. A rename there without one
/// here shows up as the park never taking effect, which
/// [`Step::WaitForRoundChannelAtCapacity`] fails on with the observed depth.
const PARK_MPC_DRAIN_AFTER_ROUND_ENV_VAR: &str = "IKA_TEST_PARK_MPC_DRAIN_AFTER_ROUND";

/// Names the file whose appearance releases the park. See above.
const PARK_MPC_DRAIN_UNPARK_FILE_ENV_VAR: &str = "IKA_TEST_PARK_MPC_DRAIN_UNPARK_FILE";

/// Overrides `ika-node`'s commit-liveness bound, in seconds (`0` disables it).
const COMMIT_LIVENESS_WATCHDOG_SECS_ENV_VAR: &str = "IKA_COMMIT_LIVENESS_WATCHDOG_SECS";

/// The unpark sentinel's name inside the parked validator's own data dir.
const UNPARK_SENTINEL_FILE_NAME: &str = "unpark-mpc-drain";

/// Park the drain the instant the boot replay releases it. The harness has no
/// way to predict the cluster's commit rate, so any positive threshold would
/// be a guess about how long the arming restart takes to become a wedge; `0`
/// makes the park deterministic.
const PARK_AFTER_ROUNDS: u64 = 0;

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
    /// the whole committee agrees on the DKG-output wire version it serves in
    /// the off-chain handoff; that version has no chain field, so this is
    /// metric-based.
    ExpectNetworkDkgOutputVersionAtLeast(u64),
    ExpectReconfigurationOutputVersionAtLeast(u64),
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
    /// does not (`present: false`) contain `needle`. Logs APPEND across
    /// restarts, so this reads the whole run: a `present: false` covers every
    /// binary the validator has run (which is what makes it the right shape
    /// for "this never happened"), while a `present: true` can be satisfied by
    /// an occurrence from before a swap — pick a needle only the phase under
    /// test can emit. For invariants observable only in logs (e.g. the
    /// one-time committee-record migration at store open); prefer a metrics
    /// step where a gauge exists.
    ExpectLogLine {
        needle: String,
        present: bool,
    },
    /// Assert ONE validator's `node.log` contains `needle`. This is the probe
    /// for a boot-time decision of a specific validator — the whole-cluster
    /// [`Step::ExpectLogLine`] would demand the line of validators whose last
    /// boot predates the condition under test. Logs append across restarts, so
    /// the needle must be one only the phase under test can emit.
    ExpectLogLineOnValidator {
        index: usize,
        needle: String,
    },
    /// Restart ONE validator with the production binary's MPC-drain park hook
    /// armed: from the moment its boot replay finishes, its drain consumes no
    /// further consensus rounds while the rest of the service keeps running.
    /// The bounded round channel then fills and the consensus fold parks on
    /// it — a drain that is alive but stuck (ika #2102).
    ///
    /// `watchdog_bound_secs` overrides that validator's commit-liveness bound
    /// for the same restart, and is what makes the "the watchdog HOLDS"
    /// assertion mean anything. At the 900s default no test-length park can
    /// reach a breach, so a broken hold would pass unnoticed; with a bound of
    /// `b` the watchdog exits at `b` seconds of counted silence once the
    /// process is older than `2b` (its floor), so a park observed for longer
    /// than `2b` of process uptime FAILS if the fold-parked hold is ever
    /// dropped. Pick `b` well above the cluster's healthy commit gap and keep
    /// the park longer than `2b`.
    ParkMpcDrain {
        index: usize,
        watchdog_bound_secs: u64,
    },
    /// Poll ONE validator until its round channel pins at capacity — the wedge
    /// has formed and the fold is parked. Bounded by the scenario's epoch
    /// timeout, because the fill time is the cluster's commit rate.
    WaitForRoundChannelAtCapacity {
        index: usize,
    },
    /// The two-sided wedge assertion, evaluated over `window` from OUTSIDE:
    /// `parked` shows blocked seconds climbing while its consumed round stays
    /// flat, its channel pinned at capacity, its commit-liveness clock held
    /// and its committed-leader round still advancing; every validator in
    /// `peers` shows none of it. The parked validator's final sample is kept
    /// for [`Step::ExpectDrainResumed`], so the recovery is compared against
    /// the wedge itself rather than against a fresh baseline that could hide a
    /// restart in between.
    ExpectDrainWedged {
        parked: usize,
        peers: Vec<usize>,
        window: Duration,
        silence_ceiling_seconds: i64,
    },
    /// Create the parked validator's unpark sentinel. The hook is one-shot:
    /// the process resumes and never parks again.
    UnparkMpcDrain {
        index: usize,
    },
    /// Assert the unparked validator recovers WITHOUT a restart: its drain
    /// consumes past the round it was stuck on, and it then satisfies the same
    /// healthy-drain predicate as the peers over `window`. `peers` are checked
    /// again over the same window, so the recovery is not read off a cluster
    /// that has meanwhile gone quiet.
    ExpectDrainResumed {
        index: usize,
        peers: Vec<usize>,
        window: Duration,
        silence_ceiling_seconds: i64,
    },
    /// Poll ONE validator's `node.log` until `needle` appears (or the
    /// epoch timeout elapses). The immediate [`Step::ExpectLogLineOnValidator`]
    /// asserts a decision that already happened; this is the variant for a
    /// condition the scenario is WAITING to happen (e.g. a restarted
    /// validator resuming a background loop).
    WaitForLogLineOnValidator {
        index: usize,
        needle: String,
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
            Step::ExpectReconfigurationOutputVersionAtLeast(v) => {
                write!(f, "expect_reconfiguration_output_version_at_least({v})")
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
            Step::ExpectLogLineOnValidator { index, needle } => {
                write!(
                    f,
                    "expect_log_line_present_on_validator({index}, {needle:?})"
                )
            }
            Step::WaitForLogLineOnValidator { index, needle } => {
                write!(f, "wait_for_log_line_on_validator({index}, {needle:?})")
            }
            Step::ParkMpcDrain {
                index,
                watchdog_bound_secs,
            } => write!(
                f,
                "park_mpc_drain({index}, watchdog={watchdog_bound_secs}s)"
            ),
            Step::WaitForRoundChannelAtCapacity { index } => {
                write!(f, "wait_for_round_channel_at_capacity({index})")
            }
            Step::ExpectDrainWedged {
                parked,
                peers,
                window,
                silence_ceiling_seconds,
            } => write!(
                f,
                "expect_drain_wedged(parked={parked}, peers={peers:?}, window={}s, \
                 silence_ceiling={silence_ceiling_seconds})",
                window.as_secs()
            ),
            Step::UnparkMpcDrain { index } => write!(f, "unpark_mpc_drain({index})"),
            Step::ExpectDrainResumed {
                index,
                peers,
                window,
                silence_ceiling_seconds,
            } => write!(
                f,
                "expect_drain_resumed({index}, peers={peers:?}, window={}s, \
                 silence_ceiling={silence_ceiling_seconds})",
                window.as_secs()
            ),
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
    /// Pins every validator's advertised protocol-version range. Set it in any
    /// scenario that must stay at ONE protocol version: with
    /// `MAX_PROTOCOL_VERSION` ahead of the version under test, a fully-swapped
    /// committee otherwise votes itself across the next boundary mid-run.
    pub supported_protocol_versions: Option<SupportedProtocolVersions>,
    /// Indices of validators kept on the DIRECT gRPC path (serving the
    /// `SuiStateMirror` relay). At a `stop_and_swap`, every OTHER swapped
    /// validator is flipped to peer-only `SuiStateMirrored` reading through
    /// these; joiners added via `join_validator_mirrored` mirror through them
    /// too. Empty (default) = every validator reads Sui directly.
    pub direct_validators: Vec<usize>,
    /// Genesis protocol version. `None` genesis-es at `ProtocolVersion::MIN`
    /// (the usual rolling-upgrade start). Set this to start the cluster at a
    /// higher version — e.g. a strict-bound v6 committee that has no relaxed
    /// (v5) phase because the binaries under test only agree at v6.
    pub genesis_protocol_version: Option<ProtocolVersion>,
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
            supported_protocol_versions: None,
            direct_validators: Vec::new(),
            genesis_protocol_version: None,
        }
    }

    /// Override the genesis protocol version (default `ProtocolVersion::MIN`).
    pub fn with_genesis_protocol_version(mut self, v: ProtocolVersion) -> Self {
        self.genesis_protocol_version = Some(v);
        self
    }

    /// Path to the `ika` CLI binary; required by `run_workload` steps.
    /// Pin every validator's advertised protocol-version range. See
    /// [`Scenario::supported_protocol_versions`].
    pub fn with_supported_protocol_versions(mut self, v: SupportedProtocolVersions) -> Self {
        self.supported_protocol_versions = Some(v);
        self
    }

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

    /// Assert every running validator installed a network-key reconfiguration
    /// output of at least `version` (3 = pre-aggregation, no longer produced
    /// since V3 is a hard error; 4 = aggregated; polled across all running
    /// validators' metrics).
    pub fn expect_reconfiguration_output_version_at_least(mut self, version: u64) -> Self {
        self.steps
            .push(Step::ExpectReconfigurationOutputVersionAtLeast(version));
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

    /// Assert the validator at `index`'s `node.log` contains `needle`. See
    /// [`Step::ExpectLogLineOnValidator`] for when to prefer this over the
    /// whole-cluster assertion.
    pub fn expect_log_line_present_on_validator(
        mut self,
        index: usize,
        needle: impl Into<String>,
    ) -> Self {
        self.steps.push(Step::ExpectLogLineOnValidator {
            index,
            needle: needle.into(),
        });
        self
    }

    /// Poll the validator at `index`'s `node.log` until `needle` appears,
    /// failing after the scenario's epoch timeout. See
    /// [`Step::WaitForLogLineOnValidator`].
    pub fn wait_for_log_line_on_validator(
        mut self,
        index: usize,
        needle: impl Into<String>,
    ) -> Self {
        self.steps.push(Step::WaitForLogLineOnValidator {
            index,
            needle: needle.into(),
        });
        self
    }

    /// Restart validator `index` with the MPC-drain park hook armed and its
    /// commit-liveness bound lowered to `watchdog_bound_secs`. See
    /// [`Step::ParkMpcDrain`] — in particular why the bound override is what
    /// makes the hold assertion non-vacuous.
    pub fn park_mpc_drain(mut self, index: usize, watchdog_bound_secs: u64) -> Self {
        self.steps.push(Step::ParkMpcDrain {
            index,
            watchdog_bound_secs,
        });
        self
    }

    /// Wait until validator `index`'s round channel pins at capacity.
    pub fn wait_for_round_channel_at_capacity(mut self, index: usize) -> Self {
        self.steps
            .push(Step::WaitForRoundChannelAtCapacity { index });
        self
    }

    /// The two-sided wedge assertion. See [`Step::ExpectDrainWedged`].
    pub fn expect_drain_wedged(
        mut self,
        parked: usize,
        peers: &[usize],
        window: Duration,
        silence_ceiling_seconds: i64,
    ) -> Self {
        self.steps.push(Step::ExpectDrainWedged {
            parked,
            peers: peers.to_vec(),
            window,
            silence_ceiling_seconds,
        });
        self
    }

    /// Release the park on validator `index`. See [`Step::UnparkMpcDrain`].
    pub fn unpark_mpc_drain(mut self, index: usize) -> Self {
        self.steps.push(Step::UnparkMpcDrain { index });
        self
    }

    /// Assert the unparked validator recovers without a restart. See
    /// [`Step::ExpectDrainResumed`].
    pub fn expect_drain_resumed(
        mut self,
        index: usize,
        peers: &[usize],
        window: Duration,
        silence_ceiling_seconds: i64,
    ) -> Self {
        self.steps.push(Step::ExpectDrainResumed {
            index,
            peers: peers.to_vec(),
            window,
            silence_ceiling_seconds,
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
        // Per-boundary, per-authority outcome of every
        // ExpectNetworkKeyOutputConverged step. Each boundary tolerates the
        // legitimate straggler ordering (quorum finalizes, the validator
        // under test's output is discarded, no comparable evidence appears in
        // time) — but the scenario as a whole must witness byte-equality
        // between EVERY validator under test and a finalizing quorum on at
        // least one boundary each, enforced after the step loop.
        let mut network_key_evidence: Vec<NetworkKeyBoundaryEvidence> = Vec::new();
        // The parked validator's LAST wedge sample, carried to the recovery
        // step. Comparing the recovery against this rather than against a
        // fresh baseline is what closes the gap between the two steps: a
        // restart there would reset the process uptime, and only a comparison
        // that straddles both windows can see it.
        let mut wedged_sample: Option<DrainWedgeSample> = None;

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
                    .with_genesis_protocol_version(
                        self.genesis_protocol_version
                            .unwrap_or(ProtocolVersion::MIN),
                    )
                    .with_genesis_global_presign_config(self.genesis_global_presign_config);
                    if let Some(versions) = self.supported_protocol_versions {
                        builder = builder.with_supported_protocol_versions(versions);
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
                Step::ExpectReconfigurationOutputVersionAtLeast(at_least) => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectReconfigurationOutputVersionAtLeast before StartAll")?;
                    let deadline = tokio::time::Instant::now() + self.epoch_timeout;
                    loop {
                        let got = c.min_latest_reconfiguration_output_version().await;
                        if got >= *at_least {
                            tracing::info!(
                                got,
                                expected = *at_least,
                                "reconfiguration output version assertion passed"
                            );
                            break;
                        }
                        if tokio::time::Instant::now() >= deadline {
                            bail!(
                                "min installed reconfiguration output version {got} < expected \
                                 {at_least} after timeout"
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
                    // an incomplete quorum observation is itself release-blocking.
                    let evidence = c
                        .expect_network_key_output_converged(
                            observer_indices,
                            self.epoch_timeout
                                .min(NETWORK_KEY_OUTPUT_OBSERVATION_TIMEOUT),
                        )
                        .await?;
                    if evidence.is_conclusive() {
                        tracing::info!(
                            evidenced = ?evidence.evidenced_authorities,
                            "network-key output convergence: byte-level candidate evidence witnessed at this boundary"
                        );
                    } else {
                        tracing::warn!(
                            unevidenced = ?evidence.unevidenced_authorities,
                            "network-key output convergence: quorum converged cleanly but validator(s) under test provided no byte-equality evidence at this boundary (production legitimately discarded a straggling output); each must be evidenced at some boundary in this scenario"
                        );
                    }
                    network_key_evidence.push(evidence);
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
                Step::ExpectLogLineOnValidator { index, needle } => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectLogLineOnValidator before StartAll")?;
                    let proc = c
                        .validators
                        .get(*index)
                        .with_context(|| format!("validator index {index} out of range"))?;
                    let log = std::fs::read_to_string(proc.log_path()).with_context(|| {
                        format!("read validator log {}", proc.log_path().display())
                    })?;
                    ensure!(
                        log.contains(needle.as_str()),
                        "expected {needle:?} to be present in {}, but it was absent",
                        proc.log_path().display(),
                    );
                    tracing::info!(
                        index = *index,
                        needle = needle.as_str(),
                        "per-validator log-line assertion passed"
                    );
                }
                Step::WaitForLogLineOnValidator { index, needle } => {
                    let c = cluster
                        .as_ref()
                        .context("WaitForLogLineOnValidator before StartAll")?;
                    let proc = c
                        .validators
                        .get(*index)
                        .with_context(|| format!("validator index {index} out of range"))?;
                    let deadline = std::time::Instant::now() + self.epoch_timeout;
                    loop {
                        let log = std::fs::read_to_string(proc.log_path()).with_context(|| {
                            format!("read validator log {}", proc.log_path().display())
                        })?;
                        if log.contains(needle.as_str()) {
                            tracing::info!(
                                index = *index,
                                needle = needle.as_str(),
                                "per-validator log line appeared"
                            );
                            break;
                        }
                        ensure!(
                            std::time::Instant::now() < deadline,
                            "timed out waiting for {needle:?} in {}",
                            proc.log_path().display(),
                        );
                        sleep(Duration::from_secs(2)).await;
                    }
                }
                Step::ParkMpcDrain {
                    index,
                    watchdog_bound_secs,
                } => {
                    let c = cluster.as_mut().context("ParkMpcDrain before StartAll")?;
                    let sentinel = c.validator_data_path(*index, UNPARK_SENTINEL_FILE_NAME)?;
                    // A previous run's sentinel would unpark the drain the
                    // instant it parked, and the scenario would then time out
                    // waiting for a wedge that had already been released.
                    if sentinel.exists() {
                        std::fs::remove_file(&sentinel).with_context(|| {
                            format!("remove stale unpark sentinel {}", sentinel.display())
                        })?;
                    }
                    c.restart_validator_with_env(
                        *index,
                        [
                            (
                                PARK_MPC_DRAIN_AFTER_ROUND_ENV_VAR.to_string(),
                                PARK_AFTER_ROUNDS.to_string(),
                            ),
                            (
                                PARK_MPC_DRAIN_UNPARK_FILE_ENV_VAR.to_string(),
                                sentinel.display().to_string(),
                            ),
                            (
                                COMMIT_LIVENESS_WATCHDOG_SECS_ENV_VAR.to_string(),
                                watchdog_bound_secs.to_string(),
                            ),
                        ],
                    )
                    .await?;
                    tracing::info!(
                        index = *index,
                        watchdog_bound_secs,
                        sentinel = %sentinel.display(),
                        "MPC drain park hook armed; this validator stops consuming rounds once \
                         its boot replay finishes"
                    );
                }
                Step::WaitForRoundChannelAtCapacity { index } => {
                    let c = cluster
                        .as_ref()
                        .context("WaitForRoundChannelAtCapacity before StartAll")?;
                    c.wait_for_round_channel_at_capacity(*index, self.epoch_timeout)
                        .await?;
                }
                Step::ExpectDrainWedged {
                    parked,
                    peers,
                    window,
                    silence_ceiling_seconds,
                } => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectDrainWedged before StartAll")?;
                    let mut before = vec![c.scrape_drain_wedge(*parked).await?];
                    for peer in peers {
                        before.push(c.scrape_drain_wedge(*peer).await?);
                    }
                    tracing::info!(
                        parked = *parked,
                        ?before,
                        window_secs = window.as_secs(),
                        "wedge observation window opened"
                    );
                    sleep(*window).await;
                    let after_parked = c.scrape_drain_wedge(*parked).await?;
                    evaluate_wedged_drain(
                        &before[0],
                        &after_parked,
                        *window,
                        *silence_ceiling_seconds,
                    )
                    .with_context(|| {
                        format!("validator {parked} is not showing the wedged-drain signature")
                    })?;
                    for (offset, peer) in peers.iter().enumerate() {
                        let after_peer = c.scrape_drain_wedge(*peer).await?;
                        evaluate_healthy_drain(
                            &before[offset + 1],
                            &after_peer,
                            *window,
                            *silence_ceiling_seconds,
                        )
                        .with_context(|| {
                            format!(
                                "peer validator {peer} tripped a wedged-drain signal while only \
                                 validator {parked} was parked"
                            )
                        })?;
                    }
                    tracing::info!(
                        parked = *parked,
                        ?after_parked,
                        "wedged-drain assertion passed: one validator's fold is parked behind its \
                         own drain, the watchdog is holding, and the peers are unaffected"
                    );
                    wedged_sample = Some(after_parked);
                }
                Step::UnparkMpcDrain { index } => {
                    let c = cluster.as_ref().context("UnparkMpcDrain before StartAll")?;
                    let sentinel = c.validator_data_path(*index, UNPARK_SENTINEL_FILE_NAME)?;
                    std::fs::write(&sentinel, b"unpark\n")
                        .with_context(|| format!("write unpark sentinel {}", sentinel.display()))?;
                    tracing::info!(
                        index = *index,
                        sentinel = %sentinel.display(),
                        "unpark sentinel written; the drain must resume without a restart"
                    );
                }
                Step::ExpectDrainResumed {
                    index,
                    peers,
                    window,
                    silence_ceiling_seconds,
                } => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectDrainResumed before StartAll")?;
                    let wedged = wedged_sample
                        .as_ref()
                        .context("ExpectDrainResumed before ExpectDrainWedged")?;
                    // Resumption first, then health: the drain has to consume
                    // past the round it was stuck on before a window means
                    // anything, and how long the backlog takes to clear is the
                    // machine's, not the scenario's, to decide.
                    let resumed = c
                        .wait_for_mpc_consumed_round_past(
                            *index,
                            wedged.last_process_mpc_consensus_round,
                            self.epoch_timeout,
                        )
                        .await?;
                    ensure!(
                        resumed.process_uptime_seconds >= wedged.process_uptime_seconds,
                        "validator {index} RESTARTED across the park: \
                         ika_validator_process_uptime_seconds went {} -> {}. The whole claim is \
                         that a wedged drain needs no restart to recover — a supervisor bounce \
                         would make the recovery evidence worthless",
                        wedged.process_uptime_seconds,
                        resumed.process_uptime_seconds
                    );
                    let mut before = vec![c.scrape_drain_wedge(*index).await?];
                    for peer in peers {
                        before.push(c.scrape_drain_wedge(*peer).await?);
                    }
                    sleep(*window).await;
                    for (offset, validator) in
                        std::iter::once(index).chain(peers.iter()).enumerate()
                    {
                        let after = c.scrape_drain_wedge(*validator).await?;
                        evaluate_healthy_drain(
                            &before[offset],
                            &after,
                            *window,
                            *silence_ceiling_seconds,
                        )
                        .with_context(|| {
                            format!(
                                "validator {validator} is not draining normally after the park \
                                 was released"
                            )
                        })?;
                    }
                    tracing::info!(
                        index = *index,
                        was_stuck_at = wedged.last_process_mpc_consensus_round,
                        "drain-resumed assertion passed: the unparked validator drained its \
                         backlog and now looks exactly like its peers, with no restart"
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
                        c.grpc_url().to_string(),
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
        require_cross_version_output_evidence(&network_key_evidence)?;
        if timing_snapshots.len() >= 2 {
            println!("{}", mpc_timings::render_comparison(&timing_snapshots));
        }
        Ok(ScenarioReport { timing_snapshots })
    }
}

/// Scenario-level cross-version compatibility gate over the per-boundary,
/// per-authority outcomes of every `expect_network_key_output_converged`
/// step.
///
/// A boundary where a validator under test produced no comparable output is
/// legitimate (production finalizes at a Byzantine quorum and discards a
/// computation that finishes afterwards) — but quorum-only convergence proves
/// nothing about that validator's bytes, so every validator that was ever
/// under test must have demonstrated byte-equality with a finalizing quorum
/// at SOME boundary, or the scenario has not demonstrated cross-version
/// output compatibility for it and must fail rather than pass vacuously.
/// Scenarios without convergence steps are unaffected.
fn require_cross_version_output_evidence(boundaries: &[NetworkKeyBoundaryEvidence]) -> Result<()> {
    let never_evidenced: Vec<String> = boundaries
        .iter()
        .flat_map(|boundary| boundary.unevidenced_authorities.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|authority| {
            !boundaries
                .iter()
                .any(|boundary| boundary.evidenced_authorities.contains(*authority))
        })
        .map(|authority| {
            let reasons: Vec<&str> = boundaries
                .iter()
                .filter_map(|boundary| {
                    boundary
                        .unevidenced_authorities
                        .get(authority)
                        .map(String::as_str)
                })
                .collect();
            format!("{authority}: {}", reasons.join(" / "))
        })
        .collect();
    ensure!(
        never_evidenced.is_empty(),
        "insufficient cross-version compatibility evidence: validator(s) under test never \
         demonstrated byte-equality with a finalizing quorum at any network-key \
         reconfiguration boundary (no submitted output inside the converged set and no \
         matching late-computation digest): {}",
        never_evidenced.join("; ")
    );
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn evidenced(authorities: &[&str]) -> NetworkKeyBoundaryEvidence {
        NetworkKeyBoundaryEvidence {
            evidenced_authorities: authorities.iter().map(|a| a.to_string()).collect(),
            unevidenced_authorities: BTreeMap::new(),
        }
    }

    fn unevidenced(authorities_and_reasons: &[(&str, &str)]) -> NetworkKeyBoundaryEvidence {
        NetworkKeyBoundaryEvidence {
            evidenced_authorities: BTreeSet::new(),
            unevidenced_authorities: authorities_and_reasons
                .iter()
                .map(|(authority, reason)| (authority.to_string(), reason.to_string()))
                .collect(),
        }
    }

    #[test]
    fn no_convergence_steps_need_no_evidence() {
        require_cross_version_output_evidence(&[]).unwrap();
    }

    #[test]
    fn one_evidenced_boundary_per_validator_satisfies_the_scenario() {
        // The straggler ordering at one boundary is legitimate as long as the
        // other boundary witnessed byte-equality — in either order.
        require_cross_version_output_evidence(&[
            evidenced(&["a"]),
            unevidenced(&[("a", "session s (no submitted output)")]),
        ])
        .unwrap();
        require_cross_version_output_evidence(&[
            unevidenced(&[("a", "session s (no submitted output)")]),
            evidenced(&["a"]),
        ])
        .unwrap();
    }

    #[test]
    fn all_boundaries_unevidenced_fail_the_scenario() {
        let error = require_cross_version_output_evidence(&[
            unevidenced(&[("a", "validator 0: session s1 (no submitted output)")]),
            unevidenced(&[("a", "validator 0: session s2 (no submitted output)")]),
        ])
        .expect_err("quorum-only convergence at every boundary must not pass the gate");
        let error = error.to_string();
        assert!(error.contains("insufficient cross-version compatibility evidence"));
        assert!(error.contains("session s1"));
        assert!(error.contains("session s2"));
    }

    #[test]
    fn a_validator_only_ever_unevidenced_fails_even_if_another_is_conclusive() {
        // Evidence is per validator under test, not per boundary: a rolling
        // scenario whose observer set grows must still byte-check every
        // upgraded validator somewhere.
        let mut second_boundary = evidenced(&["a"]);
        second_boundary.unevidenced_authorities.insert(
            "b".to_string(),
            "session s (no submitted output)".to_string(),
        );
        let error = require_cross_version_output_evidence(&[evidenced(&["a"]), second_boundary])
            .expect_err("an upgraded validator that was never byte-checked must fail the gate");
        let error = error.to_string();
        assert!(error.contains("b:"));
        assert!(!error.contains("a:"));
    }
}
