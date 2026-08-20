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

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use ika_protocol_config::ProtocolVersion;
use ika_swarm_config::sui_client::GenesisGlobalPresignConfig;
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
use tokio::time::sleep;

use crate::DEFAULT_EPOCH_DURATION_MS;
use crate::binary::{BinaryResolver, BinarySpec};
use crate::cluster::{ClusterBuilder, ClusterOfProcesses, NetworkKeyBoundaryEvidence};
use crate::mpc_timings::{self, TimingSnapshot};
use crate::workload::WorkloadDriver;

const NETWORK_KEY_OUTPUT_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(60);

/// How long to wait for a peer to witness an MPC output from a named
/// validator. Bounded well below an epoch on purpose: this assertion is only
/// meaningful inside the epoch under test, and a poll that outlives the
/// boundary reports a timeout for a question that stopped being asked. The
/// epoch ceiling aborts sooner still.
const MPC_WITNESS_TIMEOUT: Duration = Duration::from_secs(300);

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
    /// Instantaneous ceiling on the on-chain epoch: fails if the network has
    /// already advanced past `epoch`. Brackets any experiment whose subject is
    /// MID-epoch state — an epoch boundary hands every validator a fresh epoch
    /// store, so a scenario that drifts across one stops testing what it
    /// claims to and still passes.
    ExpectEpochAtMost(u64),
    ExpectAllValidatorsProtocolVersionAtMost(u64),
    ExpectNetworkKeyReconfigurationNotStarted(u64),
    WaitForNetworkKeyReconfigurationStarted(u64),
    WaitForNetworkKeyReconfigurationCompleted(u64),
    /// Poll until every running validator reports a canonical network DKG
    /// output version `>= at_least` (via its `/metrics`), or time out. Confirms
    /// the off-chain handoff migrated the DKG output (e.g. 2 -> 3 after the v4
    /// reconfiguration); the on-chain copy stays V2, so this is metric-based.
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
    /// Poll ONE validator's `node.log` until `needle` appears (or the
    /// epoch timeout elapses). The immediate [`Step::ExpectLogLineOnValidator`]
    /// asserts a decision that already happened; this is the variant for a
    /// condition the scenario is WAITING to happen (e.g. a restarted
    /// validator resuming a background loop).
    WaitForLogLineOnValidator {
        index: usize,
        needle: String,
    },
    /// Snapshot every observer's cumulative `ika_skipped_consensus_txns`
    /// under `label`, opening a measurement window that
    /// [`Step::ExpectSkippedConsensusTxnsDelta`] closes.
    RecordSkippedConsensusTxns {
        label: String,
        observer_indices: Vec<usize>,
    },
    /// Close the window opened by `since` and report how many already-folded
    /// consensus transactions the observers were re-sent inside it.
    ///
    /// `min_delta` is a liveness floor on the COUNTERS, not a claim about
    /// re-emission: a window containing a workload that records zero skips
    /// means the observation point is dead, which is the one way this
    /// measurement can be silently worthless.
    ///
    /// `compare_to` names an earlier window of equivalent composition. Its
    /// total is REPORTED alongside this one and the difference is the measured
    /// re-emission figure — it is deliberately not asserted on. An earlier
    /// version required this window to exceed the control; that was a
    /// prediction dressed as an assertion, and measuring it falsified the
    /// prediction. What the difference is worth saying about is whatever it
    /// turns out to be, including nothing.
    ExpectSkippedConsensusTxnsDelta {
        since: String,
        observer_indices: Vec<usize>,
        min_delta: u64,
        compare_to: Option<String>,
    },
    /// Snapshot, under `label`, how many times `needle` appears in one
    /// validator's log. Opens a probe that [`Step::WaitForNewLogLineOnValidator`]
    /// closes.
    RecordLogLineCountOnValidator {
        label: String,
        index: usize,
        needle: String,
    },
    /// Poll until `needle` has appeared on that validator MORE times than the
    /// `since` snapshot counted.
    ///
    /// This is the probe for a line BOTH binaries can emit. Logs append across
    /// restarts, so [`Step::WaitForLogLineOnValidator`] would be satisfied by
    /// an occurrence from before a swap; only a fresh occurrence is evidence
    /// about the binary that was swapped in.
    WaitForNewLogLineOnValidator {
        since: String,
        index: usize,
    },
    /// Wait until `index`'s consumed MPC round reaches the round its `peers`
    /// had already consumed when the step began. The target is snapshotted
    /// once, so this is "catch up to where the network was", not a moving
    /// finish line the step could chase forever.
    WaitForMpcRoundToReachPeers {
        index: usize,
        peer_indices: Vec<usize>,
    },
    /// Snapshot, under `label`, the sessions for which `observer` has already
    /// seen an MPC output authored by `subject`.
    RecordMpcOutputSessions {
        label: String,
        observer_index: usize,
        subject_index: usize,
    },
    /// Assert `observer` has since seen an MPC output authored by `subject`
    /// for a session that was NOT in the `since` snapshot — a peer witnessing
    /// the subject compute and submit for work created after that snapshot.
    /// Self-reported liveness cannot make this claim.
    ///
    /// The series it reads is ephemeral (zeroed when a session leaves the
    /// active map), so this ACCUMULATES observations across a fast poll rather
    /// than sampling: a session that begins and ends between two polls would
    /// otherwise be invisible. It also aborts the moment the epoch passes
    /// `epoch_ceiling` — a timeout blamed on the subject, reported after the
    /// boundary already handed it a fresh epoch store, is a misdiagnosis
    /// generator.
    ExpectNewMpcOutputSession {
        since: String,
        observer_index: usize,
        subject_index: usize,
        epoch_ceiling: u64,
    },
    /// Snapshot, under `label`, one validator's total completed MPC
    /// computations.
    RecordMpcCompletions {
        label: String,
        index: usize,
    },
    /// Poll until that validator's completed-session total has risen above the
    /// `since` snapshot.
    ///
    /// What this actually proves, stated narrowly because an earlier version
    /// of it overclaimed: `add_completion` fires when the node processes a
    /// session reaching quorum AND holds that session's request metadata
    /// (`mpc_manager.rs::complete_mpc_session`). It is evidence the node is
    /// tracking sessions through to completion — a pure spectator with no
    /// session state never increments it — NOT evidence that it performed
    /// cryptography. The peer-witness above is what evidences contribution.
    ///
    /// It POLLS. The counter moves when the subject processes the quorum on a
    /// later consensus round, which is after a peer can already observe the
    /// subject's output: reading it once, immediately after a workload, raced
    /// and failed twice on healthy validators that a peer had witnessed
    /// contributing 5 ms earlier.
    ExpectMoreMpcCompletions {
        since: String,
        index: usize,
        epoch_ceiling: u64,
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
            Step::ExpectEpochAtMost(epoch) => {
                write!(f, "expect_epoch_at_most({epoch})")
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
            Step::RecordSkippedConsensusTxns {
                label,
                observer_indices,
            } => write!(
                f,
                "record_skipped_consensus_txns({label:?}, {observer_indices:?})"
            ),
            Step::ExpectSkippedConsensusTxnsDelta {
                since,
                observer_indices,
                min_delta,
                compare_to,
            } => write!(
                f,
                "expect_skipped_consensus_txns_delta(since={since:?}, {observer_indices:?}, \
                 min_delta={min_delta}, compare_to={compare_to:?})"
            ),
            Step::RecordLogLineCountOnValidator {
                label,
                index,
                needle,
            } => write!(
                f,
                "record_log_line_count_on_validator({label:?}, {index}, {needle:?})"
            ),
            Step::WaitForNewLogLineOnValidator { since, index } => {
                write!(f, "wait_for_new_log_line_on_validator({since:?}, {index})")
            }
            Step::WaitForMpcRoundToReachPeers {
                index,
                peer_indices,
            } => write!(
                f,
                "wait_for_mpc_round_to_reach_peers({index}, {peer_indices:?})"
            ),
            Step::RecordMpcOutputSessions {
                label,
                observer_index,
                subject_index,
            } => write!(
                f,
                "record_mpc_output_sessions({label:?}, observer={observer_index}, \
                 subject={subject_index})"
            ),
            Step::ExpectNewMpcOutputSession {
                since,
                observer_index,
                subject_index,
                epoch_ceiling,
            } => write!(
                f,
                "expect_new_mpc_output_session(since={since:?}, observer={observer_index}, \
                 subject={subject_index}, epoch_ceiling={epoch_ceiling})"
            ),
            Step::RecordMpcCompletions { label, index } => {
                write!(f, "record_mpc_completions({label:?}, {index})")
            }
            Step::ExpectMoreMpcCompletions {
                since,
                index,
                epoch_ceiling,
            } => write!(
                f,
                "expect_more_mpc_completions(since={since:?}, {index}, \
                 epoch_ceiling={epoch_ceiling})"
            ),
        }
    }
}

/// One opened log-occurrence probe: which validator and needle it counted, and
/// how many occurrences the log already held at that moment.
struct LogLineProbe {
    index: usize,
    needle: String,
    count: usize,
}

/// One opened consensus re-submission measurement window: the observers it
/// was opened over, their cumulative skip counters at that moment, and the
/// per-kind committed-transaction counts to difference the composition
/// against.
struct ResubmissionWindow {
    observers: Vec<usize>,
    skipped: Vec<u64>,
    /// How many times each observer had been restarted when the window
    /// opened, aligned with `observers`. A counter is process-scoped, so an
    /// observer that restarts mid-window silently turns the closing
    /// subtraction into nonsense; comparing these catches it.
    observer_restarts: Vec<u64>,
    processed_by_kind: BTreeMap<String, u64>,
}

/// What a scenario run produced beyond pass/fail: the labeled MPC timing
/// snapshots, in recording order. The comparison between consecutive
/// snapshots is printed by `run` itself; tests can also inspect the raw
/// numbers here.
pub struct ScenarioReport {
    pub timing_snapshots: Vec<TimingSnapshot>,
    /// How many already-folded consensus transactions each closed
    /// re-submission window measured, by the label that opened it. Carried out
    /// of the run so a scenario whose POINT is the number can state it in its
    /// own closing line rather than leaving it buried in the step log.
    pub resubmission_totals: BTreeMap<String, u64>,
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

    /// Assert the network is still in `epoch` or earlier. Place around any
    /// experiment on mid-epoch state. See [`Step::ExpectEpochAtMost`].
    pub fn expect_epoch_at_most(mut self, epoch: u64) -> Self {
        self.steps.push(Step::ExpectEpochAtMost(epoch));
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

    /// Open a re-submission measurement window. See
    /// [`Step::RecordSkippedConsensusTxns`].
    pub fn record_skipped_consensus_txns(
        mut self,
        label: &str,
        observer_indices: &[usize],
    ) -> Self {
        self.steps.push(Step::RecordSkippedConsensusTxns {
            label: label.to_string(),
            observer_indices: observer_indices.to_vec(),
        });
        self
    }

    /// Close a re-submission window and assert what it re-sent. See
    /// [`Step::ExpectSkippedConsensusTxnsDelta`].
    pub fn expect_skipped_consensus_txns_delta(
        mut self,
        since: &str,
        observer_indices: &[usize],
        min_delta: u64,
        compare_to: Option<&str>,
    ) -> Self {
        self.steps.push(Step::ExpectSkippedConsensusTxnsDelta {
            since: since.to_string(),
            observer_indices: observer_indices.to_vec(),
            min_delta,
            compare_to: compare_to.map(str::to_string),
        });
        self
    }

    /// Open a log-occurrence probe. See
    /// [`Step::RecordLogLineCountOnValidator`].
    pub fn record_log_line_count_on_validator(
        mut self,
        label: &str,
        index: usize,
        needle: &str,
    ) -> Self {
        self.steps.push(Step::RecordLogLineCountOnValidator {
            label: label.to_string(),
            index,
            needle: needle.to_string(),
        });
        self
    }

    /// Wait for a FRESH occurrence of a probed log line. See
    /// [`Step::WaitForNewLogLineOnValidator`].
    pub fn wait_for_new_log_line_on_validator(mut self, since: &str, index: usize) -> Self {
        self.steps.push(Step::WaitForNewLogLineOnValidator {
            since: since.to_string(),
            index,
        });
        self
    }

    /// Wait for one validator's MPC round processing to catch up to its
    /// peers'. See [`Step::WaitForMpcRoundToReachPeers`].
    pub fn wait_for_mpc_round_to_reach_peers(
        mut self,
        index: usize,
        peer_indices: &[usize],
    ) -> Self {
        self.steps.push(Step::WaitForMpcRoundToReachPeers {
            index,
            peer_indices: peer_indices.to_vec(),
        });
        self
    }

    /// Snapshot which of `subject`'s MPC outputs `observer` has already seen.
    /// See [`Step::RecordMpcOutputSessions`].
    pub fn record_mpc_output_sessions(
        mut self,
        label: &str,
        observer_index: usize,
        subject_index: usize,
    ) -> Self {
        self.steps.push(Step::RecordMpcOutputSessions {
            label: label.to_string(),
            observer_index,
            subject_index,
        });
        self
    }

    /// Assert a peer has since witnessed a NEW MPC output from `subject`. See
    /// [`Step::ExpectNewMpcOutputSession`].
    pub fn expect_new_mpc_output_session(
        mut self,
        since: &str,
        observer_index: usize,
        subject_index: usize,
        epoch_ceiling: u64,
    ) -> Self {
        self.steps.push(Step::ExpectNewMpcOutputSession {
            since: since.to_string(),
            observer_index,
            subject_index,
            epoch_ceiling,
        });
        self
    }

    /// Snapshot one validator's completed-MPC-computation total. See
    /// [`Step::RecordMpcCompletions`].
    pub fn record_mpc_completions(mut self, label: &str, index: usize) -> Self {
        self.steps.push(Step::RecordMpcCompletions {
            label: label.to_string(),
            index,
        });
        self
    }

    /// Assert that validator has computed since the snapshot. See
    /// [`Step::ExpectMoreMpcCompletions`].
    pub fn expect_more_mpc_completions(
        mut self,
        since: &str,
        index: usize,
        epoch_ceiling: u64,
    ) -> Self {
        self.steps.push(Step::ExpectMoreMpcCompletions {
            since: since.to_string(),
            index,
            epoch_ceiling,
        });
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
        // Open re-submission measurement windows, by the label that opened
        // them, and the totals the closed ones measured (so a later window can
        // be asserted against an earlier one).
        let mut resubmission_windows: BTreeMap<String, ResubmissionWindow> = BTreeMap::new();
        let mut resubmission_totals: BTreeMap<String, u64> = BTreeMap::new();
        // Sessions an observer had already seen an output from a subject for,
        // by the label that snapshotted them.
        let mut mpc_output_sessions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        // Open log-occurrence probes, by the label that snapshotted them.
        let mut log_line_probes: BTreeMap<String, LogLineProbe> = BTreeMap::new();
        // Completed-MPC-computation snapshots: label -> (validator, total).
        let mut mpc_completions: BTreeMap<String, (usize, u64)> = BTreeMap::new();
        // How many times each validator's PROCESS has been replaced. Every
        // process-scoped measurement is only comparable within one generation
        // of it, so the steps that take one record this alongside the value.
        let mut restart_counts: BTreeMap<usize, u64> = BTreeMap::new();

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
                    for index in validators {
                        *restart_counts.entry(*index).or_default() += 1;
                    }
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
                Step::ExpectEpochAtMost(epoch) => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectEpochAtMost before StartAll")?;
                    let got = c.current_epoch().await?;
                    ensure!(
                        got <= *epoch,
                        "the network is in epoch {got}, past the expected ceiling of {epoch} — \
                         the boundary handed every validator a fresh epoch store, so anything \
                         this scenario asserts about mid-epoch state after that point is about \
                         a different epoch than the one under test"
                    );
                    tracing::info!(
                        got,
                        expected_at_most = *epoch,
                        "epoch ceiling assertion passed"
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
                    *restart_counts.entry(*index).or_default() += 1;
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
                Step::RecordSkippedConsensusTxns {
                    label,
                    observer_indices,
                } => {
                    let c = cluster
                        .as_ref()
                        .context("RecordSkippedConsensusTxns before StartAll")?;
                    let skipped = c.skipped_consensus_txns(observer_indices).await?;
                    let processed_by_kind = c
                        .consensus_handler_processed_by_kind(observer_indices)
                        .await?;
                    tracing::info!(
                        label = label.as_str(),
                        observers = ?observer_indices,
                        skipped = ?skipped,
                        "opened a consensus re-submission measurement window"
                    );
                    let observer_restarts = observer_indices
                        .iter()
                        .map(|index| restart_counts.get(index).copied().unwrap_or(0))
                        .collect();
                    resubmission_windows.insert(
                        label.clone(),
                        ResubmissionWindow {
                            observers: observer_indices.clone(),
                            skipped,
                            observer_restarts,
                            processed_by_kind,
                        },
                    );
                }
                Step::ExpectSkippedConsensusTxnsDelta {
                    since,
                    observer_indices,
                    min_delta,
                    compare_to,
                } => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectSkippedConsensusTxnsDelta before StartAll")?;
                    let window = resubmission_windows
                        .get(since)
                        .with_context(|| format!("no re-submission window opened as {since:?}"))?;
                    ensure!(
                        &window.observers == observer_indices,
                        "window {since:?} was opened over observers {:?} but is being closed over \
                         {observer_indices:?}; the counters would not be comparable",
                        window.observers,
                    );
                    // Before any number is computed, let alone reported: a
                    // window whose observers restarted has nothing to say.
                    let restarts_now: Vec<u64> = observer_indices
                        .iter()
                        .map(|index| restart_counts.get(index).copied().unwrap_or(0))
                        .collect();
                    require_observers_not_restarted(
                        observer_indices,
                        &window.observer_restarts,
                        &restarts_now,
                    )
                    .with_context(|| format!("re-submission window {since:?}"))?;
                    let now = c.skipped_consensus_txns(observer_indices).await?;
                    let per_observer: Vec<u64> = now
                        .iter()
                        .zip(&window.skipped)
                        .map(|(now, opened)| now.saturating_sub(*opened))
                        .collect();
                    let measured: u64 = per_observer.iter().sum();
                    // Composition of what the window carried, so the headline
                    // number says WHAT was re-sent and not only how much.
                    let committed_by_kind = c
                        .consensus_handler_processed_by_kind(observer_indices)
                        .await?;
                    let by_kind: BTreeMap<&String, u64> = committed_by_kind
                        .iter()
                        .map(|(kind, count)| {
                            let opened = window.processed_by_kind.get(kind).copied().unwrap_or(0);
                            (kind, count.saturating_sub(opened))
                        })
                        .filter(|(_, delta)| *delta > 0)
                        .collect();
                    tracing::info!(
                        window = since.as_str(),
                        re_submitted_consensus_transactions = measured,
                        per_observer = ?per_observer,
                        observers = ?observer_indices,
                        committed_by_kind = ?by_kind,
                        "MEASURED: consensus transactions re-sent for already-folded work"
                    );
                    require_resubmission_counters_alive(measured, *min_delta)
                        .with_context(|| format!("re-submission window {since:?}"))?;
                    // The figure this scenario exists to produce: how much more
                    // the window carried than a window of equivalent
                    // composition without a rollback in it. Reported, never
                    // asserted on — its value is whatever it turns out to be.
                    if let Some(control) = compare_to {
                        let control_total =
                            resubmission_totals.get(control).copied().with_context(|| {
                                format!("comparison window {control:?} has not been measured yet")
                            })?;
                        tracing::info!(
                            window = since.as_str(),
                            rollback_delta = measured,
                            comparison_window = control.as_str(),
                            control_delta = control_total,
                            difference = measured as i64 - control_total as i64,
                            "MEASURED: re-emission attributable to the rollback"
                        );
                    }
                    resubmission_totals.insert(since.clone(), measured);
                }
                Step::RecordLogLineCountOnValidator {
                    label,
                    index,
                    needle,
                } => {
                    let c = cluster
                        .as_ref()
                        .context("RecordLogLineCountOnValidator before StartAll")?;
                    let count = c.log_line_count(*index, needle)?;
                    tracing::info!(
                        label = label.as_str(),
                        index = *index,
                        needle = needle.as_str(),
                        count,
                        "snapshotted a log-line occurrence count"
                    );
                    log_line_probes.insert(
                        label.clone(),
                        LogLineProbe {
                            index: *index,
                            needle: needle.clone(),
                            count,
                        },
                    );
                }
                Step::WaitForNewLogLineOnValidator { since, index } => {
                    let c = cluster
                        .as_ref()
                        .context("WaitForNewLogLineOnValidator before StartAll")?;
                    let probe = log_line_probes
                        .get(since)
                        .with_context(|| format!("no log-line probe opened as {since:?}"))?;
                    ensure!(
                        probe.index == *index,
                        "probe {since:?} counted validator {} but is being closed on validator \
                         {index}",
                        probe.index
                    );
                    let deadline = std::time::Instant::now() + self.epoch_timeout;
                    loop {
                        let count = c.log_line_count(*index, &probe.needle)?;
                        if count > probe.count {
                            tracing::info!(
                                index = *index,
                                needle = probe.needle.as_str(),
                                was = probe.count,
                                now = count,
                                "a fresh occurrence of the probed log line appeared"
                            );
                            break;
                        }
                        ensure!(
                            std::time::Instant::now() < deadline,
                            "validator {index} never emitted {:?} again within {:?} — the log \
                             still holds the {} occurrence(s) the {since:?} probe counted, all of \
                             them predating this phase",
                            probe.needle,
                            self.epoch_timeout,
                            probe.count,
                        );
                        sleep(Duration::from_secs(2)).await;
                    }
                }
                Step::WaitForMpcRoundToReachPeers {
                    index,
                    peer_indices,
                } => {
                    let c = cluster
                        .as_ref()
                        .context("WaitForMpcRoundToReachPeers before StartAll")?;
                    let target = c.min_mpc_consensus_round(peer_indices).await?;
                    ensure!(
                        target > 0,
                        "peers {peer_indices:?} have consumed no MPC rounds, so there is nothing \
                         for validator {index} to catch up to and the wait would pass without \
                         witnessing a re-derivation"
                    );
                    let start = c.mpc_consensus_round(*index).await?;
                    tracing::info!(
                        index = *index,
                        peers = ?peer_indices,
                        target,
                        start,
                        "waiting for MPC round processing to reach the round its peers had reached"
                    );
                    let reached = c
                        .wait_for_mpc_consensus_round(*index, target, self.epoch_timeout)
                        .await?;
                    tracing::info!(
                        index = *index,
                        target,
                        reached,
                        rounds_rebuilt = reached.saturating_sub(start),
                        "MPC round processing caught up with the peers' head"
                    );
                }
                Step::RecordMpcOutputSessions {
                    label,
                    observer_index,
                    subject_index,
                } => {
                    let c = cluster
                        .as_ref()
                        .context("RecordMpcOutputSessions before StartAll")?;
                    let sessions = c
                        .mpc_output_sessions_from(*observer_index, *subject_index)
                        .await?;
                    tracing::info!(
                        label = label.as_str(),
                        observer = *observer_index,
                        subject = *subject_index,
                        sessions = sessions.len(),
                        "snapshotted the sessions this observer has seen outputs from the subject for"
                    );
                    mpc_output_sessions.insert(label.clone(), sessions);
                }
                Step::ExpectNewMpcOutputSession {
                    since,
                    observer_index,
                    subject_index,
                    epoch_ceiling,
                } => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectNewMpcOutputSession before StartAll")?;
                    let baseline = mpc_output_sessions
                        .get(since)
                        .with_context(|| format!("no MPC-output snapshot taken as {since:?}"))?;
                    let started = std::time::Instant::now();
                    let deadline = started + MPC_WITNESS_TIMEOUT;
                    // Accumulated, not sampled: the series is zeroed when a
                    // session leaves the active map, so a short session is
                    // only ever visible to the poll that happens to overlap it.
                    let mut seen: BTreeSet<String> = BTreeSet::new();
                    loop {
                        seen.extend(
                            c.mpc_output_sessions_from(*observer_index, *subject_index)
                                .await?,
                        );
                        let fresh: BTreeSet<_> = seen.difference(baseline).collect();
                        if !fresh.is_empty() {
                            tracing::info!(
                                observer = *observer_index,
                                subject = *subject_index,
                                sessions = ?fresh,
                                witness_latency_seconds = started.elapsed().as_secs(),
                                "a peer witnessed new MPC outputs authored by the subject"
                            );
                            break;
                        }
                        // Fail on the boundary, not on the clock: past the
                        // ceiling the subject has a fresh epoch store and this
                        // assertion is no longer about the rollback at all.
                        let epoch = c.current_epoch().await?;
                        ensure!(
                            epoch <= *epoch_ceiling,
                            "the network reached epoch {epoch}, past the ceiling of \
                             {epoch_ceiling}, while waiting for validator {observer_index} to \
                             witness an MPC output from validator {subject_index}. The boundary \
                             ended the experiment — this says nothing about the subject"
                        );
                        ensure!(
                            std::time::Instant::now() < deadline,
                            "validator {observer_index} never witnessed an MPC output authored by \
                             validator {subject_index} for a session outside the {since:?} \
                             snapshot ({} sessions) within {:?}, while still inside epoch \
                             {epoch}; the subject is following consensus without contributing MPC",
                            baseline.len(),
                            MPC_WITNESS_TIMEOUT,
                        );
                        sleep(Duration::from_secs(1)).await;
                    }
                }
                Step::RecordMpcCompletions { label, index } => {
                    let c = cluster
                        .as_ref()
                        .context("RecordMpcCompletions before StartAll")?;
                    let completions = c.mpc_completions_total(*index).await?;
                    tracing::info!(
                        label = label.as_str(),
                        index = *index,
                        completions,
                        "snapshotted a validator's completed MPC computations"
                    );
                    mpc_completions.insert(label.clone(), (*index, completions));
                }
                Step::ExpectMoreMpcCompletions {
                    since,
                    index,
                    epoch_ceiling,
                } => {
                    let c = cluster
                        .as_ref()
                        .context("ExpectMoreMpcCompletions before StartAll")?;
                    let (snapshot_index, before) = mpc_completions
                        .get(since)
                        .copied()
                        .with_context(|| format!("no completions snapshot taken as {since:?}"))?;
                    ensure!(
                        snapshot_index == *index,
                        "snapshot {since:?} counted validator {snapshot_index} but is being \
                         closed on validator {index}"
                    );
                    let started = std::time::Instant::now();
                    let deadline = started + MPC_WITNESS_TIMEOUT;
                    loop {
                        let now = c.mpc_completions_total(*index).await?;
                        if now > before {
                            tracing::info!(
                                index = *index,
                                before,
                                now,
                                completed = now - before,
                                latency_seconds = started.elapsed().as_secs(),
                                "the validator's completed-session total rose"
                            );
                            break;
                        }
                        let epoch = c.current_epoch().await?;
                        ensure!(
                            epoch <= *epoch_ceiling,
                            "the network reached epoch {epoch}, past the ceiling of \
                             {epoch_ceiling}, while waiting for validator {index}'s \
                             completed-session total to rise above {before}. The boundary ended \
                             the experiment — this says nothing about the subject"
                        );
                        ensure!(
                            std::time::Instant::now() < deadline,
                            "validator {index}'s completed-session total stayed at {before} for \
                             {:?} after the {since:?} snapshot, inside epoch {epoch}. It is \
                             following consensus without carrying any session through to \
                             completion — note this is about session BOOKKEEPING reaching \
                             quorum, not about local cryptography, so read it next to the \
                             peer-witness assertion rather than instead of it",
                            MPC_WITNESS_TIMEOUT,
                        );
                        sleep(Duration::from_secs(1)).await;
                    }
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
        Ok(ScenarioReport {
            timing_snapshots,
            resubmission_totals,
        })
    }
}

/// Reject a window whose own observers were restarted while it was open.
///
/// `ika_skipped_consensus_txns` is process-scoped: a restart resets it to
/// zero, so the closing `now - at_open` is no longer a delta over the window —
/// it is the restarted process's absolute count, subtracted from a number that
/// belonged to a process that no longer exists. `saturating_sub` then hides
/// the negative, and what comes out looks like an ordinary measurement.
///
/// This exists because a fault dispatch escaped. F2a pointed both windows at
/// the validator being rolled back, precisely the observer that cannot see its
/// own re-emissions, and the run went GREEN: the window opened at 51, the
/// subject restarted, and it closed at 54 — a "delta" of 54 that was really a
/// fresh process's first minute of ordinary traffic. The liveness floor cannot
/// catch that, because 54 ≥ 1.
///
/// The check is on the STRUCTURE of the measurement rather than on its value,
/// so it holds for any window and any scenario, without knowing which
/// validator is under test.
fn require_observers_not_restarted(
    observers: &[usize],
    at_open: &[u64],
    at_close: &[u64],
) -> Result<()> {
    let restarted: Vec<usize> = observers
        .iter()
        .zip(at_open)
        .zip(at_close)
        .filter(|((_, open), close)| open != close)
        .map(|((index, _), _)| *index)
        .collect();
    ensure!(
        restarted.is_empty(),
        "validator(s) {restarted:?} restarted while this measurement window was open. Their \
         `ika_skipped_consensus_txns` counters reset with their processes, so the window's \
         subtraction is not a delta and the number it produces is meaningless — measure on \
         observers that stay up for the whole window"
    );
    Ok(())
}

/// Liveness check on a closed re-submission measurement window.
///
/// This asserts on the INSTRUMENT, not on the phenomenon. A window that
/// contains real traffic and still records zero skips means the observation
/// point is dead — the one way this measurement is silently worthless — so a
/// window carrying a workload must show something.
///
/// It deliberately does NOT compare against a control window. It used to: the
/// rollback window had to exceed a window of ordinary traffic, on the theory
/// that a re-derivation sprays re-submissions. Measuring it falsified that
/// theory (v1.3.1 reconstructs replayed sessions without recomputing them, so
/// there is little to re-submit), and an assertion that encodes a prediction
/// fails when the prediction is wrong rather than when the system is. The
/// comparison is now reported instead.
fn require_resubmission_counters_alive(measured: u64, min_delta: u64) -> Result<()> {
    ensure!(
        measured >= min_delta,
        "re-sent {measured} already-folded consensus transactions, fewer than the {min_delta} \
         this window must produce for its observation point to be alive at all"
    );
    Ok(())
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
    fn a_window_whose_observer_restarted_cannot_be_closed() {
        // The F2a escape, pinned: observer 0 restarted mid-window, so its
        // counter reset and the closing subtraction is not a delta.
        let error = require_observers_not_restarted(&[0], &[0], &[1])
            .expect_err("a restarted observer's counter cannot measure its own window");
        let error = error.to_string();
        assert!(
            error.contains("[0]"),
            "names the restarted observer: {error}"
        );
        assert!(error.contains("is not a delta"), "says why: {error}");
    }

    #[test]
    fn restarting_a_non_observer_leaves_the_window_measurable() {
        // The rollback window is opened over peers and the SUBJECT restarts
        // inside it — which is the whole scenario. The guard must not fire.
        require_observers_not_restarted(&[1, 2, 3], &[0, 0, 0], &[0, 0, 0])
            .expect("a window is unaffected by restarts of validators it does not observe");
    }

    #[test]
    fn one_restarted_observer_among_many_still_fails() {
        let error = require_observers_not_restarted(&[1, 2, 3], &[0, 0, 0], &[0, 2, 0])
            .expect_err("one corrupted counter corrupts the sum they are added into");
        assert!(error.to_string().contains("[2]"));
    }

    #[test]
    fn a_window_carrying_traffic_but_counting_nothing_is_a_dead_observation_point() {
        let error = require_resubmission_counters_alive(0, 1)
            .expect_err("a window that counted nothing has proved nothing about its observers");
        assert!(error.to_string().contains("fewer than the 1"));
    }

    #[test]
    fn a_quiet_window_is_a_result_not_a_failure() {
        // The rollback window is NOT required to out-produce its control. The
        // first measured run recorded 0 against a control of 171 because
        // v1.3.1 reconstructs replayed sessions without recomputing them —
        // the phenomenon, not a broken test. Anything at or above the floor
        // passes and the difference is reported.
        require_resubmission_counters_alive(1, 1).expect("a barely-active window still reports");
        require_resubmission_counters_alive(171, 1).expect("a busy window reports too");
    }

    #[test]
    fn a_control_window_measures_without_asserting() {
        // Opened with a floor of zero: whatever ordinary traffic produced is
        // the number to compare against later, not a pass/fail of its own.
        require_resubmission_counters_alive(0, 0).expect("a control window only reports");
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
