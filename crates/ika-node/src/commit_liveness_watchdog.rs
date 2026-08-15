// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Process-lifetime watchdog over consensus-commit liveness.
//!
//! `reconfig_watchdog` bounds the node's OWN reconfiguration critical
//! section, which covers the #1864 variant it was built from: a validator
//! that parks between tearing down the outgoing epoch's consensus and
//! creating the new epoch store. It cannot cover the other variant.
//!
//! Tecnodes (mainnet, 2026-08-14) wedged at the 379→380 boundary with
//! `ika_reconfig_phase` at 0 for the whole 48 hours that followed:
//! consensus isolation happened BEFORE the node entered its own
//! reconfiguration, so there was no bounded critical section to breach and
//! nothing to exit. Its last commit was processed at 10:12:20 UTC; the
//! process stayed up (uptime 47.8h, no restart), the network layer stayed
//! connected, `ika_consensus_subscribed_to` read 0 in both directions, and
//! the epoch view stayed frozen at 379 while the fleet advanced to 381.
//! Studio Mirai produced the same signature twice. In all three cases the
//! only thing that recovered the node was an operator restarting the
//! process, which re-runs the consensus mesh join from scratch.
//!
//! The state is a stable equilibrium, which is why nothing self-heals: the
//! knowledge that epochs advanced arrives over consensus commits the node
//! no longer receives, so an isolated node cannot learn it is isolated from
//! anything it is still reading. What it CAN observe is the absence itself
//! — no commit has been processed for a long time while the process is up
//! — and that is the only signal this watchdog uses. Notably NOT
//! `ika_dwallet_mpc_catchup_gap_rounds`, which reads 0 on an isolated node:
//! it is measured against the locally persisted round stream, and that
//! stream freezes with the subscriptions.
//!
//! On breach the node exits so its supervisor restarts it — the recovery
//! all three occurrences demonstrated, applied without waiting for an
//! operator to notice. If a restarted node re-wedges immediately it will
//! exit again one bound later, and will keep doing so: that is intended and
//! is the same trade `reconfig_watchdog` makes. A validator restarting
//! every 15 minutes is loud, attributable from `ika_` metrics and one log
//! line, and still contributes between restarts; a validator silently
//! contributing nothing for 48 hours is none of those things.
//!
//! ## What holds the clock, and why each hold exists
//!
//! - **Until the first commit of the process.** A node that has processed
//!   no commit yet has nothing to be silent relative to — same sentinel
//!   discipline as `report_mpc_consensus_round_lag`, where a not-yet-
//!   reporting MPC service is a sentinel rather than a plausible-looking 0.
//!   Consequence, stated plainly: a node that boots straight into isolation
//!   and never processes a single commit never arms and is never exited.
//!   The watchdog covers the observed failure — a running validator that
//!   loses its subscriptions — and deliberately fails safe outside it,
//!   rather than exiting nodes whose first commit is merely slow to arrive.
//! - **A minimum process uptime** on top of that, so a boot that arms early
//!   (replaying persisted commits, then waiting on components that are
//!   still starting) cannot exit inside its own startup.
//! - **While consensus is torn down**, from the teardown at the epoch
//!   boundary until `ConsensusManager::start` returns. Commits legitimately
//!   stop in that window, and the prepare-then-start handoff barrier inside
//!   it can legitimately block for tens of minutes — it is the one window
//!   `reconfig_watchdog` deliberately leaves uncovered for that reason.
//!   The hold is taken explicitly by the reconfiguration path and released
//!   when consensus is running again; a node that leaves the committee
//!   never releases it, which is what keeps this watchdog off a node that
//!   correctly has no consensus to follow.
//! - **While `ika_reconfig_phase != 0`**, i.e. whenever `reconfig_watchdog`
//!   is armed. Strictly redundant with the explicit hold above (that window
//!   contains this one), and kept as a second, independent source so a
//!   future edit that moves a hold point cannot silently turn a legitimate
//!   reconfiguration into an exit. It costs one atomic load per tick, and
//!   the node inside that window is already bounded by the other watchdog.
//!
//! ## The bound
//!
//! Healthy mainnet commit cadence is sub-second to seconds; the fleet's
//! commit-timestamp staleness sits at 8–60s. The pauses this must not fire
//! on are held rather than tolerated (above), so the bound only has to
//! dwarf ordinary jitter. The stalls it must fire on ran 4.5h, 31h and 48h.
//! 15 minutes sits three orders of magnitude above the healthy cadence and
//! two below the shortest observed wedge, so both margins are large enough
//! that no plausible re-measurement of either moves the choice.
//!
//! `IKA_COMMIT_LIVENESS_WATCHDOG_SECS` overrides the bound in seconds; `0`
//! disables the watchdog (and its exit) entirely. The live silence is
//! exported on `ika_consensus_commit_silence_seconds`, so a node that
//! breaches — or one that wedges with the watchdog disabled — is
//! attributable from metrics alone, including on external operators'
//! nodes, where logs are never available to us.

use ika_core::consensus_handler::ConsensusCommitSink;
use prometheus::IntGauge;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;
use tracing::{error, info, warn};

/// See the module docs: three orders of magnitude above healthy commit
/// cadence, two below the shortest wedge this exists for.
const DEFAULT_BOUND: Duration = Duration::from_secs(900);

/// Environment override for the bound, in seconds. `0` disables the
/// watchdog entirely — an operator escape hatch, and the switch to reach
/// for if a node ever breaches while healthy.
const BOUND_ENV_VAR: &str = "IKA_COMMIT_LIVENESS_WATCHDOG_SECS";

/// The watchdog will not exit a process younger than this multiple of the
/// bound, however long its commit silence. Derived from the bound rather
/// than fixed so that lowering the bound for a test or a rehearsal lowers
/// the floor with it instead of suppressing the exit outright.
const MIN_UPTIME_BOUND_MULTIPLE: u32 = 2;

/// Silence is sampled, not computed on the commit path: the commit path is
/// hot and this only has to resolve a 15-minute bound. Also the gauge's
/// refresh rate — kept below a typical scrape interval so the exported
/// value is never a whole scrape stale.
const POLL_INTERVAL: Duration = Duration::from_secs(15);

/// Exported on `ika_consensus_commit_silence_seconds` while the watchdog is
/// unarmed or held, so "no commit has been late" is distinguishable from
/// "the last commit was 0 seconds ago" (a healthy node genuinely reads 0).
const NOT_ARMED: i64 = -1;

fn resolve_bound() -> Option<Duration> {
    parse_bound(std::env::var(BOUND_ENV_VAR).ok().as_deref())
}

fn parse_bound(raw: Option<&str>) -> Option<Duration> {
    match raw {
        None => Some(DEFAULT_BOUND),
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(secs) => Some(Duration::from_secs(secs)),
            Err(_) => {
                warn!(
                    value = raw,
                    default_secs = DEFAULT_BOUND.as_secs(),
                    "unparseable {BOUND_ENV_VAR}; using the default bound"
                );
                Some(DEFAULT_BOUND)
            }
        },
    }
}

fn default_breach_action() {
    #[cfg(not(msim))]
    std::process::exit(1);

    #[cfg(msim)]
    sui_simulator::task::shutdown_current_node();
}

/// What a tick concluded, and what the gauge should say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tick {
    /// Unarmed or held — the clock is not running.
    Idle,
    /// Armed and running: this much silence so far, under the bound.
    Silent(Duration),
    /// The bound is breached; the caller runs the breach action once.
    Breach(Duration),
}

/// The decision state, separated from the timer and the gauges so it can be
/// driven with an explicit clock in tests.
#[derive(Debug)]
struct LivenessState {
    /// When the watchdog started. The minimum-uptime floor is measured from
    /// here rather than from process start; the watchdog is created early in
    /// node startup, before any validator component exists, so the two are
    /// the same instant for every purpose this floor serves.
    started_at: Instant,
    /// The last event that counts as commit-liveness progress: the first
    /// commit this process processed, every commit after it, and every
    /// consensus (re)start once armed. `None` until the first commit —
    /// while it is `None` the watchdog cannot breach.
    last_progress: Option<Instant>,
    /// Set while consensus is torn down; see the module docs.
    held: bool,
    /// Leader round of the last commit processed, carried for the breach
    /// log: it is the round an operator correlates against the fleet to see
    /// how far behind the isolated node froze.
    last_leader_round: Option<u64>,
    /// Set when the breach action has run, so it runs exactly once even if
    /// the breach action returns (it does under msim).
    breached: bool,
}

impl LivenessState {
    fn new(now: Instant) -> Self {
        Self {
            started_at: now,
            last_progress: None,
            held: false,
            last_leader_round: None,
            breached: false,
        }
    }

    /// A commit was processed. This is also self-healing on the hold: a
    /// commit is proof that consensus is running, whatever the hold state
    /// says, so a hold that was never released cannot mask a later stall.
    fn commit_processed(&mut self, now: Instant, leader_round: u64) -> bool {
        let first = self.last_progress.is_none();
        self.last_progress = Some(now);
        self.last_leader_round = Some(leader_round);
        self.held = false;
        first
    }

    /// Consensus was torn down: freeze the clock.
    fn hold(&mut self) {
        self.held = true;
    }

    /// Consensus is running again: restart the clock from now. Deliberately
    /// does NOT arm — a process that has never processed a commit stays
    /// unarmed — but for an armed one this is what puts a silently failed
    /// mesh join back on the clock, which is the whole point.
    fn resume(&mut self, now: Instant) {
        self.held = false;
        if let Some(last_progress) = self.last_progress.as_mut() {
            *last_progress = now;
        }
    }

    fn tick(&mut self, now: Instant, bound: Duration, min_uptime: Duration, held: bool) -> Tick {
        if self.breached {
            return Tick::Idle;
        }
        let Some(last_progress) = self.last_progress else {
            return Tick::Idle;
        };
        if self.held || held {
            // Pull the anchor forward so held time is never counted, and so
            // the full bound is available again once the hold lifts.
            self.last_progress = Some(now);
            return Tick::Idle;
        }
        let silence = now.saturating_duration_since(last_progress);
        if silence >= bound && now.saturating_duration_since(self.started_at) >= min_uptime {
            self.breached = true;
            Tick::Breach(silence)
        } else {
            Tick::Silent(silence)
        }
    }
}

/// Watches the interval between processed consensus commits and exits the
/// node when it grows past the bound outside any reconfiguration.
pub(crate) struct CommitLivenessWatchdog {
    state: Mutex<LivenessState>,
    /// `ika_consensus_commit_silence_seconds`.
    silence_gauge: IntGauge,
    /// `ika_reconfig_phase`, read as a hold input; see the module docs.
    reconfig_phase_gauge: IntGauge,
    bound: Duration,
    min_uptime: Duration,
    breach_action: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl CommitLivenessWatchdog {
    /// Spawns the watchdog. `None` when it is disabled by the environment,
    /// in which case nothing is spawned and no commit sink is installed.
    ///
    /// Validators only: a node with no consensus to follow has nothing to be
    /// isolated from, and would breach on its own correctness.
    pub(crate) fn spawn(
        silence_gauge: IntGauge,
        reconfig_phase_gauge: IntGauge,
    ) -> Option<Arc<Self>> {
        Self::spawn_with(
            silence_gauge,
            reconfig_phase_gauge,
            resolve_bound(),
            default_breach_action,
        )
    }

    fn spawn_with(
        silence_gauge: IntGauge,
        reconfig_phase_gauge: IntGauge,
        bound: Option<Duration>,
        breach_action: impl FnOnce() + Send + 'static,
    ) -> Option<Arc<Self>> {
        let bound = bound?;
        let watchdog = Arc::new(Self {
            state: Mutex::new(LivenessState::new(Instant::now())),
            silence_gauge,
            reconfig_phase_gauge,
            bound,
            min_uptime: bound * MIN_UPTIME_BOUND_MULTIPLE,
            breach_action: Mutex::new(Some(Box::new(breach_action))),
        });
        watchdog.silence_gauge.set(NOT_ARMED);
        info!(
            bound_secs = bound.as_secs(),
            min_uptime_secs = watchdog.min_uptime.as_secs(),
            "commit-liveness watchdog started; it arms on this process's first consensus commit \
             and exits the node if commits then stop for longer than the bound (ika #1864)"
        );
        let ticker = watchdog.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(POLL_INTERVAL).await;
                if ticker.tick(Instant::now()) {
                    // Breached: under msim the breach action returns, and
                    // there is nothing left for this task to decide.
                    break;
                }
            }
        });
        Some(watchdog)
    }

    /// Consensus is being torn down (epoch boundary): freeze the clock.
    pub(crate) fn consensus_stopped(&self) {
        self.state.lock().unwrap().hold();
        self.silence_gauge.set(NOT_ARMED);
        info!("commit-liveness clock held while consensus is torn down");
    }

    /// Consensus is running again: restart the clock from now.
    pub(crate) fn consensus_started(&self) {
        self.state.lock().unwrap().resume(Instant::now());
        info!("commit-liveness clock resumed; consensus is running");
    }

    /// One poll iteration. Returns `true` once the breach action has run.
    fn tick(&self, now: Instant) -> bool {
        let held = self.reconfig_phase_gauge.get() != 0;
        let tick = self
            .state
            .lock()
            .unwrap()
            .tick(now, self.bound, self.min_uptime, held);
        match tick {
            Tick::Idle => {
                self.silence_gauge.set(NOT_ARMED);
                false
            }
            Tick::Silent(silence) => {
                self.silence_gauge.set(silence.as_secs() as i64);
                false
            }
            Tick::Breach(silence) => {
                self.silence_gauge.set(silence.as_secs() as i64);
                self.breach(silence);
                true
            }
        }
    }

    fn breach(&self, silence: Duration) {
        let (last_leader_round, uptime) = {
            let state = self.state.lock().unwrap();
            (
                state.last_leader_round,
                Instant::now().saturating_duration_since(state.started_at),
            )
        };
        error!(
            silence_secs = silence.as_secs(),
            bound_secs = self.bound.as_secs(),
            last_leader_round,
            uptime_secs = uptime.as_secs(),
            "this validator has processed no consensus commit for longer than the commit-liveness \
             bound, while its consensus was running and outside any reconfiguration. That is the \
             boundary-isolation form of ika #1864: the process is healthy in every other respect \
             (network connected, metrics served, Sui reads retrying) but its consensus \
             subscriptions are gone in both directions and nothing retries them, so it will \
             contribute nothing and never learn that the epoch advanced. A process restart \
             re-runs the consensus mesh join from scratch and is the only recovery observed in \
             production, so we exit for the supervisor to restart us. If this repeats every \
             bound, each join is re-wedging: capture ika_consensus_subscribed_to and \
             ika_consensus_commit_silence_seconds, report on ika #1864, and set \
             IKA_COMMIT_LIVENESS_WATCHDOG_SECS=0 to stop the exits while investigating"
        );
        if let Some(action) = self.breach_action.lock().unwrap().take() {
            action();
        }
    }
}

impl ConsensusCommitSink for CommitLivenessWatchdog {
    fn commit_processed(&self, leader_round: u64) {
        let first = self
            .state
            .lock()
            .unwrap()
            .commit_processed(Instant::now(), leader_round);
        if first {
            info!(
                leader_round,
                bound_secs = self.bound.as_secs(),
                "commit-liveness watchdog armed on this process's first consensus commit"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    const BOUND: Duration = Duration::from_secs(900);
    const MIN_UPTIME: Duration = Duration::from_secs(1800);

    fn gauge(name: &str) -> IntGauge {
        IntGauge::new(name, "test gauge").unwrap()
    }

    fn flag() -> (Arc<AtomicBool>, impl FnOnce() + Send + 'static) {
        let fired = Arc::new(AtomicBool::new(false));
        let setter = {
            let fired = fired.clone();
            move || fired.store(true, Ordering::SeqCst)
        };
        (fired, setter)
    }

    /// Drives `LivenessState` with an explicit clock: `at(secs)` is that many
    /// seconds after the watchdog started.
    struct Clock {
        t0: Instant,
        state: LivenessState,
    }

    impl Clock {
        fn new() -> Self {
            let t0 = Instant::now();
            Self {
                t0,
                state: LivenessState::new(t0),
            }
        }

        fn at(&self, secs: u64) -> Instant {
            self.t0 + Duration::from_secs(secs)
        }

        fn commit_at(&mut self, secs: u64) {
            self.state.commit_processed(self.at(secs), 1_000 + secs);
        }

        fn tick_at(&mut self, secs: u64) -> Tick {
            self.tick_at_with_phase(secs, false)
        }

        fn tick_at_with_phase(&mut self, secs: u64, reconfiguring: bool) -> Tick {
            let now = self.at(secs);
            self.state.tick(now, BOUND, MIN_UPTIME, reconfiguring)
        }
    }

    #[test]
    fn a_process_that_has_never_processed_a_commit_never_breaches() {
        let mut clock = Clock::new();
        for hour in 1..=48 {
            assert_eq!(
                clock.tick_at(hour * 3_600),
                Tick::Idle,
                "an unarmed watchdog must stay idle however long the process runs"
            );
        }
    }

    #[test]
    fn the_watchdog_arms_on_the_first_commit_and_breaches_one_bound_later() {
        let mut clock = Clock::new();
        clock.commit_at(2_000);
        assert_eq!(clock.tick_at(2_600), Tick::Silent(Duration::from_secs(600)));
        assert_eq!(clock.tick_at(2_900), Tick::Breach(Duration::from_secs(900)));
    }

    #[test]
    fn a_commit_inside_the_bound_pushes_the_deadline_out() {
        let mut clock = Clock::new();
        clock.commit_at(2_000);
        clock.commit_at(2_800);
        assert_eq!(
            clock.tick_at(2_900),
            Tick::Silent(Duration::from_secs(100)),
            "silence is measured from the latest commit, not the first"
        );
        assert_eq!(clock.tick_at(3_700), Tick::Breach(Duration::from_secs(900)));
    }

    #[test]
    fn silence_past_the_bound_does_not_breach_before_the_minimum_uptime() {
        let mut clock = Clock::new();
        clock.commit_at(60);
        assert_eq!(
            clock.tick_at(1_500),
            Tick::Silent(Duration::from_secs(1_440)),
            "24 minutes of silence is past the bound, but the process is only 25 minutes old"
        );
        assert_eq!(
            clock.tick_at(MIN_UPTIME.as_secs()),
            Tick::Breach(Duration::from_secs(1_740)),
            "the floor is a delay on the exit, never a cancellation of it"
        );
    }

    #[test]
    fn a_held_clock_never_breaches_however_long_the_hold_lasts() {
        let mut clock = Clock::new();
        clock.commit_at(2_000);
        clock.state.hold();
        for step in 1..=20 {
            assert_eq!(
                clock.tick_at(2_000 + step * 1_800),
                Tick::Idle,
                "a torn-down consensus must not be counted as silence"
            );
        }
    }

    #[test]
    fn a_nonzero_reconfig_phase_holds_the_clock_on_its_own() {
        let mut clock = Clock::new();
        clock.commit_at(2_000);
        assert_eq!(clock.tick_at_with_phase(3_000, true), Tick::Idle);
        assert_eq!(clock.tick_at_with_phase(9_000, true), Tick::Idle);
        assert_eq!(
            clock.tick_at(9_600),
            Tick::Silent(Duration::from_secs(600)),
            "the bound restarts from the end of the reconfiguration, not from its start"
        );
    }

    #[test]
    fn resuming_consensus_restarts_the_clock_without_arming_an_unarmed_watchdog() {
        let mut unarmed = Clock::new();
        unarmed.state.resume(unarmed.at(100));
        assert_eq!(
            unarmed.tick_at(100_000),
            Tick::Idle,
            "a consensus start is not a commit; it must not arm the watchdog"
        );

        let mut armed = Clock::new();
        armed.commit_at(2_000);
        armed.state.hold();
        let resume_at = armed.at(5_000);
        armed.state.resume(resume_at);
        assert_eq!(armed.tick_at(5_600), Tick::Silent(Duration::from_secs(600)));
        assert_eq!(
            armed.tick_at(5_900),
            Tick::Breach(Duration::from_secs(900)),
            "a consensus restart that never delivers a commit is exactly the #1864 wedge"
        );
    }

    #[test]
    fn a_commit_releases_a_hold_that_was_never_released() {
        let mut clock = Clock::new();
        clock.commit_at(2_000);
        clock.state.hold();
        assert_eq!(clock.tick_at(4_000), Tick::Idle);
        clock.commit_at(4_100);
        assert_eq!(
            clock.tick_at(5_100),
            Tick::Breach(Duration::from_secs(1_000)),
            "a processed commit proves consensus is running, so it must clear the hold"
        );
    }

    #[test]
    fn the_breach_is_decided_exactly_once() {
        let mut clock = Clock::new();
        clock.commit_at(2_000);
        assert_eq!(clock.tick_at(2_900), Tick::Breach(Duration::from_secs(900)));
        assert_eq!(
            clock.tick_at(3_800),
            Tick::Idle,
            "the exit is in flight; further ticks must not re-run the breach action"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_spawned_watchdog_exits_the_node_and_exports_the_silence() {
        let (fired, on_breach) = flag();
        let silence = gauge("test_commit_silence_seconds");
        let watchdog = CommitLivenessWatchdog::spawn_with(
            silence.clone(),
            gauge("test_reconfig_phase"),
            Some(BOUND),
            on_breach,
        )
        .expect("an enabled watchdog spawns");
        assert_eq!(silence.get(), NOT_ARMED);

        watchdog.commit_processed(1_234);
        // One second past a poll boundary, so the last tick to have run is
        // the one at 600s rather than a race between two timers due at the
        // same instant.
        tokio::time::sleep(Duration::from_secs(601)).await;
        assert_eq!(silence.get(), 600, "the gauge tracks the live silence");
        assert!(!fired.load(Ordering::SeqCst), "600s is inside the bound");

        // Past the bound, but the process is younger than the uptime floor.
        tokio::time::sleep(Duration::from_secs(600)).await;
        assert!(!fired.load(Ordering::SeqCst));

        tokio::time::sleep(Duration::from_secs(900)).await;
        assert!(
            fired.load(Ordering::SeqCst),
            "commit silence past the bound on a process past the uptime floor must exit"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_spawned_watchdog_holds_while_consensus_is_down() {
        let (fired, on_breach) = flag();
        let silence = gauge("test_held_commit_silence_seconds");
        let watchdog = CommitLivenessWatchdog::spawn_with(
            silence.clone(),
            gauge("test_held_reconfig_phase"),
            Some(BOUND),
            on_breach,
        )
        .expect("an enabled watchdog spawns");

        watchdog.commit_processed(1_234);
        watchdog.consensus_stopped();
        tokio::time::sleep(Duration::from_secs(6 * 3_600)).await;
        assert!(
            !fired.load(Ordering::SeqCst),
            "six hours of torn-down consensus must not exit the node"
        );
        assert_eq!(silence.get(), NOT_ARMED);

        watchdog.consensus_started();
        tokio::time::sleep(Duration::from_secs(1_000)).await;
        assert!(
            fired.load(Ordering::SeqCst),
            "once consensus is back, a mesh join that delivers no commit must exit the node"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_disabled_watchdog_spawns_nothing() {
        let (fired, on_breach) = flag();
        assert!(
            CommitLivenessWatchdog::spawn_with(
                gauge("test_disabled_commit_silence_seconds"),
                gauge("test_disabled_reconfig_phase"),
                None,
                on_breach,
            )
            .is_none(),
            "IKA_COMMIT_LIVENESS_WATCHDOG_SECS=0 must install no watchdog at all"
        );
        tokio::time::sleep(Duration::from_secs(48 * 3_600)).await;
        assert!(!fired.load(Ordering::SeqCst));
    }

    #[test]
    fn bound_parsing() {
        assert_eq!(parse_bound(None), Some(DEFAULT_BOUND));
        assert_eq!(parse_bound(Some("0")), None);
        assert_eq!(parse_bound(Some("120")), Some(Duration::from_secs(120)));
        assert_eq!(parse_bound(Some(" 45 ")), Some(Duration::from_secs(45)));
        assert_eq!(parse_bound(Some("not-a-number")), Some(DEFAULT_BOUND));
    }
}
