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
//! — and that is the signal this watchdog times. Notably NOT
//! `ika_dwallet_mpc_catchup_gap_rounds`, which reads 0 on an isolated node:
//! it is measured against the locally persisted round stream, and that
//! stream freezes with the subscriptions. Absence alone does not say whose
//! absence it is, though, which is what the network-wide halt below is about.
//!
//! On breach the node exits so its supervisor restarts it — the recovery
//! all three occurrences demonstrated, applied without waiting for an
//! operator to notice. If a restarted node re-wedges after its first live
//! commit it will exit again one bound later, and will keep doing so: that is
//! intended and is the same trade `reconfig_watchdog` makes. A validator
//! restarting every 15 minutes is loud, attributable from `ika_` metrics and
//! one log line, and still contributes between restarts; a validator
//! silently contributing nothing for 48 hours is none of those things.
//!
//! ## A network-wide halt is not isolation
//!
//! Mainnet, 2026-11-08: consensus halted at about 12:28 UTC, because too
//! many validators were restarting at once to keep 2f+1. At 12:43, exactly
//! one bound later, this watchdog exited every validator still running:
//! each one was silent, and silence alone cannot tell "I am cut off while
//! the network moves on" from "nobody is advancing". Every restart then
//! re-folds the whole epoch from the consensus store (about 4.8M commits,
//! 60–180 minutes depending on the node), and the replayed commits used to
//! arm the watchdog, so each node exited again one bound after its own
//! replay ended unless live consensus had resumed by then. Replay finish
//! times spread over more than two hours; simulating that schedule never
//! puts more than about 18 validators online together, against the 37 a
//! quorum needs. The watchdog had turned a halt into one the network could
//! not recover from on its own.
//!
//! Two of the holds below exist for that: replayed commits do not arm the
//! clock, and the clock does not run while the committee reads as halted. An
//! exit needs this node hearing nothing AND evidence that the silence is its
//! own: its peers moving on without it, or not one of them answering it.
//!
//! ## What holds the clock, and why each hold exists
//!
//! - **Until the first LIVE commit of the process.** A node that has
//!   processed no commit yet has nothing to be silent relative to — same
//!   sentinel discipline as `report_mpc_consensus_round_lag`, where a not-
//!   yet-reporting MPC service is a sentinel rather than a plausible-looking
//!   0. Commits the boot replay re-reads from this node's own store
//!   (`CommitOrigin::Replayed`) neither arm the clock nor reset it: they
//!   prove nothing about the node's connection to its peers, and arming on
//!   them is what put every replayed node of the halt above on a clock that
//!   only a recovered network could satisfy. Consequence, stated plainly: a
//!   node that comes out of its replay already isolated — including a
//!   restarted node that re-wedges before its first live commit — never
//!   arms and is never exited. The watchdog covers the observed failure — a
//!   running validator that loses its subscriptions — and deliberately
//!   fails safe outside it, rather than exiting nodes whose first live
//!   commit is merely slow to arrive.
//! - **A minimum process uptime** on top of that, so a boot that arms early
//!   (a first live commit, then waiting on components that are still
//!   starting) cannot exit inside its own startup.
//! - **By what consensus-core reports about the committee**
//!   (`ConsensusManager::peer_progress`, consensus-core's `PeerProgress`).
//!   Every few seconds the round prober asks every peer for its accepted
//!   rounds over a request of its own, independent of the block
//!   subscriptions, and publishes the highest round a quorum has accepted
//!   (`quorum_accepted_round`), the stake of the peers that answered, this
//!   node excluded (`responsive_stake`), and when the probe finished
//!   (`probed_at_ms`). The commit syncer adds the highest commit index a
//!   quorum has voted for (`quorum_commit_index`). No authority can advance
//!   a round or a commit without a quorum, so the two indices stand still
//!   when the whole committee does. Each poll judges that reading over the
//!   last stall window (a quarter of the bound):
//!
//!   | the reading | verdict | clock |
//!   |---|---|---|
//!   | no probe yet, or none new for [`PROBE_STALE_AFTER`] | no information | holds, `-2` |
//!   | the round or the commit index rose in the window | peers advance without this node | runs |
//!   | some peer answered a probe in the window, and nothing rose | network-wide halt | holds, `-2` |
//!   | no peer answered any probe in the window, and probes stayed fresh throughout it | this node is cut off | runs |
//!   | no peer answered, but probes have been fresh for less than a window | no information yet | holds, `-2` |
//!
//!   A reading whose probe time stopped moving says nothing about the
//!   present (consensus, or its prober, has stopped), so it fails safe and
//!   holds. The cut-off row is the Tecnodes wedge above: every round-prober
//!   request it made failed, about 11 a second, so the accepted round froze
//!   and a rule that looked only at the round read it as a halt and never
//!   exited. The bar is exactly zero answering stake, not "less than a
//!   quorum": during a real halt only a minority of validators may be up
//!   (13 of 55 on 2026-11-08), and a healthy node still reaches those. A
//!   single answer anywhere in the window keeps the node on the halt row, and
//!   the zero-stake row also needs fresh probes across the whole window,
//!   because the first probes after a consensus start can fail against
//!   peers that are not up yet. A live commit counts as peer progress too (it
//!   took a quorum to make), and a consensus (re)start resets the reading and
//!   gets one stall window to show progress before the halt row can apply.
//!   Neither can turn a halt into an exit: the window is a quarter of the
//!   bound, so a node silent since then is held well before it could breach.
//!   What this gives up: a node that reaches only part of the committee,
//!   which may itself be cut off from the rest, reads as a halt and is held;
//!   a validator that is the only one still running reads as cut off and
//!   exits; and a prober that stops publishing holds every silence. The `-2`
//!   reading and the log line on each change of verdict are how those cases
//!   stay visible.
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
//! The peer-stall window is a quarter of the bound (225s by default). The
//! prober reports every five seconds and a live committee advances many
//! rounds per second, so a healthy reading climbs on every 15-second poll;
//! a quarter of the bound asks for minutes of unanswered probes before
//! reading this node as cut off, and still engages the halt hold long before
//! a halted node's silence reaches the bound. Freshness is on a shorter
//! scale: [`PROBE_STALE_AFTER`] is three prober intervals, so one poll that
//! finds no new probe already reads as no information.
//!
//! `IKA_COMMIT_LIVENESS_WATCHDOG_SECS` overrides the bound in seconds; `0`
//! disables the watchdog (and its exit) entirely. The live silence is
//! exported on `ika_consensus_commit_silence_seconds`, so a node that
//! breaches — or one that wedges with the watchdog disabled — is
//! attributable from metrics alone, including on external operators'
//! nodes, where logs are never available to us.

use ika_core::consensus_handler::{CommitOrigin, ConsensusCommitSink};
use ika_core::consensus_manager::PeerProgress;
use prometheus::IntGauge;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// The committee reading is judged over the bound divided by this: the
/// network reads as halted — and the clock holds — once peers that answer
/// have not advanced for that long, and this node reads as cut off once no
/// peer has answered for that long. Derived from the bound for the same
/// reason as the uptime floor, and it has to stay a fraction of it: the hold
/// must engage before a halted node's silence reaches the bound. See the
/// module docs.
const PEER_STALL_BOUND_DIVISOR: u32 = 4;

/// A peer-progress reading whose probe time has not moved for this long
/// carries no information, and holds the clock. Three of consensus-core's
/// round-prober intervals (`round_prober_interval_ms`, 5s by default); each
/// probe is bounded by the prober's request timeout, so a running prober
/// publishes several times in this span. At the 15-second poll it means one
/// poll that finds no new probe.
const PROBE_STALE_AFTER: Duration = Duration::from_secs(15);

/// Silence is sampled, not computed on the commit path: the commit path is
/// hot and this only has to resolve a 15-minute bound. Also the gauge's
/// refresh rate — kept below a typical scrape interval so the exported
/// value is never a whole scrape stale.
const POLL_INTERVAL: Duration = Duration::from_secs(15);

/// Exported on `ika_consensus_commit_silence_seconds` while the watchdog is
/// unarmed or held, so "no commit has been late" is distinguishable from
/// "the last commit was 0 seconds ago" (a healthy node genuinely reads 0).
const NOT_ARMED: i64 = -1;

/// Exported on `ika_consensus_commit_silence_seconds` while the armed clock
/// is held by the committee reading: peers answer and none is advancing (the
/// network is halted), or there is no fresh reading to tell. Distinct from
/// [`NOT_ARMED`] so a fleet-wide halt reads as one from every validator's
/// metrics.
const NETWORK_STALLED: i64 = -2;

/// Reads this node's view of committee progress
/// (`ConsensusManager::peer_progress`); `None` when there is no consensus
/// instance to ask. Called once per poll.
pub(crate) type PeerProgressSource = Box<dyn Fn() -> Option<PeerProgress> + Send + Sync>;

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
    /// Armed, but held because peers answer and none is advancing either.
    NetworkStalled,
    /// Armed, but held because there is no fresh committee reading to judge by.
    NoPeerInformation,
    /// Armed and running: this much silence so far, under the bound.
    Silent(Duration),
    /// The bound is breached; the caller runs the breach action once.
    Breach(Duration),
}

/// What the committee reading says about this node's commit silence, judged
/// over the stall window. See the table in the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerVerdict {
    /// No probe yet, none new for [`PROBE_STALE_AFTER`], or — with no peer
    /// answering — fresh probes for less than a window. Holds.
    NoInformation,
    /// The committee's round or commit index rose inside the window, or a
    /// live commit or a consensus start happened there. The clock runs.
    Advancing,
    /// Some peer answered inside the window, but nothing rose for the whole
    /// of it. Holds.
    Halted,
    /// Probes stayed fresh for the whole window and no peer answered any of
    /// them: this node is cut off. The clock runs.
    Unreachable,
}

/// Folds `value` into a high-water mark and says whether it rose. Zero is
/// consensus-core's value before anything is reported, so it is not a
/// reading, and the first reading after a reset is a baseline, not a rise.
fn rose(high_water: &mut Option<u32>, value: u32) -> bool {
    if value == 0 {
        return false;
    }
    match *high_water {
        Some(mark) if value <= mark => false,
        Some(_) => {
            *high_water = Some(value);
            true
        }
        None => {
            *high_water = Some(value);
            false
        }
    }
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
    /// live commit this process processed, every live commit after it, and
    /// every consensus (re)start once armed. `None` until the first live
    /// commit — while it is `None` the watchdog cannot breach.
    last_progress: Option<Instant>,
    /// Set while consensus is torn down; see the module docs.
    held: bool,
    /// Leader round of the last live commit processed, carried for the
    /// breach log: it is the round an operator correlates against the fleet
    /// to see how far behind the isolated node froze.
    last_leader_round: Option<u64>,
    /// The latest committee reading, carried for the logs.
    last_peer_progress: Option<PeerProgress>,
    /// Highest `quorum_accepted_round` and `quorum_commit_index` read since
    /// consensus last (re)started. Compared as high-water marks rather than
    /// against the previous reading, so a value that dips and recovers with
    /// nobody advancing is not mistaken for progress.
    accepted_round_high_water: Option<u32>,
    commit_index_high_water: Option<u32>,
    /// The last evidence that the committee advanced: a high-water mark
    /// rising, a live commit, or a consensus (re)start. `None` until the
    /// first of those, which reads as no evidence.
    peers_advanced_at: Option<Instant>,
    /// `probed_at_ms` of the newest probe read, and when this watchdog first
    /// read it. Freshness is how long ago the probe time last moved, on this
    /// watchdog's clock: consensus-core's clock may differ from it.
    last_probe: Option<(u64, Instant)>,
    /// When the current unbroken run of fresh readings began; `None` while
    /// the reading is stale. The cut-off verdict needs it to span the window.
    fresh_since: Option<Instant>,
    /// When a probe that some peer answered was last read. `None` reads as
    /// never.
    peers_answered_at: Option<Instant>,
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
            last_peer_progress: None,
            accepted_round_high_water: None,
            commit_index_high_water: None,
            peers_advanced_at: None,
            last_probe: None,
            fresh_since: None,
            peers_answered_at: None,
            breached: false,
        }
    }

    /// A commit arrived. Returns `true` when it is the one that arms.
    ///
    /// A replayed commit is ignored outright: it neither arms nor resets the
    /// clock, and it does not release a hold. See the module docs.
    ///
    /// A live one is also self-healing on the hold — it is proof that
    /// consensus is running, whatever the hold state says, so a hold that
    /// was never released cannot mask a later stall — and it is evidence of
    /// peer progress, since it took a quorum to commit.
    fn commit_processed(&mut self, now: Instant, leader_round: u64, origin: CommitOrigin) -> bool {
        if origin == CommitOrigin::Replayed {
            return false;
        }
        let first = self.last_progress.is_none();
        self.last_progress = Some(now);
        self.last_leader_round = Some(leader_round);
        self.held = false;
        self.peers_advanced_at = Some(now);
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
    ///
    /// Also starts peer tracking over. A new consensus instance counts
    /// rounds and commits from zero, so high-water marks carried over from
    /// the previous epoch would read the new one as halted until it overtook
    /// the old. The start itself stands in as peer progress for one stall
    /// window, long enough for a first reading and a first rise.
    fn resume(&mut self, now: Instant) {
        self.held = false;
        self.accepted_round_high_water = None;
        self.commit_index_high_water = None;
        self.peers_advanced_at = Some(now);
        if let Some(last_progress) = self.last_progress.as_mut() {
            *last_progress = now;
        }
    }

    /// Folds one committee reading: the high-water marks, and whether it
    /// carries a new probe and whether any peer answered that probe.
    fn observe_peers(&mut self, now: Instant, peers: Option<PeerProgress>) {
        if let Some(peers) = peers {
            self.last_peer_progress = Some(peers);
            let round_rose = rose(
                &mut self.accepted_round_high_water,
                peers.quorum_accepted_round,
            );
            let commit_index_rose =
                rose(&mut self.commit_index_high_water, peers.quorum_commit_index);
            if round_rose || commit_index_rose {
                self.peers_advanced_at = Some(now);
            }
            let new_probe = peers.probed_at_ms != 0
                && self
                    .last_probe
                    .is_none_or(|(probed_at_ms, _)| probed_at_ms != peers.probed_at_ms);
            if new_probe {
                self.last_probe = Some((peers.probed_at_ms, now));
                self.fresh_since.get_or_insert(now);
                if peers.responsive_stake > 0 {
                    self.peers_answered_at = Some(now);
                }
            }
        }
        if !self.probe_is_fresh(now) {
            self.fresh_since = None;
        }
    }

    fn probe_is_fresh(&self, now: Instant) -> bool {
        self.last_probe
            .is_some_and(|(_, read_at)| now.saturating_duration_since(read_at) < PROBE_STALE_AFTER)
    }

    /// The table in the module docs, in its order.
    fn peer_verdict(&self, now: Instant, peer_stall_window: Duration) -> PeerVerdict {
        let within_window = |at: Instant| now.saturating_duration_since(at) < peer_stall_window;
        if !self.probe_is_fresh(now) {
            PeerVerdict::NoInformation
        } else if self.peers_advanced_at.is_some_and(within_window) {
            PeerVerdict::Advancing
        } else if self.peers_answered_at.is_some_and(within_window) {
            PeerVerdict::Halted
        } else if self.fresh_since.is_some_and(|since| !within_window(since)) {
            PeerVerdict::Unreachable
        } else {
            PeerVerdict::NoInformation
        }
    }

    fn tick(
        &mut self,
        now: Instant,
        bound: Duration,
        min_uptime: Duration,
        peer_stall_window: Duration,
        held: bool,
        peers: Option<PeerProgress>,
    ) -> Tick {
        if self.breached {
            return Tick::Idle;
        }
        // Read even while unarmed or held, so a baseline exists by the time
        // the clock first runs.
        self.observe_peers(now, peers);
        let Some(last_progress) = self.last_progress else {
            return Tick::Idle;
        };
        if self.held || held {
            // Pull the anchor forward so held time is never counted, and so
            // the full bound is available again once the hold lifts.
            self.last_progress = Some(now);
            return Tick::Idle;
        }
        let peer_hold = match self.peer_verdict(now, peer_stall_window) {
            PeerVerdict::NoInformation => Some(Tick::NoPeerInformation),
            PeerVerdict::Halted => Some(Tick::NetworkStalled),
            PeerVerdict::Advancing | PeerVerdict::Unreachable => None,
        };
        if let Some(peer_hold) = peer_hold {
            // Same anchor pull as any other hold: once the reading lets the
            // clock run again, a node that is still connected gets the full
            // bound to show it.
            self.last_progress = Some(now);
            return peer_hold;
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

/// Watches the interval between live consensus commits and exits the node
/// when it grows past the bound outside any reconfiguration, while its peers
/// keep advancing or none of them answers it.
pub(crate) struct CommitLivenessWatchdog {
    state: Mutex<LivenessState>,
    /// `ika_consensus_commit_silence_seconds`.
    silence_gauge: IntGauge,
    /// `ika_reconfig_phase`, read as a hold input; see the module docs.
    reconfig_phase_gauge: IntGauge,
    bound: Duration,
    min_uptime: Duration,
    peer_stall_window: Duration,
    /// Where peer progress is read from. Late-bound: the consensus manager
    /// that can answer is built after this watchdog, and rebuilt if the node
    /// leaves the committee and rejoins. Until it is set every reading is
    /// `None`, which an armed clock treats as no information and holds on.
    peer_progress: Mutex<Option<PeerProgressSource>>,
    /// The verdict of the last tick that judged one (`None` after an idle
    /// tick), so each change of verdict is logged once rather than every
    /// poll.
    peer_verdict: Mutex<Option<PeerVerdict>>,
    breach_action: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// True while the consensus fold is parked waiting for the MPC drain to
    /// take a round.
    ///
    /// A HOLD input, exactly like the reconfiguration phase: a parked fold is
    /// holding a commit it already received, so it is evidence of the
    /// opposite of isolation. Without it the fold's block would starve the
    /// arrival reports this watchdog runs on — the loop is not calling
    /// `recv` while it is parked — and a deep burst would read as silence and
    /// exit a healthy node.
    ///
    /// Considered and rejected: inferring the same thing from the upstream
    /// commit channel's depth. Depth greater than zero says commits arrived,
    /// but it stays greater than zero for a fold wedged for any OTHER reason
    /// too, which would extend the hold to cases it should not cover. This
    /// flag names the one legitimate reason.
    fold_blocked: Arc<AtomicBool>,
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
            Arc::new(AtomicBool::new(false)),
            None,
        )
    }

    /// Installs (or replaces) the reader of peer progress. Whoever starts
    /// consensus must call this with that consensus's manager, or the clock
    /// holds on every silence for lack of information.
    pub(crate) fn watch_peers(&self, peer_progress: PeerProgressSource) {
        *self.peer_progress.lock().unwrap() = Some(peer_progress);
    }

    /// The flag the consensus fold raises while it is parked waiting for the
    /// MPC drain. Handed to `round_transport` so the two share one cell:
    /// whoever builds the transport must take it from here, or the watchdog
    /// holds on a flag nothing ever sets.
    pub(crate) fn fold_blocked_flag(&self) -> Arc<AtomicBool> {
        self.fold_blocked.clone()
    }

    fn spawn_with(
        silence_gauge: IntGauge,
        reconfig_phase_gauge: IntGauge,
        bound: Option<Duration>,
        breach_action: impl FnOnce() + Send + 'static,
        fold_blocked: Arc<AtomicBool>,
        peer_progress: Option<PeerProgressSource>,
    ) -> Option<Arc<Self>> {
        let bound = bound?;
        let watchdog = Arc::new(Self {
            state: Mutex::new(LivenessState::new(Instant::now())),
            silence_gauge,
            reconfig_phase_gauge,
            bound,
            min_uptime: bound * MIN_UPTIME_BOUND_MULTIPLE,
            peer_stall_window: bound / PEER_STALL_BOUND_DIVISOR,
            peer_progress: Mutex::new(peer_progress),
            peer_verdict: Mutex::new(None),
            breach_action: Mutex::new(Some(Box::new(breach_action))),
            fold_blocked,
        });
        watchdog.silence_gauge.set(NOT_ARMED);
        info!(
            bound_secs = bound.as_secs(),
            min_uptime_secs = watchdog.min_uptime.as_secs(),
            peer_stall_window_secs = watchdog.peer_stall_window.as_secs(),
            "commit-liveness watchdog started; it arms on this process's first LIVE consensus \
             commit (not on the boot replay) and exits the node if commits then stop for longer \
             than the bound while its peers keep advancing or none of them answers it (ika #1864)"
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
        let held =
            self.reconfig_phase_gauge.get() != 0 || self.fold_blocked.load(Ordering::Acquire);
        let peers = self
            .peer_progress
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|read| read());
        let (tick, verdict) = {
            let mut state = self.state.lock().unwrap();
            let tick = state.tick(
                now,
                self.bound,
                self.min_uptime,
                self.peer_stall_window,
                held,
                peers,
            );
            // An idle tick (unarmed, held, or already breached) judges
            // nothing, so a verdict reached after one is logged afresh.
            let verdict =
                (tick != Tick::Idle).then(|| state.peer_verdict(now, self.peer_stall_window));
            (tick, verdict)
        };
        let previous = {
            let mut last_verdict = self.peer_verdict.lock().unwrap();
            let previous = *last_verdict;
            *last_verdict = verdict;
            previous
        };
        if verdict != previous {
            self.log_verdict(verdict, previous, peers);
        }
        match tick {
            Tick::Idle => {
                self.silence_gauge.set(NOT_ARMED);
                false
            }
            Tick::NetworkStalled | Tick::NoPeerInformation => {
                self.silence_gauge.set(NETWORK_STALLED);
                false
            }
            Tick::Silent(silence) => {
                self.silence_gauge.set(silence.as_secs() as i64);
                false
            }
            Tick::Breach(silence) => {
                self.silence_gauge.set(silence.as_secs() as i64);
                self.breach(silence, verdict);
                true
            }
        }
    }

    fn log_verdict(
        &self,
        verdict: Option<PeerVerdict>,
        previous: Option<PeerVerdict>,
        peers: Option<PeerProgress>,
    ) {
        let stall_window_secs = self.peer_stall_window.as_secs();
        match verdict {
            None => {}
            Some(PeerVerdict::NoInformation) => warn!(
                ?peers,
                stale_after_secs = PROBE_STALE_AFTER.as_secs(),
                "commit-liveness clock held: this validator is receiving no consensus commits, \
                 and consensus-core's probes of its peers do not cover enough time to judge by \
                 (no probe yet, the probe time stopped moving, or probing resumed less than a \
                 stall window ago with no peer answering), so there is no telling whether it is \
                 cut off or the network has halted. Holding is the safe side. Brief around a \
                 consensus start; if it persists, consensus or its round prober has stopped \
                 publishing (peers of None means no consensus instance to ask at all)"
            ),
            Some(PeerVerdict::Halted) => warn!(
                ?peers,
                stall_window_secs,
                "commit-liveness clock held: this validator is receiving no consensus commits, \
                 but its peers still answer and none has advanced a round or a commit either, so \
                 this reads as a network-wide consensus halt rather than this node's isolation, \
                 and exiting would only add a replaying validator to a committee that needs \
                 every live one to regain quorum. The clock restarts in full once peers advance \
                 again"
            ),
            Some(PeerVerdict::Unreachable) => warn!(
                ?peers,
                stall_window_secs,
                bound_secs = self.bound.as_secs(),
                "commit-liveness clock running: this validator is receiving no consensus commits \
                 and not one peer has answered its round prober for the whole stall window, \
                 while the prober keeps probing. That is this node cut off, not a halt (a healthy \
                 node still reaches the validators that are up), so it exits at the bound unless \
                 a live commit arrives first"
            ),
            Some(PeerVerdict::Advancing) => {
                if matches!(
                    previous,
                    Some(PeerVerdict::NoInformation | PeerVerdict::Halted)
                ) {
                    info!(
                        ?peers,
                        ?previous,
                        "commit-liveness clock left its hold: peers are advancing"
                    );
                }
            }
        }
    }

    fn breach(&self, silence: Duration, verdict: Option<PeerVerdict>) {
        let (last_leader_round, last_peer_progress, uptime) = {
            let state = self.state.lock().unwrap();
            (
                state.last_leader_round,
                state.last_peer_progress,
                Instant::now().saturating_duration_since(state.started_at),
            )
        };
        error!(
            silence_secs = silence.as_secs(),
            bound_secs = self.bound.as_secs(),
            last_leader_round,
            ?last_peer_progress,
            ?verdict,
            uptime_secs = uptime.as_secs(),
            "this validator has received no live consensus commit for longer than the \
             commit-liveness bound, while its consensus was running, outside any \
             reconfiguration, and while its peers either kept advancing without it or stopped \
             answering it altogether. That is the boundary-isolation form of ika #1864: the \
             process is healthy in every other respect (network connected, metrics served, Sui \
             reads retrying) but its consensus subscriptions are gone in both directions and \
             nothing retries them, so it will contribute nothing and never learn that the epoch \
             advanced. A process restart re-runs the consensus mesh join from scratch and is the \
             only recovery observed in production, so we exit for the supervisor to restart us. \
             If this repeats every bound, each join is re-wedging: capture \
             ika_consensus_subscribed_to and ika_consensus_commit_silence_seconds, report on ika \
             #1864, and set IKA_COMMIT_LIVENESS_WATCHDOG_SECS=0 to stop the exits while \
             investigating"
        );
        if let Some(action) = self.breach_action.lock().unwrap().take() {
            action();
        }
    }
}

impl ConsensusCommitSink for CommitLivenessWatchdog {
    fn commit_received(&self, leader_round: u64, origin: CommitOrigin) {
        let first =
            self.state
                .lock()
                .unwrap()
                .commit_processed(Instant::now(), leader_round, origin);
        if first {
            info!(
                leader_round,
                bound_secs = self.bound.as_secs(),
                "commit-liveness watchdog armed on the first live consensus commit this process \
                 received"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ika_core::authority::round_transport::{ConsensusRoundPayload, round_transport};
    use std::sync::atomic::{AtomicU32, AtomicU64};

    const BOUND: Duration = Duration::from_secs(900);
    const MIN_UPTIME: Duration = Duration::from_secs(1800);
    const PEER_STALL_WINDOW: Duration = Duration::from_secs(225);

    /// Stake of the peers that answer a probe, unless a test says otherwise.
    /// The watchdog compares it with zero only.
    const ANSWERING_STAKE: u64 = 3;

    /// A probe that finished at `secs` (so every call with a new `secs` is a
    /// new probe) and that the peers answered, with the committee at `round`.
    fn answered(secs: u64, round: u64) -> Option<PeerProgress> {
        answered_by(secs, round, ANSWERING_STAKE)
    }

    fn answered_by(secs: u64, round: u64, responsive_stake: u64) -> Option<PeerProgress> {
        let round = u32::try_from(round).unwrap();
        Some(PeerProgress {
            quorum_accepted_round: round,
            quorum_commit_index: round,
            responsive_stake,
            probed_at_ms: secs * 1_000 + 1,
        })
    }

    /// A probe that finished at `secs` and that no peer answered. `round` is
    /// what the last answered probe left behind: consensus-core never lowers
    /// it, so an isolated node reads it frozen.
    fn unanswered(secs: u64, round: u64) -> Option<PeerProgress> {
        answered_by(secs, round, 0)
    }

    /// A committee that advances between every two reads: what a spawned
    /// watchdog sees on a live network.
    fn climbing_peers() -> Option<PeerProgressSource> {
        let probe = AtomicU32::new(0);
        Some(Box::new(move || {
            let probe = probe.fetch_add(1, Ordering::SeqCst) + 1;
            Some(PeerProgress {
                quorum_accepted_round: probe,
                quorum_commit_index: probe,
                responsive_stake: ANSWERING_STAKE,
                probed_at_ms: probe.into(),
            })
        }))
    }

    /// Peers that answer every probe, at a round the test moves by hand.
    fn peers_at(round: Arc<AtomicU32>) -> Option<PeerProgressSource> {
        let probe = AtomicU64::new(0);
        Some(Box::new(move || {
            Some(PeerProgress {
                quorum_accepted_round: round.load(Ordering::SeqCst),
                quorum_commit_index: 0,
                responsive_stake: ANSWERING_STAKE,
                probed_at_ms: probe.fetch_add(1, Ordering::SeqCst) + 1,
            })
        }))
    }

    /// A prober that keeps probing and that no peer ever answers, with the
    /// committee frozen where this node last saw it: the Tecnodes wedge.
    fn unreachable_peers() -> Option<PeerProgressSource> {
        let probe = AtomicU64::new(0);
        Some(Box::new(move || {
            Some(PeerProgress {
                quorum_accepted_round: 500,
                quorum_commit_index: 400,
                responsive_stake: 0,
                probed_at_ms: probe.fetch_add(1, Ordering::SeqCst) + 1,
            })
        }))
    }

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

    /// Unless a helper says otherwise, ticks run on a LIVE network: every
    /// tick reads a new probe that peers answered, with the round one past
    /// the tick's time in seconds, so it has risen since any earlier tick and
    /// the network-stall hold never engages. (One past, because a round of 0
    /// is consensus-core's "nothing reported yet", not a reading.)
    impl Clock {
        fn new() -> Self {
            let t0 = Instant::now();
            let mut clock = Self {
                t0,
                state: LivenessState::new(t0),
            };
            // The poller's first reading, before anything arms: the peer
            // round's baseline, which every later tick rises above.
            clock.tick_at(0);
            clock
        }

        fn at(&self, secs: u64) -> Instant {
            self.t0 + Duration::from_secs(secs)
        }

        fn commit_at(&mut self, secs: u64) {
            self.state
                .commit_processed(self.at(secs), 1_000 + secs, CommitOrigin::Live);
        }

        fn replayed_commit_at(&mut self, secs: u64) {
            self.state
                .commit_processed(self.at(secs), 1_000 + secs, CommitOrigin::Replayed);
        }

        fn tick_at(&mut self, secs: u64) -> Tick {
            self.tick_at_with_phase(secs, false)
        }

        fn tick_at_with_phase(&mut self, secs: u64, reconfiguring: bool) -> Tick {
            self.tick_with(secs, reconfiguring, answered(secs, secs + 1))
        }

        /// A tick taken while the consensus fold is parked on a full round
        /// channel — the same `held` input the reconfiguration phase feeds.
        fn tick_at_while_fold_blocked(&mut self, secs: u64) -> Tick {
            self.tick_with(secs, true, answered(secs, secs + 1))
        }

        /// A tick that reads exactly `peers`; the same round on successive
        /// ticks is a committee standing still, and the same probe time is a
        /// prober that stopped.
        fn tick_at_with_peers(&mut self, secs: u64, peers: Option<PeerProgress>) -> Tick {
            self.tick_with(secs, false, peers)
        }

        fn tick_with(&mut self, secs: u64, held: bool, peers: Option<PeerProgress>) -> Tick {
            let now = self.at(secs);
            self.state
                .tick(now, BOUND, MIN_UPTIME, PEER_STALL_WINDOW, held, peers)
        }

        /// Consensus restarts at `secs`; the poller takes its first reading
        /// of the new instance one poll later, as it would in production.
        fn resume_at(&mut self, secs: u64) {
            self.state.resume(self.at(secs));
            self.tick_at(secs + POLL_INTERVAL.as_secs());
        }
    }

    #[test]
    fn the_test_stall_window_is_the_one_the_watchdog_derives() {
        assert_eq!(BOUND / PEER_STALL_BOUND_DIVISOR, PEER_STALL_WINDOW);
    }

    /// The state machine honours a hold from the fold-blocked input.
    ///
    /// NOT sufficient on its own — it drives `tick` directly and so cannot
    /// tell whether the watchdog actually DERIVES its hold from the shared
    /// flag. `a_spawned_watchdog_holds_while_the_fold_is_blocked` covers the
    /// wiring; this covers the arithmetic. Written this way because the first
    /// draft was only this half, and deleting the wiring left it green.
    #[test]
    fn a_held_clock_survives_a_burst_and_still_breaches_after_it() {
        let mut clock = Clock::new();
        clock.commit_at(2_000);

        // Two hours of burst, far past the bound, with no arrivals stamped
        // because the loop is parked inside the fold.
        let mut last_blocked_tick = 0;
        for minute in 0..120 {
            last_blocked_tick = 2_000 + minute * 60;
            assert_eq!(
                clock.tick_at_while_fold_blocked(last_blocked_tick),
                Tick::Idle,
                "a fold waiting on the drain is holding a commit, not missing one",
            );
        }

        // The burst clears: the clock restarts from the last held tick, so
        // the blocked time is not retroactively counted against the node.
        assert_eq!(
            clock.tick_at(last_blocked_tick + 60),
            Tick::Silent(Duration::from_secs(60)),
            "silence must be measured from the end of the hold, not its start",
        );
        // And a node that genuinely goes quiet after the burst still breaches,
        // so the hold buys tolerance for blocking and nothing else.
        assert_eq!(
            clock.tick_at(last_blocked_tick + 1_000),
            Tick::Breach(Duration::from_secs(1_000)),
        );
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
        unarmed.resume_at(100);
        assert_eq!(
            unarmed.tick_at(100_000),
            Tick::Idle,
            "a consensus start is not a commit; it must not arm the watchdog"
        );

        let mut armed = Clock::new();
        armed.commit_at(2_000);
        armed.state.hold();
        armed.resume_at(5_000);
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

    /// The second half of the 2026-11-08 halt: replayed commits armed the
    /// watchdog, so every node exited one bound after its own replay ended
    /// while the network was still down.
    #[test]
    fn replayed_commits_neither_arm_the_clock_nor_reset_it() {
        let mut clock = Clock::new();
        // Two hours of boot replay re-folding the epoch from the store.
        for secs in (100..=7_200).step_by(100) {
            clock.replayed_commit_at(secs);
            assert_eq!(
                clock.tick_at(secs),
                Tick::Idle,
                "a commit re-read from this node's own store must not arm the watchdog"
            );
        }
        // The replay is over and nothing live arrives: far past the bound and
        // the uptime floor, the watchdog is still unarmed.
        assert_eq!(
            clock.tick_at(7_200 + 4 * BOUND.as_secs()),
            Tick::Idle,
            "a node that finished replaying into a halted network must not be on the clock"
        );

        // The first live commit is what arms it.
        clock.commit_at(20_000);
        assert_eq!(
            clock.tick_at(20_600),
            Tick::Silent(Duration::from_secs(600))
        );
        // Stated as a property rather than a production sequence: a replayed
        // commit is no evidence of a live connection, so it cannot buy an
        // armed clock more time either.
        clock.replayed_commit_at(20_800);
        assert_eq!(
            clock.tick_at(20_900),
            Tick::Breach(Duration::from_secs(900)),
            "a replayed commit must not reset the silence clock"
        );
    }

    /// The first half of the 2026-11-08 halt: consensus stopped network-wide,
    /// and one bound later every validator still running exited.
    #[test]
    fn a_network_wide_halt_holds_the_clock_past_the_bound() {
        let mut clock = Clock::new();
        let halted = 2_000;
        // The last commit lands with the committee at round 2_000...
        assert_eq!(
            clock.tick_at_with_peers(2_000, answered(2_000, halted)),
            Tick::Idle
        );
        clock.commit_at(2_000);
        // ...and then nobody commits and the round stands still: polled at
        // the real cadence for six bounds.
        let poll = POLL_INTERVAL.as_secs() as usize;
        let mut first_stalled_tick = None;
        let mut last_tick = 2_000;
        for secs in (2_000 + POLL_INTERVAL.as_secs()..=2_000 + 6 * BOUND.as_secs()).step_by(poll) {
            let tick = clock.tick_at_with_peers(secs, answered(secs, halted));
            assert!(
                !matches!(tick, Tick::Breach(_)),
                "no peer is advancing either, so this is a halted network, not an isolated \
                 node: exiting adds one more replaying validator to a committee that needs every \
                 live one to regain quorum. Breached at {secs}s with {tick:?}"
            );
            if tick == Tick::NetworkStalled && first_stalled_tick.is_none() {
                first_stalled_tick = Some(secs);
            }
            last_tick = secs;
        }
        assert_eq!(
            first_stalled_tick,
            Some(2_000 + PEER_STALL_WINDOW.as_secs()),
            "the hold engages once peers have been flat for the stall window, well inside the bound"
        );

        // Quorum is back and peers advance: the clock restarts from the last
        // held tick, so a node that is still connected gets the full bound to
        // receive its first commit instead of exiting on the spot.
        let next_tick = last_tick + POLL_INTERVAL.as_secs();
        assert_eq!(
            clock.tick_at_with_peers(next_tick, answered(next_tick, halted + 1)),
            Tick::Silent(POLL_INTERVAL),
        );
    }

    /// The failure the watchdog exists for must survive the halt hold: a node
    /// whose subscriptions are gone still reads its peers' rounds climbing
    /// through the round prober, and must exit one bound after its last live
    /// commit — even when peers rise only just often enough to stay inside the
    /// stall window.
    #[test]
    fn an_isolated_node_still_exits_while_its_peers_keep_advancing() {
        let mut clock = Clock::new();
        clock.commit_at(2_000);
        let rise_every = PEER_STALL_WINDOW.as_secs() - POLL_INTERVAL.as_secs();
        let poll = POLL_INTERVAL.as_secs() as usize;
        let mut peer_round = 0;
        for secs in (2_000 + POLL_INTERVAL.as_secs()..2_000 + BOUND.as_secs()).step_by(poll) {
            if (secs - 2_000) % rise_every == 0 {
                peer_round += 50;
            }
            assert_eq!(
                clock.tick_at_with_peers(secs, answered(secs, peer_round)),
                Tick::Silent(Duration::from_secs(secs - 2_000)),
                "peers rose within the stall window, so the clock must keep running"
            );
        }
        let breach_tick = 2_000 + BOUND.as_secs();
        assert_eq!(
            clock.tick_at_with_peers(breach_tick, answered(breach_tick, peer_round)),
            Tick::Breach(BOUND),
            "silent for a bound while the committee moved on without it: the #1864 isolation"
        );
    }

    /// The 2026-08-14 Tecnodes wedge: every round-prober request failed, so
    /// the accepted round froze. Read by the round alone that is a halt, and
    /// the node was held forever. Fresh probes that no peer answers are this
    /// node cut off: the clock must run to the bound without a hold.
    #[test]
    fn an_unreachable_node_exits_at_the_bound() {
        let mut clock = Clock::new();
        let frozen = 2_000;
        assert_eq!(
            clock.tick_at_with_peers(2_000, answered(2_000, frozen)),
            Tick::Idle
        );
        clock.commit_at(2_000);
        let poll = POLL_INTERVAL.as_secs();
        for secs in (2_000 + poll..2_000 + BOUND.as_secs()).step_by(poll as usize) {
            assert_eq!(
                clock.tick_at_with_peers(secs, unanswered(secs, frozen)),
                Tick::Silent(Duration::from_secs(secs - 2_000)),
                "fresh probes that no peer answers are isolation, not a halt: the clock must run"
            );
        }
        let breach_tick = 2_000 + BOUND.as_secs();
        assert_eq!(
            clock.tick_at_with_peers(breach_tick, unanswered(breach_tick, frozen)),
            Tick::Breach(BOUND),
            "silent for a bound with no peer answering: the Tecnodes isolation"
        );
    }

    /// The other side of that line: a halt during which only a minority of
    /// the committee is up, so most probes fail and one peer answers now and
    /// then. One answer anywhere in the window is not isolation. The bar is
    /// exactly zero answering stake, never "below a quorum".
    #[test]
    fn a_halt_that_one_peer_still_answers_holds_past_several_bounds() {
        let mut clock = Clock::new();
        let halted = 2_000;
        assert_eq!(
            clock.tick_at_with_peers(2_000, answered(2_000, halted)),
            Tick::Idle
        );
        clock.commit_at(2_000);
        let poll = POLL_INTERVAL.as_secs();
        // Every tenth poll: inside the stall window, far from every probe.
        let answer_every = 10 * poll;
        let one_peer = 1;
        for secs in (2_000 + poll..=2_000 + 6 * BOUND.as_secs()).step_by(poll as usize) {
            let peers = if (secs - 2_000) % answer_every == 0 {
                answered_by(secs, halted, one_peer)
            } else {
                unanswered(secs, halted)
            };
            let expected = if secs < 2_000 + PEER_STALL_WINDOW.as_secs() {
                // The last commit is still inside the window.
                Tick::Silent(Duration::from_secs(secs - 2_000))
            } else {
                Tick::NetworkStalled
            };
            assert_eq!(
                clock.tick_at_with_peers(secs, peers),
                expected,
                "at {secs}s: a peer that answers inside the window makes this a halt, and \
                 exiting would add a replaying validator to a committee short of quorum"
            );
        }
    }

    /// The commit syncer's quorum commit index is peer progress on its own:
    /// while the highest accepted round reads flat, commits that a quorum
    /// keeps voting for are still the committee moving on without this node.
    #[test]
    fn a_rising_quorum_commit_index_alone_is_peers_advancing() {
        let mut clock = Clock::new();
        let round = 2_000;
        assert_eq!(
            clock.tick_at_with_peers(2_000, answered(2_000, round)),
            Tick::Idle
        );
        clock.commit_at(2_000);
        let poll = POLL_INTERVAL.as_secs();
        let rise_every = PEER_STALL_WINDOW.as_secs() - poll;
        for secs in (2_000 + poll..2_000 + BOUND.as_secs()).step_by(poll as usize) {
            let peers = Some(PeerProgress {
                quorum_commit_index: u32::try_from(round + (secs - 2_000) / rise_every).unwrap(),
                ..answered(secs, round).unwrap()
            });
            assert_eq!(
                clock.tick_at_with_peers(secs, peers),
                Tick::Silent(Duration::from_secs(secs - 2_000)),
                "the quorum commit index rose within the stall window, so the clock must run"
            );
        }
        let breach_tick = 2_000 + BOUND.as_secs();
        let peers = Some(PeerProgress {
            quorum_commit_index: u32::try_from(round + BOUND.as_secs() / rise_every).unwrap(),
            ..answered(breach_tick, round).unwrap()
        });
        assert_eq!(
            clock.tick_at_with_peers(breach_tick, peers),
            Tick::Breach(BOUND)
        );
    }

    /// No information holds: no consensus instance to ask, or one whose
    /// prober has not completed a probe yet — even while its commit syncer
    /// has already published a quorum commit index.
    #[test]
    fn no_reading_or_no_probe_yet_holds_the_clock() {
        let syncer_only = PeerProgress {
            quorum_commit_index: 800,
            ..PeerProgress::default()
        };
        for peers in [None, Some(PeerProgress::default()), Some(syncer_only)] {
            let mut clock = Clock::new();
            clock.commit_at(2_000);
            let poll = POLL_INTERVAL.as_secs();
            for secs in (2_000 + poll..=2_000 + 6 * BOUND.as_secs()).step_by(poll as usize) {
                assert_eq!(
                    clock.tick_at_with_peers(secs, peers),
                    Tick::NoPeerInformation,
                    "at {secs}s with {peers:?}: without a probe there is no telling isolation \
                     from a halt, so the clock must hold"
                );
            }
        }
    }

    /// A prober that stopped publishing leaves a reading that no longer
    /// moves. Its last probe found nobody, which on a single read is exactly
    /// what isolation looks like; only its age says it carries no
    /// information, and it must hold rather than exit. When probing resumes,
    /// still unanswered, the cut-off verdict needs a whole window of fresh
    /// probes before the clock runs.
    #[test]
    fn a_reading_that_stopped_moving_holds_even_when_no_peer_answered_it() {
        let mut clock = Clock::new();
        let frozen = 2_000;
        assert_eq!(
            clock.tick_at_with_peers(2_000, answered(2_000, frozen)),
            Tick::Idle
        );
        clock.commit_at(2_000);
        let poll = POLL_INTERVAL.as_secs();
        let last_probe = unanswered(2_000 + poll, frozen);
        assert_eq!(
            clock.tick_at_with_peers(2_000 + poll, last_probe),
            Tick::Silent(POLL_INTERVAL)
        );
        let resumed = 2_000 + 6 * BOUND.as_secs();
        for secs in (2_000 + 2 * poll..resumed).step_by(poll as usize) {
            assert_eq!(
                clock.tick_at_with_peers(secs, last_probe),
                Tick::NoPeerInformation,
                "at {secs}s: a probe time that stopped moving is no information, not isolation"
            );
        }

        let running = resumed + PEER_STALL_WINDOW.as_secs();
        for secs in (resumed..running).step_by(poll as usize) {
            assert_eq!(
                clock.tick_at_with_peers(secs, unanswered(secs, frozen)),
                Tick::NoPeerInformation,
                "at {secs}s: probing resumed less than a window ago; one probe that nobody \
                 answers is how every consensus start can look"
            );
        }
        // A whole window of fresh, unanswered probes: the clock runs from the
        // last held tick and breaches a bound later.
        for secs in (running..running - poll + BOUND.as_secs()).step_by(poll as usize) {
            assert_eq!(
                clock.tick_at_with_peers(secs, unanswered(secs, frozen)),
                Tick::Silent(Duration::from_secs(secs - (running - poll))),
            );
        }
        let breach_tick = running - poll + BOUND.as_secs();
        assert_eq!(
            clock.tick_at_with_peers(breach_tick, unanswered(breach_tick, frozen)),
            Tick::Breach(BOUND)
        );
    }

    /// A consensus restart starts the reading over: the new instance counts
    /// rounds and commits from zero, so marks carried over from the old one
    /// would read its climb as a committee standing still, and hold an
    /// isolated node as though the network had halted.
    #[test]
    fn a_consensus_restart_starts_the_peer_reading_over() {
        let mut clock = Clock::new();
        let old_instance_round = 50_000;
        assert_eq!(
            clock.tick_at_with_peers(2_000, answered(2_000, old_instance_round)),
            Tick::Idle
        );
        clock.commit_at(2_000);
        clock.state.hold();
        clock.state.resume(clock.at(3_000));
        // The new instance climbs from round 10, far below the old mark, and
        // this node still receives nothing from it.
        let poll = POLL_INTERVAL.as_secs();
        for secs in (3_000 + poll..3_000 + BOUND.as_secs()).step_by(poll as usize) {
            assert_eq!(
                clock.tick_at_with_peers(secs, answered(secs, 10 + secs - 3_000)),
                Tick::Silent(Duration::from_secs(secs - 3_000)),
                "the new instance's rising rounds are peer progress, whatever the old one reached"
            );
        }
        let breach_tick = 3_000 + BOUND.as_secs();
        assert_eq!(
            clock.tick_at_with_peers(breach_tick, answered(breach_tick, 10 + BOUND.as_secs())),
            Tick::Breach(BOUND)
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
            Arc::new(AtomicBool::new(false)),
            climbing_peers(),
        )
        .expect("an enabled watchdog spawns");
        assert_eq!(silence.get(), NOT_ARMED);

        watchdog.commit_received(1_234, CommitOrigin::Live);
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

    /// THE hazard test: a fold parked on a full round channel must not
    /// breach, and the watchdog must learn that from the shared flag rather
    /// than from anything the test hands it.
    ///
    /// While the fold waits for the MPC drain, the consensus loop is not
    /// calling `recv`, so no arrival is stamped and the silence clock runs
    /// even though commits are queuing one hop upstream. Without the hold a
    /// deep burst exits a healthy node after the bound, and the node replays
    /// into the same burst — the crash loop this design removes,
    /// reintroduced one hop below where it was fixed.
    #[tokio::test(start_paused = true)]
    async fn a_spawned_watchdog_holds_while_the_fold_is_blocked() {
        let (fired, on_breach) = flag();
        let silence = gauge("test_fold_blocked_commit_silence_seconds");
        let fold_blocked = Arc::new(AtomicBool::new(false));
        let watchdog = CommitLivenessWatchdog::spawn_with(
            silence.clone(),
            gauge("test_fold_blocked_reconfig_phase"),
            Some(BOUND),
            on_breach,
            fold_blocked.clone(),
            climbing_peers(),
        )
        .expect("an enabled watchdog spawns");

        watchdog.commit_received(1_234, CommitOrigin::Live);
        // The burst starts: the fold parks on a full channel and stamps no
        // further arrivals.
        fold_blocked.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(4 * BOUND.as_secs())).await;
        assert!(
            !fired.load(Ordering::SeqCst),
            "a fold blocked on the drain must not read as consensus silence, however long              the burst lasts"
        );

        // The burst clears and the node goes genuinely quiet: it must still
        // breach, so the hold buys tolerance for blocking and nothing else.
        fold_blocked.store(false, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(2 * BOUND.as_secs())).await;
        assert!(
            fired.load(Ordering::SeqCst),
            "silence after the burst clears must still exit the node"
        );
    }

    /// The same hazard driven end to end: a REAL round channel, filled by
    /// real sends, holding a real watchdog.
    ///
    /// The test above sets the shared flag by hand, so it proves the watchdog
    /// honours the flag but not that anything ever sets it. This wires the two
    /// halves together the way the node does — one `Arc<AtomicBool>` handed to
    /// both — so that removing either end (the transport's store, or the
    /// watchdog's load) exits a node whose only problem is a slow drain.
    #[tokio::test(start_paused = true)]
    async fn a_full_round_channel_holds_the_watchdog_while_commits_queue() {
        let (fired, on_breach) = flag();
        let fold_blocked = Arc::new(AtomicBool::new(false));
        let watchdog = CommitLivenessWatchdog::spawn_with(
            gauge("test_full_channel_commit_silence_seconds"),
            gauge("test_full_channel_reconfig_phase"),
            Some(BOUND),
            on_breach,
            fold_blocked.clone(),
            climbing_peers(),
        )
        .expect("an enabled watchdog spawns");
        // Capacity one so the second round provably parks the fold.
        let (sender, mut receiver) = round_transport(1, fold_blocked);

        watchdog.commit_received(1_234, CommitOrigin::Live);
        sender.send(round_payload(1)).await;

        // Rounds 2..=8 queue behind a drain that is not consuming. The fold
        // parks on the first of them and stamps no further arrivals.
        let fold = {
            let sender = sender.clone();
            tokio::spawn(async move {
                for round in 2..=8 {
                    sender.send(round_payload(round)).await;
                }
            })
        };
        tokio::time::sleep(Duration::from_secs(4 * BOUND.as_secs())).await;

        assert!(
            sender.fold_blocked(),
            "capacity is one and nothing has been consumed; the fold must be parked"
        );
        assert!(
            !fired.load(Ordering::SeqCst),
            "a node whose fold is parked on a full round channel is not an isolated node, and \
             must not be exited however long the queue takes to clear"
        );

        // The drain catches up. The hold must lift with it, not outlive it.
        for _ in 1..=8 {
            receiver.recv().await.expect("the fold is still sending");
        }
        fold.await.unwrap();
        assert!(!sender.fold_blocked(), "the hold lifts when the fold does");
        tokio::time::sleep(Duration::from_secs(2 * BOUND.as_secs())).await;
        assert!(
            fired.load(Ordering::SeqCst),
            "silence once the queue has cleared is ordinary commit silence and must still exit"
        );
    }

    fn round_payload(round: u64) -> ConsensusRoundPayload {
        ConsensusRoundPayload {
            round,
            mpc_messages: Vec::new(),
            mpc_outputs: Vec::new(),
            internal_mpc_outputs: Vec::new(),
            verified_dwallet_checkpoint_messages: Vec::new(),
            verified_system_checkpoint_messages: Vec::new(),
            idle_status_updates: Vec::new(),
            sui_chain_observation_updates: Vec::new(),
            global_presign_requests: Vec::new(),
            noa_observations: Vec::new(),
            noa_presign_demands: Vec::new(),
        }
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
            Arc::new(AtomicBool::new(false)),
            climbing_peers(),
        )
        .expect("an enabled watchdog spawns");

        watchdog.commit_received(1_234, CommitOrigin::Live);
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

    /// The halt hold end to end, through the late-bound reader production
    /// installs with `watch_peers`: no reading at all, then a flat one, both
    /// hold and export `-2`; a climbing one exits a node that still hears
    /// nothing.
    #[tokio::test(start_paused = true)]
    async fn a_spawned_watchdog_holds_through_a_network_wide_halt_and_exports_it() {
        let (fired, on_breach) = flag();
        let silence = gauge("test_halt_commit_silence_seconds");
        let watchdog = CommitLivenessWatchdog::spawn_with(
            silence.clone(),
            gauge("test_halt_reconfig_phase"),
            Some(BOUND),
            on_breach,
            Arc::new(AtomicBool::new(false)),
            None,
        )
        .expect("an enabled watchdog spawns");
        watchdog.commit_received(1_234, CommitOrigin::Live);

        tokio::time::sleep(2 * BOUND).await;
        assert!(
            !fired.load(Ordering::SeqCst),
            "with no peer reading at all there is no evidence that anyone is advancing"
        );
        assert_eq!(silence.get(), NETWORK_STALLED);

        let peer_round = Arc::new(AtomicU32::new(7));
        watchdog.watch_peers(peers_at(peer_round.clone()).unwrap());
        tokio::time::sleep(4 * BOUND).await;
        assert!(
            !fired.load(Ordering::SeqCst),
            "peers standing still for four bounds is a halted network, not an isolated node"
        );
        assert_eq!(
            silence.get(),
            NETWORK_STALLED,
            "a fleet-wide halt must read as one from every validator's metrics"
        );

        // Quorum is back and the committee advances, but this node still
        // receives nothing: that is isolation from a live network.
        let climbing = tokio::spawn(async move {
            loop {
                peer_round.fetch_add(10, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        tokio::time::sleep(BOUND / 2).await;
        assert!(
            (0..BOUND.as_secs() as i64).contains(&silence.get()),
            "once peers advance the clock runs again, from zero: {}",
            silence.get()
        );
        tokio::time::sleep(BOUND).await;
        climbing.abort();
        assert!(
            fired.load(Ordering::SeqCst),
            "silent for a bound while peers advanced must exit the node"
        );
    }

    /// The Tecnodes isolation end to end, through the late-bound reader
    /// production installs: probes that no peer answers keep the clock
    /// running and the gauge counting, and the node exits.
    #[tokio::test(start_paused = true)]
    async fn a_spawned_watchdog_exits_an_unreachable_node_and_exports_the_silence() {
        let (fired, on_breach) = flag();
        let silence = gauge("test_unreachable_commit_silence_seconds");
        let watchdog = CommitLivenessWatchdog::spawn_with(
            silence.clone(),
            gauge("test_unreachable_reconfig_phase"),
            Some(BOUND),
            on_breach,
            Arc::new(AtomicBool::new(false)),
            None,
        )
        .expect("an enabled watchdog spawns");
        watchdog.watch_peers(unreachable_peers().unwrap());

        // The prober has been failing for a few polls when the last live
        // commit lands, one second past a poll.
        tokio::time::sleep(Duration::from_secs(61)).await;
        watchdog.commit_received(1_234, CommitOrigin::Live);
        tokio::time::sleep(BOUND / 2).await;
        assert_eq!(
            silence.get(),
            510 - 61,
            "polls land on multiples of 15s; the last one ran at 510s, and the clock must have \
             run from the commit at 61s without a single hold"
        );
        assert!(!fired.load(Ordering::SeqCst), "inside the bound");

        tokio::time::sleep(2 * BOUND - BOUND / 2 - Duration::from_secs(61) + POLL_INTERVAL).await;
        assert!(
            fired.load(Ordering::SeqCst),
            "silent past the bound with no peer answering, on a process past the uptime floor, \
             must exit"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_spawned_watchdog_is_not_armed_by_the_boot_replay() {
        let (fired, on_breach) = flag();
        let silence = gauge("test_replay_commit_silence_seconds");
        let watchdog = CommitLivenessWatchdog::spawn_with(
            silence.clone(),
            gauge("test_replay_reconfig_phase"),
            Some(BOUND),
            on_breach,
            Arc::new(AtomicBool::new(false)),
            climbing_peers(),
        )
        .expect("an enabled watchdog spawns");

        for leader_round in 1..=10_000 {
            watchdog.commit_received(leader_round, CommitOrigin::Replayed);
        }
        tokio::time::sleep(4 * BOUND).await;
        assert!(
            !fired.load(Ordering::SeqCst),
            "a replay followed by no live commit must never exit the node"
        );
        assert_eq!(silence.get(), NOT_ARMED);

        watchdog.commit_received(10_001, CommitOrigin::Live);
        tokio::time::sleep(BOUND + POLL_INTERVAL).await;
        assert!(
            fired.load(Ordering::SeqCst),
            "the first live commit arms the clock"
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
                Arc::new(AtomicBool::new(false)),
                climbing_peers(),
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
