// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Test-only hook that parks the dWallet-MPC drain **without stopping it**.
//!
//! # Why this lives in the production binary
//!
//! The failure it builds is a composition, and every piece of it is already
//! unit-tested alone: the fold parks on a full round channel
//! (`authority::round_transport`), the commit-liveness watchdog HOLDS while it
//! is parked (`ika-node`'s `commit_liveness_watchdog`), and the counters are
//! published from a task that shares fate with nothing
//! (`DWalletMPCService::publish_round_transport_metrics`). What was never
//! exercised is the three of them together on a REAL node: a drain that is
//! alive but stuck, a fold parked behind it, a watchdog that correctly does
//! not exit, and an operator whose only evidence is the metrics (ika #2102,
//! `dev-docs/specs/event-sourced-epoch.md`).
//!
//! `ika-upgrade-test` spawns separately-compiled `ika-validator` child
//! processes; it cannot reach a `cfg(test)` seam inside them. So the hook has
//! to be readable by the production binary, which is exactly why it is written
//! the way the other production-binary-readable test knobs are
//! (`IKA_ENABLE_SMALL_PRESIGN_POOLS`, `IKA_NO_CRASH_ON_PANIC` in
//! `ika-node`'s `node_runner`): default off, an explicit value required to
//! arm it, and a WARN on every boot where it is active so it can never be
//! mistaken for a feature or left on unnoticed.
//!
//! # The knobs
//!
//! - `IKA_TEST_PARK_MPC_DRAIN_AFTER_ROUND=<n>` — arm the hook. Once the drain
//!   has consumed `n` rounds **since the boot replay finished**, it stops
//!   consuming. `n` counts rounds, it is NOT a consensus round number, and it
//!   deliberately excludes the boot replay: parking mid-replay would wedge the
//!   node's BOOT (the replay's own folds park on this channel), which is a
//!   different failure and not one a scenario can drive. `0` parks the drain
//!   the moment the replay releases it, which is what a harness wants — it
//!   needs no estimate of the commit rate.
//! - `IKA_TEST_PARK_MPC_DRAIN_UNPARK_FILE=<path>` — the release. While parked,
//!   the drain stats this path at most every
//!   [`UNPARK_POLL_INTERVAL`]; when it appears, the drain resumes and this
//!   process never parks again. A file rather than a second env var because
//!   the harness cannot edit a running child's environment, and a file it
//!   already has a data dir for costs nothing. Leave it unset and the park is
//!   permanent for the process lifetime.
//!
//! # What "park" means here, exactly
//!
//! `drain_consensus_rounds` returns without receiving anything. The service
//! loop keeps running — it still ingests keys, spawns computations, submits to
//! consensus and answers its admin and metrics endpoints — so the node is
//! alive in every way an operator can see from the outside. What stops is
//! consumption, so the bounded round channel fills, the fold parks on it, and
//! the watchdog holds. That is the shape of a wedged-but-alive drain, and it
//! is the one this hook exists to reproduce; it is NOT a simulation of a
//! crashed service (that is `recognized_self_as_malicious`, which breaks the
//! loop and detaches the fold).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tracing::warn;

/// Arms the hook: park after this many rounds consumed post-replay.
pub(crate) const PARK_AFTER_ROUND_ENV_VAR: &str = "IKA_TEST_PARK_MPC_DRAIN_AFTER_ROUND";

/// Releases the park when this path appears.
pub(crate) const UNPARK_FILE_ENV_VAR: &str = "IKA_TEST_PARK_MPC_DRAIN_UNPARK_FILE";

/// How often a parked drain stats the unpark path. Short enough that a
/// harness's "unpark now" is observable well inside one metrics scrape, long
/// enough that a park held for minutes costs a few hundred `stat` calls rather
/// than one per 20ms service iteration.
const UNPARK_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Process-wide, resolved once. `None` means the hook is off, which is the
/// only state any production process is ever in.
static HOOK: OnceLock<Option<ParkMpcDrainHook>> = OnceLock::new();

/// The hook for this process, or `None` when it is not armed.
///
/// Resolved and logged on first use — which is the first drain iteration of
/// the first epoch, i.e. once per boot.
pub(crate) fn park_mpc_drain_hook() -> Option<&'static ParkMpcDrainHook> {
    HOOK.get_or_init(|| {
        let hook = ParkMpcDrainHook::from_values(
            std::env::var(PARK_AFTER_ROUND_ENV_VAR).ok().as_deref(),
            std::env::var(UNPARK_FILE_ENV_VAR).ok().as_deref(),
        );
        if let Some(hook) = hook.as_ref() {
            warn!(
                park_after_rounds = hook.park_after_rounds,
                unpark_file = ?hook.unpark_file,
                "{PARK_AFTER_ROUND_ENV_VAR} is set: the dWallet-MPC drain will STOP CONSUMING \
                 consensus rounds after the configured count, leaving the service running while \
                 the round channel fills and the consensus fold parks. TEST/CI ONLY — this \
                 disables this validator's MPC participation for as long as it is parked, and \
                 must never be set on a production validator."
            );
        }
        hook
    })
    .as_ref()
}

/// See the module docs.
pub(crate) struct ParkMpcDrainHook {
    /// Rounds the drain may consume post-replay before it parks.
    park_after_rounds: u64,
    /// Path whose appearance releases the park; `None` = park permanently.
    unpark_file: Option<PathBuf>,
    /// Set on the first park, so the loud "now parked" line is emitted once
    /// rather than every 20ms service iteration.
    announced_park: AtomicBool,
    /// Set once the release has been observed. One-shot on purpose: a harness
    /// that unparks has moved on to asserting the RECOVERY, and a hook that
    /// could re-park (say, at the next epoch's fresh round count) would wedge
    /// the node again underneath that assertion.
    released: AtomicBool,
    /// Millis since [`Self::started_at`] at the last unpark stat; `0` = never
    /// checked.
    last_unpark_check_millis: AtomicU64,
    started_at: Instant,
}

impl ParkMpcDrainHook {
    /// Parse the two knobs. `None` = the hook is off.
    ///
    /// An absent, empty or unparseable count leaves it off: mere presence must
    /// not arm a knob that stops a validator's MPC, matching the
    /// `IKA_ENABLE_SMALL_PRESIGN_POOLS` / `IKA_NO_CRASH_ON_PANIC` convention.
    /// An unparseable value is still WARNed about, because "I set it and
    /// nothing happened" is otherwise indistinguishable from a broken hook.
    fn from_values(park_after_round: Option<&str>, unpark_file: Option<&str>) -> Option<Self> {
        let raw = park_after_round?.trim();
        if raw.is_empty() {
            return None;
        }
        let park_after_rounds = match raw.parse::<u64>() {
            Ok(rounds) => rounds,
            Err(_) => {
                warn!(
                    value = raw,
                    "unparseable {PARK_AFTER_ROUND_ENV_VAR}; the MPC drain park hook stays OFF"
                );
                return None;
            }
        };
        let unpark_file = unpark_file
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        Some(Self {
            park_after_rounds,
            unpark_file,
            announced_park: AtomicBool::new(false),
            released: AtomicBool::new(false),
            last_unpark_check_millis: AtomicU64::new(0),
            started_at: Instant::now(),
        })
    }

    /// Whether this drain iteration must consume nothing.
    ///
    /// `rounds_consumed_since_replay` is the drain's own post-replay count;
    /// see the module docs for why the replay is excluded.
    pub(crate) fn should_park(&self, rounds_consumed_since_replay: u64) -> bool {
        if self.released.load(Ordering::Acquire) {
            return false;
        }
        if rounds_consumed_since_replay < self.park_after_rounds {
            return false;
        }
        if self.poll_unpark(Path::exists) {
            return false;
        }
        if !self.announced_park.swap(true, Ordering::AcqRel) {
            warn!(
                rounds_consumed_since_replay,
                unpark_file = ?self.unpark_file,
                "{PARK_AFTER_ROUND_ENV_VAR}: the dWallet-MPC drain is now PARKED and will consume \
                 no further consensus rounds. The service stays alive, the round channel will \
                 fill, and the consensus fold will park on it (the commit-liveness watchdog holds \
                 while it is parked, by design). TEST/CI ONLY."
            );
        }
        true
    }

    /// Throttled unpark check. Returns whether the park has been released.
    ///
    /// `exists` is injected so the poll cadence is testable without a clock or
    /// a real file.
    fn poll_unpark(&self, exists: impl Fn(&Path) -> bool) -> bool {
        let Some(path) = self.unpark_file.as_ref() else {
            return false;
        };
        // `max(1)` keeps `0` meaning "never checked": a first check landing at
        // elapsed 0 would otherwise re-arm the never-checked state and stat on
        // every iteration until the clock moved.
        let elapsed_millis = u64::try_from(self.started_at.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let last = self.last_unpark_check_millis.load(Ordering::Relaxed);
        if last != 0
            && elapsed_millis.saturating_sub(last) < UNPARK_POLL_INTERVAL.as_millis() as u64
        {
            return false;
        }
        self.last_unpark_check_millis
            .store(elapsed_millis, Ordering::Relaxed);
        if !exists(path) {
            return false;
        }
        if !self.released.swap(true, Ordering::AcqRel) {
            warn!(
                unpark_file = ?path,
                "{UNPARK_FILE_ENV_VAR} appeared: the dWallet-MPC drain is UNPARKED and will \
                 consume the backlog the consensus fold has been parked on. This process will \
                 not park again."
            );
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn armed(after: &str, unpark: Option<&str>) -> ParkMpcDrainHook {
        ParkMpcDrainHook::from_values(Some(after), unpark).expect("hook should be armed")
    }

    #[test]
    fn off_unless_explicitly_armed_with_a_number() {
        // The states a production validator can be in, and the ones a typo in
        // a launch script produces. None of them may stop a drain.
        assert!(ParkMpcDrainHook::from_values(None, None).is_none());
        assert!(ParkMpcDrainHook::from_values(Some(""), None).is_none());
        assert!(ParkMpcDrainHook::from_values(Some("   "), None).is_none());
        assert!(ParkMpcDrainHook::from_values(Some("yes"), None).is_none());
        assert!(ParkMpcDrainHook::from_values(Some("-1"), None).is_none());
        assert!(ParkMpcDrainHook::from_values(Some("1"), None).is_some());
        assert!(ParkMpcDrainHook::from_values(Some(" 0 "), None).is_some());
    }

    #[test]
    fn parks_only_once_the_post_replay_count_is_reached() {
        let hook = armed("3", None);
        assert!(!hook.should_park(0));
        assert!(!hook.should_park(2));
        assert!(hook.should_park(3));
        assert!(hook.should_park(4));
    }

    #[test]
    fn a_zero_count_parks_as_soon_as_the_replay_releases_the_drain() {
        // What the harness sets: it has no way to predict the commit rate, so
        // "park the moment you go live" is the only threshold it can pick
        // without guessing.
        let hook = armed("0", None);
        assert!(hook.should_park(0));
    }

    #[test]
    fn an_unset_unpark_file_parks_permanently() {
        let hook = armed("0", None);
        assert!(hook.should_park(0));
        assert!(hook.should_park(9_999));
    }

    #[test]
    fn the_unpark_release_is_one_shot() {
        // Once released the process must never park again — a re-park would
        // wedge the node underneath the harness's recovery assertions.
        let hook = armed("0", Some("/tmp/does-not-matter"));
        hook.last_unpark_check_millis.store(0, Ordering::Relaxed);
        assert!(hook.poll_unpark(|_| true));
        assert!(!hook.should_park(0));
        assert!(!hook.should_park(u64::MAX));
    }

    #[test]
    fn the_unpark_path_is_stated_at_most_once_per_poll_interval() {
        let hook = armed("0", Some("/tmp/does-not-matter"));
        let stats = AtomicUsize::new(0);
        let counting_exists = |_: &Path| {
            stats.fetch_add(1, Ordering::Relaxed);
            false
        };
        // Several iterations inside one poll interval (the service loop runs
        // every 20ms; the interval is 500ms) must produce ONE stat.
        for _ in 0..10 {
            assert!(!hook.poll_unpark(counting_exists));
        }
        assert_eq!(stats.load(Ordering::Relaxed), 1);

        // Rewinding the recorded check timestamp is the test's stand-in for
        // the interval elapsing.
        hook.last_unpark_check_millis.store(1, Ordering::Relaxed);
        std::thread::sleep(UNPARK_POLL_INTERVAL);
        assert!(!hook.poll_unpark(counting_exists));
        assert_eq!(stats.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_real_file_appearing_releases_the_park() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sentinel = dir.path().join("unpark");
        let hook = armed("0", Some(sentinel.to_str().expect("utf-8 path")));
        assert!(hook.should_park(0), "parked while the sentinel is absent");

        std::fs::write(&sentinel, b"").expect("write sentinel");
        // Let the throttle expire, then the very next check must release.
        hook.last_unpark_check_millis.store(1, Ordering::Relaxed);
        std::thread::sleep(UNPARK_POLL_INTERVAL);
        assert!(
            !hook.should_park(0),
            "the drain must unpark once the sentinel exists"
        );
    }
}
