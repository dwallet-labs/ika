// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Bounded watchdog over the epoch-reconfiguration critical section.
//!
//! Between tearing down the outgoing epoch's services and creating the new
//! epoch store, `monitor_reconfiguration` crosses several unbounded awaits:
//! joining the aborted checkpoint services, `ConsensusManager::shutdown`,
//! and — inside `AuthorityState::reconfigure` — the `execution_lock` write
//! acquisition and the `epoch_terminated` barrier. A validator that parks
//! on any of them has already torn down its consensus subscriptions, so it
//! emerges consensus-dead with no retry and no crash: the #1864 zombie,
//! observed live twice (testnet 356→357, mainnet 372→373), both times
//! parked for days until an operator restarted the process — and both
//! times the restart recovered it.
//!
//! The watchdog makes that recovery automatic: if the covered window does
//! not complete within the bound, the node exits so its supervisor
//! restarts it. While armed, the current sub-phase is exported on the
//! `ika_reconfig_phase` gauge, so if a node ever breaches (or wedges with
//! the watchdog disabled) the hanging await is attributable from metrics
//! alone — external operators' nodes included, where logs are never
//! available to us.

use prometheus::IntGauge;
use std::time::Duration;
use tokio::sync::oneshot;
use tracing::{error, warn};

/// Values exported on `ika_reconfig_phase` while the watchdog is armed.
pub(crate) mod phase {
    /// Not inside the watchdog-covered reconfiguration window.
    pub(crate) const IDLE: i64 = 0;
    /// Aborting + joining the outgoing epoch's checkpoint services and
    /// signalling the MPC service to exit.
    pub(crate) const SERVICE_TEARDOWN: i64 = 1;
    /// Awaiting `ConsensusManager::shutdown`.
    pub(crate) const CONSENSUS_SHUTDOWN: i64 = 2;
    /// Inside `reconfigure_state`: `execution_lock` write acquisition, the
    /// `epoch_terminated` barrier, and new epoch store creation.
    pub(crate) const RECONFIGURE_STATE: i64 = 3;
    /// Pruning the outgoing epoch's consensus stores.
    pub(crate) const CONSENSUS_STORE_PRUNE: i64 = 4;
}

/// Generous by an order of magnitude: the covered window normally
/// completes in seconds, and the wedges this exists for sat in it for
/// days. Deliberately excludes the prepare-then-start handoff barrier,
/// which can legitimately block for minutes and has its own gauge, retry
/// counter, and alert.
const DEFAULT_BOUND: Duration = Duration::from_secs(600);

/// Environment override for the bound, in seconds. `0` disables the
/// watchdog entirely — an operator escape hatch if a slow host ever
/// breaches on a legitimate transition.
const BOUND_ENV_VAR: &str = "IKA_RECONFIG_WATCHDOG_SECS";

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

/// RAII guard for the covered window: arming starts the timer and sets the
/// phase gauge; dropping (or `disarm`) cancels the timer and returns the
/// gauge to `IDLE`, so every exit path — including `?` and panic unwinds —
/// disarms.
pub(crate) struct ReconfigWatchdog {
    cancel: Option<oneshot::Sender<()>>,
    phase_gauge: IntGauge,
}

impl ReconfigWatchdog {
    /// Arms the watchdog for the transition into `next_epoch`. On breach
    /// the node exits (real nodes) or shuts down the simulated node
    /// (simtests) so the supervisor restarts it.
    pub(crate) fn arm(phase_gauge: IntGauge, next_epoch: u64) -> Self {
        Self::arm_with(
            phase_gauge,
            next_epoch,
            resolve_bound(),
            default_breach_action,
        )
    }

    fn arm_with(
        phase_gauge: IntGauge,
        next_epoch: u64,
        bound: Option<Duration>,
        breach_action: impl FnOnce() + Send + 'static,
    ) -> Self {
        phase_gauge.set(phase::SERVICE_TEARDOWN);
        let cancel = bound.map(|bound| {
            let (cancel_tx, cancel_rx) = oneshot::channel();
            let gauge = phase_gauge.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep(bound) => {
                        error!(
                            next_epoch,
                            phase = gauge.get(),
                            bound_secs = bound.as_secs(),
                            "the epoch transition's teardown-to-restart window exceeded the \
                             watchdog bound; the node is presumed wedged (#1864) and a process \
                             restart is the demonstrated recovery — exiting so the supervisor \
                             restarts us"
                        );
                        breach_action();
                    }
                    _ = cancel_rx => {}
                }
            });
            cancel_tx
        });
        Self {
            cancel,
            phase_gauge,
        }
    }

    /// Records progress into a sub-phase of the covered window.
    pub(crate) fn phase(&self, phase: i64) {
        self.phase_gauge.set(phase);
    }

    /// Marks the covered window complete. (Equivalent to dropping the
    /// guard; named so the completion point is visible in the caller.)
    pub(crate) fn disarm(self) {}
}

impl Drop for ReconfigWatchdog {
    fn drop(&mut self) {
        self.phase_gauge.set(phase::IDLE);
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn gauge() -> IntGauge {
        IntGauge::new("test_reconfig_phase", "test gauge").unwrap()
    }

    fn flag() -> (Arc<AtomicBool>, impl FnOnce() + Send + 'static) {
        let fired = Arc::new(AtomicBool::new(false));
        let setter = {
            let fired = fired.clone();
            move || fired.store(true, Ordering::SeqCst)
        };
        (fired, setter)
    }

    #[tokio::test(start_paused = true)]
    async fn breach_fires_when_the_window_never_completes() {
        let (fired, on_breach) = flag();
        let gauge = gauge();
        let watchdog = ReconfigWatchdog::arm_with(
            gauge.clone(),
            373,
            Some(Duration::from_secs(600)),
            on_breach,
        );
        watchdog.phase(phase::RECONFIGURE_STATE);
        assert_eq!(gauge.get(), phase::RECONFIGURE_STATE);

        tokio::time::sleep(Duration::from_secs(601)).await;
        assert!(
            fired.load(Ordering::SeqCst),
            "an armed watchdog must fire once the bound elapses"
        );
        drop(watchdog);
    }

    #[tokio::test(start_paused = true)]
    async fn disarm_before_the_bound_never_fires() {
        let (fired, on_breach) = flag();
        let gauge = gauge();
        let watchdog = ReconfigWatchdog::arm_with(
            gauge.clone(),
            373,
            Some(Duration::from_secs(600)),
            on_breach,
        );
        assert_eq!(gauge.get(), phase::SERVICE_TEARDOWN);
        watchdog.disarm();
        assert_eq!(gauge.get(), phase::IDLE);

        tokio::time::sleep(Duration::from_secs(10_000)).await;
        assert!(
            !fired.load(Ordering::SeqCst),
            "a disarmed watchdog must never fire"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_guard_disarms() {
        let (fired, on_breach) = flag();
        let gauge = gauge();
        {
            let _watchdog = ReconfigWatchdog::arm_with(
                gauge.clone(),
                373,
                Some(Duration::from_secs(600)),
                on_breach,
            );
        }
        assert_eq!(gauge.get(), phase::IDLE);

        tokio::time::sleep(Duration::from_secs(10_000)).await;
        assert!(
            !fired.load(Ordering::SeqCst),
            "dropping the guard must disarm the watchdog"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_watchdog_never_fires() {
        let (fired, on_breach) = flag();
        let watchdog = ReconfigWatchdog::arm_with(gauge(), 373, None, on_breach);

        tokio::time::sleep(Duration::from_secs(10_000)).await;
        assert!(
            !fired.load(Ordering::SeqCst),
            "a disabled watchdog must never fire"
        );
        drop(watchdog);
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
