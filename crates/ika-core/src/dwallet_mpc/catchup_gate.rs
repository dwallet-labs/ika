// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Catch-up gate for the dWallet MPC service (issue #2023).
//!
//! A validator whose MPC processing cursor trails the consensus tip beyond
//! the *trap radius* falls into a stable non-contributing equilibrium: every
//! high-volume session it starts computing (internal presigns, user sessions)
//! has already completed network-wide by the time its contribution would
//! matter. It observes the terminal state and abandons the work — but the
//! dead-on-arrival crypto burns enough CPU to pin its round processing just
//! below the tip rate, so the backlog never drains and the trap sustains
//! itself until the epoch boundary. Measured in production: with computation
//! suppressed the round drain runs at ~40x the tip rate (the restart replay
//! path proves it), so a backlog that takes hours to *not* drain while
//! computing clears in seconds without.
//!
//! This module is the pure hysteresis state machine for that gate, kept free
//! of service state so it is testable in isolation (same pattern as
//! `reconfig_watchdog.rs`). The [`DWalletMPCManager`] holds one instance,
//! feeds it the per-iteration round gap, and consults it at the computation
//! spawn decision in `perform_cryptographic_computation`.
//!
//! [`DWalletMPCManager`]: crate::dwallet_mpc::mpc_manager::DWalletMPCManager

use ika_types::messages_dwallet_mpc::SessionType;

/// Enter catch-up mode when the round gap exceeds this.
///
/// The trap radius is roughly session-completion-time x tip-rate — ~1-2k
/// rounds on mainnet at ~19.5 rounds/s (issue #2023's live capture entered at
/// ~4-5k behind and oscillated 545-7,346 once trapped). The enter threshold
/// is ~2x the radius with margin: ordinary load jitter of a healthy at-tip
/// validator (hundreds of rounds) must never flip the gate, while any gap
/// that actually sustains the trap comfortably exceeds it.
pub(crate) const CATCH_UP_ENTER_GAP_ROUNDS: u64 = 5_000;

/// Exit catch-up mode when the round gap falls below this.
///
/// Well inside the trap radius (~25s of tip progress at mainnet rates): on
/// exit the sessions near the cursor are still genuinely live network-wide,
/// so resumed computations contribute instead of chasing already-terminal
/// sessions. The wide enter/exit band is the hysteresis that prevents
/// oscillation at either boundary.
pub(crate) const CATCH_UP_EXIT_GAP_ROUNDS: u64 = 500;

/// The gate's reaction to one gap observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CatchUpTransition {
    /// The gap crossed above [`CATCH_UP_ENTER_GAP_ROUNDS`]; computation
    /// suppression begins.
    Entered,
    /// The gap fell below [`CATCH_UP_EXIT_GAP_ROUNDS`]; computation
    /// suppression ends.
    Exited,
    /// No state change (including gaps inside the hysteresis band).
    Unchanged,
}

/// Hysteresis state machine over the "MPC cursor behind consensus tip" gap.
///
/// Enter when `gap > CATCH_UP_ENTER_GAP_ROUNDS`, exit when
/// `gap < CATCH_UP_EXIT_GAP_ROUNDS`, hold the current state anywhere in
/// between. Per-epoch and in-memory by design: the manager that owns it is
/// rebuilt at every epoch boundary and process restart, and the first
/// service iteration after a mid-epoch restart re-observes the full replay
/// backlog as its gap — exactly the entry condition the gate exists for.
#[derive(Debug)]
pub(crate) struct CatchUpGate {
    in_catch_up: bool,
}

impl CatchUpGate {
    pub(crate) fn new() -> Self {
        Self { in_catch_up: false }
    }

    /// Whether new cryptographic computations for suppressible session types
    /// should currently be withheld. Cheap enough for a per-session-per-tick
    /// caller: a single bool read.
    pub(crate) fn is_catching_up(&self) -> bool {
        self.in_catch_up
    }

    /// Feed one gap observation (`tip - cursor`, in consensus rounds) and
    /// apply the hysteresis.
    pub(crate) fn update(&mut self, gap_rounds: u64) -> CatchUpTransition {
        if !self.in_catch_up && gap_rounds > CATCH_UP_ENTER_GAP_ROUNDS {
            self.in_catch_up = true;
            CatchUpTransition::Entered
        } else if self.in_catch_up && gap_rounds < CATCH_UP_EXIT_GAP_ROUNDS {
            self.in_catch_up = false;
            CatchUpTransition::Exited
        } else {
            CatchUpTransition::Unchanged
        }
    }
}

/// Whether catch-up mode suppresses spawning computations for this session
/// type.
///
/// Suppressed — the volume that creates and sustains the trap (thousands of
/// active sessions in the live capture):
/// - [`SessionType::InternalPresign`]: pool top-up batches; the pool is
///   refilled by the network's live validators either way, and this
///   validator's own drained rounds mark the already-completed ones terminal.
/// - [`SessionType::User`]: their outputs reach quorum from the fastest
///   two-thirds of the committee; a trapped validator's contribution arrives
///   after quorum and is discarded (the `completion_races` path).
///
/// Exempt — system-critical, rare, and epoch-critical, so they must never be
/// skipped on a mere heuristic:
/// - [`SessionType::System`]: network DKG, network-key reconfiguration and
///   the other network-key sessions. Missing one can wedge the epoch
///   transition for the whole network, and their volume (a handful per
///   epoch) cannot sustain the trap.
/// - [`SessionType::NetworkOwnedAddressSign`]: checkpoint-cadence signing
///   backing the NOA checkpoint flow — low-volume and liveness-relevant.
///
/// Suppression only withholds *starting new computations*: round draining,
/// quorum observation, terminal bookkeeping, output verification, and
/// already-running computations all continue unchanged.
pub(crate) fn computation_suppressible_during_catch_up(session_type: SessionType) -> bool {
    match session_type {
        SessionType::User | SessionType::InternalPresign => true,
        SessionType::System | SessionType::NetworkOwnedAddressSign => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_out_of_catch_up() {
        let gate = CatchUpGate::new();
        assert!(!gate.is_catching_up());
    }

    #[test]
    fn enters_only_strictly_above_the_enter_threshold() {
        let mut gate = CatchUpGate::new();
        assert_eq!(
            gate.update(CATCH_UP_ENTER_GAP_ROUNDS),
            CatchUpTransition::Unchanged,
            "a gap AT the enter threshold must not enter"
        );
        assert!(!gate.is_catching_up());
        assert_eq!(
            gate.update(CATCH_UP_ENTER_GAP_ROUNDS + 1),
            CatchUpTransition::Entered
        );
        assert!(gate.is_catching_up());
    }

    #[test]
    fn stays_in_until_strictly_below_the_exit_threshold() {
        let mut gate = CatchUpGate::new();
        gate.update(CATCH_UP_ENTER_GAP_ROUNDS + 1);
        assert_eq!(
            gate.update(CATCH_UP_EXIT_GAP_ROUNDS),
            CatchUpTransition::Unchanged,
            "a gap AT the exit threshold must stay in catch-up"
        );
        assert!(gate.is_catching_up());
        assert_eq!(
            gate.update(CATCH_UP_EXIT_GAP_ROUNDS - 1),
            CatchUpTransition::Exited
        );
        assert!(!gate.is_catching_up());
    }

    #[test]
    fn hysteresis_band_holds_the_prior_state_in_both_directions() {
        let mid_band = (CATCH_UP_ENTER_GAP_ROUNDS + CATCH_UP_EXIT_GAP_ROUNDS) / 2;

        // Out of catch-up: a mid-band gap must not enter.
        let mut gate = CatchUpGate::new();
        assert_eq!(gate.update(mid_band), CatchUpTransition::Unchanged);
        assert!(!gate.is_catching_up());

        // In catch-up: the same mid-band gap must not exit.
        gate.update(CATCH_UP_ENTER_GAP_ROUNDS + 1);
        assert_eq!(gate.update(mid_band), CatchUpTransition::Unchanged);
        assert!(gate.is_catching_up());
    }

    #[test]
    fn no_oscillation_when_the_gap_hovers_at_a_boundary() {
        // Hovering around the enter threshold while out: never enters.
        let mut gate = CatchUpGate::new();
        for gap in [
            CATCH_UP_ENTER_GAP_ROUNDS - 1,
            CATCH_UP_ENTER_GAP_ROUNDS,
            CATCH_UP_ENTER_GAP_ROUNDS - 1,
            CATCH_UP_ENTER_GAP_ROUNDS,
        ] {
            assert_eq!(gate.update(gap), CatchUpTransition::Unchanged);
        }
        assert!(!gate.is_catching_up());

        // Hovering around the exit threshold while in: never exits.
        gate.update(CATCH_UP_ENTER_GAP_ROUNDS + 1);
        for gap in [
            CATCH_UP_EXIT_GAP_ROUNDS + 1,
            CATCH_UP_EXIT_GAP_ROUNDS,
            CATCH_UP_EXIT_GAP_ROUNDS + 1,
            CATCH_UP_EXIT_GAP_ROUNDS,
        ] {
            assert_eq!(gate.update(gap), CatchUpTransition::Unchanged);
        }
        assert!(gate.is_catching_up());
    }

    #[test]
    fn full_cycle_enter_hold_exit_reenter() {
        let mut gate = CatchUpGate::new();
        assert_eq!(gate.update(10_000), CatchUpTransition::Entered);
        assert_eq!(gate.update(2_000), CatchUpTransition::Unchanged);
        assert_eq!(gate.update(499), CatchUpTransition::Exited);
        assert_eq!(gate.update(499), CatchUpTransition::Unchanged);
        assert_eq!(gate.update(10_000), CatchUpTransition::Entered);
        assert!(gate.is_catching_up());
    }

    #[test]
    fn suppression_covers_exactly_the_high_volume_session_types() {
        assert!(computation_suppressible_during_catch_up(SessionType::User));
        assert!(computation_suppressible_during_catch_up(
            SessionType::InternalPresign
        ));
        assert!(!computation_suppressible_during_catch_up(
            SessionType::System
        ));
        assert!(!computation_suppressible_during_catch_up(
            SessionType::NetworkOwnedAddressSign
        ));
    }
}
