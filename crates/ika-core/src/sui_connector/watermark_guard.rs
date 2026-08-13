// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Plausibility bound for the unauthenticated latest-checkpoint watermark.
//!
//! The latest-checkpoint height is a bare integer from a fullnode or a relay:
//! it bounds a scan and signals freshness, and every checkpoint reached
//! through it is still committee-verified before it is used, so it was never
//! a trust input. The hazard is different — several consumers fold it into
//! **monotone, persisted state that cannot come back down** (the folder's
//! cursor in the perpetual tables, the cache's processed head, the reader's
//! freshness floor). One inflated sample — a buggy fullnode, a desynced
//! load-balancer backend, an endpoint pointed at the wrong network, a
//! corrupted response — therefore latches permanently and survives restarts
//! (ika #2041).
//!
//! This guard bounds how far one observation may exceed the previous one
//! **within this process**. It deliberately does NOT compare the watermark
//! against any persisted state: after downtime a genuine watermark is
//! arbitrarily far ahead of the folder's stored cursor, and that catch-up
//! must pass trivially. The first observation of a process has nothing to
//! judge it against, so it is accepted and becomes the baseline; only the
//! *deltas* that follow are bounded.

use std::time::Instant;

use parking_lot::Mutex;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;

/// Ceiling on the rate at which the allowance grows with elapsed time,
/// checkpoints per second. Sui targets a checkpoint roughly every 250 ms
/// (~4/s on mainnet); 10/s is ~2.5x that, so it cannot be outrun by real
/// production while still refusing a wrong-network endpoint (tens of
/// millions of checkpoints ahead) for months.
const MAX_CHECKPOINTS_PER_SECOND: u64 = 10;

/// Flat allowance on top of the time-scaled term: about one hour of real
/// production (~4/s). Sized so that no observation gap a running process can
/// plausibly experience — the folder polls every 250 ms, and even a
/// pathological tick that exhausts every bounded retry budget costs tens of
/// seconds — comes anywhere near the bound.
const JUMP_SLACK: u64 = 15_000;

/// The plausibility state of one watermark consumer. Cheap and independent
/// per consumer: two consumers watching different sources (the folder's own
/// fullnode, a relay's claimed head) must not seed each other's baseline.
pub(crate) struct WatermarkGuard {
    /// The highest watermark accepted so far and when it was accepted, or
    /// `None` before the first observation of this process. A refused sample
    /// never updates it, so one bad sample cannot walk the baseline upward.
    last_accepted: Mutex<Option<Observation>>,
}

struct Observation {
    seq: CheckpointSequenceNumber,
    at: Instant,
}

impl WatermarkGuard {
    pub(crate) fn new() -> Self {
        Self {
            last_accepted: Mutex::new(None),
        }
    }

    /// `true` when `seq` is a plausible next observation — the caller may fold
    /// it. `false` means it jumped implausibly far past the highest previously
    /// accepted value; the caller must skip it (and say so loudly), leaving
    /// every monotone consumer untouched.
    ///
    /// A watermark that goes *backwards* is admitted: a load balancer that
    /// lands on a lagging backend is ordinary, and every consumer already
    /// ignores a lower head (the folder scans nothing, the reader's `fetch_max`
    /// keeps the higher floor). Only implausible *increases* are refused,
    /// which is the direction that latches.
    ///
    /// The allowance grows with the time since the last accepted observation,
    /// so this can never wedge itself: if the upstream is unreachable for
    /// hours and comes back genuinely far ahead, the bound has grown to cover
    /// it. With a fixed bound, that stretch would refuse every subsequent
    /// sample forever — the baseline can only advance through an accepted one.
    pub(crate) fn admit(&self, seq: CheckpointSequenceNumber) -> bool {
        let mut last_accepted = self.last_accepted.lock();
        let admitted = last_accepted.as_ref().is_none_or(|previous| {
            let allowance = previous.seq.saturating_add(JUMP_SLACK).saturating_add(
                previous
                    .at
                    .elapsed()
                    .as_secs()
                    .saturating_mul(MAX_CHECKPOINTS_PER_SECOND),
            );
            seq <= allowance
        });
        if admitted
            && last_accepted
                .as_ref()
                .is_none_or(|previous| seq > previous.seq)
        {
            *last_accepted = Some(Observation {
                seq,
                at: Instant::now(),
            });
        }
        admitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The first observation of a process is the baseline, however large:
    /// a node starting against a chain millions of checkpoints in has no
    /// prior to judge it against, and refusing it would refuse every node
    /// start.
    #[test]
    fn first_observation_of_any_size_is_admitted() {
        let guard = WatermarkGuard::new();
        assert!(guard.admit(180_000_000));
        // ... and it is now the baseline, so the next sample is judged
        // against it rather than against zero.
        assert!(guard.admit(180_000_010));
        assert!(!guard.admit(280_000_000));
    }

    /// Steady-state production (a handful of checkpoints per 250 ms tick) is
    /// nowhere near the bound, and neither is an hour-long catch-up.
    #[test]
    fn ordinary_advance_and_hour_scale_catch_up_are_admitted() {
        let guard = WatermarkGuard::new();
        assert!(guard.admit(1_000));
        for seq in 1_001..=1_100 {
            assert!(guard.admit(seq));
        }
        // A legitimate stretch the process observed nothing (upstream
        // unreachable) still lands inside the flat slack.
        assert!(guard.admit(1_100 + JUMP_SLACK));
    }

    /// A single wildly inflated sample (a wrong-network endpoint) is refused
    /// and — the load-bearing half — does NOT become the baseline, so the
    /// genuine value that follows is still admitted, and the bound still
    /// applies from the genuine value.
    #[test]
    fn implausible_jump_is_refused_without_moving_the_baseline() {
        let guard = WatermarkGuard::new();
        assert!(guard.admit(1_000));
        assert!(!guard.admit(180_000_000));
        assert!(guard.admit(1_001));
        assert!(!guard.admit(1_001 + 1_000_000));
    }

    /// A watermark that retreats is admitted (a lagging backend behind a load
    /// balancer) but must not lower the baseline — otherwise a retreat
    /// followed by a jump could walk the guard down and then up.
    #[test]
    fn retreat_is_admitted_but_does_not_lower_the_baseline() {
        let guard = WatermarkGuard::new();
        assert!(guard.admit(100_000));
        assert!(guard.admit(90_000));
        // Judged against 100_000, not 90_000: past the slack over the
        // RETREATED value, but inside it over the real baseline.
        assert!(guard.admit(90_000 + JUMP_SLACK + 1));
    }

    /// The allowance grows with elapsed time, so a long observation gap
    /// followed by a genuinely large jump is admitted rather than latching a
    /// permanent refusal.
    #[test]
    fn allowance_grows_with_elapsed_time() {
        let guard = WatermarkGuard::new();
        assert!(guard.admit(1_000));
        // Backdate the baseline by an hour: the time term alone now covers
        // 36_000 checkpoints on top of the flat slack.
        guard.last_accepted.lock().as_mut().unwrap().at =
            Instant::now() - Duration::from_secs(3_600);
        assert!(guard.admit(1_000 + JUMP_SLACK + 30_000));
    }
}
