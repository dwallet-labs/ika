// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Rate bound for the unauthenticated latest-checkpoint watermark.
//!
//! The latest-checkpoint height is a bare integer from a fullnode or a relay:
//! it bounds a scan and signals freshness, and every checkpoint reached
//! through it is still committee-verified before it is used, so it was never
//! a trust input. The hazard is different — several consumers fold it into
//! **monotone, persisted state that cannot come back down** (the folder's
//! cursor in the perpetual tables, the cache's processed head, the reader's
//! freshness floor). An inflated watermark — a buggy fullnode, a desynced
//! load-balancer backend, an endpoint pointed at the wrong network, a
//! corrupted response — therefore latches permanently and survives restarts
//! (ika #2041).
//!
//! The bound is a **token bucket over admitted advance**, not a per-sample
//! delta limit. A per-sample limit bounds nothing over time: an upstream that
//! reports "previous + just under the limit" on every 250 ms tick is admitted
//! forever and walks the head arbitrarily far ahead, one legal step at a
//! time. Here, allowance accrues at [`SUSTAINED_CHECKPOINTS_PER_SECOND`] up
//! to a [`BURST_ALLOWANCE`] ceiling and is **spent by every accepted
//! increase**, so admitted advance is bounded by that rate over any window
//! longer than one burst, whatever the step size.
//!
//! The bucket compares observations **within this process** and never against
//! persisted state: after downtime a genuine watermark is arbitrarily far
//! ahead of the folder's stored cursor, and that catch-up must pass trivially.
//! The first observation of a process therefore seeds the head (see
//! [`WatermarkGuard::note_verified_floor`] for how a consumer that has a
//! locally-verified anchor seeds from that instead of from an untrusted
//! source's first word).

use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;

/// Rate at which admitted advance is replenished, checkpoints per second.
/// Sui targets a checkpoint roughly every 250 ms (~4/s on mainnet), so this
/// leaves ~6/s of headroom above real production: the bucket sits at its
/// ceiling in steady state, and an upstream cannot be admitted a *sustained*
/// advance faster than 10/s however it shapes its samples. It is also what
/// bounds recovery when the bucket has drained (see the module-level note on
/// long process pauses in the OCS spec).
const SUSTAINED_CHECKPOINTS_PER_SECOND: u64 = 10;

/// Ceiling on unspent allowance — the largest single jump that can be
/// admitted, about one hour of real production (~4/s). Sized so every
/// observation gap a running process can plausibly experience passes without
/// a refusal: the folder polls every 250 ms, and even a pathological tick
/// that exhausts every bounded retry budget costs tens of seconds. A gap
/// longer than the ceiling (a host paused for hours) is admitted only as the
/// bucket refills — bounded, self-healing, and cleared outright by a restart,
/// which re-seeds the guard.
const BURST_ALLOWANCE: u64 = 15_000;

/// The rate-bound state of one watermark consumer. Cheap and independent per
/// consumer: two consumers watching different sources (the folder's own
/// fullnode, a relay's claimed head) must not seed each other's head.
pub(crate) struct WatermarkGuard {
    /// `None` until the first observation (or locally-verified floor) of this
    /// process. A refused sample never updates it, so a refused sample cannot
    /// walk the head upward by being repeated.
    bucket: Mutex<Option<Bucket>>,
}

struct Bucket {
    /// Highest watermark admitted so far.
    head: CheckpointSequenceNumber,
    /// Unspent allowance, in checkpoints.
    tokens: u64,
    /// When `tokens` was last replenished. Advanced only by whole elapsed
    /// seconds, so sub-second remainders accumulate instead of being lost —
    /// at a 250 ms poll interval, truncating them would starve the bucket.
    refilled_at: Instant,
}

impl Bucket {
    fn seeded_at(head: CheckpointSequenceNumber) -> Self {
        Self {
            head,
            tokens: BURST_ALLOWANCE,
            refilled_at: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let whole_seconds = self.refilled_at.elapsed().as_secs();
        if whole_seconds == 0 {
            return;
        }
        self.tokens = self
            .tokens
            .saturating_add(whole_seconds.saturating_mul(SUSTAINED_CHECKPOINTS_PER_SECOND))
            .min(BURST_ALLOWANCE);
        self.refilled_at += Duration::from_secs(whole_seconds);
    }
}

impl WatermarkGuard {
    pub(crate) fn new() -> Self {
        Self {
            bucket: Mutex::new(None),
        }
    }

    /// `true` when `seq` is within the admitted-advance budget — the caller
    /// may fold it. `false` means the upstream is claiming advance faster than
    /// real checkpoint production can explain; the caller must skip the sample
    /// (and say so loudly), leaving every monotone consumer untouched.
    ///
    /// A watermark that goes *backwards* is admitted and costs nothing: a load
    /// balancer that lands on a lagging backend is ordinary, and every consumer
    /// already ignores a lower head (the folder scans nothing, the reader's
    /// `fetch_max` keeps the higher floor). It does not lower the head either,
    /// so a retreat cannot be used to buy a cheap jump afterwards. Only
    /// *increases* are metered, which is the direction that latches.
    pub(crate) fn admit(&self, seq: CheckpointSequenceNumber) -> bool {
        let mut guarded = self.bucket.lock();
        let bucket = guarded.get_or_insert_with(|| Bucket::seeded_at(seq));
        bucket.refill();
        let Some(advance) = seq.checked_sub(bucket.head).filter(|advance| *advance > 0) else {
            return true;
        };
        if advance > bucket.tokens {
            return false;
        }
        bucket.tokens -= advance;
        bucket.head = seq;
        true
    }

    /// Raise the head to a value the caller has verified locally, at no cost
    /// in allowance. This is how a consumer whose watermark source is
    /// untrusted (a relay's claimed head, on a mirrored node) anchors the
    /// bucket to something the relay does not control — the fold head of the
    /// verified state cache, which only ever advances to a checkpoint carrying
    /// a committee quorum signature. Called before every `admit`, so the floor
    /// keeps tracking locally-verified progress instead of being fixed at
    /// whatever was known when the first claim arrived.
    ///
    /// `0` (nothing verified locally yet) is a no-op, and never seeds: an
    /// unseeded guard must take its head from the first real observation, not
    /// from the origin.
    pub(crate) fn note_verified_floor(&self, seq: CheckpointSequenceNumber) {
        if seq == 0 {
            return;
        }
        let mut guarded = self.bucket.lock();
        let bucket = guarded.get_or_insert_with(|| Bucket::seeded_at(seq));
        bucket.head = bucket.head.max(seq);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first observation of a process is the head, however large: a node
    /// starting against a chain millions of checkpoints in has no prior to
    /// judge it against, and refusing it would refuse every node start.
    #[test]
    fn first_observation_of_any_size_is_admitted() {
        let guard = WatermarkGuard::new();
        assert!(guard.admit(180_000_000));
        // ... and it is now the head, so the next sample is metered against
        // it rather than against zero.
        assert!(guard.admit(180_000_010));
        assert!(!guard.admit(280_000_000));
    }

    /// Steady-state production (a handful of checkpoints per 250 ms tick)
    /// never approaches the budget, and a one-off gap up to the burst ceiling
    /// (an hour of production, e.g. an upstream unreachable for a while) is
    /// admitted in a single step.
    #[test]
    fn ordinary_advance_and_a_burst_sized_catch_up_are_admitted() {
        let guard = WatermarkGuard::new();
        assert!(guard.admit(1_000));
        for seq in 1_001..=1_100 {
            assert!(guard.admit(seq));
        }
        assert!(guard.admit(1_100 + BURST_ALLOWANCE - 100));
    }

    /// A single wildly inflated sample (a wrong-network endpoint) is refused
    /// and — the load-bearing half — does NOT become the head, so the genuine
    /// value that follows is still admitted and the budget still applies from
    /// it.
    #[test]
    fn implausible_jump_is_refused_without_moving_the_head() {
        let guard = WatermarkGuard::new();
        assert!(guard.admit(1_000));
        assert!(!guard.admit(180_000_000));
        assert!(guard.admit(1_001));
        assert!(!guard.admit(1_001 + 1_000_000));
    }

    /// The attack a per-sample delta limit cannot see: an upstream that keeps
    /// reporting "just under the limit" every tick. Each step is individually
    /// modest, but the bucket is spent by every accepted increase, so the ramp
    /// starts being refused as soon as the burst is consumed — total admitted
    /// advance stays within one burst plus what accrues at the sustained rate.
    #[test]
    fn a_sustained_ramp_drains_the_bucket_and_is_refused() {
        let guard = WatermarkGuard::new();
        let start = 1_000;
        assert!(guard.admit(start));

        let step = BURST_ALLOWANCE - 1;
        let mut head = start;
        let mut admitted = 0;
        for _ in 0..10 {
            if guard.admit(head + step) {
                admitted += 1;
                head += step;
            }
        }

        assert_eq!(admitted, 1, "only the first step fits in the burst");
        assert!(
            head - start <= BURST_ALLOWANCE,
            "a ramp cannot walk the head past one burst inside a second"
        );
    }

    /// A watermark that retreats is admitted (a lagging backend behind a load
    /// balancer) but must not lower the head — otherwise a retreat followed by
    /// a jump would refund allowance the bucket already spent.
    #[test]
    fn retreat_is_admitted_but_does_not_lower_the_head() {
        let guard = WatermarkGuard::new();
        assert!(guard.admit(100_000));
        assert!(guard.admit(90_000));
        // Metered against 100_000, not 90_000: this would cost more than the
        // whole burst if the retreat had lowered the head.
        assert!(guard.admit(100_000 + BURST_ALLOWANCE - 1));
    }

    /// Allowance replenishes with time, so a drained bucket recovers on its
    /// own rather than latching a permanent refusal.
    #[test]
    fn a_drained_bucket_refills_over_time() {
        let guard = WatermarkGuard::new();
        assert!(guard.admit(1_000));
        assert!(guard.admit(1_000 + BURST_ALLOWANCE));
        assert!(!guard.admit(1_000 + BURST_ALLOWANCE + 5_000));

        // Backdate the refill anchor by ten minutes: 6_000 checkpoints of
        // allowance have accrued at the sustained rate.
        let mut guarded = guard.bucket.lock();
        let bucket = guarded.as_mut().unwrap();
        bucket.refilled_at -= Duration::from_secs(600);
        drop(guarded);

        assert!(guard.admit(1_000 + BURST_ALLOWANCE + 5_000));
    }

    /// A locally-verified floor raises the head for free and, before any
    /// observation, seeds the guard — so a consumer reading from an untrusted
    /// source is metered against what it verified itself, not against that
    /// source's first word.
    #[test]
    fn a_verified_floor_seeds_and_raises_the_head_for_free() {
        let guard = WatermarkGuard::new();
        guard.note_verified_floor(1_000_000);
        // The first claim is now metered against the verified floor.
        assert!(!guard.admit(9_000_000));
        assert!(guard.admit(1_000_000 + BURST_ALLOWANCE));

        // The floor keeps tracking local progress at no cost in allowance: the
        // bucket is empty after the jump above, yet the floor still moves and
        // a claim at the new floor is admitted.
        guard.note_verified_floor(3_000_000);
        assert!(guard.admit(3_000_000));
        // Zero never seeds and never lowers.
        guard.note_verified_floor(0);
        assert!(guard.admit(3_000_000));
        assert!(!guard.admit(3_000_000 + BURST_ALLOWANCE + 1));
    }
}
