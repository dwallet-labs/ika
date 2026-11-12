// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Prometheus metrics for the OCS verifier subsystem.
//!
//! Three groups:
//! - `pusher_*`: sui-state-direct checkpoint-pusher health.
//! - `push_*`: sui-state-mirrored / handler receive-side health.
//! - `committee_head_epoch`: where the committee ratchet has reached, or
//!   `-1` when this node runs no ratchet at all.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use prometheus::{
    Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, Registry,
    register_histogram_vec_with_registry, register_histogram_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_with_registry,
};

#[derive(Clone, Debug)]
pub struct OcsMetrics {
    // Committee ratchet
    /// Highest Sui epoch the committee ratchet has reached, or
    /// [`Self::COMMITTEE_HEAD_NOT_APPLICABLE`] (`-1`) on a node that builds no
    /// OCS stack at all (a notifier/fullnode role with no trust anchor), so the
    /// mirroring task that owns this gauge is never spawned for it. Every node
    /// that does build a stack runs a ratchet — direct, mirrored and peer-only
    /// alike.
    ///
    /// The sentinel exists because `0` is otherwise ambiguous between "no
    /// ratchet, nothing to report" and "ratchet present and holding an empty
    /// committee set", and those need opposite responses: the first is normal,
    /// the second is a node whose verified reads will all fail. Distinguishing
    /// them from outside the process previously required a chain walk plus a
    /// code read (#1980). Same reasoning as the `-1` freeze-progress sentinels
    /// in `authority_per_epoch_store`: a real epoch can legitimately BE 0, so a
    /// zero default reads as a plausible-but-wrong value rather than as absent.
    ///
    /// Note this is deliberately NOT redundant with [`Self::ratchet_stalled`]:
    /// that flag reports a ratchet whose last attempt FAILED, and stays 0 both
    /// when no ratchet exists and when a ratchet has never completed an attempt
    /// at all. `head == 0 && stalled == 0` was the unreadable combination.
    pub committee_head_epoch: IntGauge,
    /// The upstream chain's current epoch, sampled by the ratchet. Lets
    /// operators alert on ratchet lag: `chain_latest_epoch -
    /// committee_head_epoch` — but that subtraction is only meaningful where
    /// the head is not [`Self::COMMITTEE_HEAD_NOT_APPLICABLE`]. Gate it:
    /// `chain_latest_epoch - (committee_head_epoch >= 0)`.
    pub chain_latest_epoch: IntGauge,
    /// 1 while the last completed committee-ratchet attempt failed, 0 once one
    /// succeeds. The direct health signal for a node that cannot advance its
    /// committee head — e.g. booted against a source that serves no historical
    /// epochs — which otherwise presents only as absent downstream series
    /// while every verified read fails `missing_committee`.
    pub ratchet_stalled: IntGauge,
    /// Committee-ratchet attempt failures by reason (`transport` is the only
    /// retryable one; every other reason is determinate and needs the operator
    /// to act — typically re-anchor against a full-retention source).
    pub ratchet_failures_total: IntCounterVec, // labels: ["reason"]

    pub pusher_lag_checkpoints: IntGauge,
    pub pusher_last_progress_timestamp_seconds: IntGauge,
    /// Unix time the sui-state-direct pusher last saw its own fullnode report
    /// a checkpoint watermark above both its previous report and the scan
    /// cursor. It measures the fullnode's reported watermark, sampled once per
    /// pusher tick, not what the node has folded. On a sui-state-direct node
    /// it is stamped at boot and again when the pusher is built if it was
    /// not, so it ages from boot even when the pusher never starts; 0 on a
    /// node that runs no pusher. Left alone by a failed probe and by an answer
    /// that does not advance, so `time() - this` keeps growing while the
    /// fullnode is unreachable, hung or no longer syncing, the cases where the
    /// lag gauges keep reading healthy. A tick held by slow checkpoint fetches
    /// ages it too.
    pub pusher_upstream_last_advance_timestamp_seconds: IntGauge,
    /// Pusher watermark probes that failed or passed their deadline (one per
    /// tick while the node's own fullnode does not answer).
    pub pusher_watermark_probe_failures_total: IntCounter,
    pub changeset_contiguous_head: IntGauge,
    pub changeset_highest_seen: IntGauge,
    pub changeset_pending_depth: IntGauge,
    pub changeset_last_progress_timestamp_seconds: IntGauge,
    pub changeset_dropped_total: IntCounter,
    pub changeset_fetch_failures_total: IntCounter,
    pub changeset_gap_total: IntCounter,

    // Pusher (sui-state-direct)
    pub pusher_cursor_seq: IntGauge,
    /// Legacy lag flag: 1 when the sampled upstream watermark exceeds the
    /// scan cursor by more than 100 checkpoints, even if the cursor advances.
    /// Use last-progress time to distinguish lag from a stopped scanner.
    pub pusher_stalled: IntGauge,
    pub pusher_pushed_total: IntCounter,
    pub pusher_skipped_irrelevant_total: IntCounter,
    pub pusher_fetch_failures_total: IntCounter,
    /// Pending-gap checkpoints the fullnode never served (pruned) that were
    /// recovered from the checkpoint archive and folded late. Non-zero means
    /// the archive fallback is doing real work — the fullnode's pruning
    /// watermark is outrunning the pusher.
    pub pusher_gap_archive_repairs_total: IntCounter,
    /// Pending-gap checkpoints dropped at the retry deadline — neither the
    /// fullnode nor the archive (if any resolved) ever served them. Each drop
    /// is a PERMANENT verified-cache gap: an Ika object whose only mutation
    /// rode the checkpoint (e.g. a session_events bag entry) never enters the
    /// cache, which can wedge an epoch close. Alert on any increase.
    pub pusher_gap_dropped_total: IntCounter,
    /// Latency of the pre-fold verification the pusher runs before folding a
    /// checkpoint into the local cache (committee BLS on the summary +
    /// artifacts-digest binding + binding each folded object to the reference
    /// the checkpoint attests for it). Recorded only when all of it passes:
    /// `_count` is the number of checkpoints verified before folding, `_sum`
    /// the total CPU time spent on it — together they quantify the verify's
    /// cost on the fold path.
    pub pusher_fold_verify_seconds: Histogram,
    /// Archive-backfill progress by outcome. Per attempt: `fetched` (the
    /// archive answered), `verified` (the blob passed the archive
    /// verification), `failed` (see `pusher_backfill_failures_total`). Per
    /// checkpoint, once settled: `folded`, `already_cached` (every current
    /// object was cached already, including a checkpoint skipped at startup for
    /// that reason), `nothing_to_fold` (no Ika object of it is still current)
    /// or `abandoned` (a recorded lost checkpoint the archive kept answering
    /// NotFound for past the give-up window — its objects stay missing; alert
    /// on any increase).
    pub pusher_backfill_outcomes_total: IntCounterVec, // labels: ["outcome"]
    /// Failed archive-backfill attempts by reason: `archive_not_found`,
    /// `archive_fetch`, `archive_timeout`, `missing_committee`,
    /// `verification` (the archive served a blob that does not verify — logged
    /// as security-critical, never folded), `over_state_cap` (the blob writes
    /// more object states than `MAX_CHECKPOINT_OBJECT_STATES`, so its tree is
    /// not built) or `currency_lookup`. Every failure is retried with capped
    /// backoff.
    pub pusher_backfill_failures_total: IntCounterVec, // labels: ["reason"]
    /// Archive-backfill checkpoints not settled yet. Non-zero for long means
    /// the node still lacks objects it was told it needs.
    pub pusher_backfill_pending: IntGauge,
    /// Lost checkpoints this node has recorded and still tracks: checkpoints
    /// the pusher gave up on (a gap dropped at its retry deadline or by a
    /// far-behind fast-forward), pending their archive backfill or folded and
    /// pinned while a snapshot from them is still current — plus pending gaps
    /// that have failed to decode or fold, recorded on the first failure and
    /// deleted if the gap is repaired before its deadline. Persisted across
    /// restarts; bounded by the record cap.
    pub pusher_lost_checkpoints: IntGauge,
    /// Lost checkpoints NOT recorded because the record was at its cap: each
    /// is a cache gap the archive backfill will not repair. Alert on any
    /// increase.
    pub pusher_lost_checkpoints_overflow_total: IntCounter,

    /// Latest-checkpoint watermark samples refused by the rate bound, by
    /// consumer (`folder` = the checkpoint folder's per-tick scan bound and
    /// persisted cursor; `reader` = the freshness floor a verified read folds).
    /// The watermark is an unauthenticated integer that several consumers fold
    /// into monotone state, so an inflated sample used to latch permanently.
    /// A refusal is skipped, not folded — steady state is zero, and any
    /// increase means an upstream is claiming advance faster than checkpoint
    /// production can explain (a desynced backend, a wrong-network endpoint, a
    /// corrupted response), or that a genuine gap exceeds the currently
    /// available allowance. Allowance keeps accruing during refusals, so a
    /// genuine upstream producing below the refill rate eventually recovers.
    /// Refusals on `folder` leave the cursor BEHIND the chain head — the
    /// opposite signature to the poisoned cursor the bound prevents.
    pub watermark_implausible_total: IntCounterVec, // labels: ["consumer"]

    // OcsVerifiedReader (consumer-side proof verification)
    pub proof_verify_total: IntCounterVec, // labels: ["kind"]
    pub proof_verify_failures_total: IntCounterVec, // labels: ["kind", "reason"]
    pub high_water_violations_total: IntCounter,
    /// Unix timestamp of the latest successfully verified read served through
    /// an untrusted relay, or zero until the first success in this process.
    pub last_successful_relay_timestamp_seconds: IntGauge,
    /// Cache-first verified-object reads, by outcome (`hit` served from the
    /// locally pusher-populated cache; `miss` fell through to the network).
    /// Only incremented on sui-state-direct (the cache is complete there).
    pub cache_read_total: IntCounterVec, // labels: ["outcome"]
    /// Cache-first reads that fell through to the network because the cache
    /// head lagged the observed upstream head beyond the staleness bound
    /// (e.g. a stalled pusher). The fall-through still verifies, so this is a
    /// liveness/health signal, not a correctness failure.
    pub cache_first_stale_total: IntCounter,

    // BagEventPump — omission detection via verified parent state.
    pub bag_omission_suspected_total: IntCounterVec, // labels: ["bag"]

    /// A singleton anchor's on-chain type names a package other than the one
    /// this binary compiled in for that role. Always fatal (the node refuses
    /// to run — the constant is baked into the build), so any non-zero value
    /// names the cause of a node that will not start. Scrape it from the
    /// crash-loop window or the last scrape before exit; a node down for this
    /// reason otherwise presents only as absent series.
    pub identity_mismatch_total: IntCounterVec, // labels: ["anchor"]

    /// End-to-end verify latency on the consumer side (transport
    /// round-trip + proof verify). Captures what consumers actually
    /// experience.
    pub verify_latency_seconds: HistogramVec, // labels: ["kind"]
}

impl OcsMetrics {
    /// Value of [`Self::committee_head_epoch`] on a node that runs no
    /// committee ratchet. See that field's documentation for why `0` could not
    /// serve.
    pub const COMMITTEE_HEAD_NOT_APPLICABLE: i64 = -1;

    pub fn new(registry: &Registry) -> Arc<Self> {
        let metrics = Arc::new(Self {
            committee_head_epoch: register_int_gauge_with_registry!(
                "ika_ocs_committee_head_epoch",
                "Highest Sui epoch the OCS committee ratchet has reached; -1 means this node runs no ratchet (sui-state-direct or peer-only), so 0 unambiguously means a ratchet exists but holds no committee",
                registry,
            )
            .unwrap(),
            chain_latest_epoch: register_int_gauge_with_registry!(
                "ika_ocs_chain_latest_epoch",
                "Upstream Sui current epoch sampled by the ratchet; alert on (chain_latest_epoch - committee_head_epoch) gated on committee_head_epoch >= 0, since -1 means the node runs no ratchet",
                registry,
            )
            .unwrap(),
            ratchet_stalled: register_int_gauge_with_registry!(
                "ika_ocs_ratchet_stalled",
                "1 while the last completed Sui-committee-ratchet attempt failed, 0 once one succeeds; a persistent 1 means verified reads past the persisted anchor cannot work (re-anchor against a full-retention source)",
                registry,
            )
            .unwrap(),
            ratchet_failures_total: register_int_counter_vec_with_registry!(
                "ika_ocs_ratchet_failures_total",
                "Sui-committee-ratchet attempt failures by reason (only `transport` is retryable; every other reason is determinate and needs operator action)",
                &["reason"],
                registry,
            )
            .unwrap(),
            pusher_lag_checkpoints: register_int_gauge_with_registry!(
                "ika_ocs_pusher_lag_checkpoints",
                "Upstream checkpoint watermark minus scanned cursor (unauthenticated diagnostic only); -1 when no pusher is active",
                registry,
            ).unwrap(),
            pusher_last_progress_timestamp_seconds: register_int_gauge_with_registry!(
                "ika_ocs_pusher_last_progress_timestamp_seconds",
                "Unix time of the last scan cursor advance, including fast-forward; 0 before any advance; not proof of successful cache folding",
                registry,
            ).unwrap(),
            pusher_upstream_last_advance_timestamp_seconds: register_int_gauge_with_registry!(
                "ika_ocs_pusher_upstream_last_advance_timestamp_seconds",
                "Unix time the sui-state-direct pusher last saw its own Sui fullnode report a checkpoint watermark above both its previous report and the scan cursor (stamped at boot on sui-state-direct until the first advance; 0 when no pusher runs); unchanged while the probe fails, hangs or answers no higher, so time() minus this is how long the fullnode has reported nothing new to the pusher",
                registry,
            ).unwrap(),
            pusher_watermark_probe_failures_total: register_int_counter_with_registry!(
                "ika_ocs_pusher_watermark_probe_failures_total",
                "sui-state-direct pusher probes of its own Sui fullnode's checkpoint watermark that failed or passed their deadline",
                registry,
            ).unwrap(),
            changeset_contiguous_head: register_int_gauge_with_registry!(
                "ika_ocs_changeset_contiguous_head",
                "Highest contiguously verified changeset sequence; -1 before bootstrap or when no receiver runs",
                registry,
            ).unwrap(),
            changeset_highest_seen: register_int_gauge_with_registry!(
                "ika_ocs_changeset_highest_seen",
                "Highest artifacts-bound and committee-verified changeset sequence received; -1 before any entry",
                registry,
            ).unwrap(),
            changeset_pending_depth: register_int_gauge_with_registry!(
                "ika_ocs_changeset_pending_depth",
                "Out-of-order changesets retained awaiting a predecessor, capped at 256",
                registry,
            ).unwrap(),
            changeset_last_progress_timestamp_seconds: register_int_gauge_with_registry!(
                "ika_ocs_changeset_last_progress_timestamp_seconds",
                "Unix time of the last contiguous changeset head advance; 0 before bootstrap",
                registry,
            ).unwrap(),
            changeset_dropped_total: register_int_counter_with_registry!(
                "ika_ocs_changeset_dropped_total",
                "Out-of-order changesets dropped because the pending queue is at capacity",
                registry,
            ).unwrap(),
            changeset_fetch_failures_total: register_int_counter_with_registry!(
                "ika_ocs_changeset_fetch_failures_total",
                "Changeset page fetch attempts that failed, including exhausted relay retention-gap fallback",
                registry,
            ).unwrap(),
            changeset_gap_total: register_int_counter_with_registry!(
                "ika_ocs_changeset_gap_total",
                "Changeset pages rejected for a non-contiguous sequence",
                registry,
            ).unwrap(),
            pusher_cursor_seq: register_int_gauge_with_registry!(
                "ika_ocs_pusher_cursor_seq",
                "Highest Sui checkpoint sequence the sui-state-direct pusher has scanned",
                registry,
            )
            .unwrap(),
            pusher_stalled: register_int_gauge_with_registry!(
                "ika_ocs_pusher_stalled",
                "Legacy lag flag: 1 while the sampled upstream watermark is over 100 checkpoints ahead of the scan cursor; does not imply no progress",
                registry,
            )
            .unwrap(),
            pusher_pushed_total: register_int_counter_with_registry!(
                "ika_ocs_pusher_pushed_total",
                "Number of Ika-relevant CheckpointData broadcast to peers",
                registry,
            )
            .unwrap(),
            pusher_skipped_irrelevant_total: register_int_counter_with_registry!(
                "ika_ocs_pusher_skipped_irrelevant_total",
                "Number of Sui checkpoints scanned and skipped as not-Ika-relevant",
                registry,
            )
            .unwrap(),
            pusher_fetch_failures_total: register_int_counter_with_registry!(
                "ika_ocs_pusher_fetch_failures_total",
                "Number of get_full_checkpoint failures during the pusher walk",
                registry,
            )
            .unwrap(),
            pusher_gap_archive_repairs_total: register_int_counter_with_registry!(
                "ika_ocs_pusher_gap_archive_repairs_total",
                "Pending-gap checkpoints the fullnode pruned that were recovered from the checkpoint archive and folded late",
                registry,
            )
            .unwrap(),
            pusher_gap_dropped_total: register_int_counter_with_registry!(
                "ika_ocs_pusher_gap_dropped_total",
                "Pending-gap checkpoints dropped at the retry deadline (fullnode pruned them and no archive served them); each is a permanent verified-cache gap that can wedge an epoch close — alert on any increase",
                registry,
            )
            .unwrap(),
            pusher_fold_verify_seconds: register_histogram_with_registry!(
                "ika_ocs_pusher_fold_verify_seconds",
                "Latency of the sui-state-direct pusher's pre-fold verification (BLS on the summary + artifacts-digest binding + binding each folded object to its attested reference), recorded only when it passes; _count is the number of checkpoints verified before folding into the cache",
                vec![0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
                registry,
            )
            .unwrap(),
            pusher_backfill_outcomes_total: register_int_counter_vec_with_registry!(
                "ika_ocs_pusher_backfill_outcomes_total",
                "sui-state-direct archive backfill progress: per attempt fetched/verified/failed, per settled checkpoint folded/already_cached/nothing_to_fold/abandoned (abandoned = a recorded lost checkpoint the archive no longer holds; alert on any increase)",
                &["outcome"],
                registry,
            )
            .unwrap(),
            pusher_backfill_failures_total: register_int_counter_vec_with_registry!(
                "ika_ocs_pusher_backfill_failures_total",
                "Failed archive-backfill attempts by reason (archive_not_found, archive_fetch, archive_timeout, missing_committee, verification, over_state_cap, currency_lookup); every failure is retried with capped backoff",
                &["reason"],
                registry,
            )
            .unwrap(),
            pusher_backfill_pending: register_int_gauge_with_registry!(
                "ika_ocs_pusher_backfill_pending",
                "Archive-backfill checkpoints this sui-state-direct node has not settled yet; non-zero for long means it still lacks objects it was told it needs",
                registry,
            )
            .unwrap(),
            pusher_lost_checkpoints: register_int_gauge_with_registry!(
                "ika_ocs_pusher_lost_checkpoints",
                "Checkpoints the sui-state-direct pusher gave up on that this node has recorded and still tracks (pending their archive backfill, or folded and pinned while still current), plus pending gaps that have failed to decode or fold (recorded on the first failure, deleted if repaired before the deadline); persisted across restarts",
                registry,
            )
            .unwrap(),
            pusher_lost_checkpoints_overflow_total: register_int_counter_with_registry!(
                "ika_ocs_pusher_lost_checkpoints_overflow_total",
                "Checkpoints the sui-state-direct pusher gave up on but could not record because the lost-checkpoint record was full; each is a cache gap the archive backfill will not repair — alert on any increase",
                registry,
            )
            .unwrap(),
            watermark_implausible_total: register_int_counter_vec_with_registry!(
                "ika_ocs_watermark_implausible_total",
                "Latest-checkpoint watermark samples refused by the rate bound (claimed advance beyond what checkpoint production can explain, metered as a token bucket over this process's admitted advance), by consumer: folder (scan bound + persisted cursor) or reader (freshness floor). Refused samples are skipped, never folded",
                &["consumer"],
                registry,
            )
            .unwrap(),
            proof_verify_total: register_int_counter_vec_with_registry!(
                "ika_ocs_proof_verify_total",
                "OCS inclusion proofs verified by the consumer side, by call kind",
                &["kind"],
                registry,
            )
            .unwrap(),
            proof_verify_failures_total: register_int_counter_vec_with_registry!(
                "ika_ocs_proof_verify_failures_total",
                "Consumer-side proof verification failures, labelled by call kind and reason",
                &["kind", "reason"],
                registry,
            )
            .unwrap(),
            high_water_violations_total: register_int_counter_with_registry!(
                "ika_ocs_high_water_violations_total",
                "Per-object version-monotonicity violations: relay served an older valid version of a tracked object",
                registry,
            )
            .unwrap(),
            last_successful_relay_timestamp_seconds: register_int_gauge_with_registry!(
                "ika_ocs_last_successful_relay_timestamp_seconds",
                "Unix timestamp of the latest OCS relay read that completed proof verification successfully in this process; 0 until the first success",
                registry,
            )
            .unwrap(),
            cache_read_total: register_int_counter_vec_with_registry!(
                "ika_ocs_cache_read_total",
                "Cache-first verified-object reads by outcome (hit: served from the local pusher-populated cache; miss: fell through to the network). Direct role only; always zero on sui-state-mirrored.",
                &["outcome"],
                registry,
            )
            .unwrap(),
            cache_first_stale_total: register_int_counter_with_registry!(
                "ika_ocs_cache_first_stale_total",
                "Cache-first reads that fell through to the network because the cache head lagged the observed upstream head beyond the staleness bound (health signal; the fall-through still verifies)",
                registry,
            )
            .unwrap(),
            bag_omission_suspected_total: register_int_counter_vec_with_registry!(
                "ika_ocs_bag_omission_suspected_total",
                "Bag walk returned fewer children than the verified parent's `Bag.size` claimed (suspected relay omission; could also be a benign race when entries are removed mid-walk — only a hard signal if it persists)",
                &["bag"],
                registry,
            )
            .unwrap(),
            identity_mismatch_total: register_int_counter_vec_with_registry!(
                "ika_ocs_identity_mismatch_total",
                "A singleton anchor object's on-chain type names a package other than the one this binary compiled in for that role (System -> ika_system_package_id, DWalletCoordinator -> ika_dwallet_2pc_mpc_package_id). Always fatal: the node refuses to run, since a compiled-in constant cannot be fixed by retrying",
                &["anchor"],
                registry,
            )
            .unwrap(),
            verify_latency_seconds: register_histogram_vec_with_registry!(
                "ika_ocs_verify_latency_seconds",
                "End-to-end consumer-side verify latency (transport + proof verify), by call kind",
                &["kind"],
                vec![
                    0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
                ],
                registry,
            )
            .unwrap(),
        });
        // Default to "no ratchet". Every node registers these metrics, but a node
        // with no OCS stack never spawns the task that maintains this gauge, so
        // without seeding it here the untouched value would be 0 — the exact
        // reading that means "ratchet present, committee empty".
        metrics
            .committee_head_epoch
            .set(Self::COMMITTEE_HEAD_NOT_APPLICABLE);
        metrics.pusher_lag_checkpoints.set(-1);
        metrics.changeset_contiguous_head.set(-1);
        metrics.changeset_highest_seen.set(-1);
        metrics
    }

    /// Start the pusher's last-advance clock
    /// ([`Self::pusher_upstream_last_advance_timestamp_seconds`]) at now,
    /// unless it has started already. A sui-state-direct node calls it at
    /// boot, so a pusher that never gets built ages from boot rather than
    /// reading 0 like a node that runs no pusher; the pusher calls it again
    /// when built, which keeps the boot start.
    pub fn start_pusher_upstream_clock(&self) {
        if self.pusher_upstream_last_advance_timestamp_seconds.get() == 0 {
            self.pusher_upstream_last_advance_timestamp_seconds.set(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
            );
        }
    }

    pub fn new_for_testing() -> Arc<Self> {
        Self::new(&Registry::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A freshly-registered `OcsMetrics` must report "no ratchet", not epoch 0.
    ///
    /// Every node registers these metrics, but a node with no OCS stack never
    /// spawns the task that maintains the gauge. Without the seed, such a node
    /// and one whose ratchet holds an empty committee are indistinguishable at
    /// 0 — the ambiguity that made #1980 require a chain walk and a code read
    /// to diagnose.
    #[test]
    fn committee_head_defaults_to_not_applicable_not_zero() {
        let metrics = OcsMetrics::new(&Registry::new());
        assert_eq!(
            metrics.committee_head_epoch.get(),
            OcsMetrics::COMMITTEE_HEAD_NOT_APPLICABLE,
        );
        assert_ne!(
            metrics.committee_head_epoch.get(),
            0,
            "0 must stay reserved for a ratchet that exists and holds no committee"
        );
    }

    /// The sentinel must not survive a ratchet reporting a real head — including
    /// a genuine epoch 0, which is why the sentinel is negative rather than 0.
    #[test]
    fn a_real_head_overwrites_the_sentinel_including_epoch_zero() {
        let metrics = OcsMetrics::new(&Registry::new());
        metrics.committee_head_epoch.set(0);
        assert_eq!(
            metrics.committee_head_epoch.get(),
            0,
            "a ratchet holding epoch 0 must be reportable as 0"
        );
        metrics.committee_head_epoch.set(1182);
        assert_eq!(metrics.committee_head_epoch.get(), 1182);
    }

    /// The two ratchet signals answer different questions, and the pair is what
    /// distinguishes the three states an operator cares about.
    #[test]
    fn head_and_stalled_together_separate_the_three_states() {
        let metrics = OcsMetrics::new(&Registry::new());

        // (a) no ratchet: nothing to report, and nothing wrong.
        assert_eq!(
            metrics.committee_head_epoch.get(),
            OcsMetrics::COMMITTEE_HEAD_NOT_APPLICABLE
        );
        assert_eq!(metrics.ratchet_stalled.get(), 0);

        // (b) ratchet present, healthy.
        metrics.committee_head_epoch.set(1182);
        assert!(metrics.committee_head_epoch.get() >= 0);
        assert_eq!(metrics.ratchet_stalled.get(), 0);

        // (c) ratchet present but holding no committee — the #1980 state, which
        // `ratchet_stalled` alone does NOT report, because no attempt has
        // failed yet (or none has completed at all).
        metrics.committee_head_epoch.set(0);
        assert_eq!(metrics.committee_head_epoch.get(), 0);
        assert_eq!(
            metrics.ratchet_stalled.get(),
            0,
            "this is precisely why the head gauge has to carry the distinction itself"
        );
    }
}
