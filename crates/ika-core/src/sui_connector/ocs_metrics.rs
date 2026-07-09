// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Prometheus metrics for the OCS verifier subsystem.
//!
//! Three groups:
//! - `pusher_*`: sui-state-direct checkpoint-pusher health.
//! - `push_*`: sui-state-mirrored / handler receive-side health.
//! - `committee_head_epoch`: where the committee ratchet has reached.

use std::sync::Arc;

use prometheus::{
    Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, Registry,
    register_histogram_vec_with_registry, register_histogram_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_with_registry,
};

#[derive(Clone, Debug)]
pub struct OcsMetrics {
    // Committee ratchet
    pub committee_head_epoch: IntGauge,
    /// The upstream chain's current epoch, sampled by the ratchet. Lets
    /// operators alert on ratchet lag: `chain_latest_epoch - committee_head_epoch`.
    pub chain_latest_epoch: IntGauge,
    /// Times the ratchet installed `committee[E+1]` via the *unverified*
    /// direct-fetch prune fallback (only possible when
    /// `allow_unverified_committee_fallback` is on). Security-critical: each
    /// increment is a link of the proof chain trusted on the endpoint's word.
    pub unverified_committee_fallback_total: IntCounter,

    // Pusher (sui-state-direct)
    pub pusher_cursor_seq: IntGauge,
    /// 1 while the local pusher is stalled (upstream advanced but the pusher
    /// cursor has not for `pusher_stall_threshold` checkpoints); 0 otherwise.
    /// A stalled pusher freezes the cache, so direct cache-first reads fall
    /// through to the network (see `cache_first_stale_total`).
    pub pusher_stalled: IntGauge,
    pub pusher_pushed_total: IntCounter,
    pub pusher_skipped_irrelevant_total: IntCounter,
    pub pusher_fetch_failures_total: IntCounter,
    /// Latency of the pre-fold committee verification the pusher runs before
    /// folding a checkpoint into the local cache (committee BLS on the summary +
    /// artifacts-digest binding). `_count` is the number of checkpoints
    /// committee-verified before folding, `_sum` the total CPU time spent on
    /// it — together they quantify the verify's cost on the fold path.
    pub pusher_fold_verify_seconds: Histogram,

    // OcsVerifiedReader (consumer-side proof verification)
    pub proof_verify_total: IntCounterVec, // labels: ["kind"]
    pub proof_verify_failures_total: IntCounterVec, // labels: ["kind", "reason"]
    pub high_water_violations_total: IntCounter,
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

    /// End-to-end verify latency on the consumer side (transport
    /// round-trip + proof verify). Captures what consumers actually
    /// experience.
    pub verify_latency_seconds: HistogramVec, // labels: ["kind"]
}

impl OcsMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        Arc::new(Self {
            committee_head_epoch: register_int_gauge_with_registry!(
                "ika_ocs_committee_head_epoch",
                "Highest Sui epoch the OCS committee ratchet has reached",
                registry,
            )
            .unwrap(),
            chain_latest_epoch: register_int_gauge_with_registry!(
                "ika_ocs_chain_latest_epoch",
                "Upstream Sui current epoch sampled by the ratchet; alert on (chain_latest_epoch - committee_head_epoch)",
                registry,
            )
            .unwrap(),
            unverified_committee_fallback_total: register_int_counter_with_registry!(
                "ika_ocs_unverified_committee_fallback_total",
                "SECURITY-CRITICAL: committee[E+1] installed via the unverified direct-fetch prune fallback (trust degraded to the endpoint's word)",
                registry,
            )
            .unwrap(),
            pusher_cursor_seq: register_int_gauge_with_registry!(
                "ika_ocs_pusher_cursor_seq",
                "Highest Sui checkpoint sequence the sui-state-direct pusher has scanned",
                registry,
            )
            .unwrap(),
            pusher_stalled: register_int_gauge_with_registry!(
                "ika_ocs_pusher_stalled",
                "1 while the sui-state-direct pusher is stalled (upstream advanced but the cursor has not); 0 otherwise",
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
            pusher_fold_verify_seconds: register_histogram_with_registry!(
                "ika_ocs_pusher_fold_verify_seconds",
                "Latency of the sui-state-direct pusher's pre-fold committee verification (BLS on the summary + artifacts-digest binding); _count is the number of checkpoints committee-verified before folding into the cache",
                vec![0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
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
        })
    }

    pub fn new_for_testing() -> Arc<Self> {
        Self::new(&Registry::new())
    }
}
