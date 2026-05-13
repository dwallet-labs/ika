// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use prometheus::{
    Histogram, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Registry,
    register_histogram_with_registry, register_int_counter_vec_with_registry,
    register_int_counter_with_registry, register_int_gauge_vec_with_registry,
    register_int_gauge_with_registry,
};
use std::sync::Arc;

pub struct DWalletCheckpointMetrics {
    pub last_dwallet_checkpoint_pending_height: IntGauge,
    pub last_certified_dwallet_checkpoint: IntGauge,
    pub last_constructed_dwallet_checkpoint: IntGauge,
    pub dwallet_checkpoint_errors: IntCounter,
    pub messages_included_in_dwallet_checkpoint: IntCounter,
    pub dwallet_checkpoint_roots_count: IntCounter,
    pub dwallet_checkpoint_participation: IntCounterVec,
    pub last_received_dwallet_checkpoint_signatures: IntGaugeVec,
    pub last_sent_dwallet_checkpoint_signature: IntGauge,
    pub last_skipped_dwallet_checkpoint_signature_submission: IntGauge,
    pub last_ignored_dwallet_checkpoint_signature_received: IntGauge,
    pub highest_accumulated_epoch: IntGauge,
    pub dwallet_checkpoint_creation_latency: Histogram,
    pub remote_dwallet_checkpoint_forks: IntCounter,
    pub split_brain_dwallet_checkpoint_forks: IntCounter,
    pub last_created_dwallet_checkpoint_age: Histogram,
    pub last_certified_dwallet_checkpoint_age: Histogram,

    /// Per-user-session: the dwallet checkpoint sequence number the response for this session
    /// was written into. Set the first time a message with that `session_sequence_number`
    /// flows through `write_checkpoints`. -1 / absent before that.
    ///
    /// Cardinality: bounded by total user-session count this epoch (~max_active_sessions_buffer
    /// plus some headroom).
    pub user_session_written_at_seq: IntGaugeVec,

    /// Number of entries in `pending_dwallet_checkpoints` table that the builder hasn't yet
    /// consumed. A persistent non-zero value with stale `last_constructed_dwallet_checkpoint`
    /// ≡ the builder is stuck.
    pub pending_dwallet_checkpoint_queue_depth: IntGauge,

    /// Sequence number of the checkpoint currently being aggregated for signatures.
    /// `-1` if no current aggregator. Pair with the stake gauges below.
    pub aggregator_current_seq: IntGauge,

    /// Total stake (across all digests) that's signed for the in-flight checkpoint.
    /// Compare to the committee's quorum_threshold to see how close we are.
    pub aggregator_committed_stake: IntGauge,

    /// Stake of validators who haven't yet signed any digest for the in-flight checkpoint.
    /// Falling toward zero with multiple distinct digests ⇒ split brain locking in.
    pub aggregator_uncommitted_stake: IntGauge,

    /// Largest single-digest stake for the in-flight checkpoint. If
    /// `uncommitted_stake + plurality_stake < quorum_threshold`, quorum is unreachable.
    pub aggregator_plurality_stake: IntGauge,

    /// Number of *distinct* digests being signed for the in-flight checkpoint. `1` is healthy;
    /// `>1` ⇒ split-brain (the existing `split_brain_dwallet_checkpoint_forks` counter logs
    /// once per detection — this gauge shows the current live state).
    pub aggregator_distinct_digests: IntGauge,
}

impl DWalletCheckpointMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let this = Self {
            last_dwallet_checkpoint_pending_height: register_int_gauge_with_registry!(
                "last_dwallet_checkpoint_pending_height",
                "Last dwallet checkpoint pending height",
                registry
            )
            .unwrap(),
            last_certified_dwallet_checkpoint: register_int_gauge_with_registry!(
                "last_certified_dwallet_checkpoint",
                "Last certified dwallet checkpoint",
                registry
            )
            .unwrap(),
            last_constructed_dwallet_checkpoint: register_int_gauge_with_registry!(
                "last_constructed_dwallet_checkpoint",
                "Last constructed dwallet checkpoint",
                registry
            )
            .unwrap(),
            last_created_dwallet_checkpoint_age: register_histogram_with_registry!(
                "last_created_dwallet_checkpoint_age",
                "Age of the last created dwallet checkpoint",
                mysten_metrics::LATENCY_SEC_BUCKETS.to_vec(),
                registry
            ).unwrap(),
            last_certified_dwallet_checkpoint_age: register_histogram_with_registry!(
                "last_certified_dwallet_checkpoint_age",
                "Age of the last certified dwallet checkpoint",
                mysten_metrics::LATENCY_SEC_BUCKETS.to_vec(),
                registry
            ).unwrap(),
            dwallet_checkpoint_errors: register_int_counter_with_registry!(
                "dwallet_checkpoint_errors",
                "Dwallet checkpoints errors count",
                registry
            )
            .unwrap(),
            messages_included_in_dwallet_checkpoint: register_int_counter_with_registry!(
                "messages_included_in_dwallet_checkpoint",
                "Messages included in a dwallet checkpoint",
                registry
            )
            .unwrap(),
            dwallet_checkpoint_roots_count: register_int_counter_with_registry!(
                "dwallet_checkpoint_roots_count",
                "Number of dwallet checkpoint roots received from consensus",
                registry
            )
            .unwrap(),
            dwallet_checkpoint_participation: register_int_counter_vec_with_registry!(
                "dwallet_checkpoint_participation",
                "Participation in dwallet checkpoint certification by validator",
                &["signer"],
                registry
            )
            .unwrap(),
            last_received_dwallet_checkpoint_signatures: register_int_gauge_vec_with_registry!(
                "last_received_dwallet_checkpoint_signatures",
                "Last received dwallet checkpoint signatures by validator",
                &["signer"],
                registry
            )
            .unwrap(),
            last_sent_dwallet_checkpoint_signature: register_int_gauge_with_registry!(
                "last_sent_dwallet_checkpoint_signature",
                "Last dwallet checkpoint signature sent by myself",
                registry
            )
            .unwrap(),
            last_skipped_dwallet_checkpoint_signature_submission: register_int_gauge_with_registry!(
                "last_skipped_dwallet_checkpoint_signature_submission",
                "Last dwallet checkpoint signature that this validator skipped submitting because it was already certfied.",
                registry
            )
            .unwrap(),
            last_ignored_dwallet_checkpoint_signature_received: register_int_gauge_with_registry!(
                "last_ignored_dwallet_checkpoint_signature_received",
                "Last received dwallet checkpoint signature that this validator ignored because it was already certfied.",
                registry
            )
            .unwrap(),
            highest_accumulated_epoch: register_int_gauge_with_registry!(
                "highest_accumulated_epoch",
                "Highest accumulated epoch",
                registry
            )
            .unwrap(),
            dwallet_checkpoint_creation_latency: register_histogram_with_registry!(
                "dwallet_checkpoint_creation_latency",
                "Latency from consensus commit timestamp to local dwallet checkpoint creation in milliseconds",
                mysten_metrics::LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            ).unwrap(),
            remote_dwallet_checkpoint_forks: register_int_counter_with_registry!(
                "remote_dwallet_checkpoint_forks",
                "Number of remote dwallet checkpoints that forked from local dwallet checkpoints",
                registry
            )
            .unwrap(),
            split_brain_dwallet_checkpoint_forks: register_int_counter_with_registry!(
                "split_brain_dwallet_checkpoint_forks",
                "Number of dwallet checkpoints that have resulted in a split brain",
                registry
            )
            .unwrap(),
            user_session_written_at_seq: register_int_gauge_vec_with_registry!(
                "dwallet_checkpoint_user_session_written_at_seq",
                "Dwallet checkpoint sequence number a session's response was written into. Labeled by session_seq.",
                &["session_seq"],
                registry
            )
            .unwrap(),
            pending_dwallet_checkpoint_queue_depth: register_int_gauge_with_registry!(
                "dwallet_checkpoint_pending_queue_depth",
                "Pending dwallet checkpoint entries not yet consumed by the builder.",
                registry
            )
            .unwrap(),
            aggregator_current_seq: register_int_gauge_with_registry!(
                "dwallet_checkpoint_aggregator_current_seq",
                "Sequence number being aggregated for signatures right now (-1 if none).",
                registry
            )
            .unwrap(),
            aggregator_committed_stake: register_int_gauge_with_registry!(
                "dwallet_checkpoint_aggregator_committed_stake",
                "Total stake (across all digests) that's signed the in-flight checkpoint.",
                registry
            )
            .unwrap(),
            aggregator_uncommitted_stake: register_int_gauge_with_registry!(
                "dwallet_checkpoint_aggregator_uncommitted_stake",
                "Stake yet to sign any digest for the in-flight checkpoint.",
                registry
            )
            .unwrap(),
            aggregator_plurality_stake: register_int_gauge_with_registry!(
                "dwallet_checkpoint_aggregator_plurality_stake",
                "Largest single-digest stake for the in-flight checkpoint.",
                registry
            )
            .unwrap(),
            aggregator_distinct_digests: register_int_gauge_with_registry!(
                "dwallet_checkpoint_aggregator_distinct_digests",
                "Distinct digests being signed for the in-flight checkpoint (>1 ⇒ split brain).",
                registry
            )
            .unwrap(),
        };
        Arc::new(this)
    }

    pub fn new_for_tests() -> Arc<Self> {
        Self::new(&Registry::new())
    }
}
