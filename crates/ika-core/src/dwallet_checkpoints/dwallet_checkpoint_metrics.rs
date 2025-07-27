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
        };
        Arc::new(this)
    }

    pub fn new_for_tests() -> Arc<Self> {
        Self::new(&Registry::new())
    }
}
