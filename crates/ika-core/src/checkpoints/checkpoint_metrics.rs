// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use prometheus::{
    Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};
use std::sync::Arc;

/// Generic checkpoint metrics parameterized by a prefix string.
/// All metric names are prefixed with the checkpoint kind name (e.g. "dwallet_checkpoint" or
/// "system_checkpoint") to preserve backward-compatible metric names.
pub struct CheckpointMetrics {
    pub last_checkpoint_pending_height: IntGauge,
    pub last_certified_checkpoint: IntGauge,
    pub last_constructed_checkpoint: IntGauge,
    pub checkpoint_errors: IntCounter,
    pub messages_included_in_checkpoint: IntCounter,
    pub checkpoint_roots_count: IntCounter,
    pub checkpoint_participation: IntCounterVec,
    pub last_received_checkpoint_signatures: IntGaugeVec,
    pub last_sent_checkpoint_signature: IntGauge,
    pub last_skipped_checkpoint_signature_submission: IntGauge,
    pub last_ignored_checkpoint_signature_received: IntGauge,
    pub highest_accumulated_epoch: IntGauge,
    pub checkpoint_creation_latency: Histogram,
    pub remote_checkpoint_forks: IntCounter,
    pub split_brain_checkpoint_forks: IntCounter,
    pub last_created_checkpoint_age: Histogram,
    pub last_certified_checkpoint_age: Histogram,
}

impl CheckpointMetrics {
    pub fn new(prefix: &str, registry: &Registry) -> Arc<Self> {
        let this = Self {
            last_checkpoint_pending_height: IntGauge::with_opts(Opts::new(
                format!("last_{prefix}_pending_height"),
                format!("Last {prefix} pending height"),
            ))
            .unwrap(),
            last_certified_checkpoint: IntGauge::with_opts(Opts::new(
                format!("last_certified_{prefix}"),
                format!("Last certified {prefix}"),
            ))
            .unwrap(),
            last_constructed_checkpoint: IntGauge::with_opts(Opts::new(
                format!("last_constructed_{prefix}"),
                format!("Last constructed {prefix}"),
            ))
            .unwrap(),
            last_created_checkpoint_age: Histogram::with_opts(
                HistogramOpts::new(
                    format!("last_created_{prefix}_age"),
                    format!("Age of the last created {prefix}"),
                )
                .buckets(mysten_metrics::LATENCY_SEC_BUCKETS.to_vec()),
            )
            .unwrap(),
            last_certified_checkpoint_age: Histogram::with_opts(
                HistogramOpts::new(
                    format!("last_certified_{prefix}_age"),
                    format!("Age of the last certified {prefix}"),
                )
                .buckets(mysten_metrics::LATENCY_SEC_BUCKETS.to_vec()),
            )
            .unwrap(),
            checkpoint_errors: IntCounter::with_opts(Opts::new(
                format!("{prefix}_errors"),
                format!("{prefix} errors count"),
            ))
            .unwrap(),
            messages_included_in_checkpoint: IntCounter::with_opts(Opts::new(
                format!("messages_included_in_{prefix}"),
                format!("Messages included in a {prefix}"),
            ))
            .unwrap(),
            checkpoint_roots_count: IntCounter::with_opts(Opts::new(
                format!("{prefix}_roots_count"),
                format!("Number of {prefix} roots received from consensus"),
            ))
            .unwrap(),
            checkpoint_participation: IntCounterVec::new(
                Opts::new(
                    format!("{prefix}_participation"),
                    format!("Participation in {prefix} certification by validator"),
                ),
                &["signer"],
            )
            .unwrap(),
            last_received_checkpoint_signatures: IntGaugeVec::new(
                Opts::new(
                    format!("last_received_{prefix}_signatures"),
                    format!("Last received {prefix} signatures by validator"),
                ),
                &["signer"],
            )
            .unwrap(),
            last_sent_checkpoint_signature: IntGauge::with_opts(Opts::new(
                format!("last_sent_{prefix}_signature"),
                format!("Last {prefix} signature sent by myself"),
            ))
            .unwrap(),
            last_skipped_checkpoint_signature_submission: IntGauge::with_opts(Opts::new(
                format!("last_skipped_{prefix}_signature_submission"),
                format!("Last {prefix} signature that this validator skipped submitting because it was already certfied."),
            ))
            .unwrap(),
            last_ignored_checkpoint_signature_received: IntGauge::with_opts(Opts::new(
                format!("last_ignored_{prefix}_signature_received"),
                format!("Last received {prefix} signature that this validator ignored because it was already certfied."),
            ))
            .unwrap(),
            highest_accumulated_epoch: IntGauge::with_opts(Opts::new(
                if prefix == "dwallet_checkpoint" {
                    "highest_accumulated_epoch".to_string()
                } else {
                    format!("highest_accumulated_{prefix}_epoch")
                },
                format!("Highest accumulated {prefix} epoch"),
            ))
            .unwrap(),
            checkpoint_creation_latency: Histogram::with_opts(
                HistogramOpts::new(
                    format!("{prefix}_creation_latency"),
                    format!("Latency from consensus commit timestamp to local {prefix} creation in milliseconds"),
                )
                .buckets(mysten_metrics::LATENCY_SEC_BUCKETS.to_vec()),
            )
            .unwrap(),
            remote_checkpoint_forks: IntCounter::with_opts(Opts::new(
                format!("remote_{prefix}_forks"),
                format!("Number of remote {prefix}s that forked from local {prefix}s"),
            ))
            .unwrap(),
            split_brain_checkpoint_forks: IntCounter::with_opts(Opts::new(
                format!("split_brain_{prefix}_forks"),
                format!("Number of {prefix}s that have resulted in a split brain"),
            ))
            .unwrap(),
        };
        registry
            .register(Box::new(this.last_checkpoint_pending_height.clone()))
            .unwrap();
        registry
            .register(Box::new(this.last_certified_checkpoint.clone()))
            .unwrap();
        registry
            .register(Box::new(this.last_constructed_checkpoint.clone()))
            .unwrap();
        registry
            .register(Box::new(this.last_created_checkpoint_age.clone()))
            .unwrap();
        registry
            .register(Box::new(this.last_certified_checkpoint_age.clone()))
            .unwrap();
        registry
            .register(Box::new(this.checkpoint_errors.clone()))
            .unwrap();
        registry
            .register(Box::new(this.messages_included_in_checkpoint.clone()))
            .unwrap();
        registry
            .register(Box::new(this.checkpoint_roots_count.clone()))
            .unwrap();
        registry
            .register(Box::new(this.checkpoint_participation.clone()))
            .unwrap();
        registry
            .register(Box::new(this.last_received_checkpoint_signatures.clone()))
            .unwrap();
        registry
            .register(Box::new(this.last_sent_checkpoint_signature.clone()))
            .unwrap();
        registry
            .register(Box::new(
                this.last_skipped_checkpoint_signature_submission.clone(),
            ))
            .unwrap();
        registry
            .register(Box::new(
                this.last_ignored_checkpoint_signature_received.clone(),
            ))
            .unwrap();
        registry
            .register(Box::new(this.highest_accumulated_epoch.clone()))
            .unwrap();
        registry
            .register(Box::new(this.checkpoint_creation_latency.clone()))
            .unwrap();
        registry
            .register(Box::new(this.remote_checkpoint_forks.clone()))
            .unwrap();
        registry
            .register(Box::new(this.split_brain_checkpoint_forks.clone()))
            .unwrap();
        Arc::new(this)
    }

    pub fn new_for_tests() -> Arc<Self> {
        // Use a unique prefix to avoid metric registration conflicts in tests
        Self::new("test_checkpoint", &Registry::new())
    }
}
