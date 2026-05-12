// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! # DWallet MPC Metrics
//!
//! This module provides Prometheus metrics for monitoring DWallet Multi-Party Computation
//! (MPC) operations.
//! It tracks various aspects of MPC protocol execution, including event processing,
//! round advancement, and completion times.
//!
//! ## Metrics Overview
//!
//! The metrics are organized around MPC protocol sessions and rounds, with labels that provide
//! detailed context about the cryptographic parameters being used:
//!
//! - **protocol_name**: The type of MPC protocol (e.g., "Sign", "Presign", "dWalletDKGFirstRound")
//! - **curve**: The elliptic curve being used (e.g., "Secp256k1")
//! - **hash_scheme**: The hash algorithm for signing operations (e.g., "SHA256", "KECCAK256")
//! - **signature_algorithm**: The signature algorithm (e.g., "ECDSA")
//! - **mpc_round**: The specific round number within a protocol session

use crate::dwallet_session_request::DWalletSessionRequestMetricData;
use prometheus::{
    GaugeVec, IntCounterVec, IntGauge, IntGaugeVec, Registry, register_gauge_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
    register_int_gauge_with_registry,
};
use std::sync::Arc;

/// Prometheus metrics for DWallet MPC operations.
///
/// This struct contains all the metrics used to monitor MPC protocol execution,
/// including event processing, round advancement, and timing information.
pub struct DWalletMPCMetrics {
    /// Tracks the number of MPC protocol sessions that have been initiated.
    ///
    /// Labels: protocol_name, curve, hash_scheme, signature_algorithm
    ///
    /// This metric increments when a new MPC event is received and processing begins.
    /// It helps monitor the overall activity level and can be used to detect
    /// when new protocols are being initiated.
    received_requests_start_count: IntGaugeVec,

    /// Tracks the number of advance calls made during MPC protocol execution.
    ///
    /// Labels: protocol_name, curve, mpc_round, hash_scheme, signature_algorithm
    ///
    /// This metric increments each time the MPC protocol attempts to advance to
    /// the next step.
    /// It includes the round number to provide granular visibility
    /// into which specific rounds are being processed.
    advance_mpc_calls: IntGaugeVec,

    native_calls: IntGaugeVec,

    /// Tracks the number of successful advance completions during MPC protocol execution.
    ///
    /// Labels: protocol_name, curve, mpc_round, hash_scheme, signature_algorithm
    ///
    /// This metric increments when an advance call successfully completes.
    /// Comparing this with `advance_calls` can help identify failure rates
    /// and problematic rounds.
    advance_completions: IntGaugeVec,

    native_completions: IntGaugeVec,

    /// Records the average duration of computations for each MPC round.
    computation_duration_avg: GaugeVec,

    /// Records the variance of the computation durations for each MPC round.
    computation_duration_variance: GaugeVec,

    /// Tracks the number of MPC protocol sessions that have been started.
    session_start_count: IntGaugeVec,

    /// Tracks the total number of completed MPC protocol sessions.
    ///
    /// Labels: protocol_name, curve, hash_scheme, signature_algorithm
    ///
    /// This metric increments when an entire MPC protocol session completes
    /// successfully.
    /// It provides insight into overall protocol success rates and throughput.
    completions_count: IntGaugeVec,

    /// Records the duration of the most recent completion for each protocol/round combination.
    ///
    /// Labels: protocol_name, curve, mpc_round, hash_scheme, signature_algorithm
    /// Value: Duration in milliseconds.
    ///
    /// This metric stores the execution time of the last completed round,
    /// allowing monitoring of performance trends and identification of
    /// slow-performing protocol rounds.
    last_completion_duration: IntGaugeVec,

    /// The number of sign sessions in which a quorum of the expected decrypters has participated.
    pub number_of_expected_sign_sessions: IntGauge,
    /// The number of sign sessions in which less than a quorum of the expected decrypters has participated.
    pub number_of_unexpected_sign_sessions: IntGauge,
    /// The last process MPC consensus round.
    pub last_process_mpc_consensus_round: IntGauge,

    /// Histogram-by-bucket of how long each currently-tracked session has been Active for.
    /// Labels: `session_type` ("user" / "system"), `age_bucket` (`<30s`, `<5m`, `<30m`, `<2h`, `>=2h`).
    /// A non-zero `>=2h` bucket for user sessions is the smoking gun of an MPC deadlock.
    pub active_sessions_by_age: IntGaugeVec,

    /// Counts of sessions currently tracked by the manager grouped by status.
    /// Labels: `state` in {`active`, `waiting_for_session_request`, `computation_completed`,
    /// `completed`, `failed`}.
    pub session_state_count: IntGaugeVec,

    /// Counter for the outcome of every `try_ready_to_advance` invocation.
    /// Labels: `protocol`, `result` in {`ready`, `not_ready`, `err`}.
    /// A growing `not_ready` or `err` count for a specific protocol/round explains why
    /// `dwallet_mpc_advance_completions` is stuck.
    pub ready_to_advance_result_total: IntCounterVec,

    /// Counter for `generate_protocol_cryptographic_data` errors that would otherwise be
    /// silently swallowed by `.ok()?` in `perform_cryptographic_computation`.
    /// Labels: `protocol`, `error` (a stable short string for the error class).
    pub protocol_data_generation_errors_total: IntCounterVec,

    /// Counter for every call into `submit_failed_session` in dwallet_mpc_service.
    /// Labels: `protocol`, `reason` (e.g. `mpc_error`, `failed_to_create_session`).
    pub sessions_rejected_total: IntCounterVec,

    /// Size of `DWalletMPCManager.malicious_actors`. Reset to 0 on each new epoch.
    /// When this approaches a threshold-relevant fraction of stake, user MPC may deadlock.
    pub malicious_actors_size: IntGauge,

    /// Size of each parking lot in `DWalletMPCManager.requests_pending_for_network_key`.
    /// Labels: `network_encryption_key_id`. Sustained non-zero values indicate the validator
    /// is missing the key data needed to process incoming sessions.
    pub requests_pending_for_network_key: IntGaugeVec,

    /// Size of `DWalletMPCManager.requests_pending_for_next_active_committee`.
    pub requests_pending_for_next_active_committee: IntGauge,
}

impl DWalletMPCMetrics {
    /// Creates a new instance of DWalletMPCMetrics and registers all metrics with the provided registry.
    ///
    /// # Arguments
    /// * `registry` — The Prometheus registry to register metrics with.
    ///
    /// # Returns
    /// An Arc-wrapped instance of DWalletMPCMetrics for shared access across threads.
    pub fn new(registry: &Registry) -> Arc<Self> {
        // Label sets for different metric types
        // Protocol-level metrics use these labels
        let protocol_metric_labels = [
            "protocol_name",
            "curve",
            "hash_scheme",
            "signature_algorithm",
        ];
        // Round-level metrics include the round number
        let round_metric_labels = [
            "protocol_name",
            "curve",
            "mpc_round",
            "hash_scheme",
            "signature_algorithm",
        ];

        Arc::new(Self {
            session_start_count: register_int_gauge_vec_with_registry!(
                "dwallet_mpc_session_start_count",
                "Number of MPC protocol sessions started",
                &protocol_metric_labels,
                registry
            )
            .unwrap(),
            received_requests_start_count: register_int_gauge_vec_with_registry!(
                "dwallet_mpc_received_requests_start_count",
                "Number of received requests",
                &protocol_metric_labels,
                registry
            )
            .unwrap(),
            advance_mpc_calls: register_int_gauge_vec_with_registry!(
                "dwallet_mpc_advance_calls",
                "Number of advance calls",
                &round_metric_labels,
                registry
            )
            .unwrap(),
            native_calls: register_int_gauge_vec_with_registry!(
                "dwallet_nativee_calls",
                "Number of native session calls",
                &protocol_metric_labels,
                registry
            )
            .unwrap(),
            computation_duration_variance: register_gauge_vec_with_registry!(
                "dwallet_mpc_computation_duration_variance",
                "Variance of the duration of MPC computations in milliseconds",
                &round_metric_labels,
                registry
            )
            .unwrap(),
            computation_duration_avg: register_gauge_vec_with_registry!(
                "dwallet_mpc_computation_duration_avg",
                "Average duration of MPC computations in milliseconds",
                &round_metric_labels,
                registry
            )
            .unwrap(),
            advance_completions: register_int_gauge_vec_with_registry!(
                "dwallet_mpc_advance_completions",
                "Number of advance completions",
                &round_metric_labels,
                registry
            )
            .unwrap(),
            native_completions: register_int_gauge_vec_with_registry!(
                "dwallet_native_completions",
                "Number of native sessions completions",
                &protocol_metric_labels,
                registry
            )
            .unwrap(),
            completions_count: register_int_gauge_vec_with_registry!(
                "dwallet_mpc_completions_count",
                "Number of completions",
                &protocol_metric_labels,
                registry
            )
            .unwrap(),
            last_completion_duration: register_int_gauge_vec_with_registry!(
                "dwallet_mpc_last_completion_duration",
                "Duration of the last completion in milliseconds",
                &round_metric_labels,
                registry
            )
            .unwrap(),
            number_of_unexpected_sign_sessions: register_int_gauge_with_registry!(
                "dwallet_mpc_number_of_unexpected_sign_sessions",
                "Number of unexpected sign sessions",
                registry
            )
            .unwrap(),
            number_of_expected_sign_sessions: register_int_gauge_with_registry!(
                "dwallet_mpc_number_of_expected_sign_sessions",
                "Number of expected sign sessions",
                registry
            )
            .unwrap(),
            last_process_mpc_consensus_round: register_int_gauge_with_registry!(
                "last_process_mpc_consensus_round",
                "Last process mpc consensus round",
                registry
            )
            .unwrap(),
            active_sessions_by_age: register_int_gauge_vec_with_registry!(
                "dwallet_mpc_active_sessions_by_age",
                "Active session count by session type and age bucket",
                &["session_type", "age_bucket"],
                registry,
            )
            .unwrap(),
            session_state_count: register_int_gauge_vec_with_registry!(
                "dwallet_mpc_session_state_count",
                "Number of sessions currently tracked, grouped by status",
                &["state"],
                registry,
            )
            .unwrap(),
            ready_to_advance_result_total: register_int_counter_vec_with_registry!(
                "dwallet_mpc_ready_to_advance_result_total",
                "Counts of try_ready_to_advance outcomes per protocol",
                &["protocol", "result"],
                registry,
            )
            .unwrap(),
            protocol_data_generation_errors_total: register_int_counter_vec_with_registry!(
                "dwallet_mpc_protocol_data_generation_errors_total",
                "Count of generate_protocol_cryptographic_data errors, by protocol and error class",
                &["protocol", "error"],
                registry,
            )
            .unwrap(),
            sessions_rejected_total: register_int_counter_vec_with_registry!(
                "dwallet_mpc_sessions_rejected_total",
                "Count of submit_failed_session calls, by protocol and reason",
                &["protocol", "reason"],
                registry,
            )
            .unwrap(),
            malicious_actors_size: register_int_gauge_with_registry!(
                "dwallet_mpc_malicious_actors_size",
                "Size of the manager's in-memory malicious_actors set",
                registry,
            )
            .unwrap(),
            requests_pending_for_network_key: register_int_gauge_vec_with_registry!(
                "dwallet_mpc_requests_pending_for_network_key",
                "Per-key pending session-request parking lot size",
                &["network_encryption_key_id"],
                registry,
            )
            .unwrap(),
            requests_pending_for_next_active_committee: register_int_gauge_with_registry!(
                "dwallet_mpc_requests_pending_for_next_active_committee",
                "Sessions parked waiting for the next active committee",
                registry,
            )
            .unwrap(),
        })
    }
}

/// Age buckets used by `active_sessions_by_age`. Order matters: we bucket into the FIRST
/// matching bucket. Keep label strings stable — alerts depend on them.
pub(crate) const AGE_BUCKETS: &[(&str, std::time::Duration)] = &[
    ("<30s", std::time::Duration::from_secs(30)),
    ("<5m", std::time::Duration::from_secs(300)),
    ("<30m", std::time::Duration::from_secs(1800)),
    ("<2h", std::time::Duration::from_secs(7200)),
];
/// Open-ended bucket label for ages >= last threshold.
pub(crate) const AGE_BUCKET_OVERFLOW: &str = ">=2h";

/// Stable label strings for `session_state_count`.
pub(crate) const SESSION_STATE_ACTIVE: &str = "active";
pub(crate) const SESSION_STATE_WAITING_FOR_REQUEST: &str = "waiting_for_session_request";
pub(crate) const SESSION_STATE_COMPUTATION_COMPLETED: &str = "computation_completed";
pub(crate) const SESSION_STATE_COMPLETED: &str = "completed";
pub(crate) const SESSION_STATE_FAILED: &str = "failed";

/// Stable label strings for `ready_to_advance_result_total`.
pub(crate) const READY_RESULT_READY: &str = "ready";
pub(crate) const READY_RESULT_NOT_READY: &str = "not_ready";
pub(crate) const READY_RESULT_ERR: &str = "err";

/// Stable label strings for the `session_type` label.
pub(crate) const SESSION_TYPE_USER: &str = "user";
pub(crate) const SESSION_TYPE_SYSTEM: &str = "system";

impl DWalletMPCMetrics {
    /// Records the completion of an MPC protocol session.
    ///
    /// This increments the `completions_count` metric with labels derived from the
    /// provided MPC event data.
    ///
    /// # Arguments
    /// * `protocol_data` - The MPC protocol initialization data containing context.
    pub(crate) fn add_completion(&self, protocol_data: &DWalletSessionRequestMetricData) {
        self.completions_count
            .with_label_values(&[
                protocol_data.name(),
                &protocol_data.curve(),
                &protocol_data.hash_scheme(),
                &protocol_data.signature_algorithm(),
            ])
            .inc();
    }

    /// Records the start of processing for a received MPC event.
    ///
    /// This increments the received_events_start_count metric with labels derived
    /// from the provided MPC event data.
    ///
    /// # Arguments
    /// * `protocol_data` - The MPC protocol initialization data containing context.
    pub(crate) fn add_received_request_start(
        &self,
        protocol_data: &DWalletSessionRequestMetricData,
    ) {
        self.received_requests_start_count
            .with_label_values(&[
                protocol_data.name(),
                &protocol_data.curve(),
                &protocol_data.hash_scheme(),
                &protocol_data.signature_algorithm(),
            ])
            .inc();
    }

    /// Records an advance call for a specific MPC round.
    ///
    /// This increments the `advance_calls` metric with labels derived from the
    /// provided MPC event data and round information.
    ///
    /// # Arguments
    /// * `protocol_data` - The MPC protocol initialization data containing context
    /// * `mpc_round` — String identifier for the specific MPC round.
    pub(crate) fn add_advance_mpc_call(
        &self,
        protocol_data: &DWalletSessionRequestMetricData,
        mpc_round: &str,
    ) {
        if mpc_round == "1" {
            self.session_start_count
                .with_label_values(&[
                    protocol_data.name(),
                    &protocol_data.curve(),
                    &protocol_data.hash_scheme(),
                    &protocol_data.signature_algorithm(),
                ])
                .inc();
        }
        self.advance_mpc_calls
            .with_label_values(&[
                protocol_data.name(),
                &protocol_data.curve(),
                mpc_round,
                &protocol_data.hash_scheme(),
                &protocol_data.signature_algorithm(),
            ])
            .inc();
    }

    pub(crate) fn add_compute_native_call(&self, protocol_data: &DWalletSessionRequestMetricData) {
        self.session_start_count
            .with_label_values(&[
                protocol_data.name(),
                &protocol_data.curve(),
                &protocol_data.hash_scheme(),
                &protocol_data.signature_algorithm(),
            ])
            .inc();
        self.native_calls
            .with_label_values(&[
                protocol_data.name(),
                &protocol_data.curve(),
                &protocol_data.hash_scheme(),
                &protocol_data.signature_algorithm(),
            ])
            .inc();
    }

    /// Records the successful completion of an advance call for a specific MPC round.
    ///
    /// This increments the `advance_completions` metric with labels derived from the
    /// provided MPC event data and round information.
    ///
    /// # Arguments
    /// * `protocol_metadata` - The MPC protocol initialization data containing context
    /// * `mpc_round` — String identifier for the specific MPC round.
    pub fn add_advance_completion(
        &self,
        protocol_data: &DWalletSessionRequestMetricData,
        mpc_round: &str,
        duration_ms: i64,
    ) {
        self.advance_completions
            .with_label_values(&[
                protocol_data.name(),
                &protocol_data.curve(),
                mpc_round,
                &protocol_data.hash_scheme(),
                &protocol_data.signature_algorithm(),
            ])
            .inc();
        let current_avg = self
            .computation_duration_avg
            .with_label_values(&[
                protocol_data.name(),
                &protocol_data.curve(),
                mpc_round,
                &protocol_data.hash_scheme(),
                &protocol_data.signature_algorithm(),
            ])
            .get();
        let advance_completions_count = self
            .advance_completions
            .with_label_values(&[
                protocol_data.name(),
                &protocol_data.curve(),
                mpc_round,
                &protocol_data.hash_scheme(),
                &protocol_data.signature_algorithm(),
            ])
            .get();
        let new_avg = (current_avg * (advance_completions_count as f64 - 1.0) + duration_ms as f64)
            / (advance_completions_count as f64);
        self.computation_duration_avg
            .with_label_values(&[
                protocol_data.name(),
                &protocol_data.curve(),
                mpc_round,
                &protocol_data.hash_scheme(),
                &protocol_data.signature_algorithm(),
            ])
            .set(new_avg);
        if advance_completions_count > 1 {
            let current_variance = self
                .computation_duration_variance
                .with_label_values(&[
                    protocol_data.name(),
                    &protocol_data.curve(),
                    mpc_round,
                    &protocol_data.hash_scheme(),
                    &protocol_data.signature_algorithm(),
                ])
                .get();
            let new_variance = update_variance(
                current_avg,
                new_avg,
                current_variance,
                duration_ms as f64,
                advance_completions_count,
            );
            self.computation_duration_variance
                .with_label_values(&[
                    protocol_data.name(),
                    &protocol_data.curve(),
                    mpc_round,
                    &protocol_data.hash_scheme(),
                    &protocol_data.signature_algorithm(),
                ])
                .set(new_variance);
        } else {
            self.computation_duration_variance
                .with_label_values(&[
                    protocol_data.name(),
                    &protocol_data.curve(),
                    mpc_round,
                    &protocol_data.hash_scheme(),
                    &protocol_data.signature_algorithm(),
                ])
                .set(0.0);
        }
    }

    pub fn add_native_completion(
        &self,
        protocol_data: &DWalletSessionRequestMetricData,
        duration_ms: i64,
    ) {
        self.native_completions
            .with_label_values(&[
                protocol_data.name(),
                &protocol_data.curve(),
                &protocol_data.hash_scheme(),
                &protocol_data.signature_algorithm(),
            ])
            .inc();
        let current_avg = self
            .computation_duration_avg
            .with_label_values(&[
                protocol_data.name(),
                &protocol_data.curve(),
                "0",
                &protocol_data.hash_scheme(),
                &protocol_data.signature_algorithm(),
            ])
            .get();
        let advance_completions_count = self
            .native_completions
            .with_label_values(&[
                protocol_data.name(),
                &protocol_data.curve(),
                &protocol_data.hash_scheme(),
                &protocol_data.signature_algorithm(),
            ])
            .get();
        let new_avg = (current_avg * (advance_completions_count as f64 - 1.0) + duration_ms as f64)
            / (advance_completions_count as f64);

        self.computation_duration_avg
            .with_label_values(&[
                protocol_data.name(),
                &protocol_data.curve(),
                "0",
                &protocol_data.hash_scheme(),
                &protocol_data.signature_algorithm(),
            ])
            .set(new_avg);
        if advance_completions_count > 1 {
            let current_variance = self
                .computation_duration_variance
                .with_label_values(&[
                    protocol_data.name(),
                    &protocol_data.curve(),
                    "0",
                    &protocol_data.hash_scheme(),
                    &protocol_data.signature_algorithm(),
                ])
                .get();
            let new_variance = update_variance(
                current_avg,
                new_avg,
                current_variance,
                duration_ms as f64,
                advance_completions_count,
            );
            self.computation_duration_variance
                .with_label_values(&[
                    protocol_data.name(),
                    &protocol_data.curve(),
                    "0",
                    &protocol_data.hash_scheme(),
                    &protocol_data.signature_algorithm(),
                ])
                .set(new_variance);
        } else {
            self.computation_duration_variance
                .with_label_values(&[
                    protocol_data.name(),
                    &protocol_data.curve(),
                    "0",
                    &protocol_data.hash_scheme(),
                    &protocol_data.signature_algorithm(),
                ])
                .set(0.0);
        }
    }

    /// Sets the duration of the last completion for a specific MPC round.
    ///
    /// This updates the last_completion_duration metric with the provided duration
    /// and labels derived from the MPC event data and round information.
    ///
    /// # Arguments
    /// * `protocol_data` - The MPC protocol initialization data containing context
    /// * `mpc_round` — String identifier for the specific MPC round
    /// * `duration_ms` — Duration of the completion in milliseconds.
    pub fn set_last_completion_duration(
        &self,
        protocol_data: &DWalletSessionRequestMetricData,
        mpc_round: &str,
        duration_ms: i64,
    ) {
        self.last_completion_duration
            .with_label_values(&[
                protocol_data.name(),
                &protocol_data.curve(),
                mpc_round,
                &protocol_data.hash_scheme(),
                &protocol_data.signature_algorithm(),
            ])
            .set(duration_ms);
    }
}

/// Calculating the variance using the Welford's method.
/// Learn more in this [article](https://jonisalonen.com/2013/deriving-welfords-method-for-computing-variance/)
fn update_variance(old_mean: f64, new_mean: f64, old_variance: f64, new_value: f64, n: i64) -> f64 {
    let n = n as f64;
    let first = old_variance * (n - 2.0);
    let second = (new_value - new_mean) * (new_value - old_mean);
    (first + second) / (n - 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_update_variance() {
        // Case 1
        let old_mean = 347.0;
        let new_mean = 356.0;
        let old_variance = 0.0;
        let new_value = 365.0;
        let n = 2;
        let updated_variance = update_variance(old_mean, new_mean, old_variance, new_value, n);
        assert_eq!(updated_variance, 162.0);

        // Case 2
        let new_value = 70.0;
        let old_mean = 55.0;
        let new_mean = 60.0;
        let old_variance = 50.0;
        let n = 3;
        let updated_variance = update_variance(old_mean, new_mean, old_variance, new_value, n);
        assert_eq!(updated_variance, 100.0);

        // Case 3
        let new_value = 60.0;
        let old_mean = 50.0;
        let new_mean = 55.0;
        let old_variance = 0.0;
        let n = 2;
        let updated_variance = update_variance(old_mean, new_mean, old_variance, new_value, n);
        assert_eq!(updated_variance, 50.0);

        // Case 4: add 30 to [10, 20]
        let old_mean = 15.0;
        let new_mean = 20.0;
        let old_variance = 50.0; // var([10, 20]) = 50
        let new_value = 30.0;
        let n = 3;
        let updated_variance = update_variance(old_mean, new_mean, old_variance, new_value, n);
        assert_eq!(updated_variance, 100.0); // var([10, 20, 30]) = 100

        // Case 5: add 99 to [100, 100, 100]
        let old_mean = 100.0;
        let new_mean = 99.0;
        let old_variance = 0.0; // var([100, 100, 100]) = 0
        let new_value = 99.0;
        let n = 3;
        let updated_variance = update_variance(old_mean, new_mean, old_variance, new_value, n);
        assert_eq!(updated_variance, 0.0); // var([100, 100, 100, 99]) = 0

        // Case 6: add 200 to [100, 120, 150]
        let old_mean = 123.3333333;
        let new_mean = 142.5;
        let old_variance = 633.3333334; // correct sample variance of [100, 120, 150]
        let new_value = 200.0;
        let n = 4;
        let updated_variance = update_variance(old_mean, new_mean, old_variance, new_value, n);
        assert_eq!(updated_variance, 1891.6666673499997); // correct sample variance of [100, 120, 150, 200]
    }
}
