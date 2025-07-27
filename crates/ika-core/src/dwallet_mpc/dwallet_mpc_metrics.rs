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

use ika_types::messages_dwallet_mpc::MPCRequestInput;
use prometheus::{
    IntGauge, IntGaugeVec, Registry, register_int_gauge_vec_with_registry,
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
    received_events_start_count: IntGaugeVec,

    /// Tracks the number of advance calls made during MPC protocol execution.
    ///
    /// Labels: protocol_name, curve, mpc_round, hash_scheme, signature_algorithm
    ///
    /// This metric increments each time the MPC protocol attempts to advance to
    /// the next step.
    /// It includes the round number to provide granular visibility
    /// into which specific rounds are being processed.
    advance_calls: IntGaugeVec,

    /// Tracks the number of successful advance completions during MPC protocol execution.
    ///
    /// Labels: protocol_name, curve, mpc_round, hash_scheme, signature_algorithm
    ///
    /// This metric increments when an advance call successfully completes.
    /// Comparing this with `advance_calls` can help identify failure rates
    /// and problematic rounds.
    advance_completions: IntGaugeVec,

    /// Records the average duration of computations for each MPC round.
    computation_duration_avg: IntGaugeVec,

    /// Records the variance of the computation durations for each MPC round.
    computation_duration_variance: IntGaugeVec,

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
            received_events_start_count: register_int_gauge_vec_with_registry!(
                "dwallet_mpc_received_events_start_count",
                "Number of received start events",
                &protocol_metric_labels,
                registry
            )
            .unwrap(),
            advance_calls: register_int_gauge_vec_with_registry!(
                "dwallet_mpc_advance_calls",
                "Number of advance calls",
                &round_metric_labels,
                registry
            )
            .unwrap(),
            computation_duration_variance: register_int_gauge_vec_with_registry!(
                "dwallet_mpc_computation_duration_variance",
                "Variance of the duration of MPC computations in milliseconds",
                &round_metric_labels,
                registry
            )
            .unwrap(),
            computation_duration_avg: register_int_gauge_vec_with_registry!(
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
        })
    }
}

impl DWalletMPCMetrics {
    /// Records the completion of an MPC protocol session.
    ///
    /// This increments the `completions_count` metric with labels derived from the
    /// provided MPC event data.
    ///
    /// # Arguments
    /// * `mpc_event_data` - The MPC protocol initialization data containing context.
    pub fn add_completion(&self, mpc_event_data: &MPCRequestInput) {
        self.completions_count
            .with_label_values(&[
                &mpc_event_data.to_string(),
                &mpc_event_data.get_curve(),
                &mpc_event_data.get_hash_scheme(),
                &mpc_event_data.get_signature_algorithm(),
            ])
            .inc();
    }

    /// Records the start of processing for a received MPC event.
    ///
    /// This increments the received_events_start_count metric with labels derived
    /// from the provided MPC event data.
    ///
    /// # Arguments
    /// * `mpc_event_data` - The MPC protocol initialization data containing context.
    pub fn add_received_event_start(&self, mpc_event_data: &MPCRequestInput) {
        self.received_events_start_count
            .with_label_values(&[
                &mpc_event_data.to_string(),
                &mpc_event_data.get_curve(),
                &mpc_event_data.get_hash_scheme(),
                &mpc_event_data.get_signature_algorithm(),
            ])
            .inc();
    }

    /// Records an advance call for a specific MPC round.
    ///
    /// This increments the `advance_calls` metric with labels derived from the
    /// provided MPC event data and round information.
    ///
    /// # Arguments
    /// * `mpc_event_data` - The MPC protocol initialization data containing context
    /// * `mpc_round` — String identifier for the specific MPC round.
    pub fn add_advance_call(&self, request_input: &MPCRequestInput, mpc_round: &str) {
        if mpc_round == "1" {
            self.session_start_count
                .with_label_values(&[
                    &request_input.to_string(),
                    &request_input.get_curve(),
                    &request_input.get_hash_scheme(),
                    &request_input.get_signature_algorithm(),
                ])
                .inc();
        }
        self.advance_calls
            .with_label_values(&[
                &request_input.to_string(),
                &request_input.get_curve(),
                mpc_round,
                &request_input.get_hash_scheme(),
                &request_input.get_signature_algorithm(),
            ])
            .inc();
    }

    /// Records the successful completion of an advance call for a specific MPC round.
    ///
    /// This increments the `advance_completions` metric with labels derived from the
    /// provided MPC event data and round information.
    ///
    /// # Arguments
    /// * `mpc_event_data` - The MPC protocol initialization data containing context
    /// * `mpc_round` — String identifier for the specific MPC round.
    pub fn add_advance_completion(
        &self,
        mpc_event_data: &MPCRequestInput,
        mpc_round: &str,
        duration_ms: i64,
    ) {
        self.advance_completions
            .with_label_values(&[
                &mpc_event_data.to_string(),
                &mpc_event_data.get_curve(),
                mpc_round,
                &mpc_event_data.get_hash_scheme(),
                &mpc_event_data.get_signature_algorithm(),
            ])
            .inc();
        let current_avg = self
            .computation_duration_avg
            .with_label_values(&[
                &mpc_event_data.to_string(),
                &mpc_event_data.get_curve(),
                mpc_round,
                &mpc_event_data.get_hash_scheme(),
                &mpc_event_data.get_signature_algorithm(),
            ])
            .get();
        let advance_completions_count = self
            .advance_completions
            .with_label_values(&[
                &mpc_event_data.to_string(),
                &mpc_event_data.get_curve(),
                mpc_round,
                &mpc_event_data.get_hash_scheme(),
                &mpc_event_data.get_signature_algorithm(),
            ])
            .get();
        let new_avg = (current_avg * (advance_completions_count - 1) + duration_ms)
            / advance_completions_count;
        self.computation_duration_avg
            .with_label_values(&[
                &mpc_event_data.to_string(),
                &mpc_event_data.get_curve(),
                mpc_round,
                &mpc_event_data.get_hash_scheme(),
                &mpc_event_data.get_signature_algorithm(),
            ])
            .set(new_avg);
        if advance_completions_count > 1 {
            let current_variance = self
                .computation_duration_variance
                .with_label_values(&[
                    &mpc_event_data.to_string(),
                    &mpc_event_data.get_curve(),
                    mpc_round,
                    &mpc_event_data.get_hash_scheme(),
                    &mpc_event_data.get_signature_algorithm(),
                ])
                .get();
            let new_variance = update_variance(
                current_avg,
                new_avg,
                current_variance,
                duration_ms,
                advance_completions_count,
            );
            self.computation_duration_variance
                .with_label_values(&[
                    &mpc_event_data.to_string(),
                    &mpc_event_data.get_curve(),
                    mpc_round,
                    &mpc_event_data.get_hash_scheme(),
                    &mpc_event_data.get_signature_algorithm(),
                ])
                .set(new_variance);
        } else {
            self.computation_duration_variance
                .with_label_values(&[
                    &mpc_event_data.to_string(),
                    &mpc_event_data.get_curve(),
                    mpc_round,
                    &mpc_event_data.get_hash_scheme(),
                    &mpc_event_data.get_signature_algorithm(),
                ])
                .set(0);
        }
    }

    /// Sets the duration of the last completion for a specific MPC round.
    ///
    /// This updates the last_completion_duration metric with the provided duration
    /// and labels derived from the MPC event data and round information.
    ///
    /// # Arguments
    /// * `mpc_event_data` - The MPC protocol initialization data containing context
    /// * `mpc_round` — String identifier for the specific MPC round
    /// * `duration_ms` — Duration of the completion in milliseconds.
    pub fn set_last_completion_duration(
        &self,
        mpc_event_data: &MPCRequestInput,
        mpc_round: &str,
        duration_ms: i64,
    ) {
        self.last_completion_duration
            .with_label_values(&[
                &mpc_event_data.to_string(),
                &mpc_event_data.get_curve(),
                mpc_round,
                &mpc_event_data.get_hash_scheme(),
                &mpc_event_data.get_signature_algorithm(),
            ])
            .set(duration_ms);
    }
}

/// Calculating the variance using the Welford's method.
/// Learn more in this [article](https://jonisalonen.com/2013/deriving-welfords-method-for-computing-variance/)
fn update_variance(old_mean: i64, new_mean: i64, old_variance: i64, new_value: i64, n: i64) -> i64 {
    // convert all the vars to f64 to avoid overflow
    let old_mean = old_mean as f64;
    let new_mean = new_mean as f64;
    let old_variance = old_variance as f64;
    let new_value = new_value as f64;
    let n = n as f64;
    let first = old_variance * (n - 2.0);
    let second = (new_value - new_mean) * (new_value - old_mean);
    let result = (first + second) / (n - 1.0);
    result as i64
}

#[cfg(test)]
mod tests {
    // test the update variance function
    #[test]
    fn test_update_variance() {
        let old_mean = 347;
        let new_mean = 356;
        let old_variance = 0;
        let new_value = 365;
        let n = 2; // number of values before adding new_value

        let updated_variance = update_variance(old_mean, new_mean, old_variance, new_value, n);
        assert_eq!(updated_variance, 162);

        let new_value = 70;
        let old_mean = 55;
        let new_mean = 60;
        let old_variance = 50;
        let n = 3;
        let updated_variance = update_variance(old_mean, new_mean, old_variance, new_value, n);
        assert_eq!(updated_variance, 100);

        let new_value = 60;
        let old_mean = 50;
        let new_mean = 55;
        let old_variance = 0;
        let n = 2;
        let updated_variance = update_variance(old_mean, new_mean, old_variance, new_value, n);
        assert_eq!(updated_variance, 50);
    }
}
