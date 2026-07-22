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
use ika_types::messages_dwallet_mpc::SessionType;
use prometheus::{
    GaugeVec, Histogram, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Registry,
    register_gauge_vec_with_registry, register_histogram_vec_with_registry,
    register_histogram_with_registry, register_int_counter_vec_with_registry,
    register_int_gauge_vec_with_registry, register_int_gauge_with_registry,
};
use std::sync::Arc;
use std::time::Duration;

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
    /// A genuine counter (monotonic, inc-only); the legacy `_count` name
    /// predates the counter/`_total` suffix convention and is kept so
    /// existing dashboards keep working.
    session_start_count: IntCounterVec,

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

    /// Internal presign pool size per (curve, signature_algorithm, key_role).
    ///
    /// The pool is keyed by `(signature_algorithm, network_key_id)`; to keep
    /// label cardinality bounded the network key is reduced to a fixed
    /// `key_role` enum — `network_owned_address_signing` for the key serving
    /// network-owned-address signing, `other` for the rest (last-write-wins
    /// across multiple non-NOA keys, which number at most a handful).
    /// Pool exhaustion (0 sustained) stalls NOA signing and global presign
    /// serving.
    pub(crate) internal_presign_pool_size: IntGaugeVec,

    /// Number of consensus-agreed global presign requests waiting in the
    /// service queue because the internal pool had no presign to serve
    /// them — the direct pool-exhausted-wait signal users feel as latency.
    pub(crate) global_presign_requests_waiting: IntGauge,

    /// Global presign requests served from the internal pool, by
    /// signature_algorithm — pairs with the pool-size gauge so a dashboard
    /// can compute serve rate vs top-up rate and predict exhaustion.
    pub(crate) global_presigns_served_total: IntCounterVec,

    /// Duration of each network-key instantiation sub-call (per-curve
    /// protocol/decryption-share public parameters + NOA DKG outputs), for
    /// both the network-DKG and reconfiguration instantiation paths.
    /// Trends the dominant epoch-boundary cost across epochs/releases.
    pub(crate) network_key_instantiation_sub_call_duration_seconds: HistogramVec,

    /// Number of network-key instantiations currently in flight on the
    /// rayon pool.
    pub(crate) network_key_instantiations_in_flight: IntGauge,

    /// Version (2 or 3) of the canonical network DKG output this validator most
    /// recently mirrored into the off-chain handoff. Migrates 2 -> 3 once, when
    /// a deployed key's cert-pinned reconfiguration output becomes V3 (protocol
    /// v4) and the validator reconstructs the full V3 output. `0` until the
    /// first off-chain instantiation. (With one network key this reflects that
    /// key; with several it reflects the most recently instantiated.)
    pub(crate) network_encryption_key_canonical_dkg_output_version: IntGauge,

    /// Version of the latest network-key reconfiguration output installed on
    /// this validator: 3 = pre-aggregation, 4 = aggregated (the protocol-v5
    /// format flip), 0 until the first reconfiguration output is installed.
    /// (With one network key this reflects that key; with several it reflects
    /// the most recently instantiated.)
    pub(crate) network_encryption_key_latest_reconfiguration_output_version: IntGauge,

    /// Network-key instantiation failures by reason (`channel_closed`,
    /// `epoch_mismatch`, `decrypt_failed`, `instantiate_failed`). Note
    /// `decrypt_failed` is an expected transient for recently-joined
    /// validators — tune alerts per reason.
    pub(crate) network_key_instantiation_failures_total: IntCounterVec,

    /// Number of prior-handoff-cert `ValidatorMpcData` blobs (∩ current
    /// committee) missing from the local perpetual store while the manager
    /// sources the current epoch's validator MPC key bundle. Non-zero means
    /// key ingestion is deferred and the peer-blob fetcher's prior-cert
    /// repair is fetching the missing blobs; 0 once the bundle assembles.
    /// Sustained non-zero = the wedge of issue #1881 (no advances, every
    /// session deferred) — previously visible only in logs.
    pub(crate) prior_cert_blobs_missing: IntGauge,

    /// Number of distinct authorities this validator has recorded as malicious
    /// in the current epoch (quorum-agreed; see
    /// `DWalletMPCManager::record_malicious_actors`). A scrapable signal that
    /// detection fired — used by the cross-binary malicious-detection test to
    /// assert exclusion programmatically instead of grepping logs.
    pub(crate) malicious_actors_count: IntGauge,

    /// Number of sessions still non-terminal on this validator, grouped by
    /// protocol name. Completed protocols are exported with zero while their
    /// session remains tracked, distinguishing a clean zero from a missing
    /// observation.
    pub(crate) protocol_sessions_pending: IntGaugeVec,

    /// Per-authority session outputs observed through consensus. The digest is
    /// over canonical BCS output bytes and excludes the sender/malicious
    /// envelope. Labels identify the protocol and concrete session, allowing
    /// targeted compatibility tests without protocol-specific instrumentation.
    pub(crate) session_output_info: IntGaugeVec,

    /// Malicious-actor count carried in each authority's session output report.
    pub(crate) session_reported_malicious_actors: IntGaugeVec,

    /// Whether each authority's session output report was rejected
    /// (0 = canonical output, 1 = rejected output).
    pub(crate) session_output_rejected: IntGaugeVec,

    /// A locally computed network-key reconfiguration output that returned
    /// after the session completed via the peers' quorum, so production
    /// discarded it without submission. The `output_digest` and
    /// `quorum_output_digest` labels are both over RAW output bytes (before
    /// any consensus envelope) — comparable with each other but NOT with
    /// `session_output_info`'s envelope digests. Label equality proves the
    /// discarded local bytes match the quorum-agreed output.
    pub(crate) session_late_output_info: IntGaugeVec,

    /// Malicious-actor count reported by the discarded late local computation
    /// recorded in `session_late_output_info`.
    pub(crate) session_late_output_malicious_actors: IntGaugeVec,

    /// Privacy-safe anomaly snapshots emitted to the validator's local log sink.
    /// Labels are fixed enums: `anomaly_kind`, `session_type` (or `unknown` when
    /// service termination has no source session), and `severity`.
    pub(crate) anomaly_snapshots_total: IntCounterVec,

    /// Expected completion races: the session completed via the peers' output
    /// quorum before this validator's own output returned through consensus,
    /// while its local computation was still running, or before that
    /// computation's late result arrived. This is how threshold cryptography
    /// behaves for any validator outside the fastest two-thirds of a session,
    /// so these are counted here — NOT in the anomaly taxonomy — to keep
    /// `anomaly_snapshots_total` meaningful. Labels: `race` (fixed condition
    /// strings), `session_type`.
    pub(crate) completion_races_total: IntCounterVec,

    /// Sessions created from peer artifacts arriving through consensus (a
    /// stray message/output before the request, or a completion replayed at
    /// restart) rather than from a locally processed session request. A
    /// bounded burst at restart is healthy recovery; a stream still climbing
    /// long after restart while `advance_completions` stays flat is a
    /// validator that is not participating at all (the mid-epoch-restart
    /// wedge class). Incremented at creation; a later upgrade to
    /// local-request origin does not retract it. Labels: `session_type`.
    pub(crate) sessions_reconstructed_total: IntCounterVec,

    /// Individual reasons present in emitted anomaly snapshots. One snapshot can
    /// increment several triggers. Trigger values are compile-time static strings.
    pub(crate) anomaly_triggers_total: IntCounterVec,

    /// Anomaly snapshots intentionally not emitted after a bounded diagnostic
    /// store reaches capacity. Labels: fixed `reason` values only.
    pub(crate) anomaly_snapshots_dropped_total: IntCounterVec,

    /// Histogram-by-bucket of how long each currently-Active session has been
    /// tracked for. Labels: `session_type` (`user` / `system` /
    /// `internal_presign` / `noa_sign`), `age_bucket` (`<30s`, `<5m`, `<30m`,
    /// `<2h`, `>=2h`). A non-zero `>=2h` bucket for user sessions is the
    /// smoking gun of an MPC deadlock.
    pub(crate) active_sessions_by_age: IntGaugeVec,

    /// Counts of sessions currently tracked by the manager grouped by status.
    /// Labels: `state` in {`active`, `waiting_for_session_request`,
    /// `computation_completed`, `completed`, `failed`}.
    pub(crate) session_state_count: IntGaugeVec,

    /// Counter for the outcome of every per-tick readiness check
    /// (`generate_protocol_cryptographic_data`) on an advanceable session.
    /// Labels: `protocol`, `result` in {`ready`, `not_ready`, `err`}.
    /// A growing `not_ready` or `err` count for a specific protocol explains
    /// why `ika_dwallet_mpc_advance_completions` is stuck.
    pub(crate) ready_to_advance_result_total: IntCounterVec,

    /// Counter for `generate_protocol_cryptographic_data` errors (the session
    /// is skipped for the tick and retried). Labels: `protocol`, `error`
    /// (a stable short string for the error class).
    pub(crate) protocol_data_generation_errors_total: IntCounterVec,

    /// Counter for every call into `submit_failed_session` in
    /// dwallet_mpc_service. Labels: `protocol`, `reason` (the error class,
    /// e.g. `mpc_error`, `mpc_session_error`).
    pub(crate) sessions_rejected_total: IntCounterVec,

    /// Size of each parking lot in `DWalletMPCManager.requests_pending_for_network_key`.
    /// Labels: `network_encryption_key_id`. Sustained non-zero values indicate the validator
    /// is missing the key data needed to process incoming sessions.
    pub(crate) requests_pending_for_network_key: IntGaugeVec,

    /// Size of `DWalletMPCManager.requests_pending_for_next_active_committee`.
    pub(crate) requests_pending_for_next_active_committee: IntGauge,

    /// Size of `DWalletMPCManager.requests_pending_for_frozen_mpc_data` — network
    /// DKG / reconfiguration requests parked on the off-chain mpc_data freeze
    /// gate. A session invisibly parked here is exactly the class of wedge the
    /// pending-request gauges target.
    pub(crate) requests_pending_for_frozen_mpc_data: IntGauge,

    /// Size of `DWalletMPCManager.internal_presign_requests_pending_for_network_key_data`
    /// — internal presign sessions parked because the target network key's data
    /// (typically the off-chain VSS validator key set at epoch entry) isn't
    /// locally available yet. Transient non-zero values at epoch entry are
    /// expected; sustained ones mean the key data never arrived.
    pub(crate) internal_presign_requests_pending_for_network_key_data: IntGauge,

    /// One series per user session currently tracked in `DWalletMPCManager.sessions`,
    /// labeled by `session_seq` (as a string) and `state`. Value is 1 for the
    /// state the session is currently in, 0 for the other four states. Sessions that leave
    /// the tracking map have all five state series flipped to 0 (one final emission).
    ///
    /// Cardinality is bounded by `max_active_sessions_buffer` on chain (~100 in practice),
    /// times 5 states. Lets an operator answer "is session 6713 on this validator?" from
    /// `curl /metrics | grep session_seq=\"6713\"`.
    pub(crate) user_session_state: IntGaugeVec,

    /// Per-user-session: earliest consensus round (since this process started) at which any
    /// output for this session arrived. `-1` until the first output. Label: `session_seq`.
    pub(crate) user_session_first_output_consensus_round: IntGaugeVec,

    /// Per-user-session: consensus round at which *this* validator's own output looped back.
    /// `-1` if this validator hasn't submitted an output. Label: `session_seq`.
    pub(crate) user_session_self_output_consensus_round: IntGaugeVec,

    /// Per-user-session: consensus round at which 2/3 quorum was first observed.
    /// `-1` if quorum hasn't been observed in this process's lifetime. A stuck session in
    /// `computation_completed` with this gauge at `-1` is the exact symptom of "submitted,
    /// no quorum". Label: `session_seq`.
    pub(crate) user_session_quorum_consensus_round: IntGaugeVec,

    /// Per-user-session: count of distinct authorities from which we've received an output.
    /// Compare to the committee's validity-threshold to see if a session is starved for
    /// participation. Label: `session_seq`.
    pub(crate) user_session_distinct_output_authorities: IntGaugeVec,

    /// Per-user-session: -1 = haven't submitted, 0 = submitted success, 1 = submitted rejected.
    /// Label: `session_seq`.
    pub(crate) user_session_local_output_rejected: IntGaugeVec,

    /// Per (session, authority): 1 if we've received an output for this session from this
    /// authority during the current process lifetime, 0 otherwise. Authority label uses the
    /// concise (4-byte prefix) form, the same one used in tracing logs.
    /// Cardinality: ~max_active_sessions_buffer × committee_size (≤ ~15k series).
    /// Answers "which validators failed to submit for session N?" without log access.
    pub(crate) user_session_output_received_from: IntGaugeVec,

    /// Per session: number of *distinct* output digests observed this lifetime. `1` ⇒ all
    /// submitters agreed on a single value (typical happy path even pre-quorum). `>1` ⇒ a
    /// vote split — different validators are submitting different outputs. Compare with the
    /// `_distinct_output_authorities` count and quorum_threshold to see if a split has
    /// stalled quorum. Label: `session_seq`.
    pub(crate) user_session_distinct_output_digests: IntGaugeVec,

    /// Mirror of `DWalletMPCService.end_of_publish` — 0 or 1. Once it flips to 1, the service
    /// stops persisting new pending dwallet checkpoints, silently dropping any quorum-reached
    /// output that arrives after. A value of 1 paired with a chain-side
    /// `received_end_of_publish == 0` means: this validator declared end-of-publish locally
    /// but the network never confirmed it — checkpoint messages are being eaten.
    pub(crate) service_end_of_publish_local: IntGauge,

    /// Per-network-encryption-key: the `epoch` of the loaded public data on this validator.
    /// If it doesn't match the current epoch, the validator will silently skip sessions
    /// targeting this key. Labels: `network_encryption_key_id`.
    pub(crate) network_key_loaded_epoch: IntGaugeVec,

    /// How many user sessions on this validator are stuck in the
    /// `self_output set && quorum_consensus_round = None` state — i.e., we submitted but
    /// nobody (us included) has seen quorum. Per-tick gauge.
    pub(crate) sessions_with_self_output_no_quorum: IntGauge,

    /// Per-completion: number of consensus rounds elapsed between this validator submitting
    /// its own output and 2/3 quorum being reached. Wide tails ≡ slow consensus, lots of
    /// retries. Observed once per session at the moment quorum is reached.
    pub(crate) self_output_to_quorum_consensus_rounds: Histogram,
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
            session_start_count: register_int_counter_vec_with_registry!(
                "ika_dwallet_mpc_session_start_count",
                "Number of MPC protocol sessions started",
                &protocol_metric_labels,
                registry
            )
            .unwrap(),
            received_requests_start_count: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_received_requests_start_count",
                "Number of received requests",
                &protocol_metric_labels,
                registry
            )
            .unwrap(),
            advance_mpc_calls: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_advance_calls",
                "Number of advance calls",
                &round_metric_labels,
                registry
            )
            .unwrap(),
            native_calls: register_int_gauge_vec_with_registry!(
                "ika_dwallet_native_calls",
                "Number of native session calls",
                &protocol_metric_labels,
                registry
            )
            .unwrap(),
            computation_duration_variance: register_gauge_vec_with_registry!(
                "ika_dwallet_mpc_computation_duration_variance",
                "Variance of the duration of MPC computations in milliseconds",
                &round_metric_labels,
                registry
            )
            .unwrap(),
            computation_duration_avg: register_gauge_vec_with_registry!(
                "ika_dwallet_mpc_computation_duration_avg",
                "Average duration of MPC computations in milliseconds",
                &round_metric_labels,
                registry
            )
            .unwrap(),
            advance_completions: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_advance_completions",
                "Number of advance completions",
                &round_metric_labels,
                registry
            )
            .unwrap(),
            native_completions: register_int_gauge_vec_with_registry!(
                "ika_dwallet_native_completions",
                "Number of native sessions completions",
                &protocol_metric_labels,
                registry
            )
            .unwrap(),
            completions_count: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_completions_count",
                "Number of completions",
                &protocol_metric_labels,
                registry
            )
            .unwrap(),
            last_completion_duration: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_last_completion_duration",
                "Duration of the last completion in milliseconds",
                &round_metric_labels,
                registry
            )
            .unwrap(),
            number_of_unexpected_sign_sessions: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_number_of_unexpected_sign_sessions",
                "Number of unexpected sign sessions",
                registry
            )
            .unwrap(),
            number_of_expected_sign_sessions: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_number_of_expected_sign_sessions",
                "Number of expected sign sessions",
                registry
            )
            .unwrap(),
            last_process_mpc_consensus_round: register_int_gauge_with_registry!(
                "ika_last_process_mpc_consensus_round",
                "Last process mpc consensus round",
                registry
            )
            .unwrap(),
            internal_presign_pool_size: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_internal_presign_pool_size",
                "Internal presign pool size per (curve, signature_algorithm, key_role)",
                &["curve", "signature_algorithm", "key_role"],
                registry
            )
            .unwrap(),
            global_presign_requests_waiting: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_global_presign_requests_waiting",
                "Global presign requests waiting because the internal pool is empty",
                registry
            )
            .unwrap(),
            global_presigns_served_total: register_int_counter_vec_with_registry!(
                "ika_dwallet_mpc_global_presigns_served_total",
                "Global presign requests served from the internal pool",
                &["signature_algorithm"],
                registry
            )
            .unwrap(),
            network_key_instantiation_sub_call_duration_seconds:
                register_histogram_vec_with_registry!(
                    "ika_dwallet_mpc_network_key_instantiation_sub_call_duration_seconds",
                    "Duration of each network-key instantiation sub-call",
                    &["sub_call"],
                    vec![
                        0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0
                    ],
                    registry
                )
                .unwrap(),
            network_key_instantiations_in_flight: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_network_key_instantiations_in_flight",
                "Network-key instantiations currently in flight on the rayon pool",
                registry
            )
            .unwrap(),
            network_encryption_key_canonical_dkg_output_version: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_network_encryption_key_canonical_dkg_output_version",
                "Version (2 or 3 or 4) of the canonical network DKG output mirrored into the off-chain handoff; migrates at the anchor migration (3 pre-aggregation, 4 aggregated)",
                registry
            )
            .unwrap(),
            network_encryption_key_latest_reconfiguration_output_version: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_network_encryption_key_latest_reconfiguration_output_version",
                "Version of the latest installed network-key reconfiguration output (3 pre-aggregation, 4 aggregated, 0 none yet)",
                registry
            )
            .unwrap(),
            network_key_instantiation_failures_total: register_int_counter_vec_with_registry!(
                "ika_dwallet_mpc_network_key_instantiation_failures_total",
                "Network-key instantiation failures by reason",
                &["reason"],
                registry
            )
            .unwrap(),
            prior_cert_blobs_missing: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_prior_cert_blobs_missing",
                "Prior-handoff-cert mpc_data blobs missing from the local perpetual store while sourcing the current epoch's validator MPC keys (non-zero = key ingestion deferred; sustained non-zero = wedged ingest)",
                registry
            )
            .unwrap(),
            malicious_actors_count: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_malicious_actors_count",
                "Number of distinct authorities recorded as malicious this epoch",
                registry
            )
            .unwrap(),
            protocol_sessions_pending: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_protocol_sessions_pending",
                "Sessions still non-terminal on this validator, grouped by protocol",
                &["protocol_name"],
                registry,
            )
            .unwrap(),
            session_output_info: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_session_output_info",
                "Per-authority canonical session output digest observed through consensus",
                &["protocol_name", "session_id", "authority", "output_digest"],
                registry,
            )
            .unwrap(),
            session_reported_malicious_actors: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_session_reported_malicious_actors",
                "Malicious-actor count carried in each authority's session output report",
                &["protocol_name", "session_id", "authority"],
                registry,
            )
            .unwrap(),
            session_output_rejected: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_session_output_rejected",
                "Whether each authority's session output report was rejected",
                &["protocol_name", "session_id", "authority"],
                registry,
            )
            .unwrap(),
            session_late_output_info: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_session_late_output_info",
                "Raw-bytes digest of a locally computed session output discarded after the quorum completed the session, next to the quorum output's raw-bytes digest",
                &[
                    "protocol_name",
                    "session_id",
                    "authority",
                    "output_digest",
                    "quorum_output_digest"
                ],
                registry,
            )
            .unwrap(),
            session_late_output_malicious_actors: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_session_late_output_malicious_actors",
                "Malicious-actor count reported by the discarded late local computation",
                &["protocol_name", "session_id", "authority"],
                registry,
            )
            .unwrap(),
            anomaly_snapshots_total: register_int_counter_vec_with_registry!(
                "ika_dwallet_mpc_anomaly_snapshots_total",
                "Privacy-safe MPC anomaly snapshots emitted to the local log sink",
                &["anomaly_kind", "session_type", "severity"],
                registry,
            )
            .unwrap(),
            anomaly_triggers_total: register_int_counter_vec_with_registry!(
                "ika_dwallet_mpc_anomaly_triggers_total",
                "Trigger conditions included in emitted privacy-safe MPC anomaly snapshots",
                &["trigger", "session_type"],
                registry,
            )
            .unwrap(),
            completion_races_total: register_int_counter_vec_with_registry!(
                "ika_dwallet_mpc_completion_races_total",
                "Expected races where a session completed via the peers' output quorum before the local validator caught up",
                &["race", "session_type"],
                registry,
            )
            .unwrap(),
            sessions_reconstructed_total: register_int_counter_vec_with_registry!(
                "ika_dwallet_mpc_sessions_reconstructed_total",
                "Sessions created from peer artifacts arriving through consensus instead of a locally processed session request",
                &["session_type"],
                registry,
            )
            .unwrap(),
            anomaly_snapshots_dropped_total: register_int_counter_vec_with_registry!(
                "ika_dwallet_mpc_anomaly_snapshots_dropped_total",
                "Privacy-safe MPC anomaly snapshots not emitted due to a bounded diagnostic capacity",
                &["reason"],
                registry,
            )
            .unwrap(),
            active_sessions_by_age: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_active_sessions_by_age",
                "Active session count by session type and age bucket",
                &["session_type", "age_bucket"],
                registry,
            )
            .unwrap(),
            session_state_count: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_session_state_count",
                "Number of sessions currently tracked, grouped by status",
                &["state"],
                registry,
            )
            .unwrap(),
            ready_to_advance_result_total: register_int_counter_vec_with_registry!(
                "ika_dwallet_mpc_ready_to_advance_result_total",
                "Counts of ready-to-advance readiness-check outcomes per protocol",
                &["protocol", "result"],
                registry,
            )
            .unwrap(),
            protocol_data_generation_errors_total: register_int_counter_vec_with_registry!(
                "ika_dwallet_mpc_protocol_data_generation_errors_total",
                "Count of generate_protocol_cryptographic_data errors, by protocol and error class",
                &["protocol", "error"],
                registry,
            )
            .unwrap(),
            sessions_rejected_total: register_int_counter_vec_with_registry!(
                "ika_dwallet_mpc_sessions_rejected_total",
                "Count of submit_failed_session calls, by protocol and reason",
                &["protocol", "reason"],
                registry,
            )
            .unwrap(),
            requests_pending_for_network_key: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_requests_pending_for_network_key",
                "Per-key pending session-request parking lot size",
                &["network_encryption_key_id"],
                registry,
            )
            .unwrap(),
            requests_pending_for_next_active_committee: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_requests_pending_for_next_active_committee",
                "Sessions parked waiting for the next active committee",
                registry,
            )
            .unwrap(),
            requests_pending_for_frozen_mpc_data: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_requests_pending_for_frozen_mpc_data",
                "Sessions parked waiting for the off-chain mpc_data freeze gate",
                registry,
            )
            .unwrap(),
            internal_presign_requests_pending_for_network_key_data: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_internal_presign_requests_pending_for_network_key_data",
                "Internal presign sessions parked waiting for their network key's data to be locally available",
                registry,
            )
            .unwrap(),
            user_session_state: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_user_session_state",
                "1 if user session is in this state on this validator, 0 otherwise (one series per (seq, state))",
                &["session_seq", "state"],
                registry,
            )
            .unwrap(),
            user_session_first_output_consensus_round: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_user_session_first_output_consensus_round",
                "Earliest consensus round (this process lifetime) at which any output for the session arrived. -1 if none.",
                &["session_seq"],
                registry,
            )
            .unwrap(),
            user_session_self_output_consensus_round: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_user_session_self_output_consensus_round",
                "Consensus round at which this validator's own output for the session looped back. -1 if not yet.",
                &["session_seq"],
                registry,
            )
            .unwrap(),
            user_session_quorum_consensus_round: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_user_session_quorum_consensus_round",
                "Consensus round at which quorum was first observed on the session output. -1 if not in this lifetime.",
                &["session_seq"],
                registry,
            )
            .unwrap(),
            user_session_distinct_output_authorities: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_user_session_distinct_output_authorities",
                "Number of distinct authorities that submitted an output for the session.",
                &["session_seq"],
                registry,
            )
            .unwrap(),
            user_session_local_output_rejected: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_user_session_local_output_rejected",
                "-1 if this validator hasn't submitted an output, 0 if submitted success, 1 if submitted rejected.",
                &["session_seq"],
                registry,
            )
            .unwrap(),
            user_session_output_received_from: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_user_session_output_received_from",
                "1 if we've received an output for this (session, authority) this lifetime, 0 otherwise.",
                &["session_seq", "authority"],
                registry,
            )
            .unwrap(),
            user_session_distinct_output_digests: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_user_session_distinct_output_digests",
                "Number of distinct output digests observed for the session this lifetime. >1 = vote split.",
                &["session_seq"],
                registry,
            )
            .unwrap(),
            service_end_of_publish_local: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_service_end_of_publish_local",
                "1 if DWalletMPCService.end_of_publish has been set this epoch; checkpoint messages after this are dropped",
                registry,
            )
            .unwrap(),
            network_key_loaded_epoch: register_int_gauge_vec_with_registry!(
                "ika_dwallet_mpc_network_key_loaded_epoch",
                "Loaded epoch of the network encryption key public data per key_id",
                &["network_encryption_key_id"],
                registry,
            )
            .unwrap(),
            sessions_with_self_output_no_quorum: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_sessions_with_self_output_no_quorum",
                "User sessions where this validator submitted an output but no quorum has been observed.",
                registry,
            )
            .unwrap(),
            self_output_to_quorum_consensus_rounds: register_histogram_with_registry!(
                "ika_dwallet_mpc_self_output_to_quorum_consensus_rounds",
                "Consensus rounds elapsed between this validator submitting an output and quorum being reached on it.",
                vec![
                    0.0, 1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0
                ],
                registry,
            )
            .unwrap(),
        })
    }

    /// Clears every per-session-sequence-number series. Called at
    /// `DWalletMPCManager` construction: the manager (and its
    /// `previously_emitted_user_session_seqs` diff set) is per-epoch, so the
    /// cross-tick diff zeroing can never clear series emitted by the previous
    /// epoch's manager — without this reset the final tick's series from
    /// epoch N would linger as stale values for the whole of epoch N+1.
    pub(crate) fn reset_per_session_series(&self) {
        self.user_session_state.reset();
        self.user_session_first_output_consensus_round.reset();
        self.user_session_self_output_consensus_round.reset();
        self.user_session_quorum_consensus_round.reset();
        self.user_session_distinct_output_authorities.reset();
        self.user_session_local_output_rejected.reset();
        self.user_session_output_received_from.reset();
        self.user_session_distinct_output_digests.reset();
        self.protocol_sessions_pending.reset();
        self.session_output_info.reset();
        self.session_reported_malicious_actors.reset();
        self.session_output_rejected.reset();
        self.session_late_output_info.reset();
        self.session_late_output_malicious_actors.reset();
    }
}

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

/// Age buckets used by `active_sessions_by_age`. Order matters: sessions are
/// bucketed into the FIRST bucket whose threshold exceeds their age. Keep
/// label strings stable — alerts depend on them.
pub(crate) const AGE_BUCKETS: &[(&str, Duration)] = &[
    ("<30s", Duration::from_secs(30)),
    ("<5m", Duration::from_secs(300)),
    ("<30m", Duration::from_secs(1800)),
    ("<2h", Duration::from_secs(7200)),
];
/// Open-ended bucket label for ages >= the last `AGE_BUCKETS` threshold.
pub(crate) const AGE_BUCKET_OVERFLOW: &str = ">=2h";

/// Stable label strings for the `state` label of `session_state_count` and
/// `user_session_state`.
pub(crate) const SESSION_STATE_ACTIVE: &str = "active";
pub(crate) const SESSION_STATE_WAITING_FOR_REQUEST: &str = "waiting_for_session_request";
pub(crate) const SESSION_STATE_COMPUTATION_COMPLETED: &str = "computation_completed";
pub(crate) const SESSION_STATE_COMPLETED: &str = "completed";
pub(crate) const SESSION_STATE_FAILED: &str = "failed";
pub(crate) const ALL_SESSION_STATES: &[&str] = &[
    SESSION_STATE_ACTIVE,
    SESSION_STATE_WAITING_FOR_REQUEST,
    SESSION_STATE_COMPUTATION_COMPLETED,
    SESSION_STATE_COMPLETED,
    SESSION_STATE_FAILED,
];

/// Stable label strings for `ready_to_advance_result_total`.
pub(crate) const READY_RESULT_READY: &str = "ready";
pub(crate) const READY_RESULT_NOT_READY: &str = "not_ready";
pub(crate) const READY_RESULT_ERR: &str = "err";

/// Stable label strings for the `session_type` label.
pub(crate) const SESSION_TYPE_USER: &str = "user";
pub(crate) const SESSION_TYPE_SYSTEM: &str = "system";
pub(crate) const SESSION_TYPE_INTERNAL_PRESIGN: &str = "internal_presign";
pub(crate) const SESSION_TYPE_NOA_SIGN: &str = "noa_sign";
pub(crate) const ALL_SESSION_TYPES: &[&str] = &[
    SESSION_TYPE_USER,
    SESSION_TYPE_SYSTEM,
    SESSION_TYPE_INTERNAL_PRESIGN,
    SESSION_TYPE_NOA_SIGN,
];

pub(crate) fn session_type_label(session_type: SessionType) -> &'static str {
    match session_type {
        SessionType::User => SESSION_TYPE_USER,
        SessionType::System => SESSION_TYPE_SYSTEM,
        SessionType::InternalPresign => SESSION_TYPE_INTERNAL_PRESIGN,
        SessionType::NetworkOwnedAddressSign => SESSION_TYPE_NOA_SIGN,
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
