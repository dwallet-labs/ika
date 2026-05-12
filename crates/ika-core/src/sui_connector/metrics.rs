// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use prometheus::{
    Histogram, IntGauge, IntGaugeVec, Registry, register_histogram_with_registry,
    register_int_gauge_vec_with_registry, register_int_gauge_with_registry,
};
use std::sync::Arc;

#[allow(unused)]
const FINE_GRAINED_LATENCY_SEC_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.6, 0.7, 0.8, 0.9,
    1.0, 1.2, 1.4, 1.6, 1.8, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0, 6.0, 6.5, 7.0, 7.5, 8.0, 8.5, 9.0, 9.5,
    10., 15., 20., 25., 30., 35., 40., 45., 50., 60., 70., 80., 90., 100., 120., 140., 160., 180.,
    200., 250., 300., 350., 400.,
];

#[derive(Clone, Debug)]
pub struct SuiConnectorMetrics {
    pub last_synced_sui_checkpoints: IntGaugeVec,

    pub gas_coin_balance: IntGauge,

    /// Sequence number of the next dwallet checkpoint to write to Sui.
    pub(crate) dwallet_checkpoint_sequence: IntGauge,

    /// Sequence number of the last dwallet checkpoint successfully written to Sui.
    pub(crate) last_written_dwallet_checkpoint_sequence: IntGauge,

    /// Total number of dwallet checkpoint write requests sent to Sui.
    pub(crate) dwallet_checkpoint_write_requests_total: IntGauge,

    /// Total number of successful dwallet checkpoint writes to Sui.
    pub(crate) dwallet_checkpoint_writes_success_total: IntGauge,

    /// Total number of failed dwallet checkpoint writes to Sui.
    pub(crate) dwallet_checkpoint_writes_failure_total: IntGauge,

    /// Sequence number of the next dwallet checkpoint to write to Sui.
    pub(crate) system_checkpoint_sequence: IntGauge,

    /// Sequence number of the last system checkpoint successfully written to Sui.
    pub(crate) last_written_system_checkpoint_sequence: IntGauge,

    /// Total number of system checkpoint write requests sent to Sui.
    pub(crate) system_checkpoint_write_requests_total: IntGauge,

    /// Total number of successful system checkpoint writes to Sui.
    pub(crate) system_checkpoint_writes_success_total: IntGauge,

    /// Total number of failed system checkpoint writes to Sui.
    pub(crate) system_checkpoint_writes_failure_total: IntGauge,

    /// Histogram of how long `submit_tx_to_sui` waits on the previous tx
    /// to be observable via `get_events_by_tx_digest`, before submitting the next one.
    /// Persistent long tails indicate the notifier is bottlenecked on RPC visibility,
    /// not on tx execution.
    pub(crate) notifier_tx_lock_wait_seconds: Histogram,

    /// Gauge (0 / 1) per epoch-switch step performed by the notifier within the current epoch.
    /// Labels: `step` in {`mid_epoch`, `network_encryption_key_mid_epoch_reconfiguration`,
    /// `calculate_protocols_pricing`, `lock_last_session`, `request_advance_epoch`}.
    /// Lets a dashboard show exactly which step the notifier got stuck on.
    pub(crate) epoch_switch_step_done: IntGaugeVec,

    /// Mirror of `received_end_of_publish` on chain.
    /// Labels: `object` in {`system`, `coordinator`}.
    /// Both must reach 1 before `process_request_advance_epoch` can be submitted.
    pub(crate) chain_received_end_of_publish: IntGaugeVec,

    /// `last_user_initiated_session_to_complete_in_current_epoch - completed_sessions_count`.
    /// Non-zero past mid-epoch ≡ user sessions are blocking epoch advance.
    pub(crate) chain_user_sessions_lag: IntGauge,

    /// Number of user sessions that are started but not yet completed
    /// (size of `sessions_manager.user_sessions_keeper.sessions`).
    pub(crate) chain_active_user_sessions_count: IntGauge,

    /// Number of system sessions that are started but not yet completed
    /// (size of `sessions_manager.system_sessions_keeper.sessions`).
    pub(crate) chain_active_system_sessions_count: IntGauge,

    /// `clock.timestamp_ms - (epoch_start + epoch_duration)`, clamped to >=0.
    /// > 0 means the epoch should already have advanced; sustained values indicate a deadlock.
    pub(crate) chain_epoch_overdue_seconds: IntGauge,

    /// Gauge (0 / 1) per condition in `sync_dwallet_end_of_publish`.
    /// Labels: `reason` in {`not_locked`, `user_sessions_lag`, `system_sessions_lag`,
    /// `next_committee_missing`, `network_keys_reconfig_lag`, `pricing_votes_open`}.
    /// 1 means that condition is currently *blocking* end-of-publish from firing.
    pub(crate) end_of_publish_blocked_reason: IntGaugeVec,
}

impl SuiConnectorMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let this = Self {
            last_synced_sui_checkpoints: register_int_gauge_vec_with_registry!(
                "sui_connector_last_synced_sui_checkpoints",
                "The latest sui checkpoints synced for each module",
                &["module_name"],
                registry,
            )
            .unwrap(),
            gas_coin_balance: register_int_gauge_with_registry!(
                "sui_connector_gas_coin_balance",
                "Current balance of gas coin, in mist",
                registry,
            )
            .unwrap(),

            dwallet_checkpoint_sequence: register_int_gauge_with_registry!(
                "sui_connector_dwallet_checkpoint_sequence",
                "Sequence number of the next dwallet checkpoint to write to Sui",
                registry,
            )
            .unwrap(),

            last_written_dwallet_checkpoint_sequence: register_int_gauge_with_registry!(
                "sui_connector_last_written_dwallet_checkpoint_sequence",
                "Sequence number of the last dwallet checkpoint successfully written to Sui",
                registry,
            )
            .unwrap(),

            dwallet_checkpoint_write_requests_total: register_int_gauge_with_registry!(
                "sui_connector_dwallet_checkpoint_write_requests_total",
                "Total number of dwallet checkpoint write requests sent to Sui",
                registry,
            )
            .unwrap(),

            dwallet_checkpoint_writes_success_total: register_int_gauge_with_registry!(
                "sui_connector_dwallet_checkpoint_writes_success_total",
                "Total number of successful dwallet checkpoint writes to Sui",
                registry,
            )
            .unwrap(),

            dwallet_checkpoint_writes_failure_total: register_int_gauge_with_registry!(
                "sui_connector_dwallet_checkpoint_writes_failure_total",
                "Total number of failed dwallet checkpoint writes to Sui",
                registry,
            )
            .unwrap(),
            system_checkpoint_writes_failure_total: register_int_gauge_with_registry!(
                "sui_connector_system_checkpoint_writes_failure_total",
                "Total number of failed system checkpoint writes to Sui",
                registry,
            )
            .unwrap(),
            system_checkpoint_writes_success_total: register_int_gauge_with_registry!(
                "sui_connector_system_checkpoint_writes_success_total",
                "Total number of successful system checkpoint writes to Sui",
                registry,
            )
            .unwrap(),
            system_checkpoint_write_requests_total: register_int_gauge_with_registry!(
                "sui_connector_system_checkpoint_write_requests_total",
                "Total number of system checkpoint write requests sent to Sui",
                registry,
            )
            .unwrap(),
            system_checkpoint_sequence: register_int_gauge_with_registry!(
                "sui_connector_system_checkpoint_sequence",
                "Sequence number of the next system checkpoint to write to Sui",
                registry,
            )
            .unwrap(),
            last_written_system_checkpoint_sequence: register_int_gauge_with_registry!(
                "sui_connector_last_written_system_checkpoint_sequence",
                "Sequence number of the last system checkpoint successfully written to Sui",
                registry,
            )
            .unwrap(),
            notifier_tx_lock_wait_seconds: register_histogram_with_registry!(
                "sui_connector_notifier_tx_lock_wait_seconds",
                "Seconds spent in submit_tx_to_sui waiting for the previous tx digest to be observable",
                vec![
                    0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0, 300.0, 600.0,
                    1800.0, 3600.0,
                ],
                registry,
            )
            .unwrap(),
            epoch_switch_step_done: register_int_gauge_vec_with_registry!(
                "sui_connector_epoch_switch_step_done",
                "Per-step gauge (0/1) for epoch-switch progress within the current epoch",
                &["step"],
                registry,
            )
            .unwrap(),
            chain_received_end_of_publish: register_int_gauge_vec_with_registry!(
                "sui_connector_chain_received_end_of_publish",
                "Mirror of received_end_of_publish on chain, one gauge per object",
                &["object"],
                registry,
            )
            .unwrap(),
            chain_user_sessions_lag: register_int_gauge_with_registry!(
                "sui_connector_chain_user_sessions_lag",
                "last_user_initiated_session_to_complete_in_current_epoch minus completed user sessions count",
                registry,
            )
            .unwrap(),
            chain_active_user_sessions_count: register_int_gauge_with_registry!(
                "sui_connector_chain_active_user_sessions_count",
                "Number of user sessions currently started but not yet completed on chain",
                registry,
            )
            .unwrap(),
            chain_active_system_sessions_count: register_int_gauge_with_registry!(
                "sui_connector_chain_active_system_sessions_count",
                "Number of system sessions currently started but not yet completed on chain",
                registry,
            )
            .unwrap(),
            chain_epoch_overdue_seconds: register_int_gauge_with_registry!(
                "sui_connector_chain_epoch_overdue_seconds",
                "Seconds elapsed past the planned end of the current epoch (clamped to >=0)",
                registry,
            )
            .unwrap(),
            end_of_publish_blocked_reason: register_int_gauge_vec_with_registry!(
                "sui_connector_end_of_publish_blocked_reason",
                "Per-condition gauge (0/1) indicating which gating condition in sync_dwallet_end_of_publish is currently false",
                &["reason"],
                registry,
            )
            .unwrap(),
        };
        Arc::new(this)
    }

    pub fn new_for_testing() -> Arc<Self> {
        let registry = Registry::new();
        Self::new(&registry)
    }
}
