// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use prometheus::{
    IntCounter, IntGauge, IntGaugeVec, Registry, register_int_counter_with_registry,
    register_int_gauge_vec_with_registry, register_int_gauge_with_registry,
};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct SuiConnectorMetrics {
    /// Latest Sui checkpoint synced per module by the legacy (v≤3)
    /// event-listening task. Unused under v4 (OCS BagEventPump).
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

    /// Number of network keys whose off-chain overlay is currently
    /// missing a required output (DKG or reconfiguration). Expected to
    /// be transiently non-zero during convergence windows; alert on a
    /// committee validator stuck non-zero.
    pub(crate) network_key_overlay_incomplete: IntGauge,

    /// Total sync ticks on which the off-chain next-committee
    /// validator-mpc_data assembly was incomplete (benign retry while
    /// announcements/blobs converge; a stall shows as sustained growth).
    pub(crate) off_chain_assembly_incomplete_ticks_total: IntCounter,

    /// 1 while the off-chain assembly is PERMANENTLY incomplete (the
    /// freeze excluded every committee member — reconfiguration into the
    /// next epoch is wedged); cleared on the next successful assembly.
    pub(crate) off_chain_assembly_wedged: IntGauge,

    /// Gauge (0/1) per epoch-switch step performed by the notifier within the
    /// current epoch. Labels: `step` in {`mid_epoch`,
    /// `network_encryption_key_mid_epoch_reconfiguration`,
    /// `calculate_protocols_pricing`, `lock_last_session`,
    /// `request_advance_epoch`}. Lets a dashboard show exactly which step the
    /// notifier got stuck on.
    pub(crate) epoch_switch_step_done: IntGaugeVec,

    /// Mirror of `received_end_of_publish` on chain.
    /// Labels: `object` in {`system`, `coordinator`}.
    /// Both must reach 1 before `process_request_advance_epoch` can be submitted.
    pub(crate) chain_received_end_of_publish: IntGaugeVec,

    /// `last_user_initiated_session_to_complete_in_current_epoch - completed_sessions_count`.
    /// Non-zero past mid-epoch means user sessions are blocking epoch advance.
    /// Negative would indicate a chain bug, hence the signed gauge.
    pub(crate) chain_user_sessions_lag: IntGauge,

    /// Number of user sessions that are started but not yet completed
    /// (size of `sessions_manager.user_sessions_keeper.sessions`).
    pub(crate) chain_active_user_sessions_count: IntGauge,

    /// Number of system sessions that are started but not yet completed
    /// (size of `sessions_manager.system_sessions_keeper.sessions`).
    pub(crate) chain_active_system_sessions_count: IntGauge,

    /// `clock.timestamp_ms - (epoch_start + epoch_duration)`, clamped to >=0.
    /// > 0 means the epoch should already have advanced; sustained values
    /// > indicate a deadlock.
    pub(crate) chain_epoch_overdue_seconds: IntGauge,

    /// Gauge (0/1) per gating condition in `sync_dwallet_end_of_publish`.
    /// Labels: `reason` in {`not_locked`, `user_sessions_lag`,
    /// `system_sessions_lag`, `next_committee_missing`,
    /// `network_keys_reconfig_lag`, `noa_checkpoints_unfinalized`,
    /// `pricing_votes_open`, `checkpoint_writer_lag`}. 1 means that condition
    /// is currently *blocking* end-of-publish from firing.
    pub(crate) end_of_publish_blocked_reason: IntGaugeVec,

    /// `highest locally-certified dwallet checkpoint - coordinator's
    /// last_processed_checkpoint_sequence_number`. Positive means completions
    /// are certified locally but their checkpoints have not landed on Sui —
    /// the checkpoint writer (notifier) is behind. Sustained positive values
    /// while `user_sessions_lag` blocks the close mean the WRITER is the
    /// blocker, not the MPC pipeline. Negative means our local certified
    /// store trails the chain (local sync lag), which is a different problem.
    pub(crate) chain_dwallet_checkpoint_writer_lag: IntGauge,

    /// Number of uncompleted session events observed on chain on the most
    /// recent pull (legacy v≤3 poller) or bag-walk snapshot (v4 BagEventPump).
    /// Persistent non-zero means a session backlog (validators are missing
    /// things); drops to 0 once chain processes the responses.
    pub(crate) uncompleted_events_backlog: IntGauge,
}

impl SuiConnectorMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let this = Self {
            last_synced_sui_checkpoints: register_int_gauge_vec_with_registry!(
                "ika_sui_connector_last_synced_sui_checkpoints",
                "The latest sui checkpoints synced for each module",
                &["module_name"],
                registry,
            )
            .unwrap(),

            gas_coin_balance: register_int_gauge_with_registry!(
                "ika_sui_connector_gas_coin_balance",
                "Current balance of gas coin, in mist",
                registry,
            )
            .unwrap(),

            dwallet_checkpoint_sequence: register_int_gauge_with_registry!(
                "ika_sui_connector_dwallet_checkpoint_sequence",
                "Sequence number of the next dwallet checkpoint to write to Sui",
                registry,
            )
            .unwrap(),

            last_written_dwallet_checkpoint_sequence: register_int_gauge_with_registry!(
                "ika_sui_connector_last_written_dwallet_checkpoint_sequence",
                "Sequence number of the last dwallet checkpoint successfully written to Sui",
                registry,
            )
            .unwrap(),

            dwallet_checkpoint_write_requests_total: register_int_gauge_with_registry!(
                "ika_sui_connector_dwallet_checkpoint_write_requests_total",
                "Total number of dwallet checkpoint write requests sent to Sui",
                registry,
            )
            .unwrap(),

            dwallet_checkpoint_writes_success_total: register_int_gauge_with_registry!(
                "ika_sui_connector_dwallet_checkpoint_writes_success_total",
                "Total number of successful dwallet checkpoint writes to Sui",
                registry,
            )
            .unwrap(),

            dwallet_checkpoint_writes_failure_total: register_int_gauge_with_registry!(
                "ika_sui_connector_dwallet_checkpoint_writes_failure_total",
                "Total number of failed dwallet checkpoint writes to Sui",
                registry,
            )
            .unwrap(),
            system_checkpoint_writes_failure_total: register_int_gauge_with_registry!(
                "ika_sui_connector_system_checkpoint_writes_failure_total",
                "Total number of failed system checkpoint writes to Sui",
                registry,
            )
            .unwrap(),
            system_checkpoint_writes_success_total: register_int_gauge_with_registry!(
                "ika_sui_connector_system_checkpoint_writes_success_total",
                "Total number of successful system checkpoint writes to Sui",
                registry,
            )
            .unwrap(),
            system_checkpoint_write_requests_total: register_int_gauge_with_registry!(
                "ika_sui_connector_system_checkpoint_write_requests_total",
                "Total number of system checkpoint write requests sent to Sui",
                registry,
            )
            .unwrap(),
            system_checkpoint_sequence: register_int_gauge_with_registry!(
                "ika_sui_connector_system_checkpoint_sequence",
                "Sequence number of the next system checkpoint to write to Sui",
                registry,
            )
            .unwrap(),
            last_written_system_checkpoint_sequence: register_int_gauge_with_registry!(
                "ika_sui_connector_last_written_system_checkpoint_sequence",
                "Sequence number of the last system checkpoint successfully written to Sui",
                registry,
            )
            .unwrap(),
            network_key_overlay_incomplete: register_int_gauge_with_registry!(
                "ika_network_key_overlay_incomplete",
                "Number of network keys whose off-chain overlay is missing a required output",
                registry,
            )
            .unwrap(),
            off_chain_assembly_incomplete_ticks_total: register_int_counter_with_registry!(
                "ika_off_chain_assembly_incomplete_ticks_total",
                "Total sync ticks on which the off-chain validator-mpc_data assembly was incomplete",
                registry,
            )
            .unwrap(),
            off_chain_assembly_wedged: register_int_gauge_with_registry!(
                "ika_off_chain_assembly_wedged",
                "1 while the off-chain validator-mpc_data assembly is permanently incomplete",
                registry,
            )
            .unwrap(),
            epoch_switch_step_done: register_int_gauge_vec_with_registry!(
                "ika_sui_connector_epoch_switch_step_done",
                "Per-step gauge (0/1) for epoch-switch progress within the current epoch, re-derived from chain state each tick (restart-proof for all steps except request_advance_epoch)",
                &["step"],
                registry,
            )
            .unwrap(),
            chain_received_end_of_publish: register_int_gauge_vec_with_registry!(
                "ika_sui_connector_chain_received_end_of_publish",
                "Mirror of received_end_of_publish on chain, one gauge per object",
                &["object"],
                registry,
            )
            .unwrap(),
            chain_user_sessions_lag: register_int_gauge_with_registry!(
                "ika_sui_connector_chain_user_sessions_lag",
                "last_user_initiated_session_to_complete_in_current_epoch minus completed user sessions count",
                registry,
            )
            .unwrap(),
            chain_active_user_sessions_count: register_int_gauge_with_registry!(
                "ika_sui_connector_chain_active_user_sessions_count",
                "Number of user sessions currently started but not yet completed on chain",
                registry,
            )
            .unwrap(),
            chain_active_system_sessions_count: register_int_gauge_with_registry!(
                "ika_sui_connector_chain_active_system_sessions_count",
                "Number of system sessions currently started but not yet completed on chain",
                registry,
            )
            .unwrap(),
            chain_epoch_overdue_seconds: register_int_gauge_with_registry!(
                "ika_sui_connector_chain_epoch_overdue_seconds",
                "Seconds elapsed past the planned end of the current epoch (clamped to >=0)",
                registry,
            )
            .unwrap(),
            end_of_publish_blocked_reason: register_int_gauge_vec_with_registry!(
                "ika_sui_connector_end_of_publish_blocked_reason",
                "Per-condition gauge (0/1) indicating which gating condition in sync_dwallet_end_of_publish is currently blocking end-of-publish",
                &["reason"],
                registry,
            )
            .unwrap(),
            uncompleted_events_backlog: register_int_gauge_with_registry!(
                "ika_sui_connector_uncompleted_events_backlog",
                "Uncompleted session events observed on chain on the most recent pull",
                registry,
            )
            .unwrap(),
            chain_dwallet_checkpoint_writer_lag: register_int_gauge_with_registry!(
                "ika_sui_connector_chain_dwallet_checkpoint_writer_lag",
                "Highest locally-certified dwallet checkpoint minus the coordinator's \
                 last processed checkpoint sequence number; sustained positive values \
                 mean certified checkpoints are not landing on Sui (checkpoint writer \
                 stalled)",
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
