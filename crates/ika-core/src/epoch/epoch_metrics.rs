// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use prometheus::{
    IntCounterVec, IntGauge, Registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry,
};
use std::sync::Arc;

pub struct EpochMetrics {
    /// The current epoch ID. This is updated only when the AuthorityState finishes reconfiguration.
    pub current_epoch: IntGauge,

    /// Current voting right of the validator in the protocol. Updated at the start of epochs.
    pub current_voting_right: IntGauge,

    /// Total duration of the epoch. This is measured from when the current epoch store is opened,
    /// until the current epoch store is replaced with the next epoch store.
    pub epoch_total_duration: IntGauge,

    /// Number of checkpoints in the epoch.
    pub epoch_checkpoint_count: IntGauge,

    /// Number of transactions in the epoch.
    pub epoch_transaction_count: IntGauge,

    /// Total amount of computation rewards in the epoch.
    pub epoch_total_computation_reward: IntGauge,

    // An active validator reconfigures through the following steps:
    // 1. Halt validator (a.k.a. close epoch) and stop accepting user transaction certs.
    // 2. Finishes processing all pending certificates and then send EndOfPublish message.
    // 3. Stop accepting messages from consensus after seeing 2f+1 EndOfPublish messages.
    // 4. Creating the last checkpoint of the epoch by augmenting it with AdvanceEpoch transaction.
    // 5. CheckpointExecutor finishes executing the last checkpoint, and triggers reconfiguration.
    // 6. During reconfiguration, we tear down consensus, reconfigure state (at which point we opens
    //    up user certs), and start consensus again.
    // 7. After reconfiguration, and eventually consensus starts successfully, at some point the first
    //    checkpoint of the new epoch will be created.
    // We introduce various metrics to cover the latency of above steps.
    /// The duration from when the epoch is closed (i.e. validator halted) to when all pending
    /// certificates are processed (i.e. ready to send EndOfPublish message).
    /// This is the duration of (1) through (2) above.
    pub epoch_pending_certs_processed_time_since_epoch_close_ms: IntGauge,

    /// The interval from when the epoch is closed to when we created the last checkpoint of the
    /// epoch.
    /// This is the duration of (1) through (4) above.
    pub epoch_last_checkpoint_created_time_since_epoch_close_ms: IntGauge,

    /// The interval from when the epoch is closed to when we finished executing the last transaction
    /// of the checkpoint (and hence triggering reconfiguration process).
    /// This is the duration of (1) through (5) above.
    pub epoch_reconfig_start_time_since_epoch_close_ms: IntGauge,

    /// The total duration when this validator is halted, and hence does not accept certs from users.
    /// This is the duration of (1) through (6) above, and is the most important latency metric
    /// reflecting reconfiguration delay for each validator.
    pub epoch_validator_halt_duration_ms: IntGauge,

    /// The interval from when the epoch begins (i.e. right after state reconfigure, when the new
    /// epoch_store is created), to when the first checkpoint of the epoch is ready for creation locally.
    /// This is (7) above, and is a good proxy to how long it takes for the validator
    /// to become useful in the network after reconfiguration.
    // TODO: This needs to be reported properly.
    pub epoch_first_checkpoint_created_time_since_epoch_begin_ms: IntGauge,

    pub epoch_first_system_checkpoint_created_time_since_epoch_begin_ms: IntGauge,

    /// Buffer stake current in effect for this epoch
    pub effective_buffer_stake: IntGauge,

    /// Set to 1 if the random beacon DKG protocol failed for the most recent epoch.
    pub epoch_random_beacon_dkg_failed: IntGauge,

    /// The number of shares held by this node after the random beacon DKG protocol completed.
    pub epoch_random_beacon_dkg_num_shares: IntGauge,

    /// The amount of time taken from epoch start to completion of random beacon DKG protocol,
    /// for the most recent epoch.
    pub epoch_random_beacon_dkg_epoch_start_completion_time_ms: IntGauge,

    /// The amount of time taken to complete random beacon DKG protocol from the time it was
    /// started (which may be a bit after the epcoh began), for the most recent epoch.
    pub epoch_random_beacon_dkg_completion_time_ms: IntGauge,

    /// The amount of time taken to start first phase of the random beacon DKG protocol,
    /// at which point the node has submitted a DKG Message, for the most recent epoch.
    pub epoch_random_beacon_dkg_message_time_ms: IntGauge,

    /// The amount of time taken to complete first phase of the random beacon DKG protocol,
    /// at which point the node has submitted a DKG Confirmation, for the most recent epoch.
    pub epoch_random_beacon_dkg_confirmation_time_ms: IntGauge,

    /// Epoch of the most recent mpc_data freeze observed locally. Alert when
    /// it lags `current_epoch` well past the freeze grace window — a freeze
    /// that never fires wedges the epoch's reconfiguration/handoff pipeline.
    /// Re-seeded from the frozen table at epoch-store open so a mid-epoch
    /// restart doesn't false-alarm.
    pub dwallet_mpc_data_freeze_epoch: IntGauge,

    /// Number of validators the mpc_data freeze partition excluded from the
    /// MPC working set this epoch. Alert > 0.
    pub dwallet_mpc_data_excluded_validators: IntGauge,

    /// Number of distinct `EpochMpcDataReadySignal` signers recorded this
    /// epoch. Re-seeded from the per-epoch table at epoch-store open.
    pub dwallet_mpc_data_ready_signals: IntGauge,

    /// Stake attested by the recorded ready signals, recomputed at each
    /// pre-freeze consensus commit. Distinguishes "short on signals" from
    /// "short on coverage" while the freeze is late.
    pub dwallet_mpc_data_ready_signal_stake: IntGauge,

    /// This validator's own locally-validated peer count (the
    /// `validated_peers` candidate set for its ready signal). Updated on
    /// every `compute_locally_validated_peers` call, including before the
    /// ready-signal emit gates, so a stuck-below-quorum state is visible.
    pub dwallet_mpc_data_locally_validated_peers: IntGauge,

    /// Number of validator mpc_data announcements recorded in this epoch's
    /// table (self, relayed-joiner, and buffered-replay paths). Re-seeded
    /// from the table at epoch-store open.
    pub dwallet_mpc_data_announcements_received: IntGauge,

    /// Epoch of the most recent certified handoff attestation formed or
    /// re-minted locally. Alert when it lags `current_epoch` near the epoch
    /// boundary — a missing cert wedges the next epoch's prepare barrier.
    pub dwallet_handoff_cert_epoch: IntGauge,

    /// Number of distinct verified handoff signatures aggregated this epoch.
    pub dwallet_handoff_signatures_collected: IntGauge,

    /// Stake accumulated by the verified handoff signatures this epoch
    /// (quorum is stake-weighted, not headcount).
    pub dwallet_handoff_signatures_stake: IntGauge,

    /// Depth of the pending handoff-signature buffer (signatures awaiting
    /// the expected attestation or the consensus-pubkey provider).
    pub dwallet_handoff_signatures_buffered: IntGauge,

    /// Handoff signatures rejected by the verification path, by verdict.
    pub dwallet_handoff_signatures_rejected_total: IntCounterVec,

    /// 1 while this validator's own announcement is in the per-epoch table
    /// but the corresponding mpc_data blob is missing/invalid in perpetual
    /// storage (it refuses to self-attest); 0 otherwise. Alert == 1.
    pub own_mpc_data_blob_unhealthy: IntGauge,
}

impl EpochMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let this = Self {
            current_epoch: register_int_gauge_with_registry!(
                "current_epoch",
                "Current epoch ID",
                registry
            )
            .unwrap(),
            current_voting_right: register_int_gauge_with_registry!(
                "current_voting_right",
                "Current voting right of the validator",
                registry
            )
            .unwrap(),
            epoch_checkpoint_count: register_int_gauge_with_registry!(
                "epoch_checkpoint_count",
                "Number of checkpoints in the epoch",
                registry
            ).unwrap(),
            epoch_total_duration: register_int_gauge_with_registry!(
                "epoch_total_duration",
                "Total duration of the epoch",
                registry
            ).unwrap(),
            epoch_transaction_count: register_int_gauge_with_registry!(
                "epoch_transaction_count",
                "Number of transactions in the epoch",
                registry
            ).unwrap(),
            epoch_total_computation_reward: register_int_gauge_with_registry!(
                "epoch_total_computation_reward",
                "Total amount of computation rewards in the epoch",
                registry
            ).unwrap(),
            epoch_pending_certs_processed_time_since_epoch_close_ms: register_int_gauge_with_registry!(
                "epoch_pending_certs_processed_time_since_epoch_close_ms",
                "Time interval from when epoch was closed to when all pending certificates are processed",
                registry
            ).unwrap(),
            epoch_last_checkpoint_created_time_since_epoch_close_ms: register_int_gauge_with_registry!(
                "epoch_last_checkpoint_created_time_since_epoch_close_ms",
                "Time interval from when epoch was closed to when the last checkpoint of the epoch is created",
                registry
            ).unwrap(),
            epoch_reconfig_start_time_since_epoch_close_ms: register_int_gauge_with_registry!(
                "epoch_reconfig_start_time_since_epoch_close_ms",
                "Total time duration from when epoch was closed to when we begin to reconfigure the validator",
                registry
            ).unwrap(),
            epoch_validator_halt_duration_ms: register_int_gauge_with_registry!(
                "epoch_validator_halt_duration_ms",
                "Total time duration when the validator was halted (i.e. epoch closed)",
                registry
            ).unwrap(),
            epoch_first_checkpoint_created_time_since_epoch_begin_ms: register_int_gauge_with_registry!(
                "epoch_first_checkpoint_created_time_since_epoch_begin_ms",
                "Time interval from when the epoch opens at new epoch to the first checkpoint is created locally",
                registry
            ).unwrap(),
            epoch_first_system_checkpoint_created_time_since_epoch_begin_ms: register_int_gauge_with_registry!(
                "epoch_first_system_checkpoint_created_time_since_epoch_begin_ms",
                "Time interval from when the epoch opens at new epoch to the first params message is created locally",
                registry
            ).unwrap(),
            effective_buffer_stake: register_int_gauge_with_registry!(
                "effective_buffer_stake",
                "Buffer stake current in effect for this epoch",
                registry,
            ).unwrap(),
            epoch_random_beacon_dkg_failed: register_int_gauge_with_registry!(
                "epoch_random_beacon_dkg_failed",
                "Set to 1 if the random beacon DKG protocol failed for the most recent epoch.",
                registry
            )
            .unwrap(),
            epoch_random_beacon_dkg_num_shares: register_int_gauge_with_registry!(
                "epoch_random_beacon_dkg_num_shares",
                "The number of shares held by this node after the random beacon DKG protocol completed",
                registry
            )
            .unwrap(),
            epoch_random_beacon_dkg_epoch_start_completion_time_ms: register_int_gauge_with_registry!(
                "epoch_random_beacon_dkg_epoch_start_completion_time_ms",
                "The amount of time taken from epoch start to completion of random beacon DKG protocol, for the most recent epoch",
                registry
            )
            .unwrap(),
            epoch_random_beacon_dkg_completion_time_ms: register_int_gauge_with_registry!(
                "epoch_random_beacon_dkg_completion_time_ms",
                "The amount of time taken to complete random beacon DKG protocol from the time it was started (which may be a bit after the epoch began), for the most recent epoch",
                registry
            )
            .unwrap(),
            epoch_random_beacon_dkg_message_time_ms: register_int_gauge_with_registry!(
                "epoch_random_beacon_dkg_message_time_ms",
                "The amount of time taken to start first phase of the random beacon DKG protocol, at which point the node has submitted a DKG Message, for the most recent epoch",
                registry
            )
            .unwrap(),
            epoch_random_beacon_dkg_confirmation_time_ms: register_int_gauge_with_registry!(
                "epoch_random_beacon_dkg_confirmation_time_ms",
                "The amount of time taken to complete first phase of the random beacon DKG protocol, at which point the node has submitted a DKG Confirmation, for the most recent epoch",
                registry
            )
            .unwrap(),
            dwallet_mpc_data_freeze_epoch: register_int_gauge_with_registry!(
                "dwallet_mpc_data_freeze_epoch",
                "Epoch of the most recent mpc_data freeze observed locally",
                registry
            )
            .unwrap(),
            dwallet_mpc_data_excluded_validators: register_int_gauge_with_registry!(
                "dwallet_mpc_data_excluded_validators",
                "Number of validators the mpc_data freeze partition excluded this epoch",
                registry
            )
            .unwrap(),
            dwallet_mpc_data_ready_signals: register_int_gauge_with_registry!(
                "dwallet_mpc_data_ready_signals",
                "Number of distinct EpochMpcDataReadySignal signers recorded this epoch",
                registry
            )
            .unwrap(),
            dwallet_mpc_data_ready_signal_stake: register_int_gauge_with_registry!(
                "dwallet_mpc_data_ready_signal_stake",
                "Stake attested by the recorded mpc_data ready signals this epoch",
                registry
            )
            .unwrap(),
            dwallet_mpc_data_locally_validated_peers: register_int_gauge_with_registry!(
                "dwallet_mpc_data_locally_validated_peers",
                "This validator's locally-validated mpc_data peer count",
                registry
            )
            .unwrap(),
            dwallet_mpc_data_announcements_received: register_int_gauge_with_registry!(
                "dwallet_mpc_data_announcements_received",
                "Number of validator mpc_data announcements recorded this epoch",
                registry
            )
            .unwrap(),
            dwallet_handoff_cert_epoch: register_int_gauge_with_registry!(
                "dwallet_handoff_cert_epoch",
                "Epoch of the most recent certified handoff attestation formed locally",
                registry
            )
            .unwrap(),
            dwallet_handoff_signatures_collected: register_int_gauge_with_registry!(
                "dwallet_handoff_signatures_collected",
                "Number of distinct verified handoff signatures aggregated this epoch",
                registry
            )
            .unwrap(),
            dwallet_handoff_signatures_stake: register_int_gauge_with_registry!(
                "dwallet_handoff_signatures_stake",
                "Stake accumulated by the verified handoff signatures this epoch",
                registry
            )
            .unwrap(),
            dwallet_handoff_signatures_buffered: register_int_gauge_with_registry!(
                "dwallet_handoff_signatures_buffered",
                "Depth of the pending handoff-signature buffer",
                registry
            )
            .unwrap(),
            dwallet_handoff_signatures_rejected_total: register_int_counter_vec_with_registry!(
                "dwallet_handoff_signatures_rejected_total",
                "Handoff signatures rejected by the verification path, by verdict",
                &["verdict"],
                registry
            )
            .unwrap(),
            own_mpc_data_blob_unhealthy: register_int_gauge_with_registry!(
                "own_mpc_data_blob_unhealthy",
                "1 while this validator's own mpc_data blob is missing/invalid in perpetual storage",
                registry
            )
            .unwrap(),
        };
        Arc::new(this)
    }
}
