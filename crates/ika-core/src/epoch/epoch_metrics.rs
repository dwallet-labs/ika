// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use prometheus::{
    Histogram, IntCounterVec, IntGauge, Registry, register_histogram_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_with_registry,
};
use std::sync::Arc;

pub struct EpochMetrics {
    /// The current epoch ID. This is updated only when the AuthorityState finishes reconfiguration.
    pub current_epoch: IntGauge,

    /// Size distribution of in-band mpc_data announcement blobs accepted
    /// for persistence. Blobs ride consensus messages with no size cap
    /// yet; this is the measurement that picks the eventual cap (see
    /// PR #1721 review fast-follow #2).
    pub mpc_data_announcement_blob_bytes: Histogram,

    /// Current voting right of the validator in the protocol. Updated at the start of epochs.
    pub current_voting_right: IntGauge,

    /// Total duration of the epoch. This is measured from when the current epoch store is opened,
    /// until the current epoch store is replaced with the next epoch store.
    pub epoch_total_duration: IntGauge,

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
    /// The active committee's quorum threshold (2f+1 in stake units). With
    /// unit stake this pairs with total_stake to draw activation lines
    /// (e.g. protocol upgrades need quorum + buffer, see
    /// ika_effective_buffer_stake) without dashboards re-deriving BFT math.
    pub committee_quorum_threshold: IntGauge,
    /// The active committee's validity threshold (f+1 in stake units).
    pub committee_validity_threshold: IntGauge,
    /// The active committee's total voting stake (3f+1-ish; unit stake =>
    /// committee size).
    pub committee_total_stake: IntGauge,

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
                "ika_current_epoch",
                "Current epoch ID",
                registry
            )
            .unwrap(),
            mpc_data_announcement_blob_bytes: register_histogram_with_registry!(
                "ika_mpc_data_announcement_blob_bytes",
                "Byte size of in-band mpc_data announcement blobs accepted for persistence",
                // Class-groups bundles are multi-MB; default buckets top out
                // at 10 and would collapse everything into +Inf.
                vec![
                    65536.0, 131072.0, 262144.0, 524288.0, 1048576.0, 2097152.0, 4194304.0,
                    8388608.0, 16777216.0, 33554432.0
                ],
                registry
            )
            .unwrap(),
            current_voting_right: register_int_gauge_with_registry!(
                "ika_current_voting_right",
                "Current voting right of the validator",
                registry
            )
            .unwrap(),
            epoch_total_duration: register_int_gauge_with_registry!(
                "ika_epoch_total_duration",
                "Total duration of the epoch",
                registry
            ).unwrap(),
            epoch_total_computation_reward: register_int_gauge_with_registry!(
                "ika_epoch_total_computation_reward",
                "Total amount of computation rewards in the epoch",
                registry
            ).unwrap(),
            epoch_reconfig_start_time_since_epoch_close_ms: register_int_gauge_with_registry!(
                "ika_epoch_reconfig_start_time_since_epoch_close_ms",
                "Total time duration from when epoch was closed to when we begin to reconfigure the validator",
                registry
            ).unwrap(),
            epoch_validator_halt_duration_ms: register_int_gauge_with_registry!(
                "ika_epoch_validator_halt_duration_ms",
                "Total time duration when the validator was halted (i.e. epoch closed)",
                registry
            ).unwrap(),
            epoch_first_checkpoint_created_time_since_epoch_begin_ms: register_int_gauge_with_registry!(
                "ika_epoch_first_checkpoint_created_time_since_epoch_begin_ms",
                "Time interval from when the epoch opens at new epoch to the first checkpoint is created locally",
                registry
            ).unwrap(),
            epoch_first_system_checkpoint_created_time_since_epoch_begin_ms: register_int_gauge_with_registry!(
                "ika_epoch_first_system_checkpoint_created_time_since_epoch_begin_ms",
                "Time interval from when the epoch opens at new epoch to the first params message is created locally",
                registry
            ).unwrap(),
            effective_buffer_stake: register_int_gauge_with_registry!(
                "ika_effective_buffer_stake",
                "Buffer stake current in effect for this epoch",
                registry,
            ).unwrap(),
            dwallet_mpc_data_freeze_epoch: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_data_freeze_epoch",
                "Epoch of the most recent mpc_data freeze observed locally",
                registry
            )
            .unwrap(),
            committee_quorum_threshold: register_int_gauge_with_registry!(
                "ika_committee_quorum_threshold",
                "Active committee quorum threshold (2f+1) in stake units",
                registry,
            )
            .unwrap(),
            committee_validity_threshold: register_int_gauge_with_registry!(
                "ika_committee_validity_threshold",
                "Active committee validity threshold (f+1) in stake units",
                registry,
            )
            .unwrap(),
            committee_total_stake: register_int_gauge_with_registry!(
                "ika_committee_total_stake",
                "Active committee total voting stake",
                registry,
            )
            .unwrap(),
            dwallet_mpc_data_excluded_validators: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_data_excluded_validators",
                "Number of validators the mpc_data freeze partition excluded this epoch",
                registry
            )
            .unwrap(),
            dwallet_mpc_data_ready_signals: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_data_ready_signals",
                "Number of distinct EpochMpcDataReadySignal signers recorded this epoch",
                registry
            )
            .unwrap(),
            dwallet_mpc_data_ready_signal_stake: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_data_ready_signal_stake",
                "Stake attested by the recorded mpc_data ready signals this epoch",
                registry
            )
            .unwrap(),
            dwallet_mpc_data_locally_validated_peers: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_data_locally_validated_peers",
                "This validator's locally-validated mpc_data peer count",
                registry
            )
            .unwrap(),
            dwallet_mpc_data_announcements_received: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_data_announcements_received",
                "Number of validator mpc_data announcements recorded this epoch",
                registry
            )
            .unwrap(),
            dwallet_handoff_cert_epoch: register_int_gauge_with_registry!(
                "ika_dwallet_handoff_cert_epoch",
                "Epoch of the most recent certified handoff attestation formed locally",
                registry
            )
            .unwrap(),
            dwallet_handoff_signatures_collected: register_int_gauge_with_registry!(
                "ika_dwallet_handoff_signatures_collected",
                "Number of distinct verified handoff signatures aggregated this epoch",
                registry
            )
            .unwrap(),
            dwallet_handoff_signatures_stake: register_int_gauge_with_registry!(
                "ika_dwallet_handoff_signatures_stake",
                "Stake accumulated by the verified handoff signatures this epoch",
                registry
            )
            .unwrap(),
            dwallet_handoff_signatures_buffered: register_int_gauge_with_registry!(
                "ika_dwallet_handoff_signatures_buffered",
                "Depth of the pending handoff-signature buffer",
                registry
            )
            .unwrap(),
            dwallet_handoff_signatures_rejected_total: register_int_counter_vec_with_registry!(
                "ika_dwallet_handoff_signatures_rejected_total",
                "Handoff signatures rejected by the verification path, by verdict",
                &["verdict"],
                registry
            )
            .unwrap(),
            own_mpc_data_blob_unhealthy: register_int_gauge_with_registry!(
                "ika_own_mpc_data_blob_unhealthy",
                "1 while this validator's own mpc_data blob is missing/invalid in perpetual storage",
                registry
            )
            .unwrap(),
        };
        Arc::new(this)
    }
}
