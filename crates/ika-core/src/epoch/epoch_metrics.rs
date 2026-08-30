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
    /// The protocol-version range THIS binary advertises in its capability
    /// votes (constant per process). Fleet aggregation of `..._max` against
    /// committee_quorum_threshold + ika_effective_buffer_stake shows exactly
    /// how much stake still has to upgrade before the next version arms.
    pub supported_protocol_version_min: IntGauge,
    pub supported_protocol_version_max: IntGauge,
    /// The stake required to arm the next protocol version:
    /// quorum_threshold + ceil(f * buffer_stake_bps / 10000). THE activation
    /// line - compare protocol_upgrade_supporting_stake against it.
    pub protocol_upgrade_effective_threshold: IntGauge,
    /// Stake whose consensus-recorded capability votes advertise support for
    /// a version ABOVE the current protocol version. When this crosses
    /// protocol_upgrade_effective_threshold, the upgrade arms and activates
    /// at the next epoch boundary.
    pub protocol_upgrade_supporting_stake: IntGauge,

    /// Epoch of the most recent mpc_data freeze observed locally. Alert when
    /// it lags `current_epoch` well past the freeze grace window — a freeze
    /// that never fires wedges the epoch's reconfiguration/handoff pipeline.
    /// Re-seeded from the frozen table at epoch-store open so a mid-epoch
    /// restart doesn't false-alarm.
    pub dwallet_mpc_data_freeze_epoch: IntGauge,

    /// Number of validators the mpc_data freeze partition excluded from the
    /// MPC working set this epoch. Alert > 0.
    pub dwallet_mpc_data_excluded_validators: IntGauge,

    /// The consensus leader round at which this epoch's mpc_data
    /// ready-signal stake quorum was first observed (the freeze-grace
    /// anchor), or `-1` before quorum. Round 0 is valid, so the sentinel
    /// is `-1`, not 0. Re-seeded from the persisted anchor at epoch-store
    /// open, so a mid-epoch restart doesn't misreport a fresh countdown.
    /// Freeze-ETA estimate: `clamp_min(this + grace_rounds -
    /// ika_last_committed_leader_consensus_round, 0)`.
    pub dwallet_mpc_data_ready_quorum_round: IntGauge,

    /// The leader round of the latest consensus commit processed at the
    /// commit boundary — the SAME round domain the freeze / epoch-close
    /// grace countdowns are measured in (`consensus_commit_info.round`),
    /// unlike `ika_last_process_mpc_consensus_round` (the MPC service's
    /// consumed round, which lags this one). `-1` before the epoch's
    /// first commit; re-seeded from the persisted consensus stats at
    /// epoch-store open.
    ///
    /// This is the commit CONSUMER's view, deliberately distinct from
    /// consensus-core's own `last_committed_leader_round` ("committed to
    /// store and sent to commit consumer" — the producer side, exported as
    /// `consensus_ika_last_committed_leader_round`). The two coincide on a
    /// healthy node and diverge exactly when ika's commit handler stalls
    /// while Mysticeti keeps committing, which is the failure class this
    /// gauge exists to expose.
    ///
    /// Until 1.2.x both sides published the identical name and the node
    /// served that family twice, dropping a sample per scrape (ika #2022).
    /// The names are now near-homonyms on purpose — same subject, different
    /// observation point — and cannot collide, because ika's metrics live
    /// under `ika_*` and the vendored registry no longer does.
    pub last_committed_leader_consensus_round: IntGauge,

    /// How many consensus rounds the MPC service trails the consensus commit
    /// path by, sampled on every commit. Small and roughly constant in normal
    /// operation (the MPC service consumes slightly behind the commit
    /// boundary); UNBOUNDED GROWTH means the MPC subsystem has stopped while
    /// consensus keeps running — the node serves consensus normally, looks
    /// alive from every angle, and contributes nothing.
    ///
    /// This is the signal a validator operator needs and previously did not
    /// have. Two validators went dark for hours in production this way (ika
    /// #1978, #1980), both diagnosed only from a fleet-wide Grafana no
    /// external operator can see, and both cleared by a restart nobody knew
    /// to perform. Locally computable on purpose: it needs no peer data and no
    /// fleet context, so it works for anyone running a validator.
    ///
    /// Bounded in normal operation, and bounded by construction: since #2074
    /// the fold hands each round to the drain over a blocking channel of
    /// `DEFAULT_ROUND_CHANNEL_CAPACITY` (`authority::round_transport`), so it
    /// parks rather than run further than a channel's worth ahead of the
    /// drain's cursor. Growth past that has one live cause — a drain that has
    /// EXITED, after which the fold detaches and runs on without it, which is
    /// exactly the self-stop above. A drain that is merely wedged holds this
    /// flat near capacity and is `ika_consensus_fold_blocked_seconds_total`'s
    /// to report.
    ///
    /// `-1` before the MPC service reports its first round, since round 0 is
    /// a legitimate value.
    pub mpc_consensus_round_lag: IntGauge,

    /// `1` while this node judges its own MPC subsystem to have stopped
    /// contributing — the condition behind the loud log, which fires only on
    /// transition and so cannot be alerted on continuously.
    ///
    /// This, not a threshold on `mpc_consensus_round_lag`, is the alert
    /// target. A threshold there fired on every restart of every production
    /// validator while a mid-epoch replay ran (ika #2036); since #2074 it has
    /// the opposite defect, because the bounded round channel keeps the raw
    /// lag within a channel's worth of the drain — the drain consumes during
    /// the boot replay, so no replay ever moves it. The epoch-scale "how far
    /// behind" is `ika_dwallet_mpc_catchup_gap_rounds`, measured against the
    /// published consensus-store head. This gauge already accounts for the
    /// catch-up the MPC service reports.
    pub mpc_stopped_contributing_condition_active: IntGauge,

    /// `1` while the MPC service is reporting a catch-up whose consensus-round
    /// gap has stopped closing.
    ///
    /// The complement of the gauge above: a reported catch-up holds the
    /// stopped-contributing condition, so this is what distinguishes a backlog
    /// being drained (healthy, no action, watch
    /// `ika_dwallet_mpc_catchup_gap_rounds` fall) from one that has stopped
    /// draining (this node will not come back on its own).
    ///
    /// The no-new-low clock behind it runs over that same catch-up gap, and
    /// not over `ika_mpc_consensus_round_lag`: the bounded round channel
    /// clamps the lag near zero, so a boot replay holds it flat above a
    /// low-water mark set seconds after boot and this condition latched on
    /// every replay that ran past the bound (ika #2095).
    pub mpc_catch_up_stuck_condition_active: IntGauge,

    /// Consensus timestamp (unix seconds) of the latest commit processed at
    /// the Ika commit boundary. Zero until this process handles its first
    /// commit; metric collection never mutates it.
    pub consensus_last_committed_timestamp_seconds: IntGauge,

    /// The configured `mpc_data_freeze_grace_rounds` for the current
    /// protocol version, or `-1` when the off-chain-metadata feature
    /// (and thus the freeze) is disabled for it or the value is
    /// undefined. Constant within an epoch.
    pub dwallet_mpc_data_freeze_grace_rounds: IntGauge,

    /// The consensus leader round at which this epoch's mpc_data input
    /// set was frozen, or `-1` until the freeze fires. Persisted with the
    /// freeze commit's batch and re-seeded at epoch-store open (left `-1`
    /// if the freeze predates the binary that persists it — never
    /// invented from the current round).
    pub dwallet_mpc_data_freeze_round: IntGauge,

    /// The ready-signal emit deadline currently anchored by
    /// `mpc_data_announcement_sender` (`ready_signal_deadline_ms`), in
    /// seconds. On the epoch's CONSENSUS clock — leader-proposed
    /// `commit_timestamp_ms` (unix ms scale) — never this machine's
    /// wall clock. `-1` while no deadline exists (no consensus commit
    /// processed this epoch, or the off-chain-metadata feature is off).
    /// Shows the 3/4-epoch backstop until the sender observes the
    /// next-epoch committee published, then tightens to the publication
    /// grace; after a restart the (local-only) publication anchor resets,
    /// so the gauge reverts to the backstop until re-observation —
    /// mirroring the emit gate's actual behavior.
    pub dwallet_mpc_data_ready_signal_deadline_timestamp_seconds: IntGauge,

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

    /// Consensus-transaction digests the epoch's fold is holding for dedup —
    /// one per verified transaction of the epoch, never pruned within it.
    ///
    /// This is the epoch store's largest single in-memory structure and it
    /// grows with the epoch's traffic, so it is the number to watch for the
    /// memory cost of holding derived state in RAM. Multiply by ~69 bytes per
    /// entry for its worst-case footprint.
    pub processed_consensus_messages: IntGauge,

    /// Peer checkpoint signatures held for aggregation, per family. Pruned
    /// below the certified watermark, so on a running node a steady value near
    /// the committee size is healthy and sustained growth means certification
    /// has stalled. During a boot replay they sawtooth instead — the fold
    /// re-inserts faster than the once-a-second prune — which is bounded and
    /// normal.
    pub pending_dwallet_checkpoint_signatures: IntGauge,
    pub pending_system_checkpoint_signatures: IntGauge,

    /// Entries in each builder's input queue, sampled where the queue is
    /// MUTATED rather than on a builder pass.
    ///
    /// That is the whole point of them: the builders wait for the boot replay
    /// before their first pass, while the MPC drain fills the queue throughout
    /// it, so a builder-sampled depth reports nothing during the one window
    /// where the queue grows without a consumer.
    /// `ika_dwallet_checkpoint_pending_queue_depth` is the builder-sampled
    /// view and stays the right one for "is the builder stuck"; these two are
    /// the right one for "how much is the replay accumulating".
    ///
    /// Entries, not bytes. Each carries one consensus round's checkpoint
    /// content, so multiply by the epoch's average checkpoint size for a
    /// footprint.
    pub pending_dwallet_checkpoints: IntGauge,
    pub pending_system_checkpoints: IntGauge,
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
            supported_protocol_version_min: register_int_gauge_with_registry!(
                "ika_supported_protocol_version_min",
                "Lowest protocol version this binary advertises support for",
                registry,
            )
            .unwrap(),
            supported_protocol_version_max: register_int_gauge_with_registry!(
                "ika_supported_protocol_version_max",
                "Highest protocol version this binary advertises support for",
                registry,
            )
            .unwrap(),
            protocol_upgrade_effective_threshold: register_int_gauge_with_registry!(
                "ika_protocol_upgrade_effective_threshold",
                "Stake required to arm the next protocol version (quorum + buffer)",
                registry,
            )
            .unwrap(),
            protocol_upgrade_supporting_stake: register_int_gauge_with_registry!(
                "ika_protocol_upgrade_supporting_stake",
                "Stake whose capability votes support a version above the current one",
                registry,
            )
            .unwrap(),
            dwallet_mpc_data_excluded_validators: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_data_excluded_validators",
                "Number of validators the mpc_data freeze partition excluded this epoch",
                registry
            )
            .unwrap(),
            dwallet_mpc_data_ready_quorum_round: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_data_ready_quorum_round",
                "Leader round where the mpc_data ready-signal stake quorum was first observed \
                 (freeze-grace anchor); -1 before quorum",
                registry
            )
            .unwrap(),
            last_committed_leader_consensus_round: register_int_gauge_with_registry!(
                "ika_last_committed_leader_consensus_round",
                "Leader round of the latest consensus commit processed at the commit boundary \
                 (the freeze-grace round domain); -1 before the epoch's first commit",
                registry
            )
            .unwrap(),
            mpc_consensus_round_lag: register_int_gauge_with_registry!(
                "ika_mpc_consensus_round_lag",
                "Consensus rounds the MPC service trails the consensus commit path by; unbounded growth means MPC has stopped while consensus keeps running (-1 before the MPC service reports its first round)",
                registry,
            )
            .unwrap(),
            mpc_stopped_contributing_condition_active: register_int_gauge_with_registry!(
                "ika_mpc_stopped_contributing_condition_active",
                "1 while this node judges its MPC subsystem to have stopped contributing; alert on this rather than on a threshold over ika_mpc_consensus_round_lag, which the bounded round channel holds within a channel's worth of the drain and so cannot show a mid-epoch restart's replay (that is ika_dwallet_mpc_catchup_gap_rounds)",
                registry,
            )
            .unwrap(),
            mpc_catch_up_stuck_condition_active: register_int_gauge_with_registry!(
                "ika_mpc_catch_up_stuck_condition_active",
                "1 while the MPC service reports a catch-up whose consensus-round gap has stopped closing (a drain that is still closing its gap is healthy and sets this to 0)",
                registry,
            )
            .unwrap(),
            consensus_last_committed_timestamp_seconds: register_int_gauge_with_registry!(
                "ika_consensus_last_committed_timestamp_seconds",
                "Consensus timestamp in unix seconds of the latest commit processed at the Ika commit boundary; 0 until this process handles its first commit",
                registry
            )
            .unwrap(),
            dwallet_mpc_data_freeze_grace_rounds: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_data_freeze_grace_rounds",
                "Configured mpc_data_freeze_grace_rounds for the current protocol version; \
                 -1 when the freeze feature is disabled or the value is undefined",
                registry
            )
            .unwrap(),
            dwallet_mpc_data_freeze_round: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_data_freeze_round",
                "Leader round where the mpc_data input set was frozen; -1 until the freeze",
                registry
            )
            .unwrap(),
            dwallet_mpc_data_ready_signal_deadline_timestamp_seconds: register_int_gauge_with_registry!(
                "ika_dwallet_mpc_data_ready_signal_deadline_timestamp_seconds",
                "Ready-signal emit deadline on the epoch's consensus clock (leader-proposed \
                 commit timestamps, unix seconds scale, NOT local wall clock); -1 while not \
                 yet computable",
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
            processed_consensus_messages: register_int_gauge_with_registry!(
                "ika_epoch_processed_consensus_messages",
                "Consensus-transaction digests the epoch's fold holds for dedup",
                registry
            )
            .unwrap(),
            pending_dwallet_checkpoint_signatures: register_int_gauge_with_registry!(
                "ika_epoch_pending_dwallet_checkpoint_signatures",
                "Peer dWallet checkpoint signatures held for aggregation",
                registry
            )
            .unwrap(),
            pending_system_checkpoint_signatures: register_int_gauge_with_registry!(
                "ika_epoch_pending_system_checkpoint_signatures",
                "Peer system checkpoint signatures held for aggregation",
                registry
            )
            .unwrap(),
            pending_dwallet_checkpoints: register_int_gauge_with_registry!(
                "ika_epoch_pending_dwallet_checkpoints",
                "Entries in the dWallet checkpoint builder's input queue, sampled on mutation",
                registry
            )
            .unwrap(),
            pending_system_checkpoints: register_int_gauge_with_registry!(
                "ika_epoch_pending_system_checkpoints",
                "Entries in the system checkpoint builder's input queue, sampled on mutation",
                registry
            )
            .unwrap(),
        };
        Arc::new(this)
    }
}

#[cfg(test)]
mod tests {
    use super::EpochMetrics;
    use prometheus::Registry;

    /// Register every ika-side metric struct that lands in the node's default
    /// registry, the way `IkaNode::start_async` composes them, and return the
    /// exported metric family names.
    ///
    /// NOTE: this is what the node actually SERVES, which is not the same as
    /// what it registers. `gather()` omits a `*_vec` family that has no label
    /// children yet, so a freshly built registry hides every labelled metric
    /// That is the right domain for this test — an unobserved family is never
    /// written to the endpoint and so cannot collide — but it means this layer
    /// alone would not catch a new *labelled* violator.
    /// `scripts/check-metric-names.sh` covers that: it extracts every
    /// registered literal statically, vec or not. The two layers are
    /// complementary, not redundant.
    fn ika_side_metric_family_names() -> Vec<String> {
        let registry = Registry::new();

        // Held so nothing is dropped before `gather()`.
        let _epoch = EpochMetrics::new(&registry);
        let _authority = crate::authority::AuthorityMetrics::new(&registry);
        let _consensus_manager = crate::consensus_manager::ConsensusManagerMetrics::new(&registry);
        let _consensus_adapter = crate::consensus_adapter::ConsensusAdapterMetrics::new(&registry);
        let _tx_validator = crate::consensus_validator::IkaTxValidatorMetrics::new(&registry);
        let _mpc = crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics::new(&registry);
        let _dwallet_checkpoint =
            crate::dwallet_checkpoints::DWalletCheckpointMetrics::new(&registry);
        let _system_checkpoint = crate::system_checkpoints::SystemCheckpointMetrics::new(&registry);
        let _sui_connector = crate::sui_connector::metrics::SuiConnectorMetrics::new(&registry);
        let _ocs = crate::sui_connector::ocs_metrics::OcsMetrics::new(&registry);

        registry
            .gather()
            .into_iter()
            .map(|family| family.name().to_string())
            .collect()
    }

    /// ika owns `ika_*` and nothing else owns any of it; the vendored consensus
    /// registry lives outside it (`consensus_ika_*`, see
    /// `consensus_manager::ConsensusManager::start`). That makes the namespace
    /// rule a bipartition with no lists on either side, and both halves are
    /// properties of SOURCE — which name literals ika registers, and which
    /// prefix each `Registry::new_custom` uses — so both are enforced by
    /// `scripts/check-metric-names.sh` rather than here.
    ///
    /// A runtime prefix check is deliberately NOT duplicated in this module:
    /// `gather()` also returns families registered by upstream types ika
    /// merely instantiates (the `verifier_runtime_per_*_latency` set arrives
    /// this way), which ika cannot rename and which the source rule rightly
    /// does not cover. Asserting on them here would mean maintaining an
    /// exception list of names we do not own — the exact failure mode this
    /// design removed. What this module tests is what only a live registry can
    /// show: that the gathered set has no duplicates, and that the #2022 pair
    /// stays distinct.
    /// Pinned regression for ika #2022: the two leader-round gauges must not
    /// share a name. ika publishes the consumer-side round under `ika_*`;
    /// consensus-core's producer-side gauge reaches the endpoint through the
    /// vendored registry as `consensus_ika_last_committed_leader_round`, which
    /// this registry never contains.
    #[test]
    fn the_two_leader_round_gauges_do_not_share_a_name() {
        let names = ika_side_metric_family_names();
        assert!(
            names
                .iter()
                .any(|n| n == "ika_last_committed_leader_consensus_round"),
            "ika's consumer-side leader-round gauge is missing"
        );
        assert!(
            !names
                .iter()
                .any(|n| n == "consensus_ika_last_committed_leader_round"),
            "ika must not register consensus-core's producer-side gauge name"
        );
    }
}
