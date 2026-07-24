// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_types::messages_dwallet_checkpoint::DWalletCheckpointSequenceNumber;
use ika_types::messages_system_checkpoints::SystemCheckpointSequenceNumber;
use prometheus::{IntGauge, Registry, register_int_gauge_with_registry};
use std::sync::Arc;
use tap::Pipe;

#[derive(Clone)]
pub(super) struct Metrics(Option<Arc<Inner>>);

impl std::fmt::Debug for Metrics {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_struct("Metrics").finish()
    }
}

impl Metrics {
    pub fn enabled(registry: &Registry) -> Self {
        Metrics(Some(Inner::new(registry)))
    }

    pub fn disabled() -> Self {
        Metrics(None)
    }

    pub fn set_highest_known_dwallet_checkpoint(
        &self,
        sequence_number: DWalletCheckpointSequenceNumber,
    ) {
        if let Some(inner) = &self.0 {
            inner
                .highest_known_dwallet_checkpoint
                .set(sequence_number as i64);
        }
    }

    pub fn set_highest_verified_dwallet_checkpoint(
        &self,
        sequence_number: DWalletCheckpointSequenceNumber,
    ) {
        if let Some(inner) = &self.0 {
            inner
                .highest_verified_dwallet_checkpoint
                .set(sequence_number as i64);
        }
    }

    pub fn set_highest_synced_dwallet_checkpoint(
        &self,
        sequence_number: DWalletCheckpointSequenceNumber,
    ) {
        if let Some(inner) = &self.0 {
            inner
                .highest_synced_dwallet_checkpoint
                .set(sequence_number as i64);
        }
    }

    pub fn set_highest_known_system_checkpoint(
        &self,
        sequence_number: DWalletCheckpointSequenceNumber,
    ) {
        if let Some(inner) = &self.0 {
            inner
                .highest_known_system_checkpoint
                .set(sequence_number as i64);
        }
    }

    pub fn set_highest_verified_system_checkpoint(
        &self,
        sequence_number: SystemCheckpointSequenceNumber,
    ) {
        if let Some(inner) = &self.0 {
            inner
                .highest_verified_system_checkpoint
                .set(sequence_number as i64);
        }
    }

    pub fn set_highest_synced_system_checkpoint(
        &self,
        sequence_number: SystemCheckpointSequenceNumber,
    ) {
        if let Some(inner) = &self.0 {
            inner
                .highest_synced_system_checkpoint
                .set(sequence_number as i64);
        }
    }

    pub fn set_dwallet_checkpoint_sync_stall_seconds(&self, seconds: u64) {
        if let Some(inner) = &self.0 {
            inner
                .dwallet_checkpoint_sync_stall_seconds
                .set(seconds as i64);
        }
    }

    pub fn set_system_checkpoint_sync_stall_seconds(&self, seconds: u64) {
        if let Some(inner) = &self.0 {
            inner
                .system_checkpoint_sync_stall_seconds
                .set(seconds as i64);
        }
    }
}

struct Inner {
    highest_known_dwallet_checkpoint: IntGauge,
    highest_verified_dwallet_checkpoint: IntGauge,
    highest_synced_dwallet_checkpoint: IntGauge,

    highest_known_system_checkpoint: IntGauge,
    highest_verified_system_checkpoint: IntGauge,
    highest_synced_system_checkpoint: IntGauge,

    dwallet_checkpoint_sync_stall_seconds: IntGauge,
    system_checkpoint_sync_stall_seconds: IntGauge,
}

impl Inner {
    pub fn new(registry: &Registry) -> Arc<Self> {
        Self {
            highest_known_dwallet_checkpoint: register_int_gauge_with_registry!(
                "ika_highest_known_dwallet_checkpoint",
                "Highest known dwallet checkpoint",
                registry
            )
            .unwrap(),

            highest_verified_dwallet_checkpoint: register_int_gauge_with_registry!(
                "ika_highest_verified_dwallet_checkpoint",
                "Highest verified dwallet checkpoint",
                registry
            )
            .unwrap(),

            highest_synced_dwallet_checkpoint: register_int_gauge_with_registry!(
                "ika_highest_synced_dwallet_checkpoint",
                "Highest synced dwallet checkpoint",
                registry
            )
            .unwrap(),

            highest_known_system_checkpoint: register_int_gauge_with_registry!(
                "ika_highest_known_system_checkpoint",
                "Highest known system message",
                registry
            )
            .unwrap(),
            highest_verified_system_checkpoint: register_int_gauge_with_registry!(
                "ika_highest_verified_system_checkpoint",
                "Highest verified system message",
                registry
            )
            .unwrap(),
            highest_synced_system_checkpoint: register_int_gauge_with_registry!(
                "ika_highest_synced_system_checkpoint",
                "Highest synced system message",
                registry
            )
            .unwrap(),

            dwallet_checkpoint_sync_stall_seconds: register_int_gauge_with_registry!(
                "ika_dwallet_checkpoint_sync_stall_seconds",
                "Seconds dwallet-checkpoint sync has made no progress while peers \
                 are known to be ahead (0 = healthy). A sustained non-zero value on \
                 the notifier means the checkpoint writer has nothing to submit and \
                 the network's epoch close is silently blocked.",
                registry
            )
            .unwrap(),
            system_checkpoint_sync_stall_seconds: register_int_gauge_with_registry!(
                "ika_system_checkpoint_sync_stall_seconds",
                "Seconds system-checkpoint sync has made no progress while peers \
                 are known to be ahead (0 = healthy).",
                registry
            )
            .unwrap(),
        }
        .pipe(Arc::new)
    }
}
