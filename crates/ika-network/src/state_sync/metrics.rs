// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_types::checkpoint::CheckpointSequenceNumber;
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

    pub fn set_highest_known_dwallet_checkpoint(&self, sequence_number: CheckpointSequenceNumber) {
        if let Some(inner) = &self.0 {
            inner
                .highest_known_dwallet_checkpoint
                .set(sequence_number as i64);
        }
    }

    pub fn set_highest_verified_dwallet_checkpoint(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) {
        if let Some(inner) = &self.0 {
            inner
                .highest_verified_dwallet_checkpoint
                .set(sequence_number as i64);
        }
    }

    pub fn set_highest_synced_dwallet_checkpoint(&self, sequence_number: CheckpointSequenceNumber) {
        if let Some(inner) = &self.0 {
            inner
                .highest_synced_dwallet_checkpoint
                .set(sequence_number as i64);
        }
    }

    pub fn set_highest_known_system_checkpoint(&self, sequence_number: CheckpointSequenceNumber) {
        if let Some(inner) = &self.0 {
            inner
                .highest_known_system_checkpoint
                .set(sequence_number as i64);
        }
    }

    pub fn set_highest_verified_system_checkpoint(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) {
        if let Some(inner) = &self.0 {
            inner
                .highest_verified_system_checkpoint
                .set(sequence_number as i64);
        }
    }

    pub fn set_highest_synced_system_checkpoint(&self, sequence_number: CheckpointSequenceNumber) {
        if let Some(inner) = &self.0 {
            inner
                .highest_synced_system_checkpoint
                .set(sequence_number as i64);
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
}

impl Inner {
    pub fn new(registry: &Registry) -> Arc<Self> {
        Self {
            highest_known_dwallet_checkpoint: register_int_gauge_with_registry!(
                "highest_known_dwallet_checkpoint",
                "Highest known dwallet checkpoint",
                registry
            )
            .unwrap(),

            highest_verified_dwallet_checkpoint: register_int_gauge_with_registry!(
                "highest_verified_dwallet_checkpoint",
                "Highest verified dwallet checkpoint",
                registry
            )
            .unwrap(),

            highest_synced_dwallet_checkpoint: register_int_gauge_with_registry!(
                "highest_synced_dwallet_checkpoint",
                "Highest synced dwallet checkpoint",
                registry
            )
            .unwrap(),

            highest_known_system_checkpoint: register_int_gauge_with_registry!(
                "highest_known_system_checkpoint",
                "Highest known system message",
                registry
            )
            .unwrap(),
            highest_verified_system_checkpoint: register_int_gauge_with_registry!(
                "highest_verified_system_checkpoint",
                "Highest verified system message",
                registry
            )
            .unwrap(),
            highest_synced_system_checkpoint: register_int_gauge_with_registry!(
                "highest_synced_system_checkpoint",
                "Highest synced system message",
                registry
            )
            .unwrap(),
        }
        .pipe(Arc::new)
    }
}
