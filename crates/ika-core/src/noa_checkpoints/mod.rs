// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub mod checkpoint_output;

use std::collections::HashMap;
use std::sync::Arc;

use ika_types::noa_checkpoint::{
    CertifiedNOACheckpointMessage, NOACheckpointKind, NOACheckpointMessage,
};
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{error, info, warn};

use crate::dwallet_mpc::NetworkOwnedAddressSignOutput;
use checkpoint_output::CertifiedNOACheckpointOutput;

/// In-memory store for locally computed NOA checkpoints awaiting certification.
/// Keyed by sequence number so the certifier can match sign outputs back to checkpoints.
pub struct NOACheckpointLocalStore<K: NOACheckpointKind> {
    pending: parking_lot::Mutex<HashMap<u64, NOACheckpointMessage<K>>>,
    certified: parking_lot::Mutex<HashMap<u64, CertifiedNOACheckpointMessage<K>>>,
}

impl<K: NOACheckpointKind> NOACheckpointLocalStore<K> {
    pub fn new() -> Self {
        Self {
            pending: parking_lot::Mutex::new(HashMap::new()),
            certified: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    pub fn insert_pending(&self, checkpoint: NOACheckpointMessage<K>) {
        self.pending
            .lock()
            .insert(checkpoint.sequence_number, checkpoint);
    }

    pub fn take_pending(&self, sequence_number: u64) -> Option<NOACheckpointMessage<K>> {
        self.pending.lock().remove(&sequence_number)
    }

    pub fn insert_certified(&self, checkpoint: CertifiedNOACheckpointMessage<K>) {
        self.certified
            .lock()
            .insert(checkpoint.checkpoint.sequence_number, checkpoint);
    }

    pub fn get_certified(&self, sequence_number: u64) -> Option<CertifiedNOACheckpointMessage<K>> {
        self.certified.lock().get(&sequence_number).cloned()
    }
}

/// Listens for completed NOA sign outputs and matches them back to locally computed checkpoints.
pub struct NOACheckpointCertifier<K: NOACheckpointKind> {
    store: Arc<NOACheckpointLocalStore<K>>,
    sign_output_receiver: UnboundedReceiver<NetworkOwnedAddressSignOutput>,
    certified_output: Box<dyn CertifiedNOACheckpointOutput<K>>,
}

impl<K: NOACheckpointKind> NOACheckpointCertifier<K> {
    pub fn new(
        store: Arc<NOACheckpointLocalStore<K>>,
        sign_output_receiver: UnboundedReceiver<NetworkOwnedAddressSignOutput>,
        certified_output: Box<dyn CertifiedNOACheckpointOutput<K>>,
    ) -> Self {
        Self {
            store,
            sign_output_receiver,
            certified_output,
        }
    }

    pub async fn run(mut self) {
        info!(kind = K::NAME, "Starting NOACheckpointCertifier");

        while let Some(sign_output) = self.sign_output_receiver.recv().await {
            let sequence_number = sign_output.sequence_number;

            let checkpoint = match self.store.take_pending(sequence_number) {
                Some(cp) => cp,
                None => {
                    warn!(
                        kind = K::NAME,
                        sequence_number,
                        "Received NOA sign output for unknown checkpoint sequence number, skipping",
                    );
                    continue;
                }
            };

            let signed_bytes = bcs::to_bytes(&checkpoint).unwrap_or_default();

            let certified = CertifiedNOACheckpointMessage {
                checkpoint,
                signature: sign_output.signature,
                signed_bytes,
                curve: sign_output.curve,
                signature_algorithm: sign_output.signature_algorithm,
            };

            info!(
                kind = K::NAME,
                sequence_number, "NOA checkpoint certified via MPC signature",
            );

            self.store.insert_certified(certified.clone());

            if let Err(e) = self
                .certified_output
                .certified_checkpoint_created(&certified)
            {
                error!(
                    kind = K::NAME,
                    sequence_number,
                    error = %e,
                    "Failed to process certified NOA checkpoint",
                );
            }
        }

        info!(
            kind = K::NAME,
            "NOACheckpointCertifier channel closed, shutting down"
        );
    }
}
