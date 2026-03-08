// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub mod checkpoint_output;

use std::collections::HashMap;
use std::sync::Arc;

use ika_types::noa_checkpoint::{
    CertifiedNOACheckpointMessage, NOACheckpointKind, NOACheckpointMessage,
};
use tokio::sync::mpsc::Receiver;
use tracing::{error, info};

use crate::dwallet_mpc::NetworkOwnedAddressSignOutput;
use checkpoint_output::CertifiedNOACheckpointOutput;

/// In-memory store for locally computed NOA checkpoints awaiting certification.
/// Keyed by message bytes so the certifier can match sign outputs back to checkpoints.
pub struct NOACheckpointLocalStore<K: NOACheckpointKind> {
    pending: parking_lot::Mutex<HashMap<Vec<u8>, NOACheckpointMessage<K>>>,
    certified: parking_lot::Mutex<HashMap<Vec<u8>, CertifiedNOACheckpointMessage<K>>>,
}

impl<K: NOACheckpointKind> NOACheckpointLocalStore<K> {
    pub fn new() -> Self {
        Self {
            pending: parking_lot::Mutex::new(HashMap::new()),
            certified: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    pub fn insert_pending(&self, message_bytes: Vec<u8>, checkpoint: NOACheckpointMessage<K>) {
        self.pending.lock().insert(message_bytes, checkpoint);
    }

    pub fn take_pending(&self, message_bytes: &[u8]) -> Option<NOACheckpointMessage<K>> {
        self.pending.lock().remove(message_bytes)
    }

    pub fn insert_certified(
        &self,
        message_bytes: Vec<u8>,
        checkpoint: CertifiedNOACheckpointMessage<K>,
    ) {
        self.certified.lock().insert(message_bytes, checkpoint);
    }

    pub fn get_certified(&self, message_bytes: &[u8]) -> Option<CertifiedNOACheckpointMessage<K>> {
        self.certified.lock().get(message_bytes).cloned()
    }
}

/// Listens for completed NOA sign outputs and matches them back to locally computed checkpoints.
pub struct NOACheckpointCertifier<K: NOACheckpointKind> {
    store: Arc<NOACheckpointLocalStore<K>>,
    sign_output_receiver: Receiver<NetworkOwnedAddressSignOutput>,
    certified_output: Box<dyn CertifiedNOACheckpointOutput<K>>,
}

impl<K: NOACheckpointKind> NOACheckpointCertifier<K> {
    pub fn new(
        store: Arc<NOACheckpointLocalStore<K>>,
        sign_output_receiver: Receiver<NetworkOwnedAddressSignOutput>,
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
            let checkpoint = match self.store.take_pending(&sign_output.message) {
                Some(cp) => cp,
                None => {
                    // This certifier doesn't own this message — another kind's certifier will.
                    continue;
                }
            };

            let sequence_number = checkpoint.sequence_number;
            let signed_bytes = sign_output.message.clone();

            let certified = CertifiedNOACheckpointMessage {
                checkpoint,
                signature: sign_output.signature,
                signed_bytes: signed_bytes.clone(),
                curve: sign_output.curve,
                signature_algorithm: sign_output.signature_algorithm,
            };

            info!(
                kind = K::NAME,
                sequence_number, "NOA checkpoint certified via MPC signature",
            );

            self.store.insert_certified(signed_bytes, certified.clone());

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
