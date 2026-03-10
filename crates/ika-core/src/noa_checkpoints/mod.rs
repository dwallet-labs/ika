// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub mod checkpoint_output;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;

use ika_types::noa_checkpoint::{
    CertifiedNOACheckpointMessage, NOACheckpointKind, NOACheckpointMessage,
};
use sui_types::base_types::EpochId;
use tokio::sync::mpsc::{Receiver, UnboundedSender};
use tracing::{error, info};

use crate::dwallet_mpc::{NetworkOwnedAddressSignOutput, NetworkOwnedAddressSignRequest};
use checkpoint_output::CertifiedNOACheckpointOutput;

/// Tracks a checkpoint whose transactions are being signed individually.
struct PendingCheckpoint<K: NOACheckpointKind> {
    checkpoint: NOACheckpointMessage<K>,
    /// All tx byte vectors from `signable_bytes()`, in order.
    expected_tx_bytes: Vec<Vec<u8>>,
    /// Collected signatures: tx_bytes → signature. Populated as sign outputs arrive.
    collected: HashMap<Vec<u8>, Vec<u8>>,
}

/// In-memory store for locally computed NOA checkpoints awaiting certification.
/// A single checkpoint may produce multiple sign requests (one per transaction).
/// The store tracks individual tx bytes → sequence number mappings so that
/// incoming sign outputs can be routed back to the correct checkpoint.
pub struct NOACheckpointLocalStore<K: NOACheckpointKind> {
    /// Maps individual tx bytes → checkpoint sequence number.
    tx_to_seq: parking_lot::Mutex<HashMap<Vec<u8>, u64>>,
    /// Maps sequence number → pending multi-tx checkpoint state.
    pending: parking_lot::Mutex<HashMap<u64, PendingCheckpoint<K>>>,
    certified: parking_lot::Mutex<HashMap<u64, CertifiedNOACheckpointMessage<K>>>,
}

impl<K: NOACheckpointKind> NOACheckpointLocalStore<K> {
    pub fn new() -> Self {
        Self {
            tx_to_seq: parking_lot::Mutex::new(HashMap::new()),
            pending: parking_lot::Mutex::new(HashMap::new()),
            certified: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Register a pending checkpoint with all its transaction byte vectors.
    pub fn insert_pending(
        &self,
        seq: u64,
        checkpoint: NOACheckpointMessage<K>,
        tx_bytes: Vec<Vec<u8>>,
    ) {
        let mut tx_to_seq = self.tx_to_seq.lock();
        for bytes in &tx_bytes {
            tx_to_seq.insert(bytes.clone(), seq);
        }

        self.pending.lock().insert(
            seq,
            PendingCheckpoint {
                checkpoint,
                expected_tx_bytes: tx_bytes,
                collected: HashMap::new(),
            },
        );
    }

    /// Record a signature for a single transaction.
    /// Returns `Some(certified)` when all transactions for that checkpoint are signed.
    pub fn add_signature(
        &self,
        tx_bytes: &[u8],
        signature: Vec<u8>,
        curve: dwallet_mpc_types::dwallet_mpc::DWalletCurve,
        signature_algorithm: dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm,
    ) -> Option<CertifiedNOACheckpointMessage<K>> {
        let seq = {
            let tx_to_seq = self.tx_to_seq.lock();
            *tx_to_seq.get(tx_bytes)?
        };

        let mut pending = self.pending.lock();
        let entry = pending.get_mut(&seq)?;
        entry.collected.insert(tx_bytes.to_vec(), signature);

        if entry.collected.len() < entry.expected_tx_bytes.len() {
            return None;
        }

        // All signatures collected — build ordered vectors and remove pending state.
        let entry = pending.remove(&seq).unwrap();
        let signatures = entry
            .expected_tx_bytes
            .iter()
            .map(|tx| entry.collected[tx].clone())
            .collect();
        let signed_bytes = entry.expected_tx_bytes;

        // Clean up tx_to_seq entries.
        let mut tx_to_seq = self.tx_to_seq.lock();
        for bytes in &signed_bytes {
            tx_to_seq.remove(bytes);
        }

        Some(CertifiedNOACheckpointMessage {
            checkpoint: entry.checkpoint,
            signatures,
            signed_bytes,
            curve,
            signature_algorithm,
        })
    }

    pub fn insert_certified(&self, seq: u64, checkpoint: CertifiedNOACheckpointMessage<K>) {
        self.certified.lock().insert(seq, checkpoint);
    }

    pub fn get_certified(&self, seq: u64) -> Option<CertifiedNOACheckpointMessage<K>> {
        self.certified.lock().get(&seq).cloned()
    }
}

/// Receives raw checkpoint messages from a channel and submits them to the NOA MPC signing
/// pipeline. This replaces the V1 bridge structs (`SubmitDWalletCheckpointToNOASign` /
/// `SubmitSystemCheckpointToNOASign`) with a channel-based, independently gated path.
pub struct NOACheckpointSubmitter<K: NOACheckpointKind> {
    receiver: tokio::sync::mpsc::Receiver<Vec<K::MessageKind>>,
    noa_sign_sender: UnboundedSender<NetworkOwnedAddressSignRequest>,
    store: Arc<NOACheckpointLocalStore<K>>,
    epoch: EpochId,
    next_sequence_number: u64,
}

impl<K: NOACheckpointKind> NOACheckpointSubmitter<K> {
    pub fn new(
        receiver: tokio::sync::mpsc::Receiver<Vec<K::MessageKind>>,
        noa_sign_sender: UnboundedSender<NetworkOwnedAddressSignRequest>,
        store: Arc<NOACheckpointLocalStore<K>>,
        epoch: EpochId,
    ) -> Self {
        Self {
            receiver,
            noa_sign_sender,
            store,
            epoch,
            next_sequence_number: 0,
        }
    }

    pub async fn run(mut self) {
        info!(
            kind = K::NAME,
            epoch = self.epoch,
            "Starting NOACheckpointSubmitter"
        );

        while let Some(messages) = self.receiver.recv().await {
            let seq = self.next_sequence_number;
            self.next_sequence_number += 1;

            let checkpoint = NOACheckpointMessage {
                epoch: self.epoch,
                sequence_number: seq,
                messages,
            };

            // BCS-serialize as placeholder signable bytes.
            let signable_bytes = bcs::to_bytes(&checkpoint).unwrap_or_default();
            let all_tx_bytes = vec![signable_bytes];

            self.store
                .insert_pending(seq, checkpoint, all_tx_bytes.clone());

            info!(
                kind = K::NAME,
                sequence_number = seq,
                epoch = self.epoch,
                tx_count = all_tx_bytes.len(),
                "Submitting NOA checkpoint to MPC signing pipeline",
            );

            for tx_bytes in all_tx_bytes {
                let request = NetworkOwnedAddressSignRequest {
                    message: tx_bytes,
                    curve: K::curve(),
                    signature_algorithm: K::signature_algorithm(),
                    hash_scheme: K::hash_scheme(),
                };

                if let Err(e) = self.noa_sign_sender.send(request) {
                    error!(
                        kind = K::NAME,
                        sequence_number = seq,
                        error = %e,
                        "Failed to send NOA checkpoint sign request",
                    );
                }
            }
        }

        info!(
            kind = K::NAME,
            "NOACheckpointSubmitter channel closed, shutting down"
        );
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
            let certified = match self.store.add_signature(
                &sign_output.message,
                sign_output.signature,
                sign_output.curve,
                sign_output.signature_algorithm,
            ) {
                Some(c) => c,
                None => continue,
            };

            let seq = certified.checkpoint.sequence_number;

            info!(
                kind = K::NAME,
                sequence_number = seq,
                tx_count = certified.signatures.len(),
                "NOA checkpoint certified via MPC signature",
            );

            self.store.insert_certified(seq, certified.clone());

            if let Err(e) = self
                .certified_output
                .certified_checkpoint_created(&certified)
            {
                error!(
                    kind = K::NAME,
                    sequence_number = seq,
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
