// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ika_types::noa_checkpoint::{
    CounterpartyChain, NOACheckpointKind, NOACheckpointMessage, NOACheckpointResolution,
    NOACheckpointTxObservation, NOACheckpointTxRef, NOACheckpointTxStatus,
};
use sui_types::base_types::EpochId;
use tracing::{error, info, warn};

use crate::dwallet_mpc::{NetworkOwnedAddressSignOutput, NetworkOwnedAddressSignRequest};
use crate::noa_checkpoints::chain_submitter::{NOAChainSubmitter, TxExecutionStatus};
use crate::noa_checkpoints::local_store::NOACheckpointLocalStore;

// === NOACheckpointHandler ===

/// Synchronous handler that drives the full checkpoint lifecycle for a single kind.
/// Owned directly by `DWalletMPCService` — no separate tokio task or channels needed.
///
/// Lifecycle: messages → MPC sign → submit to chain → poll chain → observe →
/// consensus quorum → finalize (or retry → back to MPC sign)
pub struct NOACheckpointHandler<K: NOACheckpointKind> {
    store: NOACheckpointLocalStore<K>,
    chain_submitter: Arc<dyn NOAChainSubmitter<K>>,
    epoch: EpochId,
    next_sequence_number: u64,
    noa_public_key: Vec<u8>,
    all_finalized_flag: Arc<AtomicBool>,
}

impl<K: NOACheckpointKind> NOACheckpointHandler<K> {
    pub fn new(
        chain_submitter: Arc<dyn NOAChainSubmitter<K>>,
        epoch: EpochId,
        noa_public_key: Vec<u8>,
        all_finalized_flag: Arc<AtomicBool>,
    ) -> Self {
        Self {
            store: NOACheckpointLocalStore::new(),
            chain_submitter,
            epoch,
            next_sequence_number: 0,
            noa_public_key,
            all_finalized_flag,
        }
    }

    /// Process new checkpoint messages. Returns sign requests to submit.
    pub fn handle_new_checkpoint(
        &mut self,
        messages: Vec<K::MessageKind>,
        chain_context: <K::Counterparty as CounterpartyChain>::Context,
    ) -> Vec<NetworkOwnedAddressSignRequest> {
        let seq = self.next_sequence_number;
        self.next_sequence_number += 1;

        let message_groups = K::split_messages(&messages);
        let tx_data: Vec<(Vec<u8>, Vec<K::MessageKind>)> = message_groups
            .into_iter()
            .enumerate()
            .map(|(tx_index, group)| {
                let bytes = K::build_tx_bytes(
                    self.epoch,
                    seq,
                    tx_index as u32,
                    &group,
                    &chain_context,
                    &self.noa_public_key,
                    0,
                );
                (bytes, group)
            })
            .collect();

        let checkpoint = NOACheckpointMessage {
            epoch: self.epoch,
            sequence_number: seq,
            messages,
        };

        info!(
            kind = %K::KIND_NAME,
            sequence_number = seq,
            epoch = self.epoch,
            tx_count = tx_data.len(),
            "Submitting NOA checkpoint to MPC signing pipeline",
        );

        let tx_bytes_list: Vec<Vec<u8>> = tx_data.iter().map(|(bytes, _)| bytes.clone()).collect();
        self.store.insert_pending(seq, checkpoint, tx_data);

        tx_bytes_list
            .into_iter()
            .map(|tx_bytes| NetworkOwnedAddressSignRequest {
                message: tx_bytes,
                curve: <K::Counterparty as CounterpartyChain>::CURVE,
                signature_algorithm: <K::Counterparty as CounterpartyChain>::SIGNATURE_ALGORITHM,
                hash_scheme: <K::Counterparty as CounterpartyChain>::HASH_SCHEME,
            })
            .collect()
    }

    /// Process a completed MPC sign output.
    /// Stores signature; if all txs signed, submits to chain.
    pub async fn handle_sign_output(&mut self, sign_output: NetworkOwnedAddressSignOutput) {
        let certified = match self.store.add_signature(
            &sign_output.message,
            sign_output.signature,
            sign_output.curve,
            sign_output.signature_algorithm,
        ) {
            Some(c) => c,
            None => return,
        };

        let seq = certified.checkpoint.sequence_number;

        info!(
            kind = %K::KIND_NAME,
            sequence_number = seq,
            epoch = certified.checkpoint.epoch,
            messages_count = certified.checkpoint.messages.len(),
            tx_count = certified.signatures.len(),
            curve = ?certified.curve,
            signature_algorithm = ?certified.signature_algorithm,
            certified_checkpoint = ?certified,
            "NOA checkpoint certified via MPC signature",
        );

        self.submit_certified_checkpoint(seq).await;
    }

    /// Apply a consensus quorum resolution (Finalized or RetryWithContext).
    /// Returns sign requests for retries.
    pub fn handle_resolution(
        &mut self,
        resolution: NOACheckpointResolution<K::Counterparty>,
    ) -> Vec<NetworkOwnedAddressSignRequest> {
        match resolution {
            NOACheckpointResolution::Finalized(tx_ref) => {
                self.store.mark_finalized(&tx_ref);
                vec![]
            }
            NOACheckpointResolution::RetryWithContext { tx_ref, context } => {
                if self.store.get_status(&tx_ref) == Some(NOACheckpointTxStatus::Finalized) {
                    return vec![];
                }
                self.initiate_tx_retry_with_context(&tx_ref, &context)
                    .into_iter()
                    .collect()
            }
        }
    }

    /// Poll chain for submitted tx status.
    /// Returns observations to send through consensus.
    pub async fn poll_chain_status(&mut self) -> Vec<NOACheckpointTxObservation> {
        if self.store.has_no_finalization_entries() {
            return vec![];
        }

        let mut observations = Vec::new();
        let pending_refs = self.store.get_pending_refs();
        for tx_ref in pending_refs {
            let status = match self.store.get_status(&tx_ref) {
                Some(s) => s,
                None => continue,
            };

            match status {
                NOACheckpointTxStatus::Pending => {
                    if let Some(chain_tx_id) = self.store.get_chain_tx_id(&tx_ref) {
                        match self.chain_submitter.check_tx_status(&chain_tx_id).await {
                            Ok(TxExecutionStatus::Executed) => {
                                info!(
                                    kind = %K::KIND_NAME,
                                    sequence_number = tx_ref.sequence_number,
                                    tx_index = tx_ref.tx_index,
                                    "NOA checkpoint tx confirmed on-chain, sending finalization observation"
                                );
                                self.store.mark_confirmed_locally(&tx_ref);
                                observations.push(NOACheckpointTxObservation::Finalized(tx_ref));
                                continue;
                            }
                            Ok(TxExecutionStatus::Pending) => {
                                // Still pending — wait for next poll.
                            }
                            Ok(TxExecutionStatus::Failed(reason)) => {
                                if !self.store.has_voted_failed(&tx_ref) {
                                    let retry_round = self.store.get_retry_round(&tx_ref);
                                    warn!(
                                        kind = %K::KIND_NAME,
                                        sequence_number = tx_ref.sequence_number,
                                        tx_index = tx_ref.tx_index,
                                        retry_round,
                                        reason = %reason,
                                        "NOA checkpoint tx failed on-chain, sending failure observation"
                                    );
                                    observations.push(NOACheckpointTxObservation::Failed(
                                        tx_ref.clone(),
                                        retry_round,
                                    ));
                                    self.store.set_voted_failed(&tx_ref);
                                }
                            }
                            Err(e) => {
                                warn!(
                                    kind = %K::KIND_NAME,
                                    sequence_number = tx_ref.sequence_number,
                                    tx_index = tx_ref.tx_index,
                                    error = %e,
                                    "Failed to check NOA checkpoint tx execution status"
                                );
                            }
                        }
                    }
                }
                NOACheckpointTxStatus::SubmitFailed => {
                    // Re-attempt submission with existing tx_bytes + signature.
                    if let Some((tx_bytes, signature)) = self.store.get_tx_for_submission(&tx_ref) {
                        match self.chain_submitter.submit_tx(&tx_bytes, &signature).await {
                            Ok(chain_tx_id) => {
                                info!(
                                    kind = %K::KIND_NAME,
                                    sequence_number = tx_ref.sequence_number,
                                    tx_index = tx_ref.tx_index,
                                    "Re-submitted previously failed NOA checkpoint tx to chain"
                                );
                                self.store.mark_submitted(&tx_ref, chain_tx_id);
                            }
                            Err(e) => {
                                warn!(
                                    kind = %K::KIND_NAME,
                                    sequence_number = tx_ref.sequence_number,
                                    tx_index = tx_ref.tx_index,
                                    error = %e,
                                    "Re-submission of NOA checkpoint tx still failing"
                                );
                            }
                        }
                    }
                }
                NOACheckpointTxStatus::ConfirmedLocally => {
                    // Waiting for Finalized resolution from MPC service — no-op.
                }
                NOACheckpointTxStatus::RetryPending => {
                    // Re-signed? Submit to chain.
                    if self.store.has_signature(&tx_ref) {
                        self.submit_retry_tx(&tx_ref).await;
                    }
                }
                NOACheckpointTxStatus::Finalized => {
                    // Should not appear in pending_refs.
                }
            }
        }

        observations
    }

    /// Update the shared all_finalized AtomicBool flag.
    pub fn update_finalized_flag(&self) {
        let done = self.store.has_no_finalization_entries() || self.store.all_finalized();
        self.all_finalized_flag.store(done, Ordering::Release);
    }

    /// Submit a certified checkpoint's transactions to the chain and register them
    /// for finalization tracking.
    async fn submit_certified_checkpoint(&mut self, seq: u64) {
        let certified = match self.store.get_certified(seq) {
            Some(c) => c,
            None => {
                warn!(
                    kind = %K::KIND_NAME,
                    sequence_number = seq,
                    "Cannot submit: checkpoint not certified"
                );
                return;
            }
        };

        for (tx_index, (tx_bytes, signature)) in certified
            .signed_bytes
            .iter()
            .zip(certified.signatures.iter())
            .enumerate()
        {
            let tx_ref = NOACheckpointTxRef {
                kind_name: K::KIND_NAME,
                sequence_number: seq,
                tx_index: tx_index as u32,
                epoch: self.epoch,
            };

            match self.chain_submitter.submit_tx(tx_bytes, signature).await {
                Ok(chain_tx_id) => {
                    info!(
                        kind = %K::KIND_NAME,
                        sequence_number = seq,
                        tx_index,
                        "Submitted NOA checkpoint tx to chain"
                    );
                    self.store.mark_submitted(&tx_ref, chain_tx_id);
                }
                Err(e) => {
                    error!(
                        kind = %K::KIND_NAME,
                        sequence_number = seq,
                        tx_index,
                        error = %e,
                        "Failed to submit NOA checkpoint tx to chain"
                    );
                    self.store.mark_submit_failed(&tx_ref);
                }
            }
        }
    }

    fn initiate_tx_retry_with_context(
        &mut self,
        tx_ref: &NOACheckpointTxRef,
        context: &<K::Counterparty as CounterpartyChain>::Context,
    ) -> Option<NetworkOwnedAddressSignRequest> {
        let tx_bytes = self
            .store
            .initiate_tx_retry(tx_ref, context, &self.noa_public_key)?;

        info!(
            kind = %K::KIND_NAME,
            sequence_number = tx_ref.sequence_number,
            tx_index = tx_ref.tx_index,
            "Initiating per-tx retry: 2f+1 failure quorum reached"
        );

        Some(NetworkOwnedAddressSignRequest {
            message: tx_bytes,
            curve: <K::Counterparty as CounterpartyChain>::CURVE,
            signature_algorithm: <K::Counterparty as CounterpartyChain>::SIGNATURE_ALGORITHM,
            hash_scheme: <K::Counterparty as CounterpartyChain>::HASH_SCHEME,
        })
    }

    async fn submit_retry_tx(&mut self, tx_ref: &NOACheckpointTxRef) {
        let (tx_bytes, signature) = match self.store.get_tx_for_submission(tx_ref) {
            Some(pair) => pair,
            None => return,
        };

        match self.chain_submitter.submit_tx(&tx_bytes, &signature).await {
            Ok(chain_tx_id) => {
                info!(
                    kind = %K::KIND_NAME,
                    sequence_number = tx_ref.sequence_number,
                    tx_index = tx_ref.tx_index,
                    "Submitted retry tx to chain"
                );
                self.store.mark_submitted(tx_ref, chain_tx_id);
            }
            Err(e) => {
                error!(
                    kind = %K::KIND_NAME,
                    sequence_number = tx_ref.sequence_number,
                    tx_index = tx_ref.tx_index,
                    error = %e,
                    "Failed to submit retry tx to chain"
                );
            }
        }
    }
}
