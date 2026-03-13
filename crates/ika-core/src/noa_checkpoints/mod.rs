// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use ika_types::noa_checkpoint::{
    CertifiedNOACheckpointMessage, ChainDestination, NOACheckpointCommand, NOACheckpointKind,
    NOACheckpointMessage, NOACheckpointTxObservation, NOACheckpointTxRef, NOACheckpointTxStatus,
};
use sui_types::base_types::EpochId;
use tracing::{error, info, warn};

use crate::dwallet_mpc::{NetworkOwnedAddressSignOutput, NetworkOwnedAddressSignRequest};

// === TxExecutionStatus ===

/// Tri-state result of checking a transaction's on-chain status.
#[derive(Clone, Debug)]
pub enum TxExecutionStatus {
    /// Transaction confirmed on-chain.
    Executed,
    /// Transaction not yet executed, still potentially valid.
    Pending,
    /// Transaction definitively failed (expired, reverted, etc.).
    Failed(String),
}

// === NOAChainSubmitter Trait ===

/// Abstracts submitting signed transactions to a destination chain and checking execution.
#[async_trait]
pub trait NOAChainSubmitter<K: NOACheckpointKind>: Send + Sync + 'static {
    /// Submit a signed transaction to the chain. Returns a chain-specific tx identifier.
    async fn submit_tx(&self, tx_bytes: &[u8], signature: &[u8]) -> Result<Vec<u8>, anyhow::Error>;

    /// Check a previously submitted transaction's on-chain status.
    async fn check_tx_status(
        &self,
        tx_identifier: &[u8],
    ) -> Result<TxExecutionStatus, anyhow::Error>;
}

/// No-op chain submitter that logs operations and always reports execution success.
/// Used as a placeholder until actual chain submission is implemented.
// TODO: delete it once we have a real implementation
pub struct LogOnlyChainSubmitter;

#[async_trait]
impl<K: NOACheckpointKind> NOAChainSubmitter<K> for LogOnlyChainSubmitter {
    async fn submit_tx(&self, tx_bytes: &[u8], signature: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        info!(
            tx_len = tx_bytes.len(),
            sig_len = signature.len(),
            "LogOnly: would submit tx to chain"
        );
        Ok(tx_bytes.to_vec())
    }

    async fn check_tx_status(
        &self,
        _tx_identifier: &[u8],
    ) -> Result<TxExecutionStatus, anyhow::Error> {
        Ok(TxExecutionStatus::Executed)
    }
}

// === NOACheckpointLocalStore ===

/// All per-transaction state, unified in one struct.
struct TxState<K: NOACheckpointKind> {
    /// This tx's message subset (used to regenerate bytes on retry).
    messages: Vec<K::MessageKind>,
    /// Current transaction bytes (was the IndexMap key, now a field).
    current_tx_bytes: Vec<u8>,
    /// Signature from MPC signing (None until signed).
    signature: Option<Vec<u8>>,
    /// Finalization status (None until submitted to chain).
    finalization_status: Option<NOACheckpointTxStatus>,
    /// Chain-specific transaction identifier (set after chain submission).
    chain_tx_id: Option<Vec<u8>>,
    /// Whether this validator has voted failure in the current retry round.
    voted_failed: bool,
    /// Per-tx retry round — incremented each time this tx is re-signed.
    retry_round: u32,
}

/// Consolidated per-checkpoint state. One entry per sequence number.
struct NOACheckpointEntry<K: NOACheckpointKind> {
    checkpoint: NOACheckpointMessage<K>,
    /// Per-tx state indexed by tx_index directly. Order = split_messages() output order.
    transactions: Vec<TxState<K>>,
    /// Cached certified checkpoint (built once all signatures collected on initial signing).
    certified: Option<CertifiedNOACheckpointMessage<K>>,
}

/// In-memory store for locally computed NOA checkpoints awaiting certification.
/// A single checkpoint may produce multiple sign requests (one per transaction).
/// The store tracks individual tx bytes → (sequence number, tx_index) mappings so
/// that incoming sign outputs can be routed back to the correct checkpoint and tx.
///
/// Owned by a single `NOACheckpointHandler<K>` — no Mutex needed.
///
/// NOTE: Entirely in-memory — no crash recovery. If the node restarts, state is
/// reconstructed from consensus replay during epoch initialization. This is safe
/// because the handler re-derives checkpoints deterministically from consensus
/// messages.
pub struct NOACheckpointLocalStore<K: NOACheckpointKind> {
    /// Maps individual tx bytes → (checkpoint sequence number, tx_index).
    tx_to_seq: HashMap<Vec<u8>, (u64, usize)>,
    /// All per-checkpoint state, keyed by sequence number.
    entries: HashMap<u64, NOACheckpointEntry<K>>,
}

impl<K: NOACheckpointKind> Default for NOACheckpointLocalStore<K> {
    fn default() -> Self {
        Self {
            tx_to_seq: HashMap::new(),
            entries: HashMap::new(),
        }
    }
}

impl<K: NOACheckpointKind> NOACheckpointLocalStore<K> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pending checkpoint with all its (tx_bytes, message_subset) pairs.
    pub fn insert_pending(
        &mut self,
        seq: u64,
        checkpoint: NOACheckpointMessage<K>,
        tx_data: Vec<(Vec<u8>, Vec<K::MessageKind>)>,
    ) {
        let transactions: Vec<TxState<K>> = tx_data
            .into_iter()
            .enumerate()
            .map(|(idx, (bytes, messages))| {
                self.tx_to_seq.insert(bytes.clone(), (seq, idx));
                TxState {
                    messages,
                    current_tx_bytes: bytes,
                    signature: None,
                    finalization_status: None,
                    chain_tx_id: None,
                    voted_failed: false,
                    retry_round: 0,
                }
            })
            .collect();

        self.entries.insert(
            seq,
            NOACheckpointEntry {
                checkpoint,
                transactions,
                certified: None,
            },
        );
    }

    /// Record a signature for a single transaction.
    /// Handles both initial signing and retry.
    /// Returns `Some(certified)` only on initial signing when all signatures are collected.
    /// On completion, stores the certified checkpoint directly in the entry.
    pub fn add_signature(
        &mut self,
        tx_bytes: &[u8],
        signature: Vec<u8>,
        curve: dwallet_mpc_types::dwallet_mpc::DWalletCurve,
        signature_algorithm: dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm,
    ) -> Option<CertifiedNOACheckpointMessage<K>> {
        let &(seq, tx_index) = match self.tx_to_seq.get(tx_bytes) {
            Some(pair) => pair,
            None => {
                warn!(
                    tx_bytes_len = tx_bytes.len(),
                    "add_signature: tx_to_seq lookup failed — no pending checkpoint for these tx bytes"
                );
                return None;
            }
        };
        self.tx_to_seq.remove(tx_bytes);

        let entry = self.entries.get_mut(&seq)?;
        let tx_state = entry.transactions.get_mut(tx_index)?;
        tx_state.signature = Some(signature);

        // Only build certified on initial signing, not retry.
        if entry.certified.is_some() {
            return None;
        }
        if !entry.transactions.iter().all(|t| t.signature.is_some()) {
            return None;
        }

        // Build certified — Vec iteration preserves insertion order.
        let signatures = entry
            .transactions
            .iter()
            .filter_map(|t| t.signature.clone())
            .collect();
        let signed_bytes = entry
            .transactions
            .iter()
            .map(|t| t.current_tx_bytes.clone())
            .collect();

        let certified = CertifiedNOACheckpointMessage {
            checkpoint: entry.checkpoint.clone(),
            signatures,
            signed_bytes,
            curve,
            signature_algorithm,
        };

        entry.certified = Some(certified.clone());
        Some(certified)
    }

    pub fn get_certified(&self, seq: u64) -> Option<CertifiedNOACheckpointMessage<K>> {
        self.entries.get(&seq).and_then(|e| e.certified.clone())
    }

    // === Finalization tracking methods ===

    /// Record that a transaction has been submitted to the chain.
    pub fn mark_submitted(&mut self, tx_ref: NOACheckpointTxRef, chain_tx_id: Vec<u8>) {
        let Some(entry) = self.entries.get_mut(&tx_ref.sequence_number) else {
            return;
        };
        let Some(tx_state) = entry.transactions.get_mut(tx_ref.tx_index as usize) else {
            return;
        };
        tx_state.finalization_status = Some(NOACheckpointTxStatus::Pending);
        tx_state.chain_tx_id = Some(chain_tx_id);
    }

    /// Mark a transaction as confirmed locally (this validator verified on-chain execution).
    pub fn mark_confirmed_locally(&mut self, tx_ref: &NOACheckpointTxRef) {
        if let Some(state) = self
            .entries
            .get_mut(&tx_ref.sequence_number)
            .and_then(|e| e.transactions.get_mut(tx_ref.tx_index as usize))
        {
            state.finalization_status = Some(NOACheckpointTxStatus::ConfirmedLocally);
        }
    }

    /// Mark a transaction as finalized (2f+1 validators confirmed on-chain execution).
    pub fn mark_finalized(&mut self, tx_ref: &NOACheckpointTxRef) {
        if let Some(state) = self
            .entries
            .get_mut(&tx_ref.sequence_number)
            .and_then(|e| e.transactions.get_mut(tx_ref.tx_index as usize))
        {
            state.finalization_status = Some(NOACheckpointTxStatus::Finalized);
        }
    }

    /// Get the current status of a transaction.
    pub fn get_status(&self, tx_ref: &NOACheckpointTxRef) -> Option<NOACheckpointTxStatus> {
        self.entries
            .get(&tx_ref.sequence_number)
            .and_then(|e| e.transactions.get(tx_ref.tx_index as usize))
            .and_then(|s| s.finalization_status.clone())
    }

    /// Check if all tracked transactions are finalized.
    /// Returns true when every tracked tx (not just submitted ones) is Finalized.
    pub fn all_finalized(&self) -> bool {
        let all_txs: Vec<_> = self
            .entries
            .values()
            .flat_map(|e| e.transactions.iter())
            .collect();
        !all_txs.is_empty()
            && all_txs
                .iter()
                .all(|t| t.finalization_status.as_ref() == Some(&NOACheckpointTxStatus::Finalized))
    }

    /// Returns true if no finalization entries have been registered.
    pub fn has_no_finalization_entries(&self) -> bool {
        self.entries
            .values()
            .flat_map(|e| e.transactions.iter())
            .all(|t| t.finalization_status.is_none())
    }

    /// Returns all non-finalized tx_refs (those with a finalization_status that is not Finalized).
    pub fn get_pending_refs(&self) -> Vec<NOACheckpointTxRef> {
        self.entries
            .iter()
            .flat_map(|(&seq, entry)| {
                entry
                    .transactions
                    .iter()
                    .enumerate()
                    .filter(|(_, t)| {
                        t.finalization_status
                            .as_ref()
                            .is_some_and(|s| *s != NOACheckpointTxStatus::Finalized)
                    })
                    .map(move |(idx, _)| NOACheckpointTxRef {
                        kind_name: K::KIND_NAME,
                        sequence_number: seq,
                        tx_index: idx as u32,
                        epoch: entry.checkpoint.epoch,
                    })
            })
            .collect()
    }

    /// Prepare a single tx for retry with regenerated bytes from fresh context.
    /// Sets status to RetryPending, clears signature/chain_tx_id/voted_failed,
    /// increments per-tx retry_round, rebuilds tx_bytes, and re-registers in tx_to_seq.
    ///
    /// NOTE: There is intentionally no maximum retry limit. All NOA checkpoint
    /// transactions MUST eventually succeed — the epoch cannot transition until
    /// every checkpoint is finalized. If a transaction fails permanently, manual
    /// operator intervention is required to unblock the network. This is by design:
    /// dropping a checkpoint would violate the integrity of the checkpoint chain.
    pub fn initiate_tx_retry(
        &mut self,
        tx_ref: &NOACheckpointTxRef,
        context: &<K::Destination as ChainDestination>::Context,
        noa_public_key: &[u8],
    ) -> Option<Vec<u8>> {
        let entry = self.entries.get_mut(&tx_ref.sequence_number)?;
        let tx_index = tx_ref.tx_index as usize;
        let tx_state = entry.transactions.get_mut(tx_index)?;
        let old_tx_bytes = tx_state.current_tx_bytes.clone();
        tx_state.finalization_status = Some(NOACheckpointTxStatus::RetryPending);
        tx_state.chain_tx_id = None;
        tx_state.signature = None;
        tx_state.voted_failed = false;
        tx_state.retry_round += 1;

        let new_tx_bytes = K::build_tx_bytes(
            entry.checkpoint.epoch,
            tx_ref.sequence_number,
            tx_ref.tx_index,
            &tx_state.messages,
            context,
            noa_public_key,
            tx_state.retry_round,
        );

        tx_state.current_tx_bytes = new_tx_bytes.clone();

        // Update routing: remove old key, insert new key.
        self.tx_to_seq.remove(&old_tx_bytes);
        self.tx_to_seq
            .insert(new_tx_bytes.clone(), (tx_ref.sequence_number, tx_index));

        Some(new_tx_bytes)
    }

    /// Returns the stored chain tx identifier for a given tx_ref.
    pub fn get_chain_tx_id(&self, tx_ref: &NOACheckpointTxRef) -> Option<Vec<u8>> {
        self.entries
            .get(&tx_ref.sequence_number)
            .and_then(|e| e.transactions.get(tx_ref.tx_index as usize))
            .and_then(|s| s.chain_tx_id.clone())
    }

    /// Returns the current per-tx retry round.
    pub fn get_retry_round(&self, tx_ref: &NOACheckpointTxRef) -> u32 {
        self.entries
            .get(&tx_ref.sequence_number)
            .and_then(|e| e.transactions.get(tx_ref.tx_index as usize))
            .map(|s| s.retry_round)
            .unwrap_or(0)
    }

    /// Returns whether this validator has voted failure for the given tx in the current round.
    pub fn has_voted_failed(&self, tx_ref: &NOACheckpointTxRef) -> bool {
        self.entries
            .get(&tx_ref.sequence_number)
            .and_then(|e| e.transactions.get(tx_ref.tx_index as usize))
            .map(|s| s.voted_failed)
            .unwrap_or(false)
    }

    /// Record that this validator has voted failure for the given tx.
    pub fn set_voted_failed(&mut self, tx_ref: &NOACheckpointTxRef) {
        if let Some(state) = self
            .entries
            .get_mut(&tx_ref.sequence_number)
            .and_then(|e| e.transactions.get_mut(tx_ref.tx_index as usize))
        {
            state.voted_failed = true;
        }
    }

    /// Returns whether the given tx has a signature stored.
    pub fn has_signature(&self, tx_ref: &NOACheckpointTxRef) -> bool {
        self.entries
            .get(&tx_ref.sequence_number)
            .and_then(|e| e.transactions.get(tx_ref.tx_index as usize))
            .is_some_and(|s| s.signature.is_some())
    }

    /// Returns (tx_bytes, signature) for a tx that's ready for (re-)submission.
    pub fn get_tx_for_submission(&self, tx_ref: &NOACheckpointTxRef) -> Option<(Vec<u8>, Vec<u8>)> {
        let entry = self.entries.get(&tx_ref.sequence_number)?;
        let tx_state = entry.transactions.get(tx_ref.tx_index as usize)?;
        let signature = tx_state.signature.as_ref()?;
        Some((tx_state.current_tx_bytes.clone(), signature.clone()))
    }
}

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
        chain_context: <K::Destination as ChainDestination>::Context,
    ) -> Vec<NetworkOwnedAddressSignRequest> {
        let seq = self.next_sequence_number;
        self.next_sequence_number += 1;

        let checkpoint = NOACheckpointMessage {
            epoch: self.epoch,
            sequence_number: seq,
            messages: messages.clone(),
        };

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

        info!(
            kind = K::NAME,
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
                curve: K::CURVE,
                signature_algorithm: K::SIGNATURE_ALGORITHM,
                hash_scheme: K::HASH_SCHEME,
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
            kind = K::NAME,
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

    /// Apply a quorum command (MarkFinalized or RetryWithContext).
    /// Returns sign requests for retries.
    pub fn handle_command(
        &mut self,
        cmd: NOACheckpointCommand<K::Destination>,
    ) -> Vec<NetworkOwnedAddressSignRequest> {
        match cmd {
            NOACheckpointCommand::MarkFinalized(tx_ref) => {
                self.store.mark_finalized(&tx_ref);
                vec![]
            }
            NOACheckpointCommand::RetryWithContext { tx_ref, context } => {
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
                                    kind = K::NAME,
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
                                        kind = K::NAME,
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
                                    kind = K::NAME,
                                    sequence_number = tx_ref.sequence_number,
                                    tx_index = tx_ref.tx_index,
                                    error = %e,
                                    "Failed to check NOA checkpoint tx execution status"
                                );
                            }
                        }
                    }
                }
                NOACheckpointTxStatus::ConfirmedLocally => {
                    // Waiting for MarkFinalized command from MPC service — no-op.
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
                    kind = K::NAME,
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
                        kind = K::NAME,
                        sequence_number = seq,
                        tx_index,
                        "Submitted NOA checkpoint tx to chain"
                    );
                    self.store.mark_submitted(tx_ref, chain_tx_id);
                }
                Err(e) => {
                    error!(
                        kind = K::NAME,
                        sequence_number = seq,
                        tx_index,
                        error = %e,
                        "Failed to submit NOA checkpoint tx to chain"
                    );
                    // Mark as pending so all_finalized() sees this tx and the
                    // handler doesn't stall.
                    self.store.mark_submitted(tx_ref, vec![]);
                }
            }
        }
    }

    fn initiate_tx_retry_with_context(
        &mut self,
        tx_ref: &NOACheckpointTxRef,
        context: &<K::Destination as ChainDestination>::Context,
    ) -> Option<NetworkOwnedAddressSignRequest> {
        let tx_bytes = self
            .store
            .initiate_tx_retry(tx_ref, context, &self.noa_public_key)?;

        info!(
            kind = K::NAME,
            sequence_number = tx_ref.sequence_number,
            tx_index = tx_ref.tx_index,
            "Initiating per-tx retry: 2f+1 failure quorum reached"
        );

        Some(NetworkOwnedAddressSignRequest {
            message: tx_bytes,
            curve: K::CURVE,
            signature_algorithm: K::SIGNATURE_ALGORITHM,
            hash_scheme: K::HASH_SCHEME,
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
                    kind = K::NAME,
                    sequence_number = tx_ref.sequence_number,
                    tx_index = tx_ref.tx_index,
                    "Submitted retry tx to chain"
                );
                self.store.mark_submitted(tx_ref.clone(), chain_tx_id);
            }
            Err(e) => {
                error!(
                    kind = K::NAME,
                    sequence_number = tx_ref.sequence_number,
                    tx_index = tx_ref.tx_index,
                    error = %e,
                    "Failed to submit retry tx to chain"
                );
            }
        }
    }
}
