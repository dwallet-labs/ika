// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub mod checkpoint_output;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::noa_checkpoint::{
    CertifiedNOACheckpointMessage, ChainDestination, NOACheckpointKind, NOACheckpointMessage,
    NOACheckpointTxRef, NOACheckpointTxStatus,
};
use sui_types::base_types::EpochId;
use tokio::sync::mpsc::{Receiver, UnboundedSender};
use tracing::{error, info, warn};

use crate::dwallet_mpc::{NetworkOwnedAddressSignOutput, NetworkOwnedAddressSignRequest};
use checkpoint_output::CertifiedNOACheckpointOutput;
use ika_types::crypto::AuthorityName;

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

/// Per-transaction finalization state within a checkpoint entry.
struct TxFinalizationState {
    status: NOACheckpointTxStatus,
    /// Chain-specific transaction identifier (set after submission).
    chain_tx_id: Option<Vec<u8>>,
    /// Whether this validator has voted failure for this tx in the current retry round.
    voted_failed: bool,
}

/// Consolidated per-checkpoint state. One entry per sequence number.
struct NOACheckpointEntry<K: NOACheckpointKind> {
    checkpoint: NOACheckpointMessage<K>,
    expected_tx_bytes: Vec<Vec<u8>>,
    /// Signing phase: tx_bytes → signature.
    collected_signatures: HashMap<Vec<u8>, Vec<u8>>,
    /// Set once all signatures collected (by `add_signature`).
    certified: Option<CertifiedNOACheckpointMessage<K>>,
    /// Per-tx finalization (indexed by tx_index, populated on chain submission).
    tx_states: Vec<TxFinalizationState>,
    /// Retry tracking — incremented each time a failure quorum triggers re-signing.
    retry_round: u32,
}

/// In-memory store for locally computed NOA checkpoints awaiting certification.
/// A single checkpoint may produce multiple sign requests (one per transaction).
/// The store tracks individual tx bytes → sequence number mappings so that
/// incoming sign outputs can be routed back to the correct checkpoint.
pub struct NOACheckpointLocalStore<K: NOACheckpointKind> {
    /// Maps individual tx bytes → checkpoint sequence number (routing index,
    /// kept as a separate lock to reduce contention on the main `entries` map).
    tx_to_seq: parking_lot::Mutex<HashMap<Vec<u8>, u64>>,
    /// All per-checkpoint state, keyed by sequence number.
    entries: parking_lot::Mutex<HashMap<u64, NOACheckpointEntry<K>>>,
}

impl<K: NOACheckpointKind> Default for NOACheckpointLocalStore<K> {
    fn default() -> Self {
        Self {
            tx_to_seq: parking_lot::Mutex::new(HashMap::new()),
            entries: parking_lot::Mutex::new(HashMap::new()),
        }
    }
}

impl<K: NOACheckpointKind> NOACheckpointLocalStore<K> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pending checkpoint with all its transaction byte vectors.
    /// On retry (entry already exists): clears signatures, clears certified,
    /// increments retry_round, and resets voted_failed on all tx_states.
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

        let mut entries = self.entries.lock();
        if let Some(entry) = entries.get_mut(&seq) {
            // Retry case: reset signing state, preserve finalization tracking.
            entry.checkpoint = checkpoint;
            entry.expected_tx_bytes = tx_bytes;
            entry.collected_signatures.clear();
            entry.certified = None;
            entry.retry_round += 1;
            for tx_state in &mut entry.tx_states {
                tx_state.voted_failed = false;
            }
        } else {
            entries.insert(
                seq,
                NOACheckpointEntry {
                    checkpoint,
                    expected_tx_bytes: tx_bytes,
                    collected_signatures: HashMap::new(),
                    certified: None,
                    tx_states: Vec::new(),
                    retry_round: 0,
                },
            );
        }
    }

    /// Record a signature for a single transaction.
    /// Returns `Some(certified)` when all transactions for that checkpoint are signed.
    /// On completion, stores the certified checkpoint directly in the entry.
    pub fn add_signature(
        &self,
        tx_bytes: &[u8],
        signature: Vec<u8>,
        curve: dwallet_mpc_types::dwallet_mpc::DWalletCurve,
        signature_algorithm: dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm,
    ) -> Option<CertifiedNOACheckpointMessage<K>> {
        let seq = {
            let tx_to_seq = self.tx_to_seq.lock();
            match tx_to_seq.get(tx_bytes) {
                Some(&s) => s,
                None => {
                    warn!(
                        tx_bytes_len = tx_bytes.len(),
                        "add_signature: tx_to_seq lookup failed — no pending checkpoint for these tx bytes"
                    );
                    return None;
                }
            }
        };

        let mut entries = self.entries.lock();
        let entry = entries.get_mut(&seq)?;
        entry
            .collected_signatures
            .insert(tx_bytes.to_vec(), signature);

        if entry.collected_signatures.len() < entry.expected_tx_bytes.len() {
            return None;
        }

        // All signatures collected — build certified checkpoint.
        let signatures = entry
            .expected_tx_bytes
            .iter()
            .map(|tx| entry.collected_signatures[tx].clone())
            .collect();
        let signed_bytes = entry.expected_tx_bytes.clone();

        // Clean up tx_to_seq entries.
        let mut tx_to_seq = self.tx_to_seq.lock();
        for bytes in &signed_bytes {
            tx_to_seq.remove(bytes);
        }

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
        self.entries
            .lock()
            .get(&seq)
            .and_then(|e| e.certified.clone())
    }

    // === Finalization tracking methods ===

    /// Record that a transaction has been submitted to the chain.
    pub fn mark_submitted(&self, tx_ref: NOACheckpointTxRef, chain_tx_id: Vec<u8>) {
        let mut entries = self.entries.lock();
        let Some(entry) = entries.get_mut(&tx_ref.sequence_number) else {
            return;
        };
        let idx = tx_ref.tx_index as usize;
        // Grow tx_states if needed (first submission for this checkpoint).
        if entry.tx_states.len() <= idx {
            entry
                .tx_states
                .resize_with(idx + 1, || TxFinalizationState {
                    status: NOACheckpointTxStatus::Pending,
                    chain_tx_id: None,
                    voted_failed: false,
                });
        }
        entry.tx_states[idx].status = NOACheckpointTxStatus::Pending;
        entry.tx_states[idx].chain_tx_id = Some(chain_tx_id);
        entry.tx_states[idx].voted_failed = false;
    }

    /// Mark a transaction as confirmed locally (this validator verified on-chain execution).
    pub fn mark_confirmed_locally(&self, tx_ref: &NOACheckpointTxRef) {
        let mut entries = self.entries.lock();
        if let Some(state) = entries
            .get_mut(&tx_ref.sequence_number)
            .and_then(|e| e.tx_states.get_mut(tx_ref.tx_index as usize))
        {
            state.status = NOACheckpointTxStatus::ConfirmedLocally;
        }
    }

    /// Mark a transaction as finalized (2f+1 validators confirmed on-chain execution).
    pub fn mark_finalized(&self, tx_ref: &NOACheckpointTxRef) {
        let mut entries = self.entries.lock();
        if let Some(state) = entries
            .get_mut(&tx_ref.sequence_number)
            .and_then(|e| e.tx_states.get_mut(tx_ref.tx_index as usize))
        {
            state.status = NOACheckpointTxStatus::Finalized;
        }
    }

    /// Get the current status of a transaction.
    pub fn get_status(&self, tx_ref: &NOACheckpointTxRef) -> Option<NOACheckpointTxStatus> {
        self.entries
            .lock()
            .get(&tx_ref.sequence_number)
            .and_then(|e| e.tx_states.get(tx_ref.tx_index as usize))
            .map(|s| s.status.clone())
    }

    /// Check if all tracked transactions are finalized.
    pub fn all_finalized(&self) -> bool {
        let entries = self.entries.lock();
        let has_any = entries.values().any(|e| !e.tx_states.is_empty());
        has_any
            && entries
                .values()
                .flat_map(|e| &e.tx_states)
                .all(|s| s.status == NOACheckpointTxStatus::Finalized)
    }

    /// Returns true if no finalization entries have been registered.
    pub fn has_no_finalization_entries(&self) -> bool {
        self.entries.lock().values().all(|e| e.tx_states.is_empty())
    }

    /// Returns all non-finalized tx_refs.
    pub fn get_pending_refs(&self) -> Vec<NOACheckpointTxRef> {
        let entries = self.entries.lock();
        entries
            .iter()
            .flat_map(|(&seq, entry)| {
                entry
                    .tx_states
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.status != NOACheckpointTxStatus::Finalized)
                    .map(move |(idx, _)| NOACheckpointTxRef {
                        kind_name: K::kind_name(),
                        sequence_number: seq,
                        tx_index: idx as u32,
                        epoch: entry.checkpoint.epoch,
                    })
            })
            .collect()
    }

    /// Mark a transaction as retry-pending (2f+1 failure votes received).
    /// Clears the chain_tx_id so the retry cycle starts fresh.
    pub fn mark_retry_pending(&self, tx_ref: &NOACheckpointTxRef) {
        let mut entries = self.entries.lock();
        if let Some(state) = entries
            .get_mut(&tx_ref.sequence_number)
            .and_then(|e| e.tx_states.get_mut(tx_ref.tx_index as usize))
        {
            state.status = NOACheckpointTxStatus::RetryPending;
            state.chain_tx_id = None;
        }
    }

    /// Returns the stored chain tx identifier for a given tx_ref.
    pub fn get_chain_tx_id(&self, tx_ref: &NOACheckpointTxRef) -> Option<Vec<u8>> {
        self.entries
            .lock()
            .get(&tx_ref.sequence_number)
            .and_then(|e| e.tx_states.get(tx_ref.tx_index as usize))
            .and_then(|s| s.chain_tx_id.clone())
    }

    /// Returns the current retry round for a checkpoint.
    pub fn get_retry_round(&self, seq: u64) -> u32 {
        self.entries
            .lock()
            .get(&seq)
            .map(|e| e.retry_round)
            .unwrap_or(0)
    }

    /// Returns whether this validator has voted failure for the given tx in the current round.
    pub fn has_voted_failed(&self, tx_ref: &NOACheckpointTxRef) -> bool {
        self.entries
            .lock()
            .get(&tx_ref.sequence_number)
            .and_then(|e| e.tx_states.get(tx_ref.tx_index as usize))
            .map(|s| s.voted_failed)
            .unwrap_or(false)
    }

    /// Record that this validator has voted failure for the given tx.
    pub fn set_voted_failed(&self, tx_ref: &NOACheckpointTxRef) {
        let mut entries = self.entries.lock();
        if let Some(state) = entries
            .get_mut(&tx_ref.sequence_number)
            .and_then(|e| e.tx_states.get_mut(tx_ref.tx_index as usize))
        {
            state.voted_failed = true;
        }
    }
}

// === NOACheckpointSubmitter ===

/// Receives raw checkpoint messages from a channel and submits them to the NOA MPC signing
/// pipeline via `K::signable_bytes()`, which converts checkpoint data into chain-specific
/// transaction bytes for NOA signing.
pub struct NOACheckpointSubmitter<K: NOACheckpointKind> {
    receiver: tokio::sync::mpsc::Receiver<Vec<K::MessageKind>>,
    noa_sign_sender: UnboundedSender<NetworkOwnedAddressSignRequest>,
    store: Arc<NOACheckpointLocalStore<K>>,
    epoch: EpochId,
    next_sequence_number: u64,
    chain_context: <K::Destination as ChainDestination>::Context,
    noa_public_key: Vec<u8>,
}

impl<K: NOACheckpointKind> NOACheckpointSubmitter<K> {
    pub fn new(
        receiver: tokio::sync::mpsc::Receiver<Vec<K::MessageKind>>,
        noa_sign_sender: UnboundedSender<NetworkOwnedAddressSignRequest>,
        store: Arc<NOACheckpointLocalStore<K>>,
        epoch: EpochId,
        chain_context: <K::Destination as ChainDestination>::Context,
        noa_public_key: Vec<u8>,
    ) -> Self {
        Self {
            receiver,
            noa_sign_sender,
            store,
            epoch,
            next_sequence_number: 0,
            chain_context,
            noa_public_key,
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

            let all_tx_bytes =
                K::signable_bytes(&checkpoint, &self.chain_context, &self.noa_public_key);

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

// === NOACheckpointCertifier ===

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
                epoch = certified.checkpoint.epoch,
                messages_count = certified.checkpoint.messages.len(),
                tx_count = certified.signatures.len(),
                curve = ?certified.curve,
                signature_algorithm = ?certified.signature_algorithm,
                certified_checkpoint = ?certified,
                "NOA checkpoint certified via MPC signature",
            );

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

// === NOACheckpointFinalizer ===

/// Core retry and finalization loop for NOA checkpoint transactions.
/// One instance per checkpoint kind (DWallet, System).
///
/// Polls the chain for execution confirmation of certified checkpoint transactions,
/// submits finalization/failure votes via consensus, and coordinates retry on failure quorum.
pub struct NOACheckpointFinalizer<K: NOACheckpointKind> {
    store: Arc<NOACheckpointLocalStore<K>>,
    chain_submitter: Arc<dyn NOAChainSubmitter<K>>,
    noa_sign_sender: UnboundedSender<NetworkOwnedAddressSignRequest>,
    finalization_vote_sender: tokio::sync::mpsc::Sender<ConsensusTransaction>,
    epoch: EpochId,
    authority_name: AuthorityName,
    chain_context: <K::Destination as ChainDestination>::Context,
    noa_public_key: Vec<u8>,
    poll_interval: Duration,
    /// Callback to check if a tx_ref has reached 2f+1 finalization quorum in the epoch store.
    is_finalized: Arc<dyn Fn(&NOACheckpointTxRef) -> bool + Send + Sync>,
    /// Callback to check if a tx_ref has reached 2f+1 failure quorum for a given retry_round.
    is_failure_quorum: Arc<dyn Fn(&NOACheckpointTxRef, u32) -> bool + Send + Sync>,
    /// Receives notifications when a checkpoint is certified (initial or retry).
    certified_checkpoint_receiver: tokio::sync::mpsc::Receiver<u64>,
}

impl<K: NOACheckpointKind> NOACheckpointFinalizer<K> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<NOACheckpointLocalStore<K>>,
        chain_submitter: Arc<dyn NOAChainSubmitter<K>>,
        noa_sign_sender: UnboundedSender<NetworkOwnedAddressSignRequest>,
        finalization_vote_sender: tokio::sync::mpsc::Sender<ConsensusTransaction>,
        epoch: EpochId,
        authority_name: AuthorityName,
        chain_context: <K::Destination as ChainDestination>::Context,
        noa_public_key: Vec<u8>,
        poll_interval: Duration,
        is_finalized: Arc<dyn Fn(&NOACheckpointTxRef) -> bool + Send + Sync>,
        is_failure_quorum: Arc<dyn Fn(&NOACheckpointTxRef, u32) -> bool + Send + Sync>,
        certified_checkpoint_receiver: tokio::sync::mpsc::Receiver<u64>,
    ) -> Self {
        Self {
            store,
            chain_submitter,
            noa_sign_sender,
            finalization_vote_sender,
            epoch,
            authority_name,
            chain_context,
            noa_public_key,
            poll_interval,
            is_finalized,
            is_failure_quorum,
            certified_checkpoint_receiver,
        }
    }

    pub async fn run(mut self) {
        info!(
            kind = K::NAME,
            epoch = self.epoch,
            poll_interval_secs = self.poll_interval.as_secs(),
            "Starting NOACheckpointFinalizer"
        );

        let mut interval = tokio::time::interval(self.poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.poll_loop().await;
                }
                Some(seq) = self.certified_checkpoint_receiver.recv() => {
                    self.submit_certified_checkpoint(seq).await;
                }
            }

            if !self.store.has_no_finalization_entries() && self.store.all_finalized() {
                info!(
                    kind = K::NAME,
                    epoch = self.epoch,
                    "All NOA checkpoints finalized, stopping finalizer"
                );
                return;
            }
        }
    }

    async fn poll_loop(&self) {
        if self.store.has_no_finalization_entries() {
            return;
        }

        let pending_refs = self.store.get_pending_refs();
        for tx_ref in pending_refs {
            let status = match self.store.get_status(&tx_ref) {
                Some(s) => s,
                None => continue,
            };

            match status {
                NOACheckpointTxStatus::Pending => {
                    // 1. Finalization quorum takes precedence.
                    if (self.is_finalized)(&tx_ref) {
                        self.store.mark_finalized(&tx_ref);
                        continue;
                    }

                    // 2. Check chain tx status (tri-state).
                    if let Some(chain_tx_id) = self.store.get_chain_tx_id(&tx_ref) {
                        match self.chain_submitter.check_tx_status(&chain_tx_id).await {
                            Ok(TxExecutionStatus::Executed) => {
                                info!(
                                    kind = K::NAME,
                                    sequence_number = tx_ref.sequence_number,
                                    tx_index = tx_ref.tx_index,
                                    "NOA checkpoint tx confirmed on-chain, submitting finalization vote"
                                );
                                self.store.mark_confirmed_locally(&tx_ref);
                                self.send_finalization_vote(&tx_ref).await;
                                continue;
                            }
                            Ok(TxExecutionStatus::Pending) => {
                                // Still pending — wait for next poll.
                            }
                            Ok(TxExecutionStatus::Failed(reason)) => {
                                if !self.store.has_voted_failed(&tx_ref) {
                                    let retry_round =
                                        self.store.get_retry_round(tx_ref.sequence_number);
                                    warn!(
                                        kind = K::NAME,
                                        sequence_number = tx_ref.sequence_number,
                                        tx_index = tx_ref.tx_index,
                                        retry_round,
                                        reason = %reason,
                                        "NOA checkpoint tx failed on-chain, voting failure"
                                    );
                                    self.send_failure_vote(&tx_ref, retry_round).await;
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

                    // 3. Check failure quorum (regardless of local vote status).
                    let retry_round = self.store.get_retry_round(tx_ref.sequence_number);
                    if (self.is_failure_quorum)(&tx_ref, retry_round) {
                        self.initiate_retry(&tx_ref).await;
                    }
                }
                NOACheckpointTxStatus::ConfirmedLocally => {
                    // Propagate epoch store quorum to local store.
                    if (self.is_finalized)(&tx_ref) {
                        self.store.mark_finalized(&tx_ref);
                    }
                }
                NOACheckpointTxStatus::RetryPending => {
                    // Finalization always takes precedence — abort retry if finalized.
                    if (self.is_finalized)(&tx_ref) {
                        self.store.mark_finalized(&tx_ref);
                    }
                    // Otherwise waiting for MPC re-signing — no action.
                }
                NOACheckpointTxStatus::Finalized => {
                    // Should not appear in pending_refs.
                }
            }
        }
    }

    /// Submit a certified checkpoint's transactions to the chain and register them
    /// for finalization tracking.
    pub async fn submit_certified_checkpoint(&self, seq: u64) {
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
                kind_name: K::kind_name(),
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
                }
            }
        }
    }

    async fn send_finalization_vote(&self, tx_ref: &NOACheckpointTxRef) {
        let vote =
            ConsensusTransaction::new_noa_checkpoint_finalized(self.authority_name, tx_ref.clone());
        if let Err(e) = self.finalization_vote_sender.send(vote).await {
            error!(
                kind = K::NAME,
                sequence_number = tx_ref.sequence_number,
                error = %e,
                "Failed to send NOA finalization vote"
            );
        }
    }

    async fn send_failure_vote(&self, tx_ref: &NOACheckpointTxRef, retry_round: u32) {
        let vote = ConsensusTransaction::new_noa_checkpoint_tx_failed(
            self.authority_name,
            tx_ref.clone(),
            retry_round,
        );
        if let Err(e) = self.finalization_vote_sender.send(vote).await {
            error!(
                kind = K::NAME,
                sequence_number = tx_ref.sequence_number,
                error = %e,
                "Failed to send NOA failure vote"
            );
        }
    }

    async fn initiate_retry(&self, tx_ref: &NOACheckpointTxRef) {
        let certified = match self.store.get_certified(tx_ref.sequence_number) {
            Some(c) => c,
            None => return,
        };

        info!(
            kind = K::NAME,
            sequence_number = tx_ref.sequence_number,
            "Initiating retry: 2f+1 failure quorum reached"
        );

        // Mark ALL tx_refs for this checkpoint as RetryPending.
        for i in 0..certified.signed_bytes.len() {
            let ref_i = NOACheckpointTxRef {
                kind_name: K::kind_name(),
                sequence_number: tx_ref.sequence_number,
                tx_index: i as u32,
                epoch: tx_ref.epoch,
            };
            self.store.mark_retry_pending(&ref_i);
        }

        // Reconstruct tx_bytes and re-enter the signing pipeline.
        // insert_pending handles retry state reset (increments retry_round,
        // clears voted_failed, clears signatures/certified).
        let all_tx_bytes = K::signable_bytes(
            &certified.checkpoint,
            &self.chain_context,
            &self.noa_public_key,
        );
        self.store.insert_pending(
            tx_ref.sequence_number,
            certified.checkpoint.clone(),
            all_tx_bytes.clone(),
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
                    sequence_number = tx_ref.sequence_number,
                    error = %e,
                    "Failed to send retry sign request"
                );
            }
        }
    }
}
