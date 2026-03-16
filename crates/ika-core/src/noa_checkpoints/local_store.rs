// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::HashMap;

use ika_types::noa_checkpoint::{
    CertifiedNOACheckpointMessage, CounterpartyChain, NOACheckpointKind, NOACheckpointMessage,
    NOACheckpointTxRef, NOACheckpointTxStatus,
};
use tracing::{error, warn};

// === NOACheckpointLocalStore ===

/// All per-transaction state, unified in one struct.
pub(crate) struct TxState<K: NOACheckpointKind> {
    /// This tx's message subset (used to regenerate bytes on retry).
    pub(crate) messages: Vec<K::MessageKind>,
    /// Current transaction bytes (was the IndexMap key, now a field).
    pub(crate) current_tx_bytes: Vec<u8>,
    /// Signature from MPC signing (None until signed).
    pub(crate) signature: Option<Vec<u8>>,
    /// Finalization status (None until submitted to chain).
    pub(crate) finalization_status: Option<NOACheckpointTxStatus>,
    /// Chain-specific transaction identifier (set after chain submission).
    pub(crate) chain_tx_id: Option<Vec<u8>>,
    /// Whether this validator has voted failure in the current retry round.
    pub(crate) voted_failed: bool,
    /// Per-tx retry round — incremented each time this tx is re-signed.
    pub(crate) retry_round: u32,
}

/// Consolidated per-checkpoint state. One entry per sequence number.
pub(crate) struct NOACheckpointEntry<K: NOACheckpointKind> {
    pub(crate) checkpoint: NOACheckpointMessage<K>,
    /// Per-tx state indexed by tx_index directly. Order = split_messages() output order.
    pub(crate) transactions: Vec<TxState<K>>,
    /// Cached certified checkpoint (built once all signatures collected on initial signing).
    pub(crate) certified: Option<CertifiedNOACheckpointMessage<K>>,
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
                // This can happen legitimately when sign output routing sends to the
                // wrong handler (before kind_name routing is threaded). Downgraded to
                // debug because the routing fix makes this rare and it's not an error.
                tracing::debug!(
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
    pub fn mark_submitted(&mut self, tx_ref: &NOACheckpointTxRef, chain_tx_id: Vec<u8>) {
        let Some(entry) = self.entries.get_mut(&tx_ref.sequence_number) else {
            warn!(?tx_ref, "mark_submitted: unknown tx_ref, ignoring");
            return;
        };
        let Some(tx_state) = entry.transactions.get_mut(tx_ref.tx_index as usize) else {
            warn!(?tx_ref, "mark_submitted: unknown tx_index, ignoring");
            return;
        };
        if !matches!(
            tx_state.finalization_status,
            None | Some(NOACheckpointTxStatus::RetryPending)
                | Some(NOACheckpointTxStatus::SubmitFailed)
        ) {
            error!(
                current_status = ?tx_state.finalization_status,
                ?tx_ref,
                should_never_happen = true,
                "mark_submitted: unexpected status transition",
            );
            panic!(
                "mark_submitted: unexpected status {:?} for tx_ref {:?}",
                tx_state.finalization_status, tx_ref
            );
        }
        tx_state.finalization_status = Some(NOACheckpointTxStatus::Pending);
        tx_state.chain_tx_id = Some(chain_tx_id);
    }

    /// Record that a transaction submission to the chain failed.
    pub fn mark_submit_failed(&mut self, tx_ref: &NOACheckpointTxRef) {
        let Some(entry) = self.entries.get_mut(&tx_ref.sequence_number) else {
            warn!(?tx_ref, "mark_submit_failed: unknown tx_ref, ignoring");
            return;
        };
        let Some(tx_state) = entry.transactions.get_mut(tx_ref.tx_index as usize) else {
            warn!(?tx_ref, "mark_submit_failed: unknown tx_index, ignoring");
            return;
        };
        if !matches!(
            tx_state.finalization_status,
            None | Some(NOACheckpointTxStatus::SubmitFailed)
        ) {
            error!(
                current_status = ?tx_state.finalization_status,
                ?tx_ref,
                should_never_happen = true,
                "mark_submit_failed: unexpected status transition",
            );
            panic!(
                "mark_submit_failed: unexpected status {:?} for tx_ref {:?}",
                tx_state.finalization_status, tx_ref
            );
        }
        tx_state.finalization_status = Some(NOACheckpointTxStatus::SubmitFailed);
    }

    /// Mark a transaction as confirmed locally (this validator verified on-chain execution).
    pub fn mark_confirmed_locally(&mut self, tx_ref: &NOACheckpointTxRef) {
        if let Some(state) = self
            .entries
            .get_mut(&tx_ref.sequence_number)
            .and_then(|e| e.transactions.get_mut(tx_ref.tx_index as usize))
        {
            if !matches!(
                state.finalization_status,
                Some(NOACheckpointTxStatus::Pending)
            ) {
                error!(
                    current_status = ?state.finalization_status,
                    ?tx_ref,
                    should_never_happen = true,
                    "mark_confirmed_locally: unexpected status transition",
                );
                panic!(
                    "mark_confirmed_locally: unexpected status {:?} for tx_ref {:?}",
                    state.finalization_status, tx_ref
                );
            }
            state.finalization_status = Some(NOACheckpointTxStatus::ConfirmedLocally);
        } else {
            warn!(?tx_ref, "mark_confirmed_locally: unknown tx_ref, ignoring");
        }
    }

    /// Mark a transaction as finalized (2f+1 validators confirmed on-chain execution).
    pub fn mark_finalized(&mut self, tx_ref: &NOACheckpointTxRef) {
        if let Some(state) = self
            .entries
            .get_mut(&tx_ref.sequence_number)
            .and_then(|e| e.transactions.get_mut(tx_ref.tx_index as usize))
        {
            if !matches!(
                state.finalization_status,
                Some(NOACheckpointTxStatus::Pending)
                    | Some(NOACheckpointTxStatus::ConfirmedLocally)
                    | Some(NOACheckpointTxStatus::RetryPending)
                    | Some(NOACheckpointTxStatus::SubmitFailed)
            ) {
                error!(
                    current_status = ?state.finalization_status,
                    ?tx_ref,
                    should_never_happen = true,
                    "mark_finalized: unexpected status transition",
                );
                panic!(
                    "mark_finalized: unexpected status {:?} for tx_ref {:?}",
                    state.finalization_status, tx_ref
                );
            }
            state.finalization_status = Some(NOACheckpointTxStatus::Finalized);
        } else {
            warn!(?tx_ref, "mark_finalized: unknown tx_ref, ignoring");
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
        let has_txs = self.entries.values().any(|e| !e.transactions.is_empty());
        has_txs
            && self
                .entries
                .values()
                .flat_map(|e| e.transactions.iter())
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
        context: &<K::Counterparty as CounterpartyChain>::Context,
        noa_public_key: &[u8],
    ) -> Option<Vec<u8>> {
        let entry = self.entries.get_mut(&tx_ref.sequence_number)?;
        let tx_index = tx_ref.tx_index as usize;
        let tx_state = entry.transactions.get_mut(tx_index)?;
        let old_tx_bytes = tx_state.current_tx_bytes.clone();
        if !matches!(
            tx_state.finalization_status,
            Some(NOACheckpointTxStatus::Pending) | Some(NOACheckpointTxStatus::SubmitFailed)
        ) {
            error!(
                current_status = ?tx_state.finalization_status,
                ?tx_ref,
                should_never_happen = true,
                "initiate_tx_retry: unexpected status transition",
            );
            panic!(
                "initiate_tx_retry: unexpected status {:?} for tx_ref {:?}",
                tx_state.finalization_status, tx_ref
            );
        }
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
        } else {
            warn!(?tx_ref, "set_voted_failed: unknown tx_ref, ignoring");
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
