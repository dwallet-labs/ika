// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

extern crate core;

use dwallet_session_request::DWalletSessionRequest;
use ika_types::committee::Committee;
use ika_types::messages_dwallet_mpc::DWalletNetworkEncryptionKeyData;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use sui_types::base_types::{EpochId, ObjectID};
use tokio::sync::broadcast;
use tokio::sync::watch::Receiver;
use tracing::debug;

pub mod authority;
pub mod consensus_adapter;
pub mod consensus_handler;
pub mod consensus_manager;
pub mod consensus_throughput_calculator;
pub(crate) mod consensus_types;
pub mod consensus_validator;
pub mod dwallet_checkpoints;
pub mod epoch;
pub mod metrics;
pub mod mysticeti_adapter;
mod scoring_decision;
mod stake_aggregator;
pub mod storage;
pub mod system_checkpoints;

pub mod dwallet_mpc;
pub mod noa_checkpoints;
pub mod sui_connector;

mod dwallet_session_request;
mod request_protocol_data;
pub mod runtime;

pub struct SuiDataReceivers {
    pub network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
    /// Shared across all per-epoch consumers via `Arc<Mutex<_>>`.
    ///
    /// Previously this used `broadcast::Receiver::resubscribe()` on clone, but
    /// `resubscribe()` only delivers messages produced AFTER the subscribe call.
    /// During an epoch transition (old service shuts down, new one spawns and
    /// resubscribes), any broadcast sent in that window is lost — including the
    /// mid-epoch reconfiguration event emitted right after `advance_epoch` —
    /// which wedges the chain forever: the on-chain `system.started_sessions_count`
    /// ticks up but no validator picks the event up, so `system.completed_sessions_count`
    /// never catches up and end-of-epoch is blocked. Sharing one Receiver across
    /// epochs preserves the receiver's read position, so events buffered in the
    /// broadcast channel survive the transition.
    pub new_requests_receiver: Arc<Mutex<broadcast::Receiver<Vec<DWalletSessionRequest>>>>,
    pub next_epoch_committee_receiver: Receiver<Committee>,
    pub last_session_to_complete_in_current_epoch_receiver: Receiver<(EpochId, u64)>,
    pub end_of_publish_receiver: Receiver<Option<u64>>,
    pub uncompleted_requests_receiver: Receiver<(Vec<DWalletSessionRequest>, EpochId)>,
}

impl Clone for SuiDataReceivers {
    fn clone(&self) -> Self {
        Self {
            network_keys_receiver: self.network_keys_receiver.clone(),
            // Share — do NOT resubscribe (see field doc).
            new_requests_receiver: self.new_requests_receiver.clone(),
            next_epoch_committee_receiver: self.next_epoch_committee_receiver.clone(),
            last_session_to_complete_in_current_epoch_receiver: self
                .last_session_to_complete_in_current_epoch_receiver
                .clone(),
            end_of_publish_receiver: self.end_of_publish_receiver.clone(),
            uncompleted_requests_receiver: self.uncompleted_requests_receiver.clone(),
        }
    }
}

#[cfg(test)]
pub struct SuiDataSenders {
    pub network_keys_sender:
        tokio::sync::watch::Sender<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
    pub new_events_sender: broadcast::Sender<Vec<DWalletSessionRequest>>,
    pub next_epoch_committee_sender: tokio::sync::watch::Sender<Committee>,
    pub last_session_to_complete_in_current_epoch_sender:
        tokio::sync::watch::Sender<(EpochId, u64)>,
    pub end_of_publish_sender: tokio::sync::watch::Sender<Option<u64>>,
    pub uncompleted_events_sender:
        tokio::sync::watch::Sender<(Vec<DWalletSessionRequest>, EpochId)>,
}

#[cfg(test)]
impl SuiDataReceivers {
    pub(crate) fn new_for_testing() -> (Self, SuiDataSenders) {
        let (network_keys_sender, network_keys_receiver) =
            tokio::sync::watch::channel(Arc::new(HashMap::new()));
        let (new_events_sender, new_events_receiver) = broadcast::channel(100);
        let (next_epoch_committee_sender, next_epoch_committee_receiver) =
            tokio::sync::watch::channel(Committee::new_simple_test_committee().0);
        let (
            last_session_to_complete_in_current_epoch_sender,
            last_session_to_complete_in_current_epoch_receiver,
        ) = tokio::sync::watch::channel((EpochId::default(), 0));
        let (end_of_publish_sender, end_of_publish_receiver) = tokio::sync::watch::channel(None);
        let (uncompleted_events_sender, uncompleted_events_receiver) =
            tokio::sync::watch::channel((Vec::new(), EpochId::default()));
        let senders = SuiDataSenders {
            network_keys_sender,
            new_events_sender,
            next_epoch_committee_sender,
            last_session_to_complete_in_current_epoch_sender,
            end_of_publish_sender,
            uncompleted_events_sender,
        };
        (
            SuiDataReceivers {
                network_keys_receiver,
                new_requests_receiver: Arc::new(Mutex::new(new_events_receiver)),
                next_epoch_committee_receiver,
                last_session_to_complete_in_current_epoch_receiver,
                end_of_publish_receiver,
                uncompleted_requests_receiver: uncompleted_events_receiver,
            },
            senders,
        )
    }
}

pub fn debug_variable_chunks(msg: &str, name: &str, data: &[u8]) {
    debug_variable_chunks_impl_with_size(msg, name, data, 16 * 1024);
}

/// Allows custom chunk size if you ever want 4KB, 32KB, etc.
pub fn debug_variable_chunks_impl_with_size(msg: &str, name: &str, data: &[u8], chunk_size: usize) {
    if data.is_empty() {
        return;
    }

    for (i, chunk) in data.chunks(chunk_size).enumerate() {
        let hex = hex::encode(chunk);
        debug!(
            message = %msg,
            variable = %name,
            part = i + 1,
            total_parts = data.len().div_ceil(chunk_size),
            bytes = chunk.len(),
            value = %hex,
        );
    }
}
