// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

extern crate core;

use ika_types::committee::Committee;
use ika_types::messages_dwallet_mpc::{DBSuiEvent, DWalletNetworkEncryptionKeyData};
use std::collections::HashMap;
use std::sync::Arc;
use sui_json_rpc_types::SuiEvent;
use sui_types::base_types::{EpochId, ObjectID};
use tokio::sync::broadcast;
use tokio::sync::watch::Receiver;

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
pub mod sui_connector;

pub mod runtime;

pub struct SuiDataReceivers {
    pub network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
    pub new_events_receiver: broadcast::Receiver<Vec<SuiEvent>>,
    pub next_epoch_committee_receiver: Receiver<Committee>,
    pub last_session_to_complete_in_current_epoch_receiver: Receiver<(EpochId, u64)>,
    pub end_of_publish_receiver: Receiver<Option<u64>>,
    pub uncompleted_events_receiver: Receiver<(Vec<DBSuiEvent>, EpochId)>,
}

impl Clone for SuiDataReceivers {
    fn clone(&self) -> Self {
        Self {
            network_keys_receiver: self.network_keys_receiver.clone(),
            new_events_receiver: self.new_events_receiver.resubscribe(),
            next_epoch_committee_receiver: self.next_epoch_committee_receiver.clone(),
            last_session_to_complete_in_current_epoch_receiver: self
                .last_session_to_complete_in_current_epoch_receiver
                .clone(),
            end_of_publish_receiver: self.end_of_publish_receiver.clone(),
            uncompleted_events_receiver: self.uncompleted_events_receiver.clone(),
        }
    }
}

impl SuiDataReceivers {
    pub(crate) fn new_for_testing() -> Self {
        Self {
            network_keys_receiver: tokio::sync::watch::channel(Arc::new(HashMap::new())).1,
            new_events_receiver: broadcast::channel(100).1,
            next_epoch_committee_receiver: tokio::sync::watch::channel(
                Committee::new_simple_test_committee().0,
            )
            .1,
            last_session_to_complete_in_current_epoch_receiver: tokio::sync::watch::channel((
                EpochId::default(),
                0,
            ))
            .1,
            end_of_publish_receiver: tokio::sync::watch::channel(None).1,
            uncompleted_events_receiver: tokio::sync::watch::channel((
                Vec::new(),
                EpochId::default(),
            ))
            .1,
        }
    }
}
