// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains the DWalletMPCService struct.
//! It is responsible to read DWallet MPC messages from the
//! local DB every [`READ_INTERVAL_MS`] seconds
//! and forward them to the [`DWalletMPCManager`].

use crate::consensus_adapter::SubmitToConsensus;
use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    TestingAuthorityPerEpochStore, TestingSubmitToConsensus,
};
use crate::dwallet_mpc::mpc_manager::DWalletMPCManager;
use crate::epoch::submit_to_consensus::DWalletMPCSubmitToConsensus;
use ika_types::committee::Committee;
use ika_types::messages_consensus::ConsensusTransactionKind;
use ika_types::messages_dwallet_mpc::{DBSuiEvent, IkaNetworkConfig};
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkDKGEncryptionKeyRequestEvent, DWalletSessionEvent, DWalletSessionEventTrait,
};
use ika_types::sui::EpochStartSystemTrait;
use itertools::Itertools;
use std::sync::Arc;
use std::time::Duration;
use sui_types::messages_consensus::Round;
use tracing::info;

#[tokio::test]
async fn test_network_dkg_advance_with_messages() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let ika_network_config = IkaNetworkConfig::new_for_testing();
    let epoch_id = 1;
    let (
        mut dwallet_mpc_services,
        sui_data_senders,
        mut sent_consensus_messages_collectors,
        mut epoch_stores,
    ) = utils::create_dwallet_mpc_services();
    sui_data_senders.iter().for_each(|mut sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DBSuiEvent {
                type_: DWalletSessionEvent::<DWalletNetworkDKGEncryptionKeyRequestEvent>::type_(
                    &ika_network_config,
                ),
                // The base64 encoding of an actual start network DKG event.
                contents: base64::decode("Z7MmXd0I4lvGWLDA969YOVo7wrZlXr21RMvixIFabCqAU3voWC2pRFG3QwPYD+ta0sX5poLEkq77ovCi3BBQDgEAAAAAAAAAgFN76FgtqURRt0MD2A/rWtLF+aaCxJKu+6LwotwQUA4BAQAAAAAAAAAggZwXRQsb/ha4mk5xZZfqItaokplduZGMnsuEQzdm7UTt2Z+ktotfGXHn2YVaxxqVhDM8UaafXejIDXnaPLxaMAA=").unwrap(),
                pulled: true,
            }],
            epoch_id,
        ));
    });
    advance_all_parties_and_wait_for_completions(
        &committee,
        &mut dwallet_mpc_services,
        &mut sent_consensus_messages_collectors,
    )
    .await;

    send_advance_messages_between_parties(
        &committee,
        &mut sent_consensus_messages_collectors,
        &mut epoch_stores,
        1,
    );

    advance_all_parties_and_wait_for_completions(
        &committee,
        &mut dwallet_mpc_services,
        &mut sent_consensus_messages_collectors,
    )
    .await;
}

fn send_advance_messages_between_parties(
    committee: &Committee,
    sent_consensus_messages_collectors: &mut Vec<Arc<TestingSubmitToConsensus>>,
    epoch_stores: &mut Vec<Arc<TestingAuthorityPerEpochStore>>,
    new_data_round: Round,
) {
    for i in 0..committee.voting_rights.len() {
        let consensus_messages_store = sent_consensus_messages_collectors[i]
            .submitted_messages
            .clone();
        let messages = consensus_messages_store.lock().unwrap().clone();
        consensus_messages_store.lock().unwrap().clear();
        let messages: Vec<_> = messages
            .into_iter()
            .filter_map(|message| {
                if let ConsensusTransactionKind::DWalletMPCMessage(message) = message.kind {
                    Some(message)
                } else {
                    None
                }
            })
            .collect();
        for j in 0..committee.voting_rights.len() {
            let other_epoch_store = epoch_stores.get(j).unwrap();
            other_epoch_store
                .round_to_messages
                .lock()
                .unwrap()
                .entry(new_data_round)
                .or_default()
                .extend(messages.clone());

            // The DWalletMPCService every round will have entries in all the round-specific DB tables.
            other_epoch_store
                .round_to_outputs
                .lock()
                .unwrap()
                .insert(new_data_round, vec![]);
            other_epoch_store
                .round_to_verified_checkpoint
                .lock()
                .unwrap()
                .insert(new_data_round, vec![]);
        }
    }
}

async fn advance_all_parties_and_wait_for_completions(
    committee: &Committee,
    dwallet_mpc_services: &mut Vec<DWalletMPCService>,
    sent_consensus_messages_collectors: &mut Vec<Arc<TestingSubmitToConsensus>>,
) {
    for i in 0..committee.voting_rights.len() {
        let mut dwallet_mpc_service = dwallet_mpc_services.get_mut(i).unwrap();
        let _ = dwallet_mpc_service.run_service_loop_iteration().await;
        let consensus_messages_store = sent_consensus_messages_collectors[i]
            .submitted_messages
            .clone();

        loop {
            if !consensus_messages_store.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = dwallet_mpc_service.run_service_loop_iteration().await;
        }
    }
}
