// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains the DWalletMPCService struct.
//! It is responsible to read DWallet MPC messages from the
//! local DB every [`READ_INTERVAL_MS`] seconds
//! and forward them to the [`DWalletMPCManager`].

use crate::consensus_adapter::SubmitToConsensus;
use crate::dwallet_checkpoints::PendingDWalletCheckpoint;
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
#[cfg(test)]
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
    let mut mpc_round = 1;
    loop {
        if let Some(pending_checkpoint) = advance_all_parties_and_wait_for_completions(
            &committee,
            &mut dwallet_mpc_services,
            &mut sent_consensus_messages_collectors,
            &epoch_stores,
        )
        .await
        {
            info!(?pending_checkpoint, "MPC flow completed successfully");
            break;
        }

        send_advance_results_between_parties(
            &committee,
            &mut sent_consensus_messages_collectors,
            &mut epoch_stores,
            mpc_round,
        );
        mpc_round += 1;
    }
}

fn send_advance_results_between_parties(
    committee: &Committee,
    sent_consensus_messages_collectors: &mut Vec<Arc<TestingSubmitToConsensus>>,
    epoch_stores: &mut Vec<Arc<TestingAuthorityPerEpochStore>>,
    new_data_round: Round,
) {
    for i in 0..committee.voting_rights.len() {
        let consensus_messages_store = sent_consensus_messages_collectors[i]
            .submitted_messages
            .clone();
        let consensus_messages = consensus_messages_store.lock().unwrap().clone();
        consensus_messages_store.lock().unwrap().clear();
        let dwallet_messages: Vec<_> = consensus_messages
            .clone()
            .into_iter()
            .filter_map(|message| {
                if let ConsensusTransactionKind::DWalletMPCMessage(message) = message.kind {
                    Some(message)
                } else {
                    None
                }
            })
            .collect();
        let dwallet_outputs: Vec<_> = consensus_messages
            .into_iter()
            .filter_map(|message| {
                if let ConsensusTransactionKind::DWalletMPCOutput(message) = message.kind {
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
                .extend(dwallet_messages.clone());
            other_epoch_store
                .round_to_outputs
                .lock()
                .unwrap()
                .entry(new_data_round)
                .or_default()
                .extend(dwallet_outputs.clone());

            // The DWalletMPCService every round will have entries in all the round-specific DB tables.
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
    testing_epoch_stores: &Vec<Arc<TestingAuthorityPerEpochStore>>,
) -> Option<PendingDWalletCheckpoint> {
    let mut pending_checkpoints = vec![];
    for i in 0..committee.voting_rights.len() {
        let mut dwallet_mpc_service = dwallet_mpc_services.get_mut(i).unwrap();
        let _ = dwallet_mpc_service.run_service_loop_iteration().await;
        let consensus_messages_store = sent_consensus_messages_collectors[i]
            .submitted_messages
            .clone();
        let pending_checkpoints_store = testing_epoch_stores[i].pending_checkpoints.clone();
        loop {
            if !consensus_messages_store.lock().unwrap().is_empty() {
                break;
            }
            if !pending_checkpoints_store.lock().unwrap().is_empty() {
                // TODO (this pr): Assert the checkpoint is only get created after at least five network DKG rounds.
                
                // TODO (this pr): Assert for any thing that does not makes sense.
                
                // TODO (this pr): first check I received a checkpoint notify, and then make sure there is a pending
                // checkpoint. 

                // TODO (this pr): Make sure that functions that should not get called are not getting called.
                let pending_dwallet_checkpoint =
                    pending_checkpoints_store.lock().unwrap().pop().unwrap();
                info!(?pending_dwallet_checkpoint, party_id=?i+1, "Pending checkpoint found");
                pending_checkpoints.push(pending_dwallet_checkpoint);
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = dwallet_mpc_service.run_service_loop_iteration().await;
        }
    }
    if pending_checkpoints.len() == committee.voting_rights.len()
        && pending_checkpoints
            .iter()
            .all(|x| x.clone() == pending_checkpoints[0].clone())
    {
        return Some(pending_checkpoints[0].clone());
    }
    None
}
