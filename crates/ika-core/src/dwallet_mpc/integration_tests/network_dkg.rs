// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains the DWalletMPCService struct.
//! It is responsible to read DWallet MPC messages from the
//! local DB every [`READ_INTERVAL_MS`] seconds
//! and forward them to the [`DWalletMPCManager`].

use crate::SuiDataSenders;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    IntegrationTestState, send_start_network_dkg_event_to_all_parties,
};
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::{NetworkEncryptionKeyReconfigurationData, ProtocolData};
use ika_types::committee::Committee;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState, SessionIdentifier,
    SessionType,
};
use ika_types::noa_checkpoint::CounterpartyChainKind;
use std::collections::HashMap;
use std::sync::Arc;
use sui_types::base_types::{EpochId, ObjectID};
use sui_types::messages_consensus::Round;
use tracing::{error, info};

#[tokio::test]
#[cfg(test)]
async fn test_network_dkg_full_flow() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let (
        dwallet_mpc_services,
        sui_data_senders,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        network_owned_address_sign_request_senders,
        network_owned_address_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services(4);
    let mut test_state = utils::IntegrationTestState {
        dwallet_mpc_services,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee,
        sui_data_senders,
        network_owned_address_sign_request_senders,
        network_owned_address_sign_output_receivers,
    };
    create_network_key_test(&mut test_state).await;
}

#[tokio::test]
#[cfg(test)]
async fn test_network_key_reconfiguration() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let epoch_id = 1;
    let (
        dwallet_mpc_services,
        sui_data_senders,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        network_owned_address_sign_request_senders,
        network_owned_address_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services(4);
    let mut test_state = IntegrationTestState {
        dwallet_mpc_services,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee: committee.clone(),
        sui_data_senders,
        network_owned_address_sign_request_senders,
        network_owned_address_sign_output_receivers,
    };
    let (consensus_round, _, key_id) = create_network_key_test(&mut test_state).await;
    let (
        next_epoch_dwallet_mpc_services,
        _next_epoch_sui_data_senders,
        _next_epoch_sent_consensus_messages_collectors,
        _next_epoch_epoch_stores,
        _next_epoch_notify_services,
        _next_epoch_network_owned_address_sign_request_senders,
        _next_epoch_network_owned_address_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services(4);
    let mut next_committee = (*next_epoch_dwallet_mpc_services[0].committee.clone()).clone();
    next_committee.epoch = epoch_id + 1;
    test_state
        .sui_data_senders
        .iter()
        .for_each(|sui_data_sender| {
            let _ = sui_data_sender
                .next_epoch_committee_sender
                .send(next_committee.clone());
        });
    send_start_network_key_reconfiguration_event(
        epoch_id,
        &mut test_state.sui_data_senders,
        [3u8; 32],
        3,
        key_id,
    );
    let (_, reconfiguration_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    info!(
        ?reconfiguration_checkpoint,
        "Network key reconfiguration checkpoint received"
    );
    let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(message) =
        reconfiguration_checkpoint
            .messages()
            .first()
            .expect("Expected a message")
    else {
        error!("Expected a RespondDWalletMPCNetworkReconfigurationOutput message");
        panic!("Test failed due to unexpected message type");
    };
    assert!(
        !message.rejected,
        "Network key reconfiguration should not be rejected"
    );
}

pub(crate) async fn create_network_key_test(
    test_state: &mut IntegrationTestState,
) -> (Round, Vec<u8>, ObjectID) {
    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }
    let epoch_id = test_state
        .dwallet_mpc_services
        .first()
        .expect("At least one service should exist")
        .epoch;
    send_start_network_dkg_event_to_all_parties(epoch_id, test_state).await;
    let (consensus_round, network_key_checkpoint) =
        utils::advance_mpc_flow_until_completion(test_state, 1).await;
    info!(?network_key_checkpoint, "Network key checkpoint received");
    assert!(
        consensus_round >= 5,
        "Network DKG should complete at round 5 or later (got {})",
        consensus_round
    );

    let mut network_key_bytes = vec![];
    let mut key_id = None;
    for message in network_key_checkpoint.messages() {
        let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput(message) = message
        else {
            continue;
        };
        key_id =
            Some(ObjectID::from_bytes(message.dwallet_network_encryption_key_id.clone()).unwrap());
        network_key_bytes.extend(message.public_output.clone())
    }
    test_state
        .sui_data_senders
        .iter()
        .for_each(|sui_data_sender| {
            let _ = sui_data_sender
                .network_keys_sender
                .send(Arc::new(HashMap::from([(
                    key_id.unwrap(),
                    DWalletNetworkEncryptionKeyData {
                        id: key_id.unwrap(),
                        current_epoch: 1,
                        dkg_at_epoch: 1,
                        current_reconfiguration_public_output: vec![],
                        network_dkg_public_output: network_key_bytes.clone(),
                        state: DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration,
                    },
                )])));
        });
    // Generate status updates containing the key data from each party's service loop.
    // At this point, `last_read_consensus_round = consensus_round - 1` for all parties
    // (the completion run processed `consensus_round - 1` inside
    // `advance_mpc_flow_until_completion`, and `consensus_round` was already distributed
    // there on the return path). The first service loop run below will process
    // `consensus_round` from storage, setting `last_read = consensus_round`.
    // We therefore distribute the key data status updates at `consensus_round + 1` so
    // that the second service loop run can read the new round and install the key.
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }
    // Distribute the key data status updates at a fresh round so that
    // `handle_status_updates` can vote on them and `instantiate_agreed_keys_from_voted_data`
    // can populate `network_keys` in each party's manager.
    utils::send_advance_results_between_parties(
        &test_state.committee,
        &mut test_state.sent_consensus_messages_collectors,
        &mut test_state.epoch_stores,
        consensus_round + 1,
    );
    // Process the new round to instantiate the agreed network key in every party.
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }
    // Verify every validator installed the network key before returning.
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        assert!(
            service
                .dwallet_mpc_manager()
                .network_keys
                .get_network_encryption_key_public_data(&key_id.unwrap())
                .is_ok(),
            "Validator {} should have network key {:?} installed after DKG and status voting",
            i,
            key_id.unwrap()
        );
    }
    // Return the next unused consensus round so callers start from the correct round.
    (consensus_round + 2, network_key_bytes, key_id.unwrap())
}

/// Bootstraps K0 via the normal DKG flow, then runs a SECOND
/// network DKG (K1) in the same epoch and verifies that both keys
/// end up installed in every validator's `DWalletMPCManager`.
///
/// This exercises the multi-key code paths that the production
/// off-chain pipeline depends on: the per-key
/// `agreed_network_key_data` quorum, `instantiate_agreed_keys_from_voted_data`'s
/// ability to install more than one key per epoch, and the
/// per-key digest/blob caches.
#[tokio::test]
#[cfg(test)]
async fn test_two_network_keys_same_epoch_dkg() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let (
        dwallet_mpc_services,
        sui_data_senders,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        network_owned_address_sign_request_senders,
        network_owned_address_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services(4);
    let mut test_state = IntegrationTestState {
        dwallet_mpc_services,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee,
        sui_data_senders,
        network_owned_address_sign_request_senders,
        network_owned_address_sign_output_receivers,
    };

    // K0 — bootstrap. `create_network_key_test` returns the next
    // consensus round to start from, K0's public output bytes,
    // and K0's id; it also asserts every validator installed K0.
    let (next_round_after_k0, k0_bytes, k0_id) = create_network_key_test(&mut test_state).await;

    // K1 — a fresh DKG in the same epoch, distinct
    // `session_identifier_preimage` and `key_id`. Drive the MPC
    // flow to completion the same way `create_network_key_test`
    // does for K0, then pull K1's public output out of the
    // resulting checkpoint message.
    let epoch_id = test_state
        .dwallet_mpc_services
        .first()
        .expect("at least one service should exist")
        .epoch;
    let k1_id = ObjectID::random();
    let all_parties: Vec<usize> = (0..test_state.sui_data_senders.len()).collect();
    utils::send_configurable_start_network_dkg_event(
        epoch_id,
        &mut test_state.sui_data_senders,
        [2u8; 32],
        2,
        &all_parties,
        k1_id,
    );
    let (round_after_k1, k1_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, next_round_after_k0).await;

    let mut k1_bytes = Vec::new();
    for message in k1_checkpoint.messages() {
        let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput(message) = message
        else {
            continue;
        };
        let id = ObjectID::from_bytes(message.dwallet_network_encryption_key_id.clone()).unwrap();
        assert_eq!(id, k1_id, "K1 DKG checkpoint should reference K1's id");
        k1_bytes.extend(message.public_output.clone());
    }
    assert!(
        !k1_bytes.is_empty(),
        "K1 network DKG checkpoint should carry non-empty public output"
    );
    assert_ne!(k1_bytes, k0_bytes, "K1 output should differ from K0");

    // Publish a snapshot of BOTH keys to the `network_keys` watch
    // channel so each validator's service-loop iteration sees the
    // full set when it tallies `NetworkKeyData` votes and runs
    // `instantiate_agreed_keys_from_voted_data`.
    let both_keys = Arc::new(HashMap::from([
        (
            k0_id,
            DWalletNetworkEncryptionKeyData {
                id: k0_id,
                current_epoch: epoch_id,
                dkg_at_epoch: epoch_id,
                current_reconfiguration_public_output: vec![],
                network_dkg_public_output: k0_bytes.clone(),
                state: DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration,
            },
        ),
        (
            k1_id,
            DWalletNetworkEncryptionKeyData {
                id: k1_id,
                current_epoch: epoch_id,
                dkg_at_epoch: epoch_id,
                current_reconfiguration_public_output: vec![],
                network_dkg_public_output: k1_bytes.clone(),
                state: DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration,
            },
        ),
    ]));
    test_state.sui_data_senders.iter().for_each(|sender| {
        let _ = sender.network_keys_sender.send(both_keys.clone());
    });

    // First service-loop pass: each party emits its
    // `NetworkKeyData` consensus vote for both keys. Second pass
    // (after `send_advance_results_between_parties` distributes
    // those votes) reaches quorum and calls
    // `instantiate_agreed_keys_from_voted_data`, populating
    // `manager.network_keys`.
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }
    utils::send_advance_results_between_parties(
        &test_state.committee,
        &mut test_state.sent_consensus_messages_collectors,
        &mut test_state.epoch_stores,
        round_after_k1 + 1,
    );
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }

    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let net_keys = &service.dwallet_mpc_manager().network_keys;
        assert!(
            net_keys
                .get_network_encryption_key_public_data(&k0_id)
                .is_ok(),
            "validator {i} should still have K0 ({k0_id:?}) installed after K1 DKG",
        );
        assert!(
            net_keys
                .get_network_encryption_key_public_data(&k1_id)
                .is_ok(),
            "validator {i} should have K1 ({k1_id:?}) installed after second DKG + status voting",
        );
    }
}

pub(crate) fn send_start_network_key_reconfiguration_event(
    epoch_id: EpochId,
    sui_data_senders: &mut [SuiDataSenders],
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    dwallet_network_encryption_key_id: ObjectID,
) {
    sui_data_senders.iter().for_each(|sui_data_sender| {
        info!(
            "Sending DWalletEncryptionKeyReconfigurationRequestEvent to epoch {}",
            epoch_id
        );
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DWalletSessionRequest {
                counterparty_chain: Some(CounterpartyChainKind::Sui),
                session_type: SessionType::System,
                session_identifier: SessionIdentifier::new(
                    SessionType::System,
                    session_identifier_preimage,
                ),
                session_sequence_number: Some(session_sequence_number),
                protocol_data: ProtocolData::NetworkEncryptionKeyReconfiguration {
                    data: NetworkEncryptionKeyReconfigurationData {},
                    dwallet_network_encryption_key_id,
                },
                epoch: 1,
                requires_network_key_data: true,
                requires_next_active_committee: true,
                pulled: false,
            }],
            epoch_id,
        ));
    });
}

/// Validates the multi-key `NetworkKeyData` re-broadcast path:
/// after K0 is installed, simulate an off-chain reconfig output
/// update by pushing a *new* `DWalletNetworkEncryptionKeyData`
/// shape to `network_keys_sender` (same `id`, same DKG bytes,
/// non-empty `current_reconfiguration_public_output`). The
/// `dwallet_mpc_service` should detect the content change via its
/// fingerprint, re-emit `NetworkKeyData` to consensus, and the
/// receiver-side `agreed_network_key_data` should overwrite with
/// the new shape. Before the fix that lives next to this test,
/// the broadcast was one-shot and the updated reconfig output
/// never propagated to lagging validators.
#[tokio::test]
#[cfg(test)]
async fn test_network_key_data_rebroadcast_on_reconfig_output_change() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let (
        dwallet_mpc_services,
        sui_data_senders,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        network_owned_address_sign_request_senders,
        network_owned_address_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services(4);
    let mut test_state = IntegrationTestState {
        dwallet_mpc_services,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee,
        sui_data_senders,
        network_owned_address_sign_request_senders,
        network_owned_address_sign_output_receivers,
    };

    // Bootstrap K0 + assert every validator has it installed.
    let (next_round, k0_bytes, k0_id) = create_network_key_test(&mut test_state).await;

    // Sanity: at this point every validator's
    // `agreed_network_key_data` should hold K0 with empty
    // `current_reconfiguration_public_output`.
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let agreed = service
            .dwallet_mpc_manager()
            .agreed_network_key_data
            .get(&k0_id)
            .unwrap_or_else(|| panic!("validator {i} missing K0 in agreed_network_key_data"));
        assert!(
            agreed.current_reconfiguration_public_output.is_empty(),
            "validator {i} K0 should start with empty reconfig output"
        );
    }

    // Simulate an off-chain reconfig output arriving on the chain
    // snapshot — same K0 id, same DKG bytes, but now a non-empty
    // reconfig output blob.
    let reconfig_output: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
    let updated = Arc::new(HashMap::from([(
        k0_id,
        DWalletNetworkEncryptionKeyData {
            id: k0_id,
            current_epoch: 1,
            dkg_at_epoch: 1,
            current_reconfiguration_public_output: reconfig_output.clone(),
            network_dkg_public_output: k0_bytes.clone(),
            state: DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted,
        },
    )]));
    test_state.sui_data_senders.iter().for_each(|sender| {
        let _ = sender.network_keys_sender.send(updated.clone());
    });

    // First pass: each validator detects the content fingerprint
    // change and emits a fresh `NetworkKeyData` vote.
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }
    utils::send_advance_results_between_parties(
        &test_state.committee,
        &mut test_state.sent_consensus_messages_collectors,
        &mut test_state.epoch_stores,
        next_round,
    );
    // Second pass: with the votes distributed, the receiver side
    // hits quorum on the new content and overwrites
    // `agreed_network_key_data` with the reconfig-output-bearing
    // shape.
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }

    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let agreed = service
            .dwallet_mpc_manager()
            .agreed_network_key_data
            .get(&k0_id)
            .unwrap_or_else(|| panic!("validator {i} lost K0 from agreed map"));
        assert_eq!(
            agreed.current_reconfiguration_public_output, reconfig_output,
            "validator {i} did not pick up the updated reconfig output bytes — \
             rebroadcast path or content-only fingerprint regressed"
        );
        assert!(
            matches!(
                agreed.state,
                DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted
            ),
            "validator {i} K0 state should track the updated shape"
        );
    }
}
