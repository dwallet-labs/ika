// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains the DWalletMPCService struct.
//! It is responsible to read DWallet MPC messages from the
//! local DB every [`READ_INTERVAL_MS`] seconds
//! and forward them to the [`DWalletMPCManager`].

use crate::SuiDataSenders;
use crate::dwallet_mpc::crytographic_computation::mpc_computations::network_dkg::instantiate_dwallet_mpc_network_encryption_key_public_data_from_public_output;
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

/// Like [`create_network_key_test`] but additionally runs a network reconfiguration
/// (to the **same** committee at the next epoch) and installs the resulting **V3
/// reconfiguration output** on every validator's network key.
///
/// Fast Schnorr (VSS) sign requires a reconfigured key: the DKG-only public output
/// does not expose the per-curve secret-key polynomial commitments / masked parts
/// the VSS sign reads, and each validator recovers its Shamir share from the
/// reconfiguration dealings using its own (seed-derived, hence committee-stable)
/// PVSS key — so reconfiguring to the *same* committee keeps those shares
/// recoverable by the signing validators.
///
/// Returns `(next_unused_consensus_round, network_dkg_public_output_bytes, network_key_id)`.
pub(crate) async fn create_reconfigured_network_key_test(
    test_state: &mut IntegrationTestState,
) -> (Round, Vec<u8>, ObjectID) {
    let (consensus_round, network_key_bytes, key_id) = create_network_key_test(test_state).await;
    let consensus_round = reconfigure_network_key(
        test_state,
        consensus_round,
        key_id,
        network_key_bytes.clone(),
    )
    .await;
    (consensus_round, network_key_bytes, key_id)
}

/// Runs a network reconfiguration (to the same key-bearing committee at the next
/// epoch) on an already-created network key, then installs the resulting V3
/// reconfiguration output on every validator's key in place. Returns the next
/// unused consensus round.
///
/// Split out of [`create_reconfigured_network_key_test`] so a caller can create
/// dWallets *before* reconfiguring — the dWallet DKG runs against the pre-reconfig
/// key, exactly as the user-driven sign flow does.
pub(crate) async fn reconfigure_network_key(
    test_state: &mut IntegrationTestState,
    consensus_round: Round,
    key_id: ObjectID,
    network_key_bytes: Vec<u8>,
) -> Round {
    let epoch_id = test_state
        .dwallet_mpc_services
        .first()
        .expect("at least one service should exist")
        .epoch;

    // Reconfigure to the same validators at the next epoch. Use the services'
    // key-bearing committee, NOT `test_state.committee` (the simple/keyless
    // committee used only for message routing): reconfiguration decodes the
    // upcoming committee members' published class-groups + PVSS key bundles, which
    // only the key-bearing committee carries. Same validators ⇒ the signing
    // validators can still recover their Shamir shares from the reconfig dealings.
    let mut next_committee = (*test_state.dwallet_mpc_services[0].committee).clone();
    next_committee.epoch = epoch_id + 1;
    for sui_data_sender in &test_state.sui_data_senders {
        let _ = sui_data_sender
            .next_epoch_committee_sender
            .send(next_committee.clone());
    }

    send_start_network_key_reconfiguration_event(
        epoch_id,
        &mut test_state.sui_data_senders,
        [10u8; 32],
        10,
        key_id,
    );

    let (consensus_round, reconfiguration_checkpoint) =
        utils::advance_mpc_flow_until_completion(test_state, consensus_round).await;

    // Reassemble the (chunked) reconfiguration public output across all
    // `RespondDWalletMPCNetworkReconfigurationOutput` messages. These bytes are
    // already `bcs(VersionedDecryptionKeyReconfigurationOutput::V3(..))`, so they go
    // into `current_reconfiguration_public_output` verbatim.
    let mut reconfiguration_output_bytes = vec![];
    for message in reconfiguration_checkpoint.messages() {
        let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(message) =
            message
        else {
            continue;
        };
        assert!(!message.rejected, "reconfiguration should not be rejected");
        reconfiguration_output_bytes.extend(message.public_output.clone());
    }
    assert!(
        !reconfiguration_output_bytes.is_empty(),
        "reconfiguration output should not be empty"
    );

    // Install the V3 reconfiguration output on every validator's network key.
    // `create_network_key_test` installed the key with an EMPTY reconfiguration
    // output (DKG-only public data, which VSS sign rejects). The consensus
    // status-vote path cannot carry this update: it dedups already-agreed keys
    // (`handle_network_key_data_messages`) and already-loaded keys
    // (`instantiate_agreed_keys_from_voted_data`). In production the reconfigured key
    // is loaded fresh by the next-epoch manager; here we update each manager's key in
    // place via the same path the installer uses (`update_network_key`).
    for service in test_state.dwallet_mpc_services.iter_mut() {
        let manager = service.dwallet_mpc_manager_mut();
        let access_structure = manager.access_structure.clone();
        let reconfigured_key_data = DWalletNetworkEncryptionKeyData {
            id: key_id,
            current_epoch: epoch_id,
            dkg_at_epoch: 1,
            current_reconfiguration_public_output: reconfiguration_output_bytes.clone(),
            network_dkg_public_output: network_key_bytes.clone(),
            state: DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted,
        };
        let reconfigured_key =
            instantiate_dwallet_mpc_network_encryption_key_public_data_from_public_output(
                epoch_id,
                access_structure.clone(),
                reconfigured_key_data,
            )
            .await
            .expect("instantiate reconfigured network key public data");
        manager
            .network_keys
            .update_network_key(key_id, &reconfigured_key, &access_structure)
            .await
            .expect("update validator network key with reconfiguration output");
    }

    // Verify every validator now exposes a reconfiguration output on the key.
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let public_data = service
            .dwallet_mpc_manager()
            .network_keys
            .get_network_encryption_key_public_data(&key_id)
            .unwrap_or_else(|e| {
                panic!("validator {i} should have the reconfigured network key installed: {e:?}")
            });
        assert!(
            public_data
                .latest_network_reconfiguration_public_output()
                .is_some(),
            "validator {i} should expose a reconfiguration output after reconfiguration",
        );
    }

    consensus_round
}
