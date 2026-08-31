// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Integration tests for the network DKG and network-key reconfiguration
//! flows, plus the shared `create_network_key_test` / `reconfigure_network_key`
//! helpers other test modules build on.

use crate::SuiDataSenders;
use crate::dwallet_mpc::crytographic_computation::mpc_computations::network_dkg::spawn_network_encryption_key_public_data_instantiation;
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

/// Partial validator keys: the committee is full (4) but only 3 validators'
/// off-chain key bundles are delivered — simulating one validator
/// offline/withholding. The network DKG must deal only to the 3 that have keys
/// and still complete (3 = quorum for n=4); the 4th stays a committee member,
/// just undealt.
///
/// This is the regression test for the all-N gate that previously rejected a
/// partial key set with `InvalidMPCPartyType` and wedged the network on a single
/// missing validator. A completed DKG output here proves the readiness is the
/// consensus freeze (agreed set), not all-N.
#[tokio::test]
#[cfg(test)]
async fn test_network_dkg_completes_with_partial_validator_keys() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, seeds, mut bundles) = utils::build_committee_with_random_seeds(4);

    // Drop one validator's ENTIRE bundle (atomic — all five maps), so the agreed
    // set covers 3 of the 4 committee members.
    let dropped = committee
        .voting_rights
        .last()
        .expect("committee has members")
        .0;
    bundles.class_groups.remove(&dropped);
    bundles.secp256k1_pvss.remove(&dropped);
    bundles.secp256r1_pvss.remove(&dropped);
    bundles.ristretto_pvss.remove(&dropped);
    bundles.vss_hpke.remove(&dropped);
    assert_eq!(
        bundles.secp256k1_pvss.len(),
        3,
        "exactly 3 of 4 validators should have keys"
    );

    let (
        dwallet_mpc_services,
        sui_data_senders,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        network_owned_address_sign_request_senders,
        network_owned_address_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services_with_committee_and_seeds(
        committee.clone(),
        seeds,
        bundles,
    );
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

    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }
    let epoch_id = test_state
        .dwallet_mpc_services
        .first()
        .expect("at least one service")
        .epoch;
    send_start_network_dkg_event_to_all_parties(epoch_id, &mut test_state).await;

    // Drive only the 3 keyed validators (the 4th is offline — no keys, not run),
    // and wait for THOSE 3 to complete. With the all-N gate in place this would
    // never complete: every keyed party rejects on `InvalidMPCPartyType` (the
    // key set is 3/4) and the request re-queues forever.
    let (consensus_round, network_key_checkpoint) =
        utils::advance_mpc_flow_until_completion_for_parties(&mut test_state, 1, &[0, 1, 2]).await;
    assert!(
        consensus_round >= 5,
        "network DKG with 3/4 validator keys should complete (got round {consensus_round})"
    );

    let mut produced_key = false;
    for message in network_key_checkpoint.messages() {
        if let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput(message) = message {
            assert!(
                !message.public_output.is_empty(),
                "network DKG should produce a non-empty public output dealing to the 3-validator subset"
            );
            produced_key = true;
        }
    }
    assert!(
        produced_key,
        "expected a RespondDWalletMPCNetworkDKGOutput from the partial-keys DKG"
    );
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
    // The upcoming committee: a fresh validator set (its own seeds). Its
    // off-chain PVSS/VSS keys travel on the next-epoch key channel (no longer on
    // `Committee`), so deliver both the committee and its bundles — reconfig
    // encrypts the dealings under the upcoming parties' PVSS keys.
    let (mut next_committee, _next_seeds, next_bundles) =
        utils::build_committee_with_random_seeds(4);
    next_committee.epoch = epoch_id + 1;
    test_state
        .sui_data_senders
        .iter()
        .for_each(|sui_data_sender| {
            let _ = sui_data_sender
                .next_epoch_committee_sender
                .send(next_committee.clone());
            let _ = sui_data_sender
                .next_epoch_mpc_keys_sender
                .send(Some((next_committee.epoch, next_bundles.clone())));
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

/// Partial UPCOMING keys: reconfigure into a full (4-member) next committee where
/// only 3 of the upcoming validators delivered off-chain keys. The withholding
/// validator is offline for the reshare (it never delivered its next-epoch key
/// and is not advanced), so the reshare deals only to the 3 upcoming parties that
/// have keys and still completes (3 = quorum for n=4); the 4th stays a committee
/// member, just undealt.
///
/// Regression test for the all-N reconfig gate (now removed) and for sourcing the
/// upcoming `class_groups` from the off-chain agreed set rather than the full
/// committee — with the old code this rejected on `InvalidMPCPartyType` (3/4) and
/// wedged reconfiguration on a single missing upcoming validator.
#[tokio::test]
#[cfg(test)]
async fn test_reconfiguration_completes_with_partial_upcoming_keys() {
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
    // Full DKG on the current committee (all 4 have keys), then reconfigure.
    let (consensus_round, _, key_id) = create_network_key_test(&mut test_state).await;

    // Upcoming committee of 4, but deliver off-chain keys for only 3 — the 4th
    // (party index 3, the last voting-rights entry) is the offline/withholding
    // validator. Both committees share authority names (deterministic test
    // committees), so this is also current party index 3, which we leave offline
    // for the reshare below.
    let (mut next_committee, _next_seeds, mut next_bundles) =
        utils::build_committee_with_random_seeds(4);
    next_committee.epoch = epoch_id + 1;
    let dropped = next_committee
        .voting_rights
        .last()
        .expect("committee has members")
        .0;
    next_bundles.class_groups.remove(&dropped);
    next_bundles.secp256k1_pvss.remove(&dropped);
    next_bundles.secp256r1_pvss.remove(&dropped);
    next_bundles.ristretto_pvss.remove(&dropped);
    next_bundles.vss_hpke.remove(&dropped);
    assert_eq!(
        next_bundles.secp256k1_pvss.len(),
        3,
        "exactly 3 of 4 upcoming validators should have keys"
    );

    test_state
        .sui_data_senders
        .iter()
        .for_each(|sui_data_sender| {
            let _ = sui_data_sender
                .next_epoch_committee_sender
                .send(next_committee.clone());
            let _ = sui_data_sender
                .next_epoch_mpc_keys_sender
                .send(Some((next_committee.epoch, next_bundles.clone())));
        });
    send_start_network_key_reconfiguration_event(
        epoch_id,
        &mut test_state.sui_data_senders,
        [3u8; 32],
        3,
        key_id,
    );
    // Reshare with the 3 keyed validators online (the 4th withheld its upcoming
    // key and is offline). The reshare deals only to the 3-party agreed upcoming
    // set and completes (3 = quorum for n=4).
    let (_, reconfiguration_checkpoint) = utils::advance_mpc_flow_until_completion_for_parties(
        &mut test_state,
        consensus_round,
        &[0, 1, 2],
    )
    .await;
    let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(message) =
        reconfiguration_checkpoint
            .messages()
            .first()
            .expect("Expected a reconfiguration message")
    else {
        panic!("Expected a RespondDWalletMPCNetworkReconfigurationOutput message");
    };
    assert!(
        !message.rejected,
        "reconfiguration into a 3/4-keyed upcoming committee should not be rejected"
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
    // `consensus_round` off the round channel, setting `last_read = consensus_round`.
    // We therefore distribute the key data status updates at `consensus_round + 1` so
    // that the second service loop run can read the new round and install the key.
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration().await;
    }
    // Distribute a fresh consensus round so the next service iterations
    // drive adoption and `instantiate_adopted_network_keys` populates
    // `network_keys` in each party's manager.
    utils::send_advance_results_between_parties(
        &test_state.committee,
        &mut test_state.sent_consensus_messages_collectors,
        &mut test_state.epoch_stores,
        consensus_round + 1,
    )
    .await;
    // Process the new round to instantiate the agreed network key in every party.
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration().await;
    }
    // The instantiation runs on the rayon pool and installs on a later
    // tick — keep iterating until it lands everywhere.
    utils::run_service_loops_until_network_key_installed(
        &mut test_state.dwallet_mpc_services,
        key_id.unwrap(),
    )
    .await;
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
/// `adopted_network_key_data` quorum, `instantiate_adopted_network_keys`'s
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
    // The insecure `unsafe_mock` protocol mocks return a single deterministic network-DKG
    // output for every key, so two keys created in the same epoch have identical bytes (they
    // are still distinct keys, tracked by their distinct ids). Per-key output uniqueness is a
    // real-crypto property, so only assert it when not running under the mock.
    #[cfg(not(feature = "dwallet-mpc-unsafe-mock"))]
    assert_ne!(k1_bytes, k0_bytes, "K1 output should differ from K0");

    // Publish a snapshot of BOTH keys to the `network_keys` overlay
    // watch channel so each validator's service-loop iteration sees
    // the full set when `adopt_cert_verified_keys` adopts it
    // (cert-digest-gated) and `instantiate_adopted_network_keys`
    // spawns both instantiations on the rayon pool.
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

    // These service-loop passes drive the adoption/instantiation
    // ticks: each iteration runs `adopt_cert_verified_keys` on the
    // published overlay (cert-digest-gated) and
    // `instantiate_adopted_network_keys` spawns the instantiation of
    // both keys on the rayon pool;
    // `run_service_loops_until_network_key_installed` below polls
    // further iterations until each key installs on every party,
    // populating `manager.network_keys`.
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration().await;
    }
    utils::send_advance_results_between_parties(
        &test_state.committee,
        &mut test_state.sent_consensus_messages_collectors,
        &mut test_state.epoch_stores,
        round_after_k1 + 1,
    )
    .await;
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration().await;
    }
    // Both instantiations complete asynchronously on the rayon pool.
    utils::run_service_loops_until_network_key_installed(
        &mut test_state.dwallet_mpc_services,
        k0_id,
    )
    .await;
    utils::run_service_loops_until_network_key_installed(
        &mut test_state.dwallet_mpc_services,
        k1_id,
    )
    .await;

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

/// Like [`create_network_key_test`] but additionally runs a network reconfiguration
/// (to the **same** committee at the next epoch) and installs the resulting
/// **versioned reconfiguration output** (V4 aggregated — the only shape the
/// protocol produces) on every validator's network key.
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
/// epoch) on an already-created network key, then installs the resulting
/// versioned reconfiguration output on every validator's key in place. Returns
/// the next unused consensus round.
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
    // already versioned (`bcs(VersionedDecryptionKeyReconfigurationOutput::V4(..))`),
    // so they go into `current_reconfiguration_public_output` verbatim.
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

    // Install the versioned reconfiguration output on every validator's network key.
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
        let metrics = manager.dwallet_mpc_metrics.clone();
        let reconfigured_key_data = DWalletNetworkEncryptionKeyData {
            id: key_id,
            current_epoch: epoch_id,
            dkg_at_epoch: 1,
            current_reconfiguration_public_output: reconfiguration_output_bytes.clone(),
            network_dkg_public_output: network_key_bytes.clone(),
            state: DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted,
        };
        let reconfigured_key = spawn_network_encryption_key_public_data_instantiation(
            epoch_id,
            access_structure.clone(),
            reconfigured_key_data,
            metrics,
        )
        .await
        .expect("recv reconfigured network key public data")
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
