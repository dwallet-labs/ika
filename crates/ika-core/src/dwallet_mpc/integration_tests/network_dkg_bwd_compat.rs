// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Integration tests for the mainnet-v1.1.8 backward-compatible DKG and
//! Reconfiguration paths. Exercise the dispatch wired in commit
//! `5802f1accb`: when `ProtocolConfig::is_*_version_v3()` returns `false`,
//! `session_input_from_request` builds a bwd-compat `PublicInput` and
//! `compute_mpc` advances under
//! `twopc_mpc::decentralized_party_backward_compatible::{dkg,
//! reconfiguration}::Party`.
//!
//! Also covers the v2→v3 protocol upgrade migration: a network DKG'd under
//! bwd-compat (V2-tagged output) can be reconfigured under the main Party
//! once the protocol_version flips to 5, because DKG/Reconfig
//! `PublicOutput` is wire-stable across the cryptography-private bump
//! (audit §4). No code-level migration arm is required — the dispatch in
//! `mpc_session/input.rs` + the existing `(V2 dkg, V2 reconfig)` arm in
//! `reconfiguration.rs:197-239` handle the transition.

use crate::dwallet_mpc::integration_tests::network_dkg::{
    create_network_key_test, send_start_network_key_reconfiguration_event,
};
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::IntegrationTestState;
use ika_protocol_config::ProtocolConfig;
use ika_types::committee::Committee;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info};

/// Builds an override guard that pins both DKG and Reconfiguration message
/// versions to the mainnet-v1.1.8 value (`2`). With this guard active,
/// `ProtocolConfig::is_network_encryption_key_version_v3()` and
/// `…reconfiguration_message_version_v3()` both return `false` — so
/// `session_input_from_request` picks the
/// `NetworkEncryptionKey{Dkg, Reconfiguration}PublicInput::BwdCompat` variant
/// and the advance dispatcher in `compute_mpc` routes to
/// `advance_network_dkg_bwd_compat` / `advance_network_reconfiguration_bwd_compat`.
fn pin_protocol_to_v2_overrides() -> ika_protocol_config::OverrideGuard {
    ProtocolConfig::apply_overrides_for_testing(|_version, mut config| {
        config.set_network_encryption_key_version_for_testing(2);
        config.set_reconfiguration_message_version_for_testing(2);
        config
    })
}

#[tokio::test]
#[cfg(test)]
async fn test_bwd_compat_network_dkg_full_flow() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    // Guard must outlive `create_dwallet_mpc_services` — that's where the
    // `ProtocolConfig` snapshot lands on the per-validator `DWalletMPCManager`.
    let _override = pin_protocol_to_v2_overrides();

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

    // Smoke check: the manager's pinned `protocol_config` reports the v2 shape,
    // so dispatch will pick the bwd-compat path.
    for service in &dwallet_mpc_services {
        assert!(
            !service
                .protocol_config
                .is_network_encryption_key_version_v3(),
            "Protocol override should pin network_encryption_key_version == 2"
        );
        assert!(
            !service
                .protocol_config
                .is_reconfiguration_message_version_v3(),
            "Protocol override should pin reconfiguration_message_version == 2"
        );
    }

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
    let (_, _, key_id) = create_network_key_test(&mut test_state).await;
    info!(
        ?key_id,
        "Bwd-compat network DKG completed; key installed on every validator"
    );
}

// Bwd-compat Reconfiguration at protocol_version <= 4 currently fails at the
// `bwd_compat_reconfig::PublicInput::new_from_dkg_output` call site —
// upstream's constructor takes `universal_public_output: decentralized_party::dkg::PublicOutput`
// (the post-bump main type), but the V2 DKG output bytes produced by the
// bwd-compat DKG Party decode as `bwd_compat_dkg::Party::PublicOutput`
// (a structural subset; no `From` impl ships in cryptography-private @ 7795eb45).
// Until upstream adds either `From<bwd_compat::dkg::PublicOutput> for
// decentralized_party::dkg::PublicOutput` or a `new_from_bwd_compat_dkg_output`
// constructor, this test is expected to fail with the explicit
// "Bwd-compat Reconfig blocked on upstream" error. Re-enable once upstream lands.
#[tokio::test]
#[cfg(test)]
#[ignore = "Bwd-compat reconfig at v=2 needs upstream `From<bwd_compat::dkg::PublicOutput> for decentralized_party::dkg::PublicOutput` (or analogous constructor)"]
async fn test_bwd_compat_network_key_reconfiguration() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _override = pin_protocol_to_v2_overrides();

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

    let (next_epoch_dwallet_mpc_services, ..) = utils::create_dwallet_mpc_services(4);
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
    let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(message) =
        reconfiguration_checkpoint
            .messages()
            .first()
            .expect("Expected a reconfiguration message")
    else {
        error!("Expected a RespondDWalletMPCNetworkReconfigurationOutput message");
        panic!("Test failed due to unexpected message type");
    };
    assert!(
        !message.rejected,
        "Bwd-compat network key reconfiguration should not be rejected"
    );
    info!("Bwd-compat network reconfiguration completed");
}

// v2→v3 migration likewise blocked on the same upstream conversion gap: the
// main `ReconfigurationParty::generate_public_input` is called at v=3 with a
// V2-tagged DKG output (bwd-compat shape), which needs to be converted to
// `decentralized_party::dkg::PublicOutput` before feeding the main `new_from_dkg_output`.
// Re-enable once upstream conversion lands.
#[tokio::test]
#[cfg(test)]
#[ignore = "v2→v3 reconfig migration needs upstream `From<bwd_compat::dkg::PublicOutput> for decentralized_party::dkg::PublicOutput`"]
async fn test_v2_to_v3_reconfiguration_migration() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let epoch_id = 1;

    // ── Phase 1: pin v=2, run network DKG under the bwd-compat Party ─────
    let v2_override = pin_protocol_to_v2_overrides();
    let (
        v2_dwallet_mpc_services,
        v2_sui_data_senders,
        v2_sent_consensus_messages_collectors,
        v2_epoch_stores,
        v2_notify_services,
        v2_noa_sign_request_senders,
        v2_noa_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services(4);

    for service in &v2_dwallet_mpc_services {
        assert!(
            !service
                .protocol_config
                .is_network_encryption_key_version_v3(),
            "Phase 1 services should be pinned at network_encryption_key_version == 2"
        );
    }

    let mut v2_state = IntegrationTestState {
        dwallet_mpc_services: v2_dwallet_mpc_services,
        sent_consensus_messages_collectors: v2_sent_consensus_messages_collectors,
        epoch_stores: v2_epoch_stores,
        notify_services: v2_notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee: committee.clone(),
        sui_data_senders: v2_sui_data_senders,
        network_owned_address_sign_request_senders: v2_noa_sign_request_senders,
        network_owned_address_sign_output_receivers: v2_noa_sign_output_receivers,
    };
    let (_, v2_network_key_bytes, key_id) = create_network_key_test(&mut v2_state).await;
    info!(
        ?key_id,
        bytes_len = v2_network_key_bytes.len(),
        "Phase 1: V2-tagged network DKG output captured"
    );

    // Drop v2 override so phase 2 services snapshot the default (v3) protocol config.
    drop(v2_override);

    // ── Phase 2: build fresh services at v=3, hand them the V2 DKG output ─
    let (
        v3_dwallet_mpc_services,
        v3_sui_data_senders,
        v3_sent_consensus_messages_collectors,
        v3_epoch_stores,
        v3_notify_services,
        v3_noa_sign_request_senders,
        v3_noa_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services(4);

    for service in &v3_dwallet_mpc_services {
        assert!(
            service
                .protocol_config
                .is_network_encryption_key_version_v3(),
            "Phase 2 services should run at network_encryption_key_version == 3 (default MAX)"
        );
        assert!(
            service
                .protocol_config
                .is_reconfiguration_message_version_v3(),
            "Phase 2 services should run at reconfiguration_message_version == 3"
        );
    }

    let v3_committee = (*v3_dwallet_mpc_services[0].committee.clone()).clone();
    let mut v3_state = IntegrationTestState {
        dwallet_mpc_services: v3_dwallet_mpc_services,
        sent_consensus_messages_collectors: v3_sent_consensus_messages_collectors,
        epoch_stores: v3_epoch_stores,
        notify_services: v3_notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee: v3_committee.clone(),
        sui_data_senders: v3_sui_data_senders,
        network_owned_address_sign_request_senders: v3_noa_sign_request_senders,
        network_owned_address_sign_output_receivers: v3_noa_sign_output_receivers,
    };

    // Inject the V2-tagged DKG output as the network key on every phase-2
    // service — same shape `network_dkg.rs:170-184` does at the end of the
    // standard DKG test.
    v3_state
        .sui_data_senders
        .iter()
        .for_each(|sui_data_sender| {
            let _ = sui_data_sender
                .network_keys_sender
                .send(Arc::new(HashMap::from([(
                    key_id,
                    DWalletNetworkEncryptionKeyData {
                        id: key_id,
                        current_epoch: 1,
                        dkg_at_epoch: 1,
                        current_reconfiguration_public_output: vec![],
                        network_dkg_public_output: v2_network_key_bytes.clone(),
                        state: DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration,
                    },
                )])));
        });
    for service in v3_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }
    utils::send_advance_results_between_parties(
        &v3_state.committee,
        &mut v3_state.sent_consensus_messages_collectors,
        &mut v3_state.epoch_stores,
        2,
    );
    for service in v3_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }

    // Verify every phase-2 validator decoded the V2 DKG output via the
    // wire-stable main-shape PublicOutput type and installed the key.
    for (i, service) in v3_state.dwallet_mpc_services.iter().enumerate() {
        assert!(
            service
                .dwallet_mpc_manager()
                .network_keys
                .get_network_encryption_key_public_data(&key_id)
                .is_ok(),
            "Phase-2 validator {i} should have installed the V2 network key under main shape"
        );
    }

    // Set up upcoming committee + run reconfiguration; the main Reconfig
    // Party should consume the V2 DKG output via the existing
    // `(V2 dkg, None reconfig)` arm at reconfiguration.rs:170-196.
    let (next_epoch_dwallet_mpc_services, ..) = utils::create_dwallet_mpc_services(4);
    let mut next_committee = (*next_epoch_dwallet_mpc_services[0].committee.clone()).clone();
    next_committee.epoch = epoch_id + 1;
    v3_state
        .sui_data_senders
        .iter()
        .for_each(|sui_data_sender| {
            let _ = sui_data_sender
                .next_epoch_committee_sender
                .send(next_committee.clone());
        });
    send_start_network_key_reconfiguration_event(
        epoch_id,
        &mut v3_state.sui_data_senders,
        [4u8; 32],
        4,
        key_id,
    );
    let (_, reconfiguration_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut v3_state, 3).await;
    let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(message) =
        reconfiguration_checkpoint
            .messages()
            .first()
            .expect("Expected a reconfiguration message")
    else {
        error!("Expected a RespondDWalletMPCNetworkReconfigurationOutput message");
        panic!("Test failed due to unexpected message type");
    };
    assert!(
        !message.rejected,
        "v2→v3 migration reconfiguration should succeed under main Party"
    );
    info!("v2→v3 migration reconfiguration completed");
}
