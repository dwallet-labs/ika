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
use dwallet_mpc_types::dwallet_mpc::{
    VersionedDecryptionKeyReconfigurationOutput, VersionedNetworkDkgOutput,
};
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

#[tokio::test]
#[cfg(test)]
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

#[tokio::test]
#[cfg(test)]
async fn test_v2_to_v3_reconfiguration_migration() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let epoch_id = 1;

    // Pin committee + per-validator seeds up front so phase 1 (under v=2) and phase 2
    // (under v=3) share the same class-groups decryption keys. A real v4→v5 upgrade
    // keeps validator keys across the protocol_config flip — without seed sharing, phase 2
    // validators couldn't decrypt phase 1's V2 DKG output (it's encrypted to phase 1's
    // class-groups encryption keys).
    let (committee, seeds, bundles) = utils::build_committee_with_random_seeds(4);

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
    ) = utils::create_dwallet_mpc_services_with_committee_and_seeds(
        committee.clone(),
        seeds.clone(),
        bundles.clone(),
    );

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

    // ── Phase 2: rebuild services at v=3 sharing phase 1's committee + seeds ─
    let (
        v3_dwallet_mpc_services,
        v3_sui_data_senders,
        v3_sent_consensus_messages_collectors,
        v3_epoch_stores,
        v3_notify_services,
        v3_noa_sign_request_senders,
        v3_noa_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services_with_committee_and_seeds(
        committee.clone(),
        seeds.clone(),
        bundles.clone(),
    );

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

    let mut v3_state = IntegrationTestState {
        dwallet_mpc_services: v3_dwallet_mpc_services,
        sent_consensus_messages_collectors: v3_sent_consensus_messages_collectors,
        epoch_stores: v3_epoch_stores,
        notify_services: v3_notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee: committee.clone(),
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
    // Fresh phase-2 services start with `last_read_consensus_round = Some(0)`, so the next
    // round read from storage must be `1`. Distribute the status updates from the loop above
    // at round 1 to keep `round_to_messages` contiguous; advancing the reconfig flow below
    // continues at round 2.
    utils::send_advance_results_between_parties(
        &v3_state.committee,
        &mut v3_state.sent_consensus_messages_collectors,
        &mut v3_state.epoch_stores,
        1,
    );
    for service in v3_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }
    // The instantiation runs on the rayon pool and installs on a later
    // tick — keep iterating until it lands everywhere.
    utils::run_service_loops_until_network_key_installed(
        &mut v3_state.dwallet_mpc_services,
        key_id,
    )
    .await;

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
    // Upcoming committee: a fresh validator set whose off-chain PVSS/VSS keys
    // travel on the next-epoch key channel (no longer on `Committee`), so deliver
    // both the committee and its bundles.
    let (mut next_committee, _next_seeds, next_bundles) =
        utils::build_committee_with_random_seeds(4);
    next_committee.epoch = epoch_id + 1;
    v3_state
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
        &mut v3_state.sui_data_senders,
        [4u8; 32],
        4,
        key_id,
    );
    let (_, reconfiguration_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut v3_state, 2).await;
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

/// Reconfiguration of a key that carries the DEPLOYED mainnet/testnet anchor
/// shape: a **V1-tagged network DKG anchor** (a raw `class_groups::dkg::PublicOutput`)
/// plus a **V2-tagged reconfiguration output**.
///
/// Regression test for the panic-abort that used to wedge every deployed
/// network at its first reconfiguration: `reconfiguration_bwd_compat_public_input`
/// had `VersionedNetworkDkgOutput::V1(_) => unreachable!()`, so every validator
/// aborted the moment it read a deployed key's on-chain anchor. The fix adds a
/// functional V1 arm that decodes the V1 inner bytes directly as the class-groups
/// DKG output and feeds it, alongside the prior V2 reconfiguration output, to
/// `bwd_compat_reconfig::PublicInput::new_from_reconfiguration_output`.
///
/// Pinned at v2 (= deployed protocol v3, `reconfiguration_message_version == 2`)
/// for the WHOLE test, so both reconfigurations route through the bwd-compat
/// builder.
///
/// Assertion level: FULL — drives the V1-anchor builder path end to end and
/// asserts the resulting `RespondDWalletMPCNetworkReconfigurationOutput` is
/// `!rejected` (not merely that the input builder returns `Ok`).
#[tokio::test]
#[cfg(test)]
async fn test_v1_anchor_bwd_compat_reconfiguration() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let epoch_id = 1;

    // Pin at v2 for the whole test — the deployed-shape path. The guard must
    // outlive every `create_dwallet_mpc_services_*` call (each snapshots the
    // `ProtocolConfig` onto its `DWalletMPCManager`), so keep it in scope.
    let _override = pin_protocol_to_v2_overrides();

    // Share committee + per-validator seeds + off-chain bundles across both
    // phases so the phase-2 validators hold the same class-groups decryption
    // keys as phase 1 — they must recover their Shamir shares from phase 1's
    // reconfiguration output, which was dealt to these exact keys.
    let (committee, seeds, bundles) = utils::build_committee_with_random_seeds(4);

    // ── Phase 1: network DKG (→ V2 anchor), then ONE reconfiguration to the
    //    SAME committee (epoch+1, same identities/keys) to obtain a V2-tagged
    //    reconfiguration output that stays usable by those identities. ───────
    let (
        p1_dwallet_mpc_services,
        p1_sui_data_senders,
        p1_sent_consensus_messages_collectors,
        p1_epoch_stores,
        p1_notify_services,
        p1_noa_sign_request_senders,
        p1_noa_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services_with_committee_and_seeds(
        committee.clone(),
        seeds.clone(),
        bundles.clone(),
    );
    let mut p1_state = IntegrationTestState {
        dwallet_mpc_services: p1_dwallet_mpc_services,
        sent_consensus_messages_collectors: p1_sent_consensus_messages_collectors,
        epoch_stores: p1_epoch_stores,
        notify_services: p1_notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee: committee.clone(),
        sui_data_senders: p1_sui_data_senders,
        network_owned_address_sign_request_senders: p1_noa_sign_request_senders,
        network_owned_address_sign_output_receivers: p1_noa_sign_output_receivers,
    };

    let (consensus_round, v2_network_key_bytes, key_id) =
        create_network_key_test(&mut p1_state).await;
    info!(
        ?key_id,
        bytes_len = v2_network_key_bytes.len(),
        "Phase 1: V2-tagged network DKG anchor captured"
    );

    // Reconfigure to the SAME committee at the next epoch. At v2 the bwd-compat
    // builder reads the (current + upcoming) class-groups keys off the committee,
    // so only the committee is delivered (the off-chain next-epoch key channel is
    // a v3-only input).
    let mut p1_next_committee = (*p1_state.dwallet_mpc_services[0].committee).clone();
    p1_next_committee.epoch = epoch_id + 1;
    for sui_data_sender in &p1_state.sui_data_senders {
        let _ = sui_data_sender
            .next_epoch_committee_sender
            .send(p1_next_committee.clone());
    }
    send_start_network_key_reconfiguration_event(
        epoch_id,
        &mut p1_state.sui_data_senders,
        [7u8; 32],
        7,
        key_id,
    );
    let (_, p1_reconfiguration_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut p1_state, consensus_round).await;
    let mut v2_reconfiguration_output_bytes = vec![];
    for message in p1_reconfiguration_checkpoint.messages() {
        let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(message) =
            message
        else {
            continue;
        };
        assert!(
            !message.rejected,
            "phase-1 reconfiguration (to seed the prior V2 output) should not be rejected"
        );
        // At v2 these bytes are `bcs(VersionedDecryptionKeyReconfigurationOutput::V2(..))`
        // — the exact shape a deployed key stores in `current_reconfiguration_public_output`.
        v2_reconfiguration_output_bytes.extend(message.public_output.clone());
    }
    assert!(
        !v2_reconfiguration_output_bytes.is_empty(),
        "phase-1 reconfiguration output must be non-empty"
    );
    info!(
        bytes_len = v2_reconfiguration_output_bytes.len(),
        "Phase 1: V2-tagged reconfiguration output captured"
    );

    // ── Project the captured V2 anchor into the deployed V1-tagged shape ─────
    //
    // The deployed keys carry a V1 anchor: a raw `class_groups::dkg::PublicOutput`
    // written once at the original (pre-1.1.8) DKG and never rewritten. We
    // synthesize that exact shape from the V2 anchor produced above. The
    // projection is FAITHFUL, not a hand-rolled stand-in: the V2 arm of
    // `reconfiguration_bwd_compat_public_input` feeds the constructor
    // `bwd_compat_dkg_public_output.into()` — the very same
    // `From<PublicOutputCore> for class_groups::dkg::PublicOutput` conversion
    // applied here. The fixed V1 arm decodes the V1 inner bytes straight back
    // with `bcs::from_bytes`, so it recovers a value byte-identical to what the
    // V2 arm hands the constructor. Both arms therefore run identical crypto ⇒
    // the reconfiguration must not be rejected. (The class-groups DKG output's
    // BCS layout is also stable across the crypto bump, matching the on-chain
    // deployed bytes.)
    let VersionedNetworkDkgOutput::V2(v2_dkg_inner) = bcs::from_bytes(&v2_network_key_bytes)
        .expect("decode the captured versioned network anchor")
    else {
        panic!("phase-1 network DKG at v2 must produce a V2-tagged anchor");
    };
    let bwd_compat_dkg_public_output: <twopc_mpc::decentralized_party_backward_compatible::dkg::Party as mpc::Party>::PublicOutput =
        bcs::from_bytes(&v2_dkg_inner).expect("decode the bwd-compat DKG PublicOutput");
    let class_groups_dkg_output: class_groups::dkg::PublicOutput<
        { twopc_mpc::secp256k1::SCALAR_LIMBS },
        { twopc_mpc::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { twopc_mpc::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    > = bwd_compat_dkg_public_output.into();
    let v1_dkg_inner = bcs::to_bytes(&class_groups_dkg_output)
        .expect("re-encode the projected class-groups DKG output");
    let v1_anchor_bytes = bcs::to_bytes(&VersionedNetworkDkgOutput::V1(v1_dkg_inner))
        .expect("encode the V1-tagged anchor");

    // ── Phase 2: fresh services (same committee + seeds), still v2-pinned.
    //    Inject the deployed-shape key (V1 anchor + V2 reconfig output) and
    //    reconfigure again — this drives the fixed V1-anchor builder path. ────
    let (
        p2_dwallet_mpc_services,
        p2_sui_data_senders,
        p2_sent_consensus_messages_collectors,
        p2_epoch_stores,
        p2_notify_services,
        p2_noa_sign_request_senders,
        p2_noa_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services_with_committee_and_seeds(
        committee.clone(),
        seeds.clone(),
        bundles.clone(),
    );
    let mut p2_state = IntegrationTestState {
        dwallet_mpc_services: p2_dwallet_mpc_services,
        sent_consensus_messages_collectors: p2_sent_consensus_messages_collectors,
        epoch_stores: p2_epoch_stores,
        notify_services: p2_notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee: committee.clone(),
        sui_data_senders: p2_sui_data_senders,
        network_owned_address_sign_request_senders: p2_noa_sign_request_senders,
        network_owned_address_sign_output_receivers: p2_noa_sign_output_receivers,
    };

    // Inject the deployed-shape key. A non-empty `current_reconfiguration_public_output`
    // routes instantiation through the reconfiguration-output path
    // (`spawn_network_encryption_key_public_data_instantiation`), which reads the
    // V1 anchor verbatim — so a successful install already proves instantiation
    // tolerates the V1 anchor.
    p2_state
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
                        current_reconfiguration_public_output: v2_reconfiguration_output_bytes
                            .clone(),
                        network_dkg_public_output: v1_anchor_bytes.clone(),
                        state: DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration,
                    },
                )])));
        });
    for service in p2_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }
    // Fresh phase-2 services start with `last_read_consensus_round = Some(0)`, so
    // distribute the status updates from the loop above at round 1 to keep
    // `round_to_messages` contiguous; the reconfig flow below continues at round 2.
    utils::send_advance_results_between_parties(
        &p2_state.committee,
        &mut p2_state.sent_consensus_messages_collectors,
        &mut p2_state.epoch_stores,
        1,
    );
    for service in p2_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }
    utils::run_service_loops_until_network_key_installed(
        &mut p2_state.dwallet_mpc_services,
        key_id,
    )
    .await;
    for (i, service) in p2_state.dwallet_mpc_services.iter().enumerate() {
        assert!(
            service
                .dwallet_mpc_manager()
                .network_keys
                .get_network_encryption_key_public_data(&key_id)
                .is_ok(),
            "phase-2 validator {i} should have installed the V1-anchor deployed-shape key"
        );
    }

    // Reconfigure the deployed-shape key. At v2 only the committee is delivered.
    let (mut p2_next_committee, _p2_next_seeds, _p2_next_bundles) =
        utils::build_committee_with_random_seeds(4);
    p2_next_committee.epoch = epoch_id + 1;
    for sui_data_sender in &p2_state.sui_data_senders {
        let _ = sui_data_sender
            .next_epoch_committee_sender
            .send(p2_next_committee.clone());
    }
    send_start_network_key_reconfiguration_event(
        epoch_id,
        &mut p2_state.sui_data_senders,
        [8u8; 32],
        8,
        key_id,
    );
    let (_, p2_reconfiguration_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut p2_state, 2).await;
    let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(message) =
        p2_reconfiguration_checkpoint
            .messages()
            .first()
            .expect("Expected a reconfiguration message")
    else {
        error!("Expected a RespondDWalletMPCNetworkReconfigurationOutput message");
        panic!("Test failed due to unexpected message type");
    };
    assert!(
        !message.rejected,
        "V1-anchor bwd-compat reconfiguration should not be rejected"
    );
    info!("V1-anchor bwd-compat reconfiguration completed");
}

/// The deployed-anchor shape under the MAIN (protocol-v4) reconfiguration
/// party, plus the one-time V1→V3 anchor migration:
///
/// 1. A key carrying a **V1 network DKG anchor + V2 reconfiguration output**
///    (the deployed mainnet/testnet shape) is reconfigured at the default
///    protocol config (`reconfiguration_message_version == 3`), driving the
///    main builder's `(V1 anchor, Some(V2 prior))` arm — the first v4
///    reconfiguration a deployed key will run.
/// 2. The resulting **V3-tagged** reconfiguration output is injected back
///    alongside the still-V1 anchor, and the instantiation must reconstruct
///    the full V3 DKG output (`reconstructed_full_network_dkg_output`), the
///    value the canonical-anchor mirror persists — i.e. the deployed keys'
///    V1→V3 anchor migration fires.
///
/// Phase 1 runs pinned at v2 to fabricate the deployed shape (exactly like
/// `test_v1_anchor_bwd_compat_reconfiguration`); the pin is dropped before the
/// main-path phases. Both reconfigurations reshare to the SAME committee so
/// every phase can reuse one committee + seed + off-chain-bundle set.
#[tokio::test]
#[cfg(test)]
async fn test_v1_anchor_main_reconfiguration_and_anchor_migration() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let epoch_id = 1;

    let (committee, seeds, bundles) = utils::build_committee_with_random_seeds(4);

    // ── Phase 1 (pinned v2): DKG → V2 anchor, then ONE bwd-compat
    //    reconfiguration to the SAME committee → V2 reconfiguration output. ──
    let v2_override = pin_protocol_to_v2_overrides();
    let (
        p1_dwallet_mpc_services,
        p1_sui_data_senders,
        p1_sent_consensus_messages_collectors,
        p1_epoch_stores,
        p1_notify_services,
        p1_noa_sign_request_senders,
        p1_noa_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services_with_committee_and_seeds(
        committee.clone(),
        seeds.clone(),
        bundles.clone(),
    );
    let mut p1_state = IntegrationTestState {
        dwallet_mpc_services: p1_dwallet_mpc_services,
        sent_consensus_messages_collectors: p1_sent_consensus_messages_collectors,
        epoch_stores: p1_epoch_stores,
        notify_services: p1_notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee: committee.clone(),
        sui_data_senders: p1_sui_data_senders,
        network_owned_address_sign_request_senders: p1_noa_sign_request_senders,
        network_owned_address_sign_output_receivers: p1_noa_sign_output_receivers,
    };

    let (consensus_round, v2_network_key_bytes, key_id) =
        create_network_key_test(&mut p1_state).await;
    info!(
        ?key_id,
        bytes_len = v2_network_key_bytes.len(),
        "Phase 1: V2-tagged network DKG anchor captured"
    );

    let mut p1_next_committee = (*p1_state.dwallet_mpc_services[0].committee).clone();
    p1_next_committee.epoch = epoch_id + 1;
    for sui_data_sender in &p1_state.sui_data_senders {
        let _ = sui_data_sender
            .next_epoch_committee_sender
            .send(p1_next_committee.clone());
    }
    send_start_network_key_reconfiguration_event(
        epoch_id,
        &mut p1_state.sui_data_senders,
        [9u8; 32],
        9,
        key_id,
    );
    let (_, p1_reconfiguration_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut p1_state, consensus_round).await;
    let mut v2_reconfiguration_output_bytes = vec![];
    for message in p1_reconfiguration_checkpoint.messages() {
        let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(message) =
            message
        else {
            continue;
        };
        assert!(
            !message.rejected,
            "phase-1 reconfiguration (to seed the prior V2 output) should not be rejected"
        );
        v2_reconfiguration_output_bytes.extend(message.public_output.clone());
    }
    assert!(
        !v2_reconfiguration_output_bytes.is_empty(),
        "phase-1 reconfiguration output must be non-empty"
    );

    // Drop the v2 pin — every later phase snapshots the default (v3) config.
    drop(v2_override);

    // ── Project the V2 anchor into the deployed V1-tagged shape (same
    //    faithful projection as `test_v1_anchor_bwd_compat_reconfiguration`:
    //    the V1 inner bytes ARE the raw class-groups DKG output). ─────────────
    let VersionedNetworkDkgOutput::V2(v2_dkg_inner) = bcs::from_bytes(&v2_network_key_bytes)
        .expect("decode the captured versioned network anchor")
    else {
        panic!("phase-1 network DKG at v2 must produce a V2-tagged anchor");
    };
    let bwd_compat_dkg_public_output: <twopc_mpc::decentralized_party_backward_compatible::dkg::Party as mpc::Party>::PublicOutput =
        bcs::from_bytes(&v2_dkg_inner).expect("decode the bwd-compat DKG PublicOutput");
    let class_groups_dkg_output: class_groups::dkg::PublicOutput<
        { twopc_mpc::secp256k1::SCALAR_LIMBS },
        { twopc_mpc::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { twopc_mpc::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    > = bwd_compat_dkg_public_output.into();
    let v1_dkg_inner = bcs::to_bytes(&class_groups_dkg_output)
        .expect("re-encode the projected class-groups DKG output");
    let v1_anchor_bytes = bcs::to_bytes(&VersionedNetworkDkgOutput::V1(v1_dkg_inner))
        .expect("encode the V1-tagged anchor");

    // ── Phase 2 (default v3): inject the deployed shape (V1 anchor + V2
    //    reconfig output) and reconfigure under the MAIN party — the
    //    `(V1 anchor, Some(V2 prior))` builder arm. ───────────────────────────
    let (
        p2_dwallet_mpc_services,
        p2_sui_data_senders,
        p2_sent_consensus_messages_collectors,
        p2_epoch_stores,
        p2_notify_services,
        p2_noa_sign_request_senders,
        p2_noa_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services_with_committee_and_seeds(
        committee.clone(),
        seeds.clone(),
        bundles.clone(),
    );
    for service in &p2_dwallet_mpc_services {
        assert!(
            service
                .protocol_config
                .is_reconfiguration_message_version_v3(),
            "Phase 2 services should run at reconfiguration_message_version == 3 (default MAX)"
        );
    }
    let mut p2_state = IntegrationTestState {
        dwallet_mpc_services: p2_dwallet_mpc_services,
        sent_consensus_messages_collectors: p2_sent_consensus_messages_collectors,
        epoch_stores: p2_epoch_stores,
        notify_services: p2_notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee: committee.clone(),
        sui_data_senders: p2_sui_data_senders,
        network_owned_address_sign_request_senders: p2_noa_sign_request_senders,
        network_owned_address_sign_output_receivers: p2_noa_sign_output_receivers,
    };

    p2_state
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
                        current_reconfiguration_public_output: v2_reconfiguration_output_bytes
                            .clone(),
                        network_dkg_public_output: v1_anchor_bytes.clone(),
                        state: DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration,
                    },
                )])));
        });
    for service in p2_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }
    utils::send_advance_results_between_parties(
        &p2_state.committee,
        &mut p2_state.sent_consensus_messages_collectors,
        &mut p2_state.epoch_stores,
        1,
    );
    for service in p2_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }
    utils::run_service_loops_until_network_key_installed(
        &mut p2_state.dwallet_mpc_services,
        key_id,
    )
    .await;

    // Reshare to the SAME committee at the next epoch; at v3 the upcoming
    // committee's off-chain PVSS/VSS keys travel on the next-epoch key channel.
    let mut p2_next_committee = committee.clone();
    p2_next_committee.epoch = epoch_id + 1;
    for sui_data_sender in &p2_state.sui_data_senders {
        let _ = sui_data_sender
            .next_epoch_committee_sender
            .send(p2_next_committee.clone());
        let _ = sui_data_sender
            .next_epoch_mpc_keys_sender
            .send(Some((p2_next_committee.epoch, bundles.clone())));
    }
    send_start_network_key_reconfiguration_event(
        epoch_id,
        &mut p2_state.sui_data_senders,
        [10u8; 32],
        10,
        key_id,
    );
    let (_, p2_reconfiguration_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut p2_state, 2).await;
    let mut v3_reconfiguration_output_bytes = vec![];
    for message in p2_reconfiguration_checkpoint.messages() {
        let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(message) =
            message
        else {
            continue;
        };
        assert!(
            !message.rejected,
            "V1-anchor main (v4) reconfiguration should not be rejected"
        );
        v3_reconfiguration_output_bytes.extend(message.public_output.clone());
    }
    assert!(
        !v3_reconfiguration_output_bytes.is_empty(),
        "phase-2 main reconfiguration output must be non-empty"
    );
    let versioned_reconfiguration_output: VersionedDecryptionKeyReconfigurationOutput =
        bcs::from_bytes(&v3_reconfiguration_output_bytes)
            .expect("decode the phase-2 reconfiguration output");
    assert!(
        matches!(
            versioned_reconfiguration_output,
            VersionedDecryptionKeyReconfigurationOutput::V3(_)
        ),
        "the main reconfiguration party must produce a V3-tagged output"
    );
    info!("Phase 2: V1-anchor main reconfiguration completed with a V3-tagged output");

    // ── Phase 3 (default v3): inject (V1 anchor, V3 reconfig output) — the
    //    deployed shape one epoch after the first v4 reconfiguration — and
    //    assert instantiation reconstructs the full V3 anchor, which is what
    //    the canonical mirror persists (the one-time V1→V3 anchor migration). ─
    let (
        p3_dwallet_mpc_services,
        p3_sui_data_senders,
        p3_sent_consensus_messages_collectors,
        p3_epoch_stores,
        p3_notify_services,
        p3_noa_sign_request_senders,
        p3_noa_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services_with_committee_and_seeds(
        committee.clone(),
        seeds.clone(),
        bundles.clone(),
    );
    let mut p3_state = IntegrationTestState {
        dwallet_mpc_services: p3_dwallet_mpc_services,
        sent_consensus_messages_collectors: p3_sent_consensus_messages_collectors,
        epoch_stores: p3_epoch_stores,
        notify_services: p3_notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee: committee.clone(),
        sui_data_senders: p3_sui_data_senders,
        network_owned_address_sign_request_senders: p3_noa_sign_request_senders,
        network_owned_address_sign_output_receivers: p3_noa_sign_output_receivers,
    };
    p3_state
        .sui_data_senders
        .iter()
        .for_each(|sui_data_sender| {
            let _ = sui_data_sender
                .network_keys_sender
                .send(Arc::new(HashMap::from([(
                    key_id,
                    DWalletNetworkEncryptionKeyData {
                        id: key_id,
                        // Must equal the manager's epoch — data carrying any
                        // other epoch is rejected before instantiation spawns
                        // (the stale-chain-snapshot guard in `mpc_manager.rs`).
                        current_epoch: 1,
                        dkg_at_epoch: 1,
                        current_reconfiguration_public_output: v3_reconfiguration_output_bytes
                            .clone(),
                        network_dkg_public_output: v1_anchor_bytes.clone(),
                        state: DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration,
                    },
                )])));
        });
    for service in p3_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }
    utils::send_advance_results_between_parties(
        &p3_state.committee,
        &mut p3_state.sent_consensus_messages_collectors,
        &mut p3_state.epoch_stores,
        1,
    );
    for service in p3_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }
    utils::run_service_loops_until_network_key_installed(
        &mut p3_state.dwallet_mpc_services,
        key_id,
    )
    .await;
    for (i, service) in p3_state.dwallet_mpc_services.iter().enumerate() {
        let key_public_data = service
            .dwallet_mpc_manager()
            .network_keys
            .get_network_encryption_key_public_data(&key_id)
            .unwrap_or_else(|e| {
                panic!("phase-3 validator {i} should have installed the key: {e:?}")
            })
            .clone();
        assert!(
            matches!(
                key_public_data.network_dkg_output(),
                VersionedNetworkDkgOutput::V1(_)
            ),
            "phase-3 validator {i}: the stored anchor must still be V1 (never rewritten on chain)"
        );
        assert!(
            matches!(
                key_public_data.reconstructed_full_network_dkg_output(),
                Some(VersionedNetworkDkgOutput::V3(_))
            ),
            "phase-3 validator {i}: instantiation from (V1 anchor, V3 reconfiguration output) \
             must reconstruct the full V3 DKG output — the deployed keys' one-time anchor \
             migration"
        );
    }
    info!("Phase 3: V1→V3 anchor reconstruction verified on every validator");
}
