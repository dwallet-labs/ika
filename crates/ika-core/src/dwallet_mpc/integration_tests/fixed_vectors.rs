// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Fixed-vector determinism pins for the aggregated-output migration.
//!
//! At the protocol-v5 flip epoch every validator independently derives and
//! persists the aggregated (V4) bytes — the reconfiguration output via
//! `NonAggregatedPublicOutput::upgrade()` and the canonical anchor via
//! `new_from_reconfiguration_output` — so byte-identical quorum rests entirely
//! on those derivations being canonically ordered (receivers, curve-parts,
//! summation, bcs map encoding) across binaries and refactors. These tests pin
//! the derivations against committed fixtures captured from one real protocol
//! run: any change to the derived bytes — an iteration-order regression, a
//! serializer change, a struct reshape — fails them.
//!
//! Both deployed starting states are covered:
//! - **testnet** (protocol v4): pinned pre-aggregation reconfiguration output
//!   → exact aggregated bytes, and the V3-anchor → V4-anchor migration;
//! - **mainnet** (protocol 3 → 5 direct): the compound path — a V2 (core-only)
//!   anchor's class-group DKG output combined with the aggregated
//!   reconfiguration output → exact V4 anchor bytes.
//!
//! The fixtures are INPUTS captured once (`generate_aggregated_output_fixed_vectors`,
//! `#[ignore]`d — rerun it only when the fixture format itself legitimately
//! changes, and commit the regenerated files) plus the PINNED derived bytes.

use std::path::PathBuf;

use dwallet_mpc_types::dwallet_mpc::{
    VersionedDecryptionKeyReconfigurationOutput, VersionedNetworkDkgOutput,
};

use crate::dwallet_mpc::crytographic_computation::mpc_computations::network_dkg::reconstruct_full_network_dkg_output;

const NON_AGGREGATED_RECONFIGURATION_OUTPUT: &[u8] =
    include_bytes!("fixtures/reconfiguration_output_non_aggregated.bcs");
const PINNED_AGGREGATED_RECONFIGURATION_OUTPUT: &[u8] =
    include_bytes!("fixtures/reconfiguration_output_aggregated.bcs");
const DKG_OUTPUT_CORE: &[u8] = include_bytes!("fixtures/dkg_output_core.bcs");
const PINNED_AGGREGATED_ANCHOR: &[u8] = include_bytes!("fixtures/dkg_anchor_aggregated.bcs");

/// Testnet flip determinism: upgrading the pinned pre-aggregation
/// reconfiguration output must yield the exact pinned aggregated bytes.
#[test]
fn upgrade_of_reconfiguration_output_matches_fixed_vector() {
    let non_aggregated: twopc_mpc::decentralized_party::reconfiguration::NonAggregatedPublicOutput =
        bcs::from_bytes(NON_AGGREGATED_RECONFIGURATION_OUTPUT)
            .expect("decode the pre-aggregation reconfiguration fixture");

    let aggregated = non_aggregated
        .upgrade()
        .expect("upgrade the pre-aggregation reconfiguration fixture");

    assert_eq!(
        bcs::to_bytes(&aggregated).expect("serialize the upgraded output"),
        PINNED_AGGREGATED_RECONFIGURATION_OUTPUT,
        "upgrade() no longer reproduces the pinned aggregated reconfiguration bytes — \
         a canonical-ordering or serialization regression that would split the \
         byte-identical quorum at the protocol-v5 flip epoch"
    );
}

/// Mainnet compound-path determinism (protocol 3 → 5 direct): rebuilding the
/// canonical anchor from a V2 (core-only) anchor's class-group DKG output and
/// the aggregated reconfiguration output must yield the exact pinned V4
/// anchor bytes.
#[test]
fn v2_start_anchor_migration_matches_fixed_vector() {
    let core: twopc_mpc::decentralized_party::dkg::PublicOutputCore =
        bcs::from_bytes(DKG_OUTPUT_CORE).expect("decode the V2 (core) anchor fixture");
    let aggregated_reconfiguration: twopc_mpc::decentralized_party::reconfiguration::PublicOutput =
        bcs::from_bytes(PINNED_AGGREGATED_RECONFIGURATION_OUTPUT)
            .expect("decode the aggregated reconfiguration fixture");

    let anchor =
        twopc_mpc::decentralized_party::dkg::PublicOutput::new_from_reconfiguration_output(
            core.class_group_dkg_output(),
            aggregated_reconfiguration,
        )
        .expect("rebuild the anchor from the aggregated reconfiguration output");

    assert_eq!(
        bcs::to_bytes(&anchor).expect("serialize the rebuilt anchor"),
        PINNED_AGGREGATED_ANCHOR,
        "the V2-start anchor migration no longer reproduces the pinned V4 anchor bytes — \
         a determinism regression on mainnet's 3→5 flip path"
    );
}

/// Testnet anchor-migration determinism: the (V3 anchor, V4 reconfiguration
/// output) reconstruction — the migration off the pre-aggregation encoding —
/// must yield the same pinned V4 anchor bytes as the V2-start path (both
/// rebuild from the identical class-group DKG output + aggregated
/// reconfiguration output).
#[test]
fn v3_start_anchor_migration_matches_fixed_vector() {
    // Fabricate the V3 anchor exactly as testnet's V2→V3 canonical migration
    // did: core's class-group output + the pre-aggregation reconfiguration
    // output.
    let core: twopc_mpc::decentralized_party::dkg::PublicOutputCore =
        bcs::from_bytes(DKG_OUTPUT_CORE).expect("decode the V2 (core) anchor fixture");
    let non_aggregated_reconfiguration: twopc_mpc::decentralized_party::reconfiguration::NonAggregatedPublicOutput =
        bcs::from_bytes(NON_AGGREGATED_RECONFIGURATION_OUTPUT)
            .expect("decode the pre-aggregation reconfiguration fixture");
    let v3_anchor =
        twopc_mpc::decentralized_party::dkg::NonAggregatedPublicOutput::new_from_reconfiguration_output(
            core.class_group_dkg_output(),
            non_aggregated_reconfiguration,
        )
        .expect("build the testnet-shaped V3 anchor");

    let migrated = reconstruct_full_network_dkg_output(
        &VersionedNetworkDkgOutput::V3(bcs::to_bytes(&v3_anchor).expect("serialize the V3 anchor")),
        Some(&VersionedDecryptionKeyReconfigurationOutput::V4(
            PINNED_AGGREGATED_RECONFIGURATION_OUTPUT.to_vec(),
        )),
    )
    .expect("the V3→V4 anchor migration must succeed on the fixtures");

    let Some(VersionedNetworkDkgOutput::V4(migrated_bytes)) = migrated else {
        panic!("the (V3 anchor, V4 reconfiguration output) pair must reconstruct a V4 anchor");
    };
    assert_eq!(
        migrated_bytes, PINNED_AGGREGATED_ANCHOR,
        "the V3-start anchor migration no longer reproduces the pinned V4 anchor bytes — \
         a determinism regression on testnet's 4→5 flip path"
    );
}

/// One-time fixture capture: runs a real 4-party network DKG plus a
/// same-committee pre-aggregation reconfiguration (the deployed protocol-v4
/// configuration) and writes the input fixtures and the pinned derived bytes.
/// Rerun only when the fixture format itself legitimately changes (e.g. an
/// intentional wire-format bump), and commit the regenerated files —
/// regenerating to "fix" a red pin defeats the tests above.
#[tokio::test]
#[ignore = "fixture generator — run once manually and commit the outputs"]
async fn generate_aggregated_output_fixed_vectors() {
    use ika_types::message::DWalletCheckpointMessageKind;
    use tracing::info;

    use crate::dwallet_mpc::integration_tests::network_dkg::{
        create_network_key_test, send_start_network_key_reconfiguration_event,
    };
    use crate::dwallet_mpc::integration_tests::network_dkg_bwd_compat::pin_pre_aggregation_outputs_overrides;
    use crate::dwallet_mpc::integration_tests::utils;
    use crate::dwallet_mpc::integration_tests::utils::IntegrationTestState;

    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _pre_aggregation_override = pin_pre_aggregation_outputs_overrides();

    let (committee, seeds, bundles) = utils::build_committee_with_random_seeds(4);
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
        bundles.clone(),
    );
    let mut state = IntegrationTestState {
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
    let (consensus_round, anchor_bytes, key_id) = create_network_key_test(&mut state).await;

    let mut next_committee = (*state.dwallet_mpc_services[0].committee).clone();
    next_committee.epoch = 2;
    for sui_data_sender in &state.sui_data_senders {
        let _ = sui_data_sender
            .next_epoch_committee_sender
            .send(next_committee.clone());
        let _ = sui_data_sender
            .next_epoch_mpc_keys_sender
            .send(Some((next_committee.epoch, bundles.clone())));
    }
    send_start_network_key_reconfiguration_event(
        1,
        &mut state.sui_data_senders,
        [10u8; 32],
        10,
        key_id,
    );
    let (_, reconfiguration_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut state, consensus_round).await;
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

    let VersionedDecryptionKeyReconfigurationOutput::V3(non_aggregated_reconfiguration_bytes) =
        bcs::from_bytes(&reconfiguration_output_bytes)
            .expect("decode the versioned reconfiguration output")
    else {
        panic!("the pre-aggregation-pinned reconfiguration must produce a V3-tagged output");
    };
    let VersionedNetworkDkgOutput::V4(aggregated_anchor_bytes) =
        bcs::from_bytes(&anchor_bytes).expect("decode the versioned anchor")
    else {
        panic!("the network DKG must produce a V4-tagged anchor");
    };
    let aggregated_anchor: twopc_mpc::decentralized_party::dkg::PublicOutput =
        bcs::from_bytes(&aggregated_anchor_bytes).expect("decode the aggregated anchor");
    let core_bytes = bcs::to_bytes(&aggregated_anchor.core).expect("serialize the anchor core");

    let non_aggregated: twopc_mpc::decentralized_party::reconfiguration::NonAggregatedPublicOutput =
        bcs::from_bytes(&non_aggregated_reconfiguration_bytes)
            .expect("decode the pre-aggregation reconfiguration output");
    let aggregated_reconfiguration_bytes = bcs::to_bytes(
        &non_aggregated
            .upgrade()
            .expect("upgrade the reconfiguration output"),
    )
    .expect("serialize the aggregated reconfiguration output");

    let aggregated_reconfiguration: twopc_mpc::decentralized_party::reconfiguration::PublicOutput =
        bcs::from_bytes(&aggregated_reconfiguration_bytes)
            .expect("decode the aggregated reconfiguration output");
    let anchor =
        twopc_mpc::decentralized_party::dkg::PublicOutput::new_from_reconfiguration_output(
            aggregated_anchor.core.class_group_dkg_output(),
            aggregated_reconfiguration,
        )
        .expect("rebuild the anchor from the aggregated reconfiguration output");
    let pinned_anchor_bytes = bcs::to_bytes(&anchor).expect("serialize the rebuilt anchor");

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/dwallet_mpc/integration_tests/fixtures");
    std::fs::create_dir_all(&dir).expect("create the fixtures directory");
    std::fs::write(
        dir.join("reconfiguration_output_non_aggregated.bcs"),
        &non_aggregated_reconfiguration_bytes,
    )
    .expect("write the pre-aggregation reconfiguration fixture");
    std::fs::write(
        dir.join("reconfiguration_output_aggregated.bcs"),
        &aggregated_reconfiguration_bytes,
    )
    .expect("write the aggregated reconfiguration fixture");
    std::fs::write(dir.join("dkg_output_core.bcs"), &core_bytes)
        .expect("write the anchor core fixture");
    std::fs::write(dir.join("dkg_anchor_aggregated.bcs"), &pinned_anchor_bytes)
        .expect("write the pinned aggregated anchor fixture");
    info!(
        non_aggregated = non_aggregated_reconfiguration_bytes.len(),
        aggregated = aggregated_reconfiguration_bytes.len(),
        core = core_bytes.len(),
        anchor = pinned_anchor_bytes.len(),
        "fixed-vector fixtures written"
    );
}
