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
//! The fixtures are INPUTS captured once plus the PINNED derived bytes. The
//! generator that produced them was removed together with protocol-v4
//! support (it needed the deleted pre-aggregation reconfiguration-output
//! production path); the fixtures are frozen historical state from the
//! deployed networks' v4→v5 flip and must never be regenerated.

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

// The one-time fixture GENERATOR that produced the committed fixture bytes
// was removed together with protocol-v4 support: it needed the deleted
// pre-aggregation (V3-tagged) reconfiguration-output production path. The
// fixtures are frozen historical state (the deployed networks' v4->v5 flip)
// and must never be regenerated.
