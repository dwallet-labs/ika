// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Fixed-vector determinism pins for the aggregated-output anchor migration.
//!
//! Every validator independently derives and persists the aggregated (V4)
//! canonical anchor via `new_from_reconfiguration_output`, so byte-identical
//! quorum rests entirely on that derivation being canonically ordered
//! (receivers, curve-parts, summation, bcs map encoding) across binaries and
//! refactors. This test pins the derivation against committed fixtures
//! captured from one real protocol run: any change to the derived bytes — an
//! iteration-order regression, a serializer change, a struct reshape — fails
//! it.
//!
//! The pre-aggregation (V3) fixture pins that lived here were removed with
//! the crypto types they exercised (`NonAggregatedPublicOutput` and its
//! `upgrade()` no longer exist in inkrypto); V3-tagged state is a hard decode
//! error now.
//!
//! The fixtures are INPUTS captured once plus the PINNED derived bytes. The
//! generator that produced them was removed together with protocol-v4
//! support (it needed the deleted pre-aggregation reconfiguration-output
//! production path); the fixtures are frozen historical state from the
//! deployed networks' v4→v5 flip and must never be regenerated.

const PINNED_AGGREGATED_RECONFIGURATION_OUTPUT: &[u8] =
    include_bytes!("fixtures/reconfiguration_output_aggregated.bcs");
const DKG_OUTPUT_CORE: &[u8] = include_bytes!("fixtures/dkg_output_core.bcs");
const PINNED_AGGREGATED_ANCHOR: &[u8] = include_bytes!("fixtures/dkg_anchor_aggregated.bcs");

/// Anchor-migration determinism: rebuilding the canonical anchor from a V2
/// (core-only) anchor's class-group DKG output and the aggregated
/// reconfiguration output must yield the exact pinned V4 anchor bytes.
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
         a determinism regression that would split the byte-identical quorum on the \
         deployed keys' one-time anchor migration"
    );
}
