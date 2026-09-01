// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Fixed-vector wire-format pin for the aggregated (V4) canonical anchor.
//!
//! Nothing in this binary calls
//! `decentralized_party::dkg::PublicOutput::new_from_reconfiguration_output`
//! any more — the derivation ran once, on an earlier binary, and the V4
//! anchors it produced are the live state the deployed networks hold. The pin
//! stays because that encoding is still load-bearing wire format here: every
//! epoch this binary decodes those very bytes and derives the protocol public
//! parameters from them, so an inkrypto-side reshape of
//! `decentralized_party::dkg::PublicOutput` — a field reorder, a serializer
//! change, an ordering regression in the derivation — would silently
//! reinterpret state nobody can regenerate, and every MPC output computed
//! against it would byte-diverge from the rest of the committee. Re-running
//! the original derivation is simply the sharpest way to pin that encoding: it
//! reproduces the exact bytes of a real protocol run, inputs and output both
//! committed as fixtures.
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

/// Anchor encoding pin: rebuilding the canonical anchor from a V2 (core-only)
/// anchor's class-group DKG output and the aggregated reconfiguration output
/// must yield the exact pinned V4 anchor bytes — the bytes the deployed keys
/// hold today and that this binary re-reads every epoch.
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
        "the pinned V4 anchor bytes are no longer reproduced — the encoding of \
         `decentralized_party::dkg::PublicOutput` moved out from under the anchors the \
         deployed keys already hold, so this binary would derive different protocol \
         public parameters from that unregenerable state than its peers do"
    );
}
