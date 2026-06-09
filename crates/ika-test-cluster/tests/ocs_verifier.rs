// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! End-to-end cluster test for the OCS (Object-Checkpoint-State) verified
//! Sui-state path, active at protocol v4
//! (`off_chain_validator_metadata_enabled`).
//!
//! With `.with_ocs_genesis_anchor(true)` every validator boots from the Sui
//! localnet's epoch-0 committee (the unsafe-genesis bootstrap), which makes
//! `has_anchor` true so the OCS stack is built. At v4 this flips MPC session-
//! event ingestion from the legacy JSON-RPC `query_events` listener to the
//! OCS `BagEventPump`, which walks the verified `session_events` bags through
//! `OcsVerifiedReader` (every read checked against the committee via an
//! inclusion proof against the checkpoint's artifacts digest).
//!
//! The test asserts the full path works by driving real MPC sessions to
//! completion and crossing an epoch boundary:
//!   1. Network-key DKG completes — a *system* session delivered by the pump.
//!   2. A user dWallet DKG completes — a *user* session delivered by the pump.
//!   3. The cluster advances an epoch — exercising the Sui-committee ratchet
//!      and verified `System`/`DWalletCoordinator` reads across the boundary.
//!
//! If OCS event ingestion or verified reads were broken, the MPC engine would
//! never receive the session requests and these waits would time out.

use ika_protocol_config::ProtocolVersion;
use ika_test_cluster::IkaTestClusterBuilder;

/// dWallet curve id for secp256k1 (matches the on-chain enum discriminant).
const DWALLET_CURVE_SECP256K1: u32 = 0;

#[tokio::test(flavor = "multi_thread")]
async fn ocs_verifier_v4_drives_user_dkg_and_epoch_advance() {
    telemetry_subscribers::init_for_testing();

    // 4 direct validators (default `SuiStateDirect { serve_mirror: true }`),
    // protocol v4, OCS anchored on the localnet genesis committee.
    //
    // 45s epoch (vs a tighter 30s) so the per-epoch off-chain class-groups
    // blob propagation has headroom: on a loaded machine a shorter epoch can
    // lapse before all four validators' bundles propagate, leaving the
    // network-key reconfiguration at 3/4 and stalling the user DKG.
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(45_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .with_ocs_genesis_anchor(true)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    // Bootstrap completes: committee installed from the genesis anchor, the
    // OCS verified reader is feeding the BagEventPump.
    cluster.wait_for_epoch(1).await;

    // (1) System session via OCS: the network-encryption-key DKG ran because
    // the pump delivered its session event from the verified system bag.
    let (network_key_id, network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("network key DKG did not complete — OCS system-event ingestion likely broken");

    // (2) User session via OCS: register a user encryption key and run a
    // dWallet DKG. Completion proves the pump delivered the user-bag session
    // event and the verified reads of the coordinator inner succeeded.
    let user_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [7u8; 32])
        .await
        .expect("register_user_encryption_key failed");

    let ika_coin_id = cluster.packages.ika_supply_id;
    let dkg_handle = cluster
        .request_user_dwallet_dkg(
            DWALLET_CURVE_SECP256K1,
            network_key_id,
            network_dkg_public_output,
            &user_key,
            ika_coin_id,
        )
        .await
        .expect("request_user_dwallet_dkg failed");

    cluster
        .wait_for_dwallet_dkg_complete(dkg_handle.dwallet_id, std::time::Duration::from_secs(600))
        .await
        .expect("user dWallet DKG did not complete — OCS user-event ingestion likely broken");

    // (3) Cross an epoch boundary: exercises the Sui-committee ratchet and
    // verified System/Coordinator reads across reconfiguration.
    cluster.wait_for_epoch(2).await;
}

/// Same end-to-end OCS path, but with a *mirrored* read topology: only the
/// first two validators read Sui directly (and serve the `SuiStateMirror`
/// relay); the other two are `SuiStateMirrored` and read *verified* Sui state
/// through a direct validator's anemo relay (`SuiMirrorTransport` /
/// `SuiMirrorProofProvider`) rather than their own gRPC connection.
///
/// With four validators the MPC quorum threshold is three, and the two direct
/// validators alone cannot reach it. So driving a user dWallet DKG to
/// completion *requires* at least one mirrored validator to have successfully
/// read the verified coordinator state and `session_events` bag over the relay
/// and fed its MPC engine. If the relay path (mirror server, anemo transport,
/// or `SuiMirrorProofProvider` verification) were broken, the mirrored
/// validators would contribute nothing and the DKG would time out.
#[tokio::test(flavor = "multi_thread")]
async fn ocs_verifier_v4_mirrored_relay_drives_user_dkg_and_epoch_advance() {
    telemetry_subscribers::init_for_testing();

    // 2 direct validators (serve the relay) + 2 mirrored validators (read
    // verified Sui state through the relay), protocol v4, OCS anchored on the
    // localnet genesis committee.
    //
    // A longer epoch than the direct test: mirrored validators read through
    // an extra relay hop, so the per-epoch off-chain class-groups blob
    // propagation has more latency to absorb. On a loaded machine a shorter
    // epoch can lapse before all four validators' bundles propagate, leaving
    // the reconfiguration incomplete and stalling the user DKG. 60s (matching
    // the peer-only test) gives that propagation headroom even under heavy
    // load, without materially lengthening the test.
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(60_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .with_ocs_genesis_anchor(true)
        .with_sui_state_direct_count(2)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    // Bootstrap completes for both direct and mirrored validators: the mirrored
    // ones waited for a direct peer, then built their OCS stack on the relay.
    cluster.wait_for_epoch(1).await;

    // (1) System session via OCS: network-encryption-key DKG. Reaching quorum
    // here already needs a mirrored validator's relay reads to succeed.
    let (network_key_id, network_dkg_public_output) = cluster.wait_for_network_key().await.expect(
        "network key DKG did not complete — OCS relay system-event ingestion likely broken",
    );

    // (2) User session via OCS over the relay: register a user encryption key
    // and run a dWallet DKG to completion.
    let user_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [7u8; 32])
        .await
        .expect("register_user_encryption_key failed");

    let ika_coin_id = cluster.packages.ika_supply_id;
    let dkg_handle = cluster
        .request_user_dwallet_dkg(
            DWALLET_CURVE_SECP256K1,
            network_key_id,
            network_dkg_public_output,
            &user_key,
            ika_coin_id,
        )
        .await
        .expect("request_user_dwallet_dkg failed");

    cluster
        .wait_for_dwallet_dkg_complete(dkg_handle.dwallet_id, std::time::Duration::from_secs(600))
        .await
        .expect("user dWallet DKG did not complete — OCS relay user-event ingestion likely broken");

    // (3) Cross an epoch boundary: the mirrored validators ratchet their Sui
    // committee and re-read System/Coordinator state across reconfiguration,
    // all through the relay.
    cluster.wait_for_epoch(2).await;
}

/// Same end-to-end OCS path, but with *peer-only* mirrored validators: the two
/// `SuiStateMirrored` validators have NO `fallback_grpc_url`, so they have no
/// direct Sui uplink whatsoever. Every `sui_client` read they make — the
/// boot-time committee/epoch bootstrap (which a direct or fallback node does
/// over gRPC before the p2p network even exists), the periodic
/// System/Coordinator reads, the cross-epoch committee ratchet — is served over
/// a direct validator's anemo relay through the verified reader
/// (`VerifiedSuiTransport`).
///
/// This forces the hardest part of the peer-only path: a node with no uplink
/// must stand up its p2p network + OCS relay stack *before* reading any Sui
/// state, then bootstrap its IKA committee + epoch over the relay. As in the
/// mirrored test, the MPC quorum (three of four) can't be reached by the two
/// direct validators alone, so completing a user dWallet DKG *requires* at
/// least one peer-only validator to have bootstrapped entirely over the relay
/// and fed its MPC engine. A peer-only node that couldn't bootstrap over the
/// relay would never join the network, the quorum would stall, and these waits
/// would time out.
#[tokio::test(flavor = "multi_thread")]
async fn ocs_verifier_v4_peer_only_validator_drives_user_dkg_and_epoch_advance() {
    telemetry_subscribers::init_for_testing();

    // 2 direct validators (serve the relay) + 2 peer-only validators
    // (`SuiStateMirrored`, no fallback URL — no direct uplink), protocol v4,
    // OCS anchored on the localnet genesis committee. 60s epoch (vs the
    // mirrored test's 45s): peer-only is the most latency-sensitive topology —
    // every Sui read, including the per-epoch reconfiguration reads, crosses
    // the relay — so the off-chain class-groups assembly needs the extra
    // per-epoch headroom to win its propagation race on a loaded machine.
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(60_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .with_ocs_genesis_anchor(true)
        .with_sui_state_direct_count(2)
        .with_peer_only_mirrored(true)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    // Reaching epoch 1 already proves the peer-only validators bootstrapped:
    // with no direct uplink, each had to build its p2p network + OCS relay
    // reader first, then read its committee + epoch-start state over the relay.
    cluster.wait_for_epoch(1).await;

    // (1) System session via the relay: the network-encryption-key DKG reached
    // quorum, which needs a peer-only validator's relay reads to succeed.
    let (network_key_id, network_dkg_public_output) = cluster.wait_for_network_key().await.expect(
        "network key DKG did not complete — peer-only relay bootstrap/system reads likely broken",
    );

    // (2) User session via the relay: register a user encryption key and run a
    // dWallet DKG to completion.
    let user_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [7u8; 32])
        .await
        .expect("register_user_encryption_key failed");

    let ika_coin_id = cluster.packages.ika_supply_id;
    let dkg_handle = cluster
        .request_user_dwallet_dkg(
            DWALLET_CURVE_SECP256K1,
            network_key_id,
            network_dkg_public_output,
            &user_key,
            ika_coin_id,
        )
        .await
        .expect("request_user_dwallet_dkg failed");

    cluster
        .wait_for_dwallet_dkg_complete(dkg_handle.dwallet_id, std::time::Duration::from_secs(600))
        .await
        .expect("user dWallet DKG did not complete — peer-only relay user reads likely broken");

    // (3) Cross an epoch boundary: the peer-only validators ratchet their Sui
    // committee and re-read System/Coordinator state across reconfiguration,
    // entirely over the relay.
    cluster.wait_for_epoch(2).await;
}
