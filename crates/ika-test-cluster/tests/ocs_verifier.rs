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
use ika_test_cluster::{IkaTestCluster, IkaTestClusterBuilder};

/// dWallet curve id for secp256k1 (matches the on-chain enum discriminant).
const DWALLET_CURVE_SECP256K1: u32 = 0;

/// The shared end-to-end assertion all three topology tests drive:
///
/// 1. Bootstrap completes (`wait_for_epoch(1)`) — the committee installed
///    from the genesis anchor, the OCS verified reader feeding the pump.
/// 2. Network-encryption-key DKG completes — a *system* session delivered
///    by the pump from the verified system bag.
/// 3. A user dWallet DKG completes — a *user* session, proving verified
///    coordinator reads + user-bag ingestion.
/// 4. The cluster crosses an epoch boundary — the Sui-committee ratchet and
///    verified System/Coordinator reads across reconfiguration.
///
/// `topology` names the read path under test so a timeout's panic message
/// points at the right suspect.
async fn drive_dkg_and_epoch_advance(cluster: &mut IkaTestCluster, topology: &str) {
    cluster.wait_for_epoch(1).await;

    let (network_key_id, network_dkg_public_output) =
        cluster.wait_for_network_key().await.unwrap_or_else(|e| {
            panic!(
                "[{topology}] network key DKG did not complete — \
                 system-event ingestion likely broken: {e:?}"
            )
        });

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
        .unwrap_or_else(|e| {
            panic!(
                "[{topology}] user dWallet DKG did not complete — \
                 user-event ingestion likely broken: {e:?}"
            )
        });

    cluster.wait_for_epoch(2).await;
}

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

    drive_dkg_and_epoch_advance(&mut cluster, "direct").await;
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

    // With four validators the MPC quorum is three, so completing the DKGs
    // requires a mirrored validator's relay reads to have succeeded.
    drive_dkg_and_epoch_advance(&mut cluster, "mirrored-relay").await;
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
    // reader first, then read its committee + epoch-start state over the
    // relay. The DKGs then need a peer-only validator's relay reads for
    // quorum (three of four), and the epoch advance exercises their
    // committee ratchet — entirely over the relay.
    drive_dkg_and_epoch_advance(&mut cluster, "peer-only").await;
}

/// Peer-only validators (no Sui uplink) crossing MULTIPLE epoch boundaries.
/// After the initial DKGs, the cluster advances through several more
/// reconfigurations, exercising the committee ratchet + follower over a run of
/// boundaries entirely over the relay — the finding-17 committee half: a skipped
/// or mis-derived `committee[E+1]` would stall reconfiguration. The single-epoch
/// topology tests above prove one crossing; this proves the chain holds over
/// many. Slow (several 60s epochs) — a cluster-suite test, not the fast unit pass.
#[tokio::test(flavor = "multi_thread")]
async fn ocs_verifier_v4_peer_only_ratchet_survives_multiple_epoch_boundaries() {
    telemetry_subscribers::init_for_testing();

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

    // Initial DKGs + the first boundary (reaches epoch 2).
    drive_dkg_and_epoch_advance(&mut cluster, "peer-only-multi-epoch").await;
    // Cross several more boundaries: each peer-only validator's committee ratchet
    // + follower must install every committee[E+1] over the relay without
    // skipping, or reconfiguration would stall here.
    cluster.wait_for_epoch(5).await;
}

/// A direct validator is stopped and restarted mid-run. On reboot its OCS stack
/// rehydrates: the verified state cache reloads from the perpetual
/// `verified_object_cache` (N1/N2 — `open` restores the head and seeds the
/// processed head from the fold head so the staleness tripwire doesn't fire
/// spuriously on boot) and the committee ratchet resumes from the persisted
/// committee chain rather than cold-starting from the fullnode. The proof is
/// liveness THROUGH the restart: the cluster keeps advancing and a fresh user
/// DKG completes afterwards, which requires the restarted validator's verified
/// reads + MPC ingestion to be working again. A broken rehydration (stale-on-boot
/// tripwire, a lost cache that can't refill, or a re-anchor that breaks the
/// ratchet) would drop it below quorum and stall. Acquire node handles ON DEMAND
/// only — a handle held across stop/start keeps the old RocksDB store lock and
/// the respawn dies on it (see restart_mid_grace). Slow — a cluster-suite test.
#[tokio::test(flavor = "multi_thread")]
async fn ocs_verifier_v4_direct_validator_restart_resumes_and_keeps_serving() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(45_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .with_ocs_genesis_anchor(true)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    // Reach a steady state: the pusher has folded Ika objects into the persisted
    // cache and the committee chain has crossed a boundary.
    cluster.wait_for_epoch(2).await;
    let (network_key_id, network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("network key DKG did not complete before the restart");

    // Restart one validator. Never bind its handle across stop()/start().
    let restart_name = cluster.validator_names[3];
    cluster
        .swarm
        .node(&restart_name)
        .expect("validator exists")
        .stop();
    cluster
        .swarm
        .node(&restart_name)
        .expect("validator exists")
        .start()
        .await
        .expect("validator failed to restart");

    // Liveness through the restart: a fresh user DKG must complete, which needs
    // the restarted validator's rehydrated verified reads + MPC ingestion.
    let user_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [9u8; 32])
        .await
        .expect("register_user_encryption_key failed");
    let dkg_handle = cluster
        .request_user_dwallet_dkg(
            DWALLET_CURVE_SECP256K1,
            network_key_id,
            network_dkg_public_output,
            &user_key,
            cluster.packages.ika_supply_id,
        )
        .await
        .expect("request_user_dwallet_dkg failed");
    cluster
        .wait_for_dwallet_dkg_complete(dkg_handle.dwallet_id, std::time::Duration::from_secs(600))
        .await
        .expect("user DKG did not complete after the validator restart — OCS rehydration broken");

    // And cross another boundary: the restarted validator's committee ratchet
    // resumed from persisted state, so reconfiguration still works.
    cluster.wait_for_epoch(4).await;
}

/// Relay failover: in the mirrored topology the first two (direct) validators
/// serve the `SuiStateMirror` relay to the two mirrored validators. Kill ONE
/// direct relay-serving validator after the network is live: each mirrored
/// validator's `SuiMirrorPeers::try_peers` must fail over to the surviving relay
/// peer (demoting the dead one) and keep reading verified Sui state, so the
/// cluster still completes a user DKG. (The single-pass classification —
/// NotFound only if every reached peer agrees, timeout/error -> Network — is
/// unit-tested in `try_peers_verdict_*`; this is the live multi-peer failover the
/// in-process harness CAN express, unlike a hung-but-connected peer, which needs
/// fault injection the harness lacks.) Slow — a cluster-suite test.
#[tokio::test(flavor = "multi_thread")]
async fn ocs_verifier_v4_mirrored_relay_fails_over_when_a_relay_peer_dies() {
    telemetry_subscribers::init_for_testing();

    // 2 direct (relay servers) + 2 mirrored, as in the mirrored-relay test.
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(60_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .with_ocs_genesis_anchor(true)
        .with_sui_state_direct_count(2)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;
    let (network_key_id, network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("network key DKG did not complete before the relay kill");

    // Kill one of the two direct relay-serving validators. Each mirrored
    // validator now has exactly one surviving relay peer to fail over to; with
    // four validators the MPC quorum is three, so completing the DKG below
    // REQUIRES the two mirrored validators' failed-over relay reads.
    let dead_relay = cluster.validator_names[0];
    cluster
        .swarm
        .node(&dead_relay)
        .expect("relay validator exists")
        .stop();

    let user_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [11u8; 32])
        .await
        .expect("register_user_encryption_key failed");
    let dkg_handle = cluster
        .request_user_dwallet_dkg(
            DWALLET_CURVE_SECP256K1,
            network_key_id,
            network_dkg_public_output,
            &user_key,
            cluster.packages.ika_supply_id,
        )
        .await
        .expect("request_user_dwallet_dkg failed");
    cluster
        .wait_for_dwallet_dkg_complete(dkg_handle.dwallet_id, std::time::Duration::from_secs(600))
        .await
        .expect("user DKG did not complete after a relay peer died — relay failover broken");
}
