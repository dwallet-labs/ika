// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! An MPC-inactive epoch (#2119) must retain nothing it will never process.
//!
//! The non-participating state is not an abort: the node runs the whole epoch
//! as a consensus member with MPC gated off. Two structures feed on work that
//! only MPC completes, and both are unbounded over an epoch:
//!
//! - `pending_network_owned_address_sign_requests` — filled from the bounded
//!   channel the checkpoint handlers write to, drained only by instantiating a
//!   signing session, which needs a network key this state never adopts.
//! - the manager's `internal_presign_requests_pending_for_network_key_data` —
//!   parked precisely on the network-key data whose ingest and instantiation
//!   are gated on `mpc_active`.
//!
//! On a 24h mainnet epoch, retaining either is a memory hazard, and the first
//! also emits a starvation `warn!` every 30s about a wait that is by design.
//! Peers complete these demands without this validator, exactly as they would
//! if it were down — so the inactive state drops both at intake.
//!
//! The channel itself must still be DRAINED: it is bounded, and a blocked
//! sender would back-pressure the checkpoint handlers. "Drained but not
//! retained" is the property under test.

use crate::dwallet_mpc::NetworkOwnedAddressSignRequest;
use crate::dwallet_mpc::integration_tests::utils::{
    build_test_state, create_test_protocol_config_guard_with_noa_checkpoints,
};
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm};

fn sign_request(tag: u8) -> NetworkOwnedAddressSignRequest {
    let message = vec![tag; 8];
    NetworkOwnedAddressSignRequest {
        demand_id: ika_types::noa_checkpoint::NOAPresignDemandId::GrpcAttestation {
            session_identifier: ika_types::crypto::keccak256_digest(&message),
            signature_algorithm: DWalletSignatureAlgorithm::ECDSASecp256k1,
        },
        message,
        curve: DWalletCurve::Secp256k1,
        hash_scheme: DWalletHashScheme::Keccak256,
    }
}

/// Intake in the inactive state drains the channel and keeps nothing.
///
/// The control is the same intake with MPC ACTIVE: it must RETAIN the
/// requests. Without that half, a bug that dropped the channel on the floor
/// unconditionally would pass the inactive assertion.
#[tokio::test]
async fn inactive_intake_drains_the_channel_and_retains_nothing() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard_with_noa_checkpoints();

    let mut test_state = build_test_state(4);

    // --- control: MPC active, requests are retained ---
    let active = test_state
        .dwallet_mpc_services
        .first_mut()
        .expect("a service");
    test_state.network_owned_address_sign_request_senders[0]
        .send(sign_request(1))
        .await
        .expect("send");
    active.process_network_owned_address_sign_requests_for_testing();
    assert_eq!(
        active.pending_network_owned_address_sign_request_count(),
        1,
        "with MPC active the request must be retained until a presign is \
         assigned; if this is 0 the inactive assertion below proves nothing"
    );

    // --- the state under test: MPC inactive ---
    active.set_mpc_active_for_testing(false);
    // Park a presign request on missing network-key data, so the second
    // structure is non-empty going in.
    active.park_internal_presign_request_for_testing();
    assert_eq!(active.parked_internal_presign_request_count(), 1);

    test_state.network_owned_address_sign_request_senders[0]
        .send(sign_request(2))
        .await
        .expect("send");
    active.process_network_owned_address_sign_requests_for_testing();

    assert_eq!(
        active.pending_network_owned_address_sign_request_count(),
        0,
        "an MPC-inactive epoch must retain no network-owned-address sign \
         request — including the one it was already holding when it went \
         inactive, which would otherwise outlive the whole epoch"
    );
    assert_eq!(
        active.parked_internal_presign_request_count(),
        0,
        "internal presign requests parked on network-key data must be dropped \
         too: their retry is gated on `mpc_active`, so they are parked on \
         something that cannot arrive this epoch"
    );
    // And the channel really was drained rather than left full.
    assert!(
        test_state.network_owned_address_sign_request_senders[0]
            .try_send(sign_request(3))
            .is_ok(),
        "the bounded channel must still accept sends; a request left queued \
         would back-pressure the checkpoint handlers that write to it"
    );
}
