// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Network-owned-address (NOA) sign DKG support.
//!
//! Phase 4f of the cryptography-private bump removed ika's pre-protocol emulation of the
//! centralized party (DKG and sign). Upstream `9d35fa76` provides the equivalent capabilities
//! natively:
//! - DKG side: `<DKGProtocol as twopc_mpc::dkg::Protocol>::threshold_dkg_output(pp, session_id)`
//!   returns the decentralized-party DKG output for the threshold (no centralized party) mode.
//! - Sign side: `twopc_mpc::sign::SignData::ToBeEmulated` makes the sign protocol emulate the
//!   centralized party's partial signature internally (in a Rayon-dispatched advance, not
//!   synchronously off-Rayon as ika's previous emulator did).
//!
//! All that remains in this module is the session-id derivation, which is pure ika-side
//! bookkeeping with no upstream equivalent.

use dwallet_mpc_types::dwallet_mpc::DWalletCurve;
use ika_types::messages_dwallet_mpc::SessionIdentifier;
use ika_types::messages_dwallet_mpc::SessionType;
use merlin::Transcript;

/// DKG session identifier for network-owned-address signing.
///
/// DKG is curve-specific but signature-algorithm-independent: a single DKG on a curve
/// produces key shares usable by any signature algorithm on that curve.
pub fn network_owned_address_sign_dkg_session_identifier(
    network_key_id: &[u8],
    curve: DWalletCurve,
) -> SessionIdentifier {
    // Use binary enum discriminant instead of string representation to prevent
    // collision if two variants ever produce the same Display output.
    let mut transcript =
        Transcript::new(b"Network Owned Address Sign DKG session identifier preimage");
    transcript.append_message(b"network_key_id", network_key_id);
    transcript.append_u64(b"curve", curve as u64);

    let mut session_identifier_preimage: [u8; SessionIdentifier::LENGTH] =
        [0; SessionIdentifier::LENGTH];
    transcript.challenge_bytes(
        b"session_identifier_preimage",
        &mut session_identifier_preimage,
    );

    SessionIdentifier::new(SessionType::System, session_identifier_preimage)
}
