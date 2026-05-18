// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Network-owned-address (NOA) sign DKG support.
//!
//! Holds two ika-side helpers for the NOA-DKG path that have no upstream equivalent:
//! - [`network_owned_address_sign_dkg_session_identifier`] derives a curve-specific
//!   (sig-algo-independent) session id from `network_key_id + curve`.
//! - [`compute_noa_dkg`] runs upstream's native
//!   `<D as twopc_mpc::dkg::Protocol>::threshold_dkg_output(pp, session_id)`
//!   for a single curve, extracts the public key, and wraps the output in
//!   `VersionedDwalletDKGPublicOutput::V2` so downstream sign-input construction
//!   can round-trip it through the standard user-driven sign path.

use crate::dwallet_mpc::crytographic_computation::mpc_computations::network_dkg::PerCurveNetworkOwnedAddressDkgData;
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, VersionedDwalletDKGPublicOutput,
    public_key_from_decentralized_dkg_output_by_curve_v2,
};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
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

/// Runs the threshold-only DKG for a single curve, extracts the public key and
/// wraps the output in `VersionedDwalletDKGPublicOutput::V2` for downstream
/// sign-input construction.
///
/// ika's NOA emulator was removed; this calls upstream's native
/// `<D as twopc_mpc::dkg::Protocol>::threshold_dkg_output(pp, session_id)` directly
/// to produce the decentralized-party DKG output for threshold (no centralized
/// party) mode. The session id is derived from `network_key_id + curve`
/// (curve-specific, sig-algo independent) per
/// [`network_owned_address_sign_dkg_session_identifier`].
pub(crate) fn compute_noa_dkg<D>(
    network_key_id: &[u8; 32],
    curve: DWalletCurve,
    protocol_public_parameters: &D::ProtocolPublicParameters,
) -> DwalletMPCResult<PerCurveNetworkOwnedAddressDkgData>
where
    D: twopc_mpc::dkg::Protocol,
{
    let session_identifier =
        network_owned_address_sign_dkg_session_identifier(network_key_id, curve);
    let session_id = CommitmentSizedNumber::from_le_slice(&session_identifier.into_bytes());

    let dkg_output =
        D::threshold_dkg_output(protocol_public_parameters, session_id).map_err(|e| {
            DwalletMPCError::InternalError(format!("threshold_dkg_output {curve:?}: {e}"))
        })?;
    let dkg_output = bcs::to_bytes(&dkg_output)?;
    let public_key = public_key_from_decentralized_dkg_output_by_curve_v2(curve, &dkg_output)
        .map_err(|e| {
            DwalletMPCError::InternalError(format!("public_key extract {curve:?}: {e}"))
        })?;
    // Wrap in VersionedDwalletDKGPublicOutput::V2 so downstream sign-input
    // construction (which decodes via VersionedDwalletDKGPublicOutput) can
    // round-trip through the standard user-driven sign path.
    let dkg_output = bcs::to_bytes(&VersionedDwalletDKGPublicOutput::V2 {
        public_key_bytes: public_key.clone(),
        dkg_output,
    })?;
    Ok(PerCurveNetworkOwnedAddressDkgData {
        dkg_output,
        public_key,
    })
}
