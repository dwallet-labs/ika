// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Internal Checkpoint DKG Module
//!
//! This module provides functionality to compute the decentralized party DKG output
//! for internal checkpoint signing. It emulates the centralized party (user) using
//! a deterministic zero-returning RNG (`ZeroRng`), enabling the network to perform
//! internal signing operations without requiring an actual user.
//!
//! # Security Model
//!
//! The "user" (centralized party) key share is effectively zero/deterministic, meaning
//! there is no user secret to protect. Security for internal signing comes entirely
//! from the network's threshold signature scheme, not from user randomness.
//!
//! # Usage
//!
//! This module is used when creating a network key to also prepare the internal
//! checkpoint DKG output. The output can then be used for signing checkpoints
//! without requiring user participation.

use crypto_bigint::Uint;
use dwallet_mpc_centralized_party::{
    CentralizedDKGWasmResult, advance_sign_by_protocol_with_rng, centralized_dkg_output_v2_with_rng,
};
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletSignatureAlgorithm, VersionedDwalletUserSecretShare,
};
use dwallet_rng::ZeroRng;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use twopc_mpc::dkg::centralized_party::SecretKeyShare;

/// The result of emulating the centralized party DKG using ZeroRng.
///
/// # Security Note
///
/// The secret key share is zero (derived from ZeroRng) and is not stored here.
/// When needed for signing, a zero scalar is used directly.
/// This is intentional for internal signing where there is no user secret to protect.
#[derive(Debug, Clone)]
pub struct EmulatedCentralizedDKGResult {
    /// The public key share and proof from the emulated centralized party.
    /// This is used as input to the decentralized party DKG.
    pub public_key_share_and_proof: Vec<u8>,

    /// The public output of the emulated centralized party DKG.
    pub public_output: Vec<u8>,
}

/// Emulates the centralized party DKG for a given curve using ZeroRng.
///
/// This function creates a deterministic "user" DKG output that can be used
/// for internal checkpoint signing. All validators calling this function with
/// the same inputs will produce identical outputs.
///
/// # Arguments
///
/// * `curve` - The curve to use for the DKG (e.g., Curve25519)
/// * `protocol_public_parameters` - The serialized protocol public parameters
/// * `session_id` - The session identifier (used for domain separation)
///
/// # Returns
///
/// Returns the emulated centralized party DKG result, including:
/// - The public key share and proof (to be used as decentralized party input)
/// - The public output
/// - The "secret" key share (which is deterministic, not actually secret)
///
/// # Security Warning
///
/// This function uses ZeroRng which provides NO randomness. The output is
/// deterministic and the "secret" key share is not secret at all.
/// This is intentional for internal signing operations.
pub fn emulate_centralized_dkg_for_internal_signing(
    curve: DWalletCurve,
    protocol_public_parameters: &[u8],
    session_id: &[u8],
) -> DwalletMPCResult<EmulatedCentralizedDKGResult> {
    match curve {
        DWalletCurve::Secp256k1 => emulate_centralized_dkg_v2::<
            twopc_mpc::secp256k1::class_groups::DKGProtocol,
            { twopc_mpc::secp256k1::SCALAR_LIMBS },
            twopc_mpc::secp256k1::Scalar,
        >(protocol_public_parameters, session_id),
        DWalletCurve::Secp256r1 => emulate_centralized_dkg_v2::<
            twopc_mpc::secp256r1::class_groups::DKGProtocol,
            { twopc_mpc::secp256r1::SCALAR_LIMBS },
            twopc_mpc::secp256r1::Scalar,
        >(protocol_public_parameters, session_id),
        DWalletCurve::Curve25519 => emulate_centralized_dkg_v2::<
            twopc_mpc::curve25519::class_groups::DKGProtocol,
            { twopc_mpc::curve25519::SCALAR_LIMBS },
            twopc_mpc::curve25519::Scalar,
        >(protocol_public_parameters, session_id),
        DWalletCurve::Ristretto => emulate_centralized_dkg_v2::<
            twopc_mpc::ristretto::class_groups::DKGProtocol,
            { twopc_mpc::ristretto::SCALAR_LIMBS },
            twopc_mpc::ristretto::Scalar,
        >(protocol_public_parameters, session_id),
    }
}

/// Internal implementation of emulated centralized DKG for a specific protocol.
///
/// Uses the shared `centralized_dkg_output_v2_with_rng` from `dwallet_mpc_centralized_party`
/// with `ZeroRng` to produce deterministic output.
///
/// # Type Parameters
///
/// * `P` - The DKG protocol type
/// * `SCALAR_LIMBS` - The number of limbs for the scalar type (curve-specific)
/// * `ScalarValue` - The scalar type used by the protocol
///
/// # Security Warning
///
/// This function uses ZeroRng - a deterministic RNG that always returns zeros.
/// The output is intentionally deterministic for internal signing operations.
fn emulate_centralized_dkg_v2<P, const SCALAR_LIMBS: usize, ScalarValue>(
    protocol_pp_bytes: &[u8],
    session_id_bytes: &[u8],
) -> DwalletMPCResult<EmulatedCentralizedDKGResult>
where
    P: twopc_mpc::dkg::Protocol<CentralizedPartySecretKeyShare = SecretKeyShare<ScalarValue>>,
    ScalarValue:
        From<Uint<SCALAR_LIMBS>> + PartialEq + serde::Serialize + for<'a> serde::Deserialize<'a>,
{
    // CRITICAL: Using ZeroRng for deterministic output.
    // This is intentional - all validators must produce identical outputs,
    // so we use a deterministic RNG that always returns zero.
    let mut rng = ZeroRng::new();

    // Use the shared centralized party DKG function with ZeroRng
    let CentralizedDKGWasmResult {
        public_key_share_and_proof,
        public_output,
        centralized_secret_output,
    } = centralized_dkg_output_v2_with_rng::<P, _>(
        protocol_pp_bytes.to_vec(),
        session_id_bytes.to_vec(),
        &mut rng,
    )
    .map_err(|e| DwalletMPCError::InternalError(format!("Emulated centralized DKG failed: {e}")))?;

    // Verify that the private_output (centralized party secret key share) is zero.
    // Since we use ZeroRng, the scalar must be zero. If it's not, something is wrong.
    let zero_scalar: ScalarValue = Uint::<SCALAR_LIMBS>::ZERO.into();
    let zero_secret_key_share = SecretKeyShare::from(zero_scalar);
    let expected_zero_secret = bcs::to_bytes(&VersionedDwalletUserSecretShare::V1(bcs::to_bytes(
        &zero_secret_key_share,
    )?))
    .map_err(DwalletMPCError::BcsError)?;

    if centralized_secret_output != expected_zero_secret {
        return Err(DwalletMPCError::InternalError(
            "Emulated centralized DKG private_output is not zero despite using ZeroRng. This indicates a bug in the DKG implementation."
                .to_string(),
        ));
    }

    Ok(EmulatedCentralizedDKGResult {
        public_key_share_and_proof,
        public_output,
    })
}

/// Returns the serialized zero centralized party "secret" key share for internal signing.
///
/// This function returns a zero scalar without performing any DKG computation.
/// The emulated centralized DKG uses ZeroRng which always produces zero bytes,
/// resulting in a deterministic zero scalar for the centralized party's secret.
///
/// # Type Parameters
///
/// * `SCALAR_LIMBS` - The number of limbs for the scalar type (curve-specific)
/// * `ScalarValue` - The scalar type used by the curve
///
/// # Security Note
///
/// The returned "secret" is NOT actually secret - it's explicitly zero.
/// This is intentional for internal signing where there is no user secret to protect.
/// The security comes from the network's threshold signature, not from this value.
///
/// # Returns
///
/// The serialized zero scalar (wrapped in `VersionedDwalletUserSecretShare`).
pub fn get_zero_centralized_secret(curve: DWalletCurve)
    -> DwalletMPCResult<Vec<u8>>
{
    match curve {
        DWalletCurve::Secp256k1 => {
            get_zero_centralized_secret_internal::<
                { twopc_mpc::secp256k1::SCALAR_LIMBS },
                twopc_mpc::secp256k1::Scalar,
            >()
        }
        DWalletCurve::Secp256r1 => {
            get_zero_centralized_secret_internal::<
                { twopc_mpc::secp256r1::SCALAR_LIMBS },
                twopc_mpc::secp256r1::Scalar,
            >()
        }
        DWalletCurve::Curve25519 => {
            get_zero_centralized_secret_internal::<
                { twopc_mpc::curve25519::SCALAR_LIMBS },
                twopc_mpc::curve25519::Scalar,
            >()
        }
        DWalletCurve::Ristretto => {
            get_zero_centralized_secret_internal::<
                { twopc_mpc::ristretto::SCALAR_LIMBS },
                twopc_mpc::ristretto::Scalar,
            >()
        }
    }
}

pub fn get_zero_centralized_secret_internal<const SCALAR_LIMBS: usize, ScalarValue>()
-> DwalletMPCResult<Vec<u8>>
where
    ScalarValue: From<Uint<SCALAR_LIMBS>> + serde::Serialize,
{
    // Return Uint::ZERO converted to ScalarValue and serialized as the centralized party's secret key share.
    // The emulated centralized DKG (emulate_centralized_dkg_v2) verifies that
    // ZeroRng produces a zero secret key share, so we can use Uint::ZERO directly.
    let zero_scalar: ScalarValue = Uint::<SCALAR_LIMBS>::ZERO.into();
    let zero_secret_key_share = SecretKeyShare::from(zero_scalar);
    let zero_scalar_bytes =
        bcs::to_bytes(&zero_secret_key_share).map_err(DwalletMPCError::BcsError)?;
    let centralized_secret_output =
        bcs::to_bytes(&VersionedDwalletUserSecretShare::V1(zero_scalar_bytes))
            .map_err(DwalletMPCError::BcsError)?;
    Ok(centralized_secret_output)
}

/// Emulates the centralized party's partial signature for internal signing.
///
/// This function creates a deterministic partial signature using ZeroRng to emulate
/// the centralized party. All validators calling this function with the same inputs
/// will produce identical outputs.
///
/// # Arguments
///
/// * `signature_algorithm` - The signature algorithm (e.g., EdDSA)
/// * `emulated_dkg_result` - The emulated DKG result from `emulate_centralized_dkg_for_internal_signing`
/// * `message` - The message to sign
/// * `hash_scheme` - The hash scheme to use
/// * `presign` - The presign data (from internal presign pool)
/// * `protocol_public_parameters` - The protocol public parameters
///
/// # Returns
///
/// The serialized partial signature from the emulated centralized party.
///
/// # Security Warning
///
/// This function uses ZeroRng which provides NO randomness. The output is
/// deterministic. This is intentional for internal signing operations.
pub fn emulate_centralized_party_partial_signature(
    signature_algorithm: DWalletSignatureAlgorithm,
    emulated_dkg_result: &EmulatedCentralizedDKGResult,
    message: Vec<u8>,
    hash_scheme: group::HashScheme,
    presign: &[u8],
    protocol_public_parameters: &[u8],
) -> DwalletMPCResult<Vec<u8>> {
    match signature_algorithm {
        DWalletSignatureAlgorithm::ECDSASecp256k1 => emulate_sign_centralized::<
            twopc_mpc::secp256k1::class_groups::ECDSAProtocol,
            { twopc_mpc::secp256k1::SCALAR_LIMBS },
            twopc_mpc::secp256k1::Scalar,
        >(
            emulated_dkg_result,
            message,
            hash_scheme,
            presign,
            protocol_public_parameters,
        ),
        DWalletSignatureAlgorithm::ECDSASecp256r1 => emulate_sign_centralized::<
            twopc_mpc::secp256r1::class_groups::ECDSAProtocol,
            { twopc_mpc::secp256r1::SCALAR_LIMBS },
            twopc_mpc::secp256r1::Scalar,
        >(
            emulated_dkg_result,
            message,
            hash_scheme,
            presign,
            protocol_public_parameters,
        ),
        DWalletSignatureAlgorithm::EdDSA => emulate_sign_centralized::<
            twopc_mpc::curve25519::class_groups::EdDSAProtocol,
            { twopc_mpc::curve25519::SCALAR_LIMBS },
            twopc_mpc::curve25519::Scalar,
        >(
            emulated_dkg_result,
            message,
            hash_scheme,
            presign,
            protocol_public_parameters,
        ),
        DWalletSignatureAlgorithm::Taproot => emulate_sign_centralized::<
            twopc_mpc::secp256k1::class_groups::TaprootProtocol,
            { twopc_mpc::secp256k1::SCALAR_LIMBS },
            twopc_mpc::secp256k1::Scalar,
        >(
            emulated_dkg_result,
            message,
            hash_scheme,
            presign,
            protocol_public_parameters,
        ),
        DWalletSignatureAlgorithm::SchnorrkelSubstrate => emulate_sign_centralized::<
            twopc_mpc::ristretto::class_groups::SchnorrkelSubstrateProtocol,
            { twopc_mpc::ristretto::SCALAR_LIMBS },
            twopc_mpc::ristretto::Scalar,
        >(
            emulated_dkg_result,
            message,
            hash_scheme,
            presign,
            protocol_public_parameters,
        ),
    }
}

/// Internal implementation of emulated centralized party signing for a specific protocol.
///
/// Uses the shared `advance_sign_by_protocol_with_rng` from `dwallet_mpc_centralized_party`
/// with `ZeroRng` to produce deterministic output.
///
/// Type parameters:
/// - `P`: The signing protocol
/// - `SCALAR_LIMBS`: The number of limbs for the scalar type (curve-specific)
/// - `ScalarValue`: The scalar type used by the protocol
fn emulate_sign_centralized<P: twopc_mpc::sign::Protocol, const SCALAR_LIMBS: usize, ScalarValue>(
    emulated_dkg_result: &EmulatedCentralizedDKGResult,
    message: Vec<u8>,
    hash_scheme: group::HashScheme,
    presign_bytes: &[u8],
    protocol_pp_bytes: &[u8],
) -> DwalletMPCResult<Vec<u8>>
where
    ScalarValue: From<Uint<SCALAR_LIMBS>> + serde::Serialize,
{
    // Get the zero secret key share (the centralized party's secret is always zero for internal signing)
    let zero_secret_key_share = get_zero_centralized_secret_internal::<SCALAR_LIMBS, ScalarValue>()?;

    // Deserialize the centralized party DKG public output
    let centralized_party_dkg_public_output: P::CentralizedPartyDKGOutput =
        bcs::from_bytes(&emulated_dkg_result.public_output).map_err(DwalletMPCError::BcsError)?;

    // CRITICAL: Using ZeroRng for deterministic output.
    // This is intentional - all validators must produce identical outputs,
    // so we use a deterministic RNG that always returns zero.
    let mut rng = ZeroRng::new();

    // Use the shared centralized party sign function with ZeroRng
    advance_sign_by_protocol_with_rng::<P, _>(
        &zero_secret_key_share,
        presign_bytes,
        message,
        hash_scheme,
        centralized_party_dkg_public_output,
        protocol_pp_bytes,
        &mut rng,
    )
    .map_err(|e| DwalletMPCError::InternalError(format!("Emulated centralized sign failed: {e}")))
}

/// Gets the session identifier for internal checkpoint DKG.
///
/// This creates a deterministic session ID based on the network key ID,
/// curve, and signature algorithm, ensuring all validators agree on the same
/// session identifier.
///
/// The function computes a preimage using Merlin transcript and creates a
/// `SessionIdentifier` from it, consistent with how session IDs are created
/// elsewhere in the codebase.
///
/// # Arguments
///
/// * `network_key_id` - The object ID of the network encryption key
/// * `curve` - The curve being used
/// * `signature_algorithm` - The signature algorithm being used
///
/// # Returns
///
/// A `SessionIdentifier` for the internal checkpoint DKG.
pub fn internal_checkpoint_dkg_session_id(
    network_key_id: &[u8],
    curve: DWalletCurve,
    signature_algorithm: DWalletSignatureAlgorithm,
) -> ika_types::messages_dwallet_mpc::SessionIdentifier {
    use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
    use merlin::Transcript;

    // Compute a deterministic preimage using Merlin transcript
    let mut transcript = Transcript::new(b"Internal Checkpoint DKG Session ID");
    transcript.append_message(b"network_key_id", network_key_id);
    transcript.append_message(b"curve", curve.to_string().as_bytes());
    transcript.append_message(
        b"signature_algorithm",
        signature_algorithm.to_string().as_bytes(),
    );

    let mut session_id_preimage = [0u8; 32];
    transcript.challenge_bytes(b"session_id_preimage", &mut session_id_preimage);

    // Create a SessionIdentifier from the preimage, using System session type
    // for internal operations
    SessionIdentifier::new(SessionType::System, session_id_preimage)
}

/// Computes the internal checkpoint DKG output for checkpoint signing.
///
/// This function emulates the centralized party DKG using ZeroRng to produce
/// deterministic output that all validators will agree on. The output is used
/// for internal signing operations where the network signs without user participation.
///
/// # Arguments
///
/// * `network_key_id` - The 32-byte network key identifier
/// * `curve` - The curve to use for the DKG
/// * `algorithm` - The signature algorithm
/// * `protocol_pp` - The serialized protocol public parameters for the curve
///
/// # Returns
///
/// A tuple of (curve, algorithm, serialized_output) if successful, or None if the
/// emulation fails.
pub fn compute_internal_checkpoint_dkg_output(
    network_key_id: &[u8; 32],
    curve: DWalletCurve,
    algorithm: DWalletSignatureAlgorithm,
    protocol_pp: &[u8],
) -> Option<(DWalletCurve, DWalletSignatureAlgorithm, Vec<u8>)> {
    // Compute the session ID for deterministic DKG
    let session_id = internal_checkpoint_dkg_session_id(network_key_id, curve, algorithm);

    // Emulate the centralized party DKG
    match emulate_centralized_dkg_for_internal_signing(curve, protocol_pp, session_id.as_ref()) {
        Ok(result) => {
            // The output contains the public key share and proof and public output.
            // The "secret" key share is not stored because it's deterministic (derived from ZeroRng)
            // and can be recomputed when needed.
            let serialized_output =
                bcs::to_bytes(&(result.public_key_share_and_proof, result.public_output)).ok()?;

            Some((curve, algorithm, serialized_output))
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                ?curve,
                ?algorithm,
                "Failed to compute internal checkpoint DKG output"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internal_checkpoint_dkg_session_id_is_deterministic() {
        let network_key_id = [1u8; 32];
        let curve = DWalletCurve::Curve25519;
        let algorithm = DWalletSignatureAlgorithm::EdDSA;

        let session_id_1 = internal_checkpoint_dkg_session_id(&network_key_id, curve, algorithm);
        let session_id_2 = internal_checkpoint_dkg_session_id(&network_key_id, curve, algorithm);

        assert_eq!(session_id_1, session_id_2);
    }

    #[test]
    fn test_internal_checkpoint_dkg_session_id_varies_with_inputs() {
        let network_key_id = [1u8; 32];
        let curve = DWalletCurve::Curve25519;
        let algorithm = DWalletSignatureAlgorithm::EdDSA;

        let session_id_1 = internal_checkpoint_dkg_session_id(&network_key_id, curve, algorithm);

        // Different network key
        let different_key = [2u8; 32];
        let session_id_2 = internal_checkpoint_dkg_session_id(&different_key, curve, algorithm);

        // Different curve
        let session_id_3 =
            internal_checkpoint_dkg_session_id(&network_key_id, DWalletCurve::Secp256k1, algorithm);

        assert_ne!(session_id_1, session_id_2);
        assert_ne!(session_id_1, session_id_3);
        assert_ne!(session_id_2, session_id_3);
    }
}
