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

use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletSignatureAlgorithm, VersionedDwalletUserSecretShare,
    VersionedPublicKeyShareAndProof,
};
use dwallet_rng::ZeroRng;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use mpc::two_party::Round;
use twopc_mpc::dkg::Protocol;

/// The result of emulating the centralized party DKG using ZeroRng.
///
/// # Security Warning
///
/// The `centralized_secret_output` is NOT actually secret - it's derived from zeros.
/// This is intentional for internal signing where there is no user secret to protect.
#[derive(Debug, Clone)]
pub struct EmulatedCentralizedDKGResult {
    /// The public key share and proof from the emulated centralized party.
    /// This is used as input to the decentralized party DKG.
    pub public_key_share_and_proof: Vec<u8>,

    /// The public output of the emulated centralized party DKG.
    pub public_output: Vec<u8>,

    /// The "secret" key share of the emulated centralized party.
    ///
    /// # Security Note
    ///
    /// This is NOT actually secret since it's derived from ZeroRng (all zeros).
    /// For internal signing, this key share is made "public" because there is
    /// no user secret to protect - security comes from the network's threshold
    /// signature, not from this randomness.
    pub centralized_secret_output: Vec<u8>,
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
        DWalletCurve::Secp256k1 => {
            emulate_centralized_dkg_v2::<twopc_mpc::secp256k1::class_groups::DKGProtocol>(
                protocol_public_parameters,
                session_id,
            )
        }
        DWalletCurve::Secp256r1 => {
            emulate_centralized_dkg_v2::<twopc_mpc::secp256r1::class_groups::DKGProtocol>(
                protocol_public_parameters,
                session_id,
            )
        }
        DWalletCurve::Curve25519 => {
            emulate_centralized_dkg_v2::<twopc_mpc::curve25519::class_groups::DKGProtocol>(
                protocol_public_parameters,
                session_id,
            )
        }
        DWalletCurve::Ristretto => {
            emulate_centralized_dkg_v2::<twopc_mpc::ristretto::class_groups::DKGProtocol>(
                protocol_public_parameters,
                session_id,
            )
        }
    }
}

/// Internal implementation of emulated centralized DKG for a specific protocol.
///
/// # Security Warning
///
/// This function uses ZeroRng - a deterministic RNG that always returns zeros.
/// The output is intentionally deterministic for internal signing operations.
fn emulate_centralized_dkg_v2<P: Protocol>(
    protocol_pp_bytes: &[u8],
    session_id_bytes: &[u8],
) -> DwalletMPCResult<EmulatedCentralizedDKGResult> {
    let protocol_public_parameters: P::ProtocolPublicParameters =
        bcs::from_bytes(protocol_pp_bytes).map_err(|e| {
            DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                "Failed to deserialize protocol public parameters: {:?}",
                e
            )))
        })?;

    let session_identifier = CommitmentSizedNumber::from_le_slice(session_id_bytes);

    // CRITICAL: Using ZeroRng for deterministic output.
    // This is intentional - all validators must produce identical outputs.
    let mut rng = ZeroRng::new();

    let round_result = P::DKGCentralizedPartyRound::advance(
        (),
        &(),
        &(protocol_public_parameters, session_identifier).into(),
        &mut rng,
    )
    .map_err(|e| DwalletMPCError::FailedToAdvanceMPC(e.into()))?;

    // Serialize the public key share and proof
    let public_key_share_and_proof_inner =
        bcs::to_bytes(&round_result.outgoing_message).map_err(DwalletMPCError::BcsError)?;
    let public_key_share_and_proof = bcs::to_bytes(&VersionedPublicKeyShareAndProof::V1(
        public_key_share_and_proof_inner,
    ))
    .map_err(DwalletMPCError::BcsError)?;

    // Serialize the public output
    let public_output =
        bcs::to_bytes(&round_result.public_output).map_err(DwalletMPCError::BcsError)?;

    // Serialize the "secret" output (which is deterministic, not actually secret)
    let centralized_secret_inner =
        bcs::to_bytes(&round_result.private_output).map_err(DwalletMPCError::BcsError)?;
    let centralized_secret_output =
        bcs::to_bytes(&VersionedDwalletUserSecretShare::V1(centralized_secret_inner))
            .map_err(DwalletMPCError::BcsError)?;

    Ok(EmulatedCentralizedDKGResult {
        public_key_share_and_proof,
        public_output,
        centralized_secret_output,
    })
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
        DWalletSignatureAlgorithm::ECDSASecp256k1 => {
            emulate_sign_centralized::<twopc_mpc::secp256k1::class_groups::ECDSAProtocol>(
                emulated_dkg_result,
                message,
                hash_scheme,
                presign,
                protocol_public_parameters,
            )
        }
        DWalletSignatureAlgorithm::ECDSASecp256r1 => {
            emulate_sign_centralized::<twopc_mpc::secp256r1::class_groups::ECDSAProtocol>(
                emulated_dkg_result,
                message,
                hash_scheme,
                presign,
                protocol_public_parameters,
            )
        }
        DWalletSignatureAlgorithm::EdDSA => {
            emulate_sign_centralized::<twopc_mpc::curve25519::class_groups::EdDSAProtocol>(
                emulated_dkg_result,
                message,
                hash_scheme,
                presign,
                protocol_public_parameters,
            )
        }
        DWalletSignatureAlgorithm::Taproot => {
            emulate_sign_centralized::<twopc_mpc::secp256k1::class_groups::TaprootProtocol>(
                emulated_dkg_result,
                message,
                hash_scheme,
                presign,
                protocol_public_parameters,
            )
        }
        DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
            emulate_sign_centralized::<twopc_mpc::ristretto::class_groups::SchnorrkelSubstrateProtocol>(
                emulated_dkg_result,
                message,
                hash_scheme,
                presign,
                protocol_public_parameters,
            )
        }
    }
}

/// Internal implementation of emulated centralized party signing for a specific protocol.
fn emulate_sign_centralized<P: twopc_mpc::sign::Protocol>(
    emulated_dkg_result: &EmulatedCentralizedDKGResult,
    message: Vec<u8>,
    hash_scheme: group::HashScheme,
    presign_bytes: &[u8],
    protocol_pp_bytes: &[u8],
) -> DwalletMPCResult<Vec<u8>> {
    use dwallet_mpc_types::dwallet_mpc::VersionedUserSignedMessage;

    // Deserialize the emulated secret key share
    let versioned_secret: VersionedDwalletUserSecretShare =
        bcs::from_bytes(&emulated_dkg_result.centralized_secret_output)
            .map_err(DwalletMPCError::BcsError)?;
    let VersionedDwalletUserSecretShare::V1(secret_bytes) = versioned_secret;

    let centralized_party_secret_key_share: P::CentralizedPartySecretKeyShare =
        bcs::from_bytes(&secret_bytes).map_err(DwalletMPCError::BcsError)?;

    // Deserialize the centralized party DKG public output
    let centralized_party_dkg_public_output: P::CentralizedPartyDKGOutput =
        bcs::from_bytes(&emulated_dkg_result.public_output).map_err(DwalletMPCError::BcsError)?;

    // Deserialize presign and protocol public parameters
    let presign: <P as twopc_mpc::presign::Protocol>::Presign =
        bcs::from_bytes(presign_bytes).map_err(DwalletMPCError::BcsError)?;
    let protocol_public_parameters: P::ProtocolPublicParameters =
        bcs::from_bytes(protocol_pp_bytes).map_err(DwalletMPCError::BcsError)?;

    // Build the public input for the sign centralized party
    let centralized_party_public_input =
        <P as twopc_mpc::sign::Protocol>::SignCentralizedPartyPublicInput::from((
            message,
            hash_scheme,
            centralized_party_dkg_public_output,
            presign,
            protocol_public_parameters,
        ));

    // CRITICAL: Using ZeroRng for deterministic output.
    // This is intentional - all validators must produce identical partial signatures.
    let mut rng = ZeroRng::new();

    type SignCentralizedParty<P> = <P as twopc_mpc::sign::Protocol>::SignCentralizedParty;

    let round_result = SignCentralizedParty::<P>::advance(
        (),
        &centralized_party_secret_key_share,
        &centralized_party_public_input,
        &mut rng,
    )
    .map_err(|e| DwalletMPCError::FailedToAdvanceMPC(e.into()))?;

    // Serialize the partial signature
    let signed_message =
        VersionedUserSignedMessage::V1(bcs::to_bytes(&round_result.outgoing_message)
            .map_err(DwalletMPCError::BcsError)?);

    bcs::to_bytes(&signed_message).map_err(DwalletMPCError::BcsError)
}

/// Gets the session identifier for internal checkpoint DKG.
///
/// This creates a deterministic session ID based on the network key ID and epoch,
/// ensuring all validators agree on the same session identifier.
///
/// # Arguments
///
/// * `network_key_id` - The object ID of the network encryption key
/// * `epoch` - The epoch when the internal DKG is being computed
/// * `curve` - The curve being used
/// * `signature_algorithm` - The signature algorithm being used
///
/// # Returns
///
/// A deterministic 32-byte session identifier.
pub fn internal_checkpoint_dkg_session_id(
    network_key_id: &[u8],
    epoch: u64,
    curve: DWalletCurve,
    signature_algorithm: DWalletSignatureAlgorithm,
) -> [u8; 32] {
    use merlin::Transcript;

    let mut transcript = Transcript::new(b"Internal Checkpoint DKG Session ID");
    transcript.append_message(b"network_key_id", network_key_id);
    transcript.append_message(b"epoch", &epoch.to_le_bytes());
    transcript.append_message(b"curve", curve.to_string().as_bytes());
    transcript.append_message(
        b"signature_algorithm",
        signature_algorithm.to_string().as_bytes(),
    );

    let mut session_id = [0u8; 32];
    transcript.challenge_bytes(b"session_id", &mut session_id);
    session_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internal_checkpoint_dkg_session_id_is_deterministic() {
        let network_key_id = [1u8; 32];
        let epoch = 42;
        let curve = DWalletCurve::Curve25519;
        let algorithm = DWalletSignatureAlgorithm::EdDSA;

        let session_id_1 = internal_checkpoint_dkg_session_id(
            &network_key_id,
            epoch,
            curve,
            algorithm,
        );
        let session_id_2 = internal_checkpoint_dkg_session_id(
            &network_key_id,
            epoch,
            curve,
            algorithm,
        );

        assert_eq!(session_id_1, session_id_2);
    }

    #[test]
    fn test_internal_checkpoint_dkg_session_id_varies_with_inputs() {
        let network_key_id = [1u8; 32];
        let epoch = 42;
        let curve = DWalletCurve::Curve25519;
        let algorithm = DWalletSignatureAlgorithm::EdDSA;

        let session_id_1 = internal_checkpoint_dkg_session_id(
            &network_key_id,
            epoch,
            curve,
            algorithm,
        );

        // Different epoch
        let session_id_2 = internal_checkpoint_dkg_session_id(
            &network_key_id,
            epoch + 1,
            curve,
            algorithm,
        );

        // Different network key
        let different_key = [2u8; 32];
        let session_id_3 = internal_checkpoint_dkg_session_id(
            &different_key,
            epoch,
            curve,
            algorithm,
        );

        assert_ne!(session_id_1, session_id_2);
        assert_ne!(session_id_1, session_id_3);
        assert_ne!(session_id_2, session_id_3);
    }
}
