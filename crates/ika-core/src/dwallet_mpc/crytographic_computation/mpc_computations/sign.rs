// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the Sign protocol from the 2PC-MPC library.
//!
//! It integrates the Sign party (representing a round in the protocol).

use crate::dwallet_mpc::crytographic_computation::mpc_computations;
use crate::dwallet_mpc::crytographic_computation::mpc_computations::parse_signature_from_sign_output;
use crate::dwallet_mpc::dwallet_dkg::DWalletDKGPublicInputByCurve;
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::request_protocol_data::SignData;
use class_groups::CiphertextSpaceGroupElement;
use commitment::CommitmentSizedNumber;
use dwallet_classgroups_types::ValidatorMPCSecrets;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletSignatureAlgorithm, NetworkEncryptionKeyPublicData,
    SerializedWrappedMPCPublicOutput, VersionedDecryptionKeyReconfigurationOutput,
    VersionedDwalletDKGPublicOutput, VersionedNetworkDkgOutput, VersionedPresignOutput,
    VersionedUserSignedMessage, public_key_from_decentralized_dkg_output_by_curve_v2,
};
use dwallet_rng::RootSeed;
use group::CsRng;
use group::{HashScheme, OsCsRng, PartyID};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    Curve25519AsyncDKGProtocol, Curve25519EdDSAProtocol, Curve25519EdDSAVSSProtocol,
    RistrettoAsyncDKGProtocol, RistrettoSchnorrkelSubstrateProtocol,
    RistrettoSchnorrkelSubstrateVSSProtocol, Secp256k1AsyncDKGProtocol, Secp256k1ECDSAProtocol,
    Secp256k1TaprootProtocol, Secp256k1TaprootVSSProtocol, Secp256r1AsyncDKGProtocol,
    Secp256r1ECDSAProtocol, SessionIdentifier,
};
use mpc::guaranteed_output_delivery::AdvanceRequest;
use mpc::{AsynchronouslyAdvanceable, GuaranteesOutputDelivery};
use mpc::{GuaranteedOutputDeliveryRoundResult, Party, Weight, WeightedThresholdAccessStructure};
use rand_core::SeedableRng;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::error;
use twopc_mpc::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS;
use twopc_mpc::sign;

pub(crate) type SignParty<P> = <P as twopc_mpc::sign::Protocol>::SignDecentralizedParty;
pub(crate) type DKGAndSignParty<P> = <P as twopc_mpc::sign::Protocol>::DKGSignDecentralizedParty;

#[derive(Clone, Debug, Eq, PartialEq, strum_macros::Display)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum SignPublicInputByProtocol {
    #[strum(to_string = "Sign Public Input - curve: Secp256k1, protocol: ECDSA")]
    Secp256k1ECDSA(<SignParty<Secp256k1ECDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Sign Public Input - curve: Secp256k1, protocol: Taproot")]
    Secp256k1Taproot(<SignParty<Secp256k1TaprootProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Sign Public Input - curve: Secp256r1, protocol: ECDSA")]
    Secp256r1(<SignParty<Secp256r1ECDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Sign Public Input - curve: Curve25519, protocol: EdDSA")]
    Curve25519(<SignParty<Curve25519EdDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Sign Public Input - curve: Ristretto, protocol: SchnorrkelSubstrate")]
    Ristretto(<SignParty<RistrettoSchnorrkelSubstrateProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Sign Public Input - curve: Secp256k1, protocol: TaprootVSS")]
    TaprootVSS(<SignParty<Secp256k1TaprootVSSProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Sign Public Input - curve: Curve25519, protocol: EdDSAVSS")]
    EdDSAVSS(<SignParty<Curve25519EdDSAVSSProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Sign Public Input - curve: Ristretto, protocol: SchnorrkelSubstrateVSS")]
    SchnorrkelSubstrateVSS(
        <SignParty<RistrettoSchnorrkelSubstrateVSSProtocol> as mpc::Party>::PublicInput,
    ),
}

#[derive(Clone, Debug, Eq, PartialEq, strum_macros::Display)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum DKGAndSignPublicInputByProtocol {
    #[strum(to_string = "DKG and Sign Public Input - curve: Secp256k1, protocol: ECDSA")]
    Secp256k1ECDSA(<DKGAndSignParty<Secp256k1ECDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "DKG and Sign Public Input - curve: Secp256k1, protocol: Taproot")]
    Secp256k1Taproot(<DKGAndSignParty<Secp256k1TaprootProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "DKG and Sign Public Input - curve: Secp256r1, protocol: ECDSA")]
    Secp256r1(<DKGAndSignParty<Secp256r1ECDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "DKG and Sign Public Input - curve: Curve25519, protocol: EdDSA")]
    Curve25519(<DKGAndSignParty<Curve25519EdDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(
        to_string = "DKG and Sign Public Input - curve: Ristretto, protocol: SchnorrkelSubstrate"
    )]
    Ristretto(<DKGAndSignParty<RistrettoSchnorrkelSubstrateProtocol> as mpc::Party>::PublicInput),
}

#[derive(strum_macros::Display)]
pub(crate) enum SignAdvanceRequestByProtocol {
    #[strum(to_string = "Sign Advance Request - curve: Secp256k1, protocol: ECDSA")]
    Secp256k1ECDSA(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <SignParty<Secp256k1ECDSAProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "Sign Advance Request - curve: Secp256k1, protocol: Taproot")]
    Secp256k1Taproot(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <SignParty<Secp256k1TaprootProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "Sign Advance Request - curve: Secp256r1, protocol: ECDSA")]
    Secp256r1(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <SignParty<Secp256r1ECDSAProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "Sign Advance Request - curve: Curve25519, protocol: EdDSA")]
    Curve25519(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <SignParty<Curve25519EdDSAProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "Sign Advance Request - curve: Ristretto, protocol: SchnorrkelSubstrate")]
    Ristretto(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <SignParty<RistrettoSchnorrkelSubstrateProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "Sign Advance Request - curve: Secp256k1, protocol: TaprootVSS")]
    TaprootVSS(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <SignParty<Secp256k1TaprootVSSProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "Sign Advance Request - curve: Curve25519, protocol: EdDSAVSS")]
    EdDSAVSS(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <SignParty<Curve25519EdDSAVSSProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(
        to_string = "Sign Advance Request - curve: Ristretto, protocol: SchnorrkelSubstrateVSS"
    )]
    SchnorrkelSubstrateVSS(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <SignParty<RistrettoSchnorrkelSubstrateVSSProtocol> as mpc::Party>::Message,
        >,
    ),
}

#[derive(strum_macros::Display)]
pub(crate) enum DWalletDKGAndSignAdvanceRequestByProtocol {
    #[strum(to_string = "DKG and Sign Advance Request - curve: Secp256k1, protocol: ECDSA")]
    Secp256k1ECDSA(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <DKGAndSignParty<Secp256k1ECDSAProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "DKG and Sign Advance Request - curve: Secp256k1, protocol: Taproot")]
    Secp256k1Taproot(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <DKGAndSignParty<Secp256k1TaprootProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "DKG and Sign Advance Request - curve: Secp256r1, protocol: ECDSA")]
    Secp256r1(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <DKGAndSignParty<Secp256r1ECDSAProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "DKG and Sign Advance Request - curve: Curve25519, protocol: EdDSA")]
    Curve25519(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <DKGAndSignParty<Curve25519EdDSAProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(
        to_string = "DKG and Sign Advance Request - curve: Ristretto, protocol: SchnorrkelSubstrate"
    )]
    Ristretto(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <DKGAndSignParty<RistrettoSchnorrkelSubstrateProtocol> as mpc::Party>::Message,
        >,
    ),
}

/// Deterministically determine the set of expected decrypters for an optimization of the
/// threshold decryption in the Sign protocol.
/// Pseudo-randomly samples a subset of size `t + 10% * n`,
/// i.e., we add an extra ten-percent of validators,
/// of which at least `t` should be online (sent a message) during the first round of
/// Sign, i.e., they are expected to decrypt the signature.
///
/// This is a non-stateful way to agree on a subset (that has to be the same for all validators);
/// in the future, we may consider generating this subset in a stateful manner that takes into
/// account the validators' online/offline states, malicious activities etc.
/// This would be better, though harder to implement in practice, and will only be done
/// if we see that the current method is ineffective;
/// however, we expect 10% to cover for these effects successfully.
///
/// Note: this is only an optimization: if we don't have at least `t` online decrypters out of
/// the `expected_decrypters` subset, the Sign protocol still completes successfully, only slower.
fn generate_expected_decrypters(
    access_structure: &WeightedThresholdAccessStructure,
    session_identifier: SessionIdentifier,
) -> DwalletMPCResult<HashSet<PartyID>> {
    let total_weight = access_structure.total_weight();
    let expected_decrypters_weight =
        access_structure.threshold + (total_weight as f64 * 0.10).floor() as Weight;

    let mut seed_rng = rand_chacha::ChaCha20Rng::from_seed(session_identifier.into_bytes());
    let expected_decrypters = access_structure
        .random_subset_with_target_weight(expected_decrypters_weight, &mut seed_rng)
        .map_err(DwalletMPCError::from)?;

    Ok(expected_decrypters)
}

impl SignAdvanceRequestByProtocol {
    pub fn try_new(
        protocol: &DWalletSignatureAlgorithm,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        consensus_round: u64,
        serialized_messages_by_consensus_round: HashMap<u64, HashMap<PartyID, Vec<u8>>>,
    ) -> DwalletMPCResult<Option<Self>> {
        let advance_request = match protocol {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                let advance_request =
                    mpc_computations::try_ready_to_advance::<SignParty<Secp256k1ECDSAProtocol>>(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
                        &serialized_messages_by_consensus_round,
                    )?;

                advance_request.map(SignAdvanceRequestByProtocol::Secp256k1ECDSA)
            }
            DWalletSignatureAlgorithm::Taproot => {
                let advance_request =
                    mpc_computations::try_ready_to_advance::<SignParty<Secp256k1TaprootProtocol>>(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
                        &serialized_messages_by_consensus_round,
                    )?;

                advance_request.map(SignAdvanceRequestByProtocol::Secp256k1Taproot)
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    SignParty<RistrettoSchnorrkelSubstrateProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(SignAdvanceRequestByProtocol::Ristretto)
            }
            DWalletSignatureAlgorithm::EdDSA => {
                let advance_request =
                    mpc_computations::try_ready_to_advance::<SignParty<Curve25519EdDSAProtocol>>(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
                        &serialized_messages_by_consensus_round,
                    )?;

                advance_request.map(SignAdvanceRequestByProtocol::Curve25519)
            }
            DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                let advance_request =
                    mpc_computations::try_ready_to_advance::<SignParty<Secp256r1ECDSAProtocol>>(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
                        &serialized_messages_by_consensus_round,
                    )?;

                advance_request.map(SignAdvanceRequestByProtocol::Secp256r1)
            }
            DWalletSignatureAlgorithm::TaprootVSS => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    SignParty<Secp256k1TaprootVSSProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(SignAdvanceRequestByProtocol::TaprootVSS)
            }
            DWalletSignatureAlgorithm::EdDSAVSS => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    SignParty<Curve25519EdDSAVSSProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(SignAdvanceRequestByProtocol::EdDSAVSS)
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrateVSS => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    SignParty<RistrettoSchnorrkelSubstrateVSSProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(SignAdvanceRequestByProtocol::SchnorrkelSubstrateVSS)
            }
        };

        Ok(advance_request)
    }
}

impl DWalletDKGAndSignAdvanceRequestByProtocol {
    pub fn try_new(
        protocol: &DWalletSignatureAlgorithm,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        consensus_round: u64,
        serialized_messages_by_consensus_round: HashMap<u64, HashMap<PartyID, Vec<u8>>>,
    ) -> DwalletMPCResult<Option<Self>> {
        let advance_request = match protocol {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    DKGAndSignParty<Secp256k1ECDSAProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(Self::Secp256k1ECDSA)
            }
            DWalletSignatureAlgorithm::Taproot => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    DKGAndSignParty<Secp256k1TaprootProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(Self::Secp256k1Taproot)
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    DKGAndSignParty<RistrettoSchnorrkelSubstrateProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(Self::Ristretto)
            }
            DWalletSignatureAlgorithm::EdDSA => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    DKGAndSignParty<Curve25519EdDSAProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(Self::Curve25519)
            }
            DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    DKGAndSignParty<Secp256r1ECDSAProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(Self::Secp256r1)
            }
            // Fast Schnorr (VSS) does not support the combined DKG-and-sign fast
            // path (deferred by decision; the upstream combined VSS party exists
            // but is not wired here). Such requests are rejected at construction
            // (`dwallet_dkg_and_sign_protocol_data`), so this is unreachable; kept
            // exhaustive with a clear error as defense-in-depth.
            DWalletSignatureAlgorithm::TaprootVSS
            | DWalletSignatureAlgorithm::EdDSAVSS
            | DWalletSignatureAlgorithm::SchnorrkelSubstrateVSS => {
                return Err(DwalletMPCError::InvalidInput(format!(
                    "Fast Schnorr (VSS) algorithm {protocol} is not supported for \
                     the combined DKG-and-sign fast path"
                )));
            }
        };

        Ok(advance_request)
    }
}

impl SignPublicInputByProtocol {
    pub(crate) fn try_new(
        session_identifier: SessionIdentifier,
        dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
        message: Vec<u8>,
        presign: &SerializedWrappedMPCPublicOutput,
        message_centralized_signature: &SerializedWrappedMPCPublicOutput,
        hash_scheme: HashScheme,
        access_structure: &WeightedThresholdAccessStructure,
        network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
        protocol: DWalletSignatureAlgorithm,
    ) -> DwalletMPCResult<Self> {
        let expected_decrypters =
            generate_expected_decrypters(access_structure, session_identifier)?;

        match protocol {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => Ok(
                SignPublicInputByProtocol::Secp256k1ECDSA(build_secp256k1_ecdsa_sign_public_input(
                    expected_decrypters,
                    dwallet_decentralized_public_output,
                    message,
                    presign,
                    message_centralized_signature,
                    hash_scheme,
                    network_encryption_key_public_data,
                )?),
            ),
            DWalletSignatureAlgorithm::Taproot => Ok(SignPublicInputByProtocol::Secp256k1Taproot(
                build_secp256k1_taproot_sign_public_input(
                    expected_decrypters,
                    dwallet_decentralized_public_output,
                    message,
                    presign,
                    message_centralized_signature,
                    hash_scheme,
                    network_encryption_key_public_data,
                )?,
            )),
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => Ok(
                SignPublicInputByProtocol::Ristretto(build_ristretto_schnorrkel_sign_public_input(
                    expected_decrypters,
                    dwallet_decentralized_public_output,
                    message,
                    presign,
                    message_centralized_signature,
                    hash_scheme,
                    network_encryption_key_public_data,
                )?),
            ),
            DWalletSignatureAlgorithm::EdDSA => Ok(SignPublicInputByProtocol::Curve25519(
                build_curve25519_eddsa_sign_public_input(
                    expected_decrypters,
                    dwallet_decentralized_public_output,
                    message,
                    presign,
                    message_centralized_signature,
                    hash_scheme,
                    network_encryption_key_public_data,
                )?,
            )),
            DWalletSignatureAlgorithm::ECDSASecp256r1 => Ok(SignPublicInputByProtocol::Secp256r1(
                build_secp256r1_ecdsa_sign_public_input(
                    expected_decrypters,
                    dwallet_decentralized_public_output,
                    message,
                    presign,
                    message_centralized_signature,
                    hash_scheme,
                    network_encryption_key_public_data,
                )?,
            )),
            // Fast Schnorr (VSS) sign PublicInput: the 8-field struct. Commitments
            // come from the latest reconfiguration output (see
            // `vss_reconfiguration_public_output`); dkg_output/presign/sign_data
            // decode exactly like the AHE Schnorr path (generic over the protocol).
            DWalletSignatureAlgorithm::TaprootVSS => Ok(SignPublicInputByProtocol::TaprootVSS(
                build_secp256k1_taproot_vss_sign_public_input(
                    dwallet_decentralized_public_output,
                    message,
                    presign,
                    message_centralized_signature,
                    hash_scheme,
                    network_encryption_key_public_data,
                )?,
            )),
            DWalletSignatureAlgorithm::EdDSAVSS => Ok(SignPublicInputByProtocol::EdDSAVSS(
                build_curve25519_eddsa_vss_sign_public_input(
                    dwallet_decentralized_public_output,
                    message,
                    presign,
                    message_centralized_signature,
                    hash_scheme,
                    network_encryption_key_public_data,
                )?,
            )),
            DWalletSignatureAlgorithm::SchnorrkelSubstrateVSS => {
                Ok(SignPublicInputByProtocol::SchnorrkelSubstrateVSS(
                    build_ristretto_schnorrkel_vss_sign_public_input(
                        dwallet_decentralized_public_output,
                        message,
                        presign,
                        message_centralized_signature,
                        hash_scheme,
                        network_encryption_key_public_data,
                    )?,
                ))
            }
        }
    }
}

// Per-curve concrete sign-public-input builders. Each pulls its
// `decryption_key_share_public_parameters` and `protocol_public_parameters` from
// `network_encryption_key_public_data` directly and constructs the per-protocol
// decentralized `PublicInput` via struct literal. An empty
// `message_centralized_signature` selects `SignData::ToBeEmulated` (NOA path);
// otherwise `SignData::Unverified(deserialized_sign_message)` (user-driven path).

/// Recovers the presign `session_id` from a public VSS presign — the key under
/// which this presign's private nonce output was persisted at presign-finalize.
/// Deserializes the curve-specific public `schnorr::vss::Presign`.
pub(crate) fn vss_public_presign_session_id(
    signature_algorithm: DWalletSignatureAlgorithm,
    presign: &SerializedWrappedMPCPublicOutput,
) -> DwalletMPCResult<commitment::CommitmentSizedNumber> {
    let versioned: VersionedPresignOutput = bcs::from_bytes(presign).map_err(|e| {
        DwalletMPCError::BcsError(bcs::Error::Custom(format!(
            "failed to deserialize VSS presign output: {e}"
        )))
    })?;
    let VersionedPresignOutput::V2(inner) = versioned else {
        return Err(DwalletMPCError::InvalidInput(
            "Fast Schnorr (VSS) presign must be V2".to_string(),
        ));
    };
    let decode = |bytes: &[u8]| -> DwalletMPCResult<commitment::CommitmentSizedNumber> {
        match signature_algorithm {
            DWalletSignatureAlgorithm::TaprootVSS => Ok(bcs::from_bytes::<
                <Secp256k1TaprootVSSProtocol as twopc_mpc::presign::Protocol>::Presign,
            >(bytes)
            .map_err(|e| DwalletMPCError::BcsError(bcs::Error::Custom(e.to_string())))?
            .session_id),
            DWalletSignatureAlgorithm::EdDSAVSS => Ok(bcs::from_bytes::<
                <Curve25519EdDSAVSSProtocol as twopc_mpc::presign::Protocol>::Presign,
            >(bytes)
            .map_err(|e| DwalletMPCError::BcsError(bcs::Error::Custom(e.to_string())))?
            .session_id),
            DWalletSignatureAlgorithm::SchnorrkelSubstrateVSS => Ok(bcs::from_bytes::<
                <RistrettoSchnorrkelSubstrateVSSProtocol as twopc_mpc::presign::Protocol>::Presign,
            >(bytes)
            .map_err(|e| DwalletMPCError::BcsError(bcs::Error::Custom(e.to_string())))?
            .session_id),
            _ => Err(DwalletMPCError::InvalidInput(format!(
                "{signature_algorithm} is not a Fast Schnorr (VSS) algorithm"
            ))),
        }
    };
    decode(&inner)
}

/// The network key's current threshold-encryption-to-sharing material, in serialized
/// form, from which a Fast Schnorr (VSS) sign recovers its secret-key Shamir shares
/// and reads the secret-key polynomial commitments.
///
/// It is the reconfiguration output once the network key has reconfigured, else the
/// network DKG output (a freshly-DKG'd key that has not reconfigured yet). Both carry
/// the same `threshold_encryption_to_sharing_output`, so VSS sign works off either —
/// it does NOT require a prior reconfiguration. Carried (serialized) across the
/// compute boundary in `ProtocolCryptographicData::SignVSS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VssSecretKeySharesVersionedSource {
    Reconfiguration(VersionedDecryptionKeyReconfigurationOutput),
    NetworkDkg(VersionedNetworkDkgOutput),
}

impl VssSecretKeySharesVersionedSource {
    /// Selects the reconfiguration output if the key has reconfigured, else the
    /// network DKG output.
    pub(crate) fn select(
        network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
    ) -> Self {
        match network_encryption_key_public_data.latest_network_reconfiguration_public_output() {
            Some(reconfiguration) => Self::Reconfiguration(reconfiguration),
            None => Self::NetworkDkg(
                network_encryption_key_public_data
                    .network_dkg_output()
                    .clone(),
            ),
        }
    }
}

/// The deserialized counterpart of [`VssSecretKeySharesVersionedSource`]: the actual
/// reconfiguration or DKG `PublicOutput`, exposing one uniform per-curve API so the
/// VSS sign builders never branch on which one is current. The reconfiguration output
/// exposes `compute_*_shamir_shares_*`, the DKG output the equivalent `derive_*`; both
/// expose `*_polynomial_commitments`.
enum VssSecretKeyShareSource {
    Reconfiguration(
        <twopc_mpc::decentralized_party::reconfiguration::Party as Party>::PublicOutput,
    ),
    NetworkDkg(<twopc_mpc::decentralized_party::dkg::Party as Party>::PublicOutput),
}

impl VssSecretKeyShareSource {
    fn from_versioned(source: &VssSecretKeySharesVersionedSource) -> DwalletMPCResult<Self> {
        let bcs_error = |what: &str, e: bcs::Error| {
            DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                "failed to deserialize {what} V3 public output: {e}"
            )))
        };
        match source {
            VssSecretKeySharesVersionedSource::Reconfiguration(
                VersionedDecryptionKeyReconfigurationOutput::V3(bytes),
            ) => Ok(Self::Reconfiguration(
                bcs::from_bytes(bytes).map_err(|e| bcs_error("reconfiguration", e))?,
            )),
            VssSecretKeySharesVersionedSource::NetworkDkg(VersionedNetworkDkgOutput::V3(bytes)) => {
                Ok(Self::NetworkDkg(
                    bcs::from_bytes(bytes).map_err(|e| bcs_error("network DKG", e))?,
                ))
            }
            // Pre-V3 network keys predate the threshold-encryption-to-sharing output
            // VSS needs; such a key must reconfigure to a V3 output before it can sign.
            _ => Err(DwalletMPCError::InvalidInput(
                "Fast Schnorr (VSS) sign requires a V3 reconfiguration or network DKG output"
                    .to_string(),
            )),
        }
    }

    fn from_network_key_public_data(
        network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
    ) -> DwalletMPCResult<Self> {
        Self::from_versioned(&VssSecretKeySharesVersionedSource::select(
            network_encryption_key_public_data,
        ))
    }

    fn secp256k1_shamir_shares(
        &self,
        party_id: PartyID,
        pvss_decryption_key: dwallet_classgroups_types::Secp256k1PvssDecryptionKey,
        pvss_encryption_key: class_groups::CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> DwalletMPCResult<(
        group::Value<group::secp256k1::Scalar>,
        group::Value<group::secp256k1::Scalar>,
    )> {
        match self {
            Self::Reconfiguration(output) => output
                .compute_secp256k1_shamir_shares_of_secret_key_share_parts(
                    party_id,
                    pvss_decryption_key,
                    pvss_encryption_key,
                ),
            Self::NetworkDkg(output) => output
                .derive_shamir_shares_of_secp256k1_secret_key_share_parts(
                    party_id,
                    pvss_decryption_key,
                    pvss_encryption_key,
                ),
        }
        .map_err(|e| {
            DwalletMPCError::InvalidInput(format!(
                "failed to recover secp256k1 VSS secret-key Shamir shares: {e:?}"
            ))
        })
    }

    fn curve25519_shamir_shares(
        &self,
        party_id: PartyID,
        pvss_decryption_key: dwallet_classgroups_types::RistrettoPvssDecryptionKey,
        pvss_encryption_key: class_groups::CompactIbqf<
            { twopc_mpc::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        >,
    ) -> DwalletMPCResult<(
        group::Value<group::curve25519::Scalar>,
        group::Value<group::curve25519::Scalar>,
    )> {
        match self {
            Self::Reconfiguration(output) => output
                .compute_curve25519_shamir_shares_of_secret_key_share_parts(
                    party_id,
                    pvss_decryption_key,
                    pvss_encryption_key,
                ),
            Self::NetworkDkg(output) => output
                .derive_shamir_shares_of_curve25519_secret_key_share_parts(
                    party_id,
                    pvss_decryption_key,
                    pvss_encryption_key,
                ),
        }
        .map_err(|e| {
            DwalletMPCError::InvalidInput(format!(
                "failed to recover curve25519 VSS secret-key Shamir shares: {e:?}"
            ))
        })
    }

    fn ristretto_shamir_shares(
        &self,
        party_id: PartyID,
        pvss_decryption_key: dwallet_classgroups_types::RistrettoPvssDecryptionKey,
        pvss_encryption_key: class_groups::CompactIbqf<
            { twopc_mpc::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        >,
    ) -> DwalletMPCResult<(
        group::Value<group::ristretto::Scalar>,
        group::Value<group::ristretto::Scalar>,
    )> {
        match self {
            Self::Reconfiguration(output) => output
                .compute_ristretto_shamir_shares_of_secret_key_share_parts(
                    party_id,
                    pvss_decryption_key,
                    pvss_encryption_key,
                ),
            Self::NetworkDkg(output) => output
                .derive_shamir_shares_of_ristretto_secret_key_share_parts(
                    party_id,
                    pvss_decryption_key,
                    pvss_encryption_key,
                ),
        }
        .map_err(|e| {
            DwalletMPCError::InvalidInput(format!(
                "failed to recover ristretto VSS secret-key Shamir shares: {e:?}"
            ))
        })
    }

    fn secp256k1_polynomial_commitments(
        &self,
    ) -> (
        &Vec<group::Value<group::secp256k1::GroupElement>>,
        &Vec<group::Value<group::secp256k1::GroupElement>>,
    ) {
        match self {
            Self::Reconfiguration(output) => output.secp256k1_polynomial_commitments(),
            Self::NetworkDkg(output) => output.secp256k1_polynomial_commitments(),
        }
    }

    fn curve25519_polynomial_commitments(
        &self,
    ) -> (
        &Vec<group::Value<group::curve25519::GroupElement>>,
        &Vec<group::Value<group::curve25519::GroupElement>>,
    ) {
        match self {
            Self::Reconfiguration(output) => output.curve25519_polynomial_commitments(),
            Self::NetworkDkg(output) => output.curve25519_polynomial_commitments(),
        }
    }

    fn ristretto_polynomial_commitments(
        &self,
    ) -> (
        &Vec<group::Value<group::ristretto::GroupElement>>,
        &Vec<group::Value<group::ristretto::GroupElement>>,
    ) {
        match self {
            Self::Reconfiguration(output) => output.ristretto_polynomial_commitments(),
            Self::NetworkDkg(output) => output.ristretto_polynomial_commitments(),
        }
    }
}

/// Deserializes the persisted VSS presign `PrivateOutput` (`Vec<PrivatePresignOutput>`).
/// The caller selects the matching entry by `session_id` + `presign_blending_index`;
/// the args here are used only for the error message. `None` private output (missing
/// row) → soft-fail error so this validator drops out of the sign quorum rather than
/// crashing the session.
fn vss_presign_private_outputs<P>(
    presign_private_output: Option<Vec<u8>>,
    session_id: commitment::CommitmentSizedNumber,
    presign_blending_index: u16,
) -> DwalletMPCResult<<<P as twopc_mpc::presign::Protocol>::PresignParty as Party>::PrivateOutput>
where
    P: twopc_mpc::presign::Protocol,
    <<P as twopc_mpc::presign::Protocol>::PresignParty as Party>::PrivateOutput:
        serde::de::DeserializeOwned,
{
    let bytes = presign_private_output.ok_or_else(|| {
        DwalletMPCError::InvalidInput(format!(
            "VSS presign private output missing for session {session_id:?} blending index \
             {presign_blending_index}; this validator cannot contribute to the sign"
        ))
    })?;
    bcs::from_bytes(&bytes).map_err(|e| {
        DwalletMPCError::BcsError(bcs::Error::Custom(format!(
            "failed to deserialize persisted VSS presign private output: {e}"
        )))
    })
}

pub(crate) fn build_secp256k1_taproot_vss_sign_private_input(
    party_id: PartyID,
    root_seed: &RootSeed,
    secret_key_shares_source: &VssSecretKeySharesVersionedSource,
    presign_private_output: Option<Vec<u8>>,
    public_input: &<SignParty<Secp256k1TaprootVSSProtocol> as Party>::PublicInput,
) -> DwalletMPCResult<
    <SignParty<Secp256k1TaprootVSSProtocol> as AsynchronouslyAdvanceable>::PrivateInput,
> {
    let secret_key_shares_source =
        VssSecretKeyShareSource::from_versioned(secret_key_shares_source)?;
    let validator_keys = ValidatorMPCSecrets::from_seed(root_seed);
    let (secret_key_share_first_part, secret_key_share_second_part) = secret_key_shares_source
        .secp256k1_shamir_shares(
            party_id,
            validator_keys.secp256k1_pvss_decryption_key(),
            validator_keys.secp256k1_pvss_encryption_key_and_proof().0,
        )?;

    let session_id = public_input.presign.session_id;
    let presign_blending_index = public_input.presign.presign_blending_index;
    let private_presign_outputs = vss_presign_private_outputs::<Secp256k1TaprootVSSProtocol>(
        presign_private_output,
        session_id,
        presign_blending_index,
    )?;
    let entry = private_presign_outputs
        .into_iter()
        .find(|output| {
            output.session_id == session_id
                && output.presign_blending_index == presign_blending_index
        })
        .ok_or_else(|| {
            DwalletMPCError::InvalidInput(format!(
                "no persisted VSS presign output for session {session_id:?} blending index \
                 {presign_blending_index}"
            ))
        })?;

    Ok(
        twopc_mpc::schnorr::vss::sign::decentralized_party::PrivateInput {
            secret_key_share_first_part,
            secret_key_share_second_part,
            session_id: entry.session_id,
            presign_blending_index: entry.presign_blending_index,
            nonce_share_first_part: entry.nonce_share_first_part,
            nonce_share_second_part: entry.nonce_share_second_part,
            first_nonce_polynomial_commitments: entry
                .nonce_share_first_part_coefficient_commitments,
            second_nonce_polynomial_commitments: entry
                .nonce_share_second_part_coefficient_commitments,
        },
    )
}

pub(crate) fn build_curve25519_eddsa_vss_sign_private_input(
    party_id: PartyID,
    root_seed: &RootSeed,
    secret_key_shares_source: &VssSecretKeySharesVersionedSource,
    presign_private_output: Option<Vec<u8>>,
    public_input: &<SignParty<Curve25519EdDSAVSSProtocol> as Party>::PublicInput,
) -> DwalletMPCResult<
    <SignParty<Curve25519EdDSAVSSProtocol> as AsynchronouslyAdvanceable>::PrivateInput,
> {
    let secret_key_shares_source =
        VssSecretKeyShareSource::from_versioned(secret_key_shares_source)?;
    let validator_keys = ValidatorMPCSecrets::from_seed(root_seed);
    // curve25519's threshold-encryption-to-sharing uses the ristretto PVSS key (same
    // const-generic discriminant limbs; the validator publishes no separate curve25519
    // PVSS key — `curve25519_shamir_shares` takes `RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS`).
    let (secret_key_share_first_part, secret_key_share_second_part) = secret_key_shares_source
        .curve25519_shamir_shares(
            party_id,
            validator_keys.ristretto_pvss_decryption_key(),
            validator_keys.ristretto_pvss_encryption_key_and_proof().0,
        )?;

    let session_id = public_input.presign.session_id;
    let presign_blending_index = public_input.presign.presign_blending_index;
    let private_presign_outputs = vss_presign_private_outputs::<Curve25519EdDSAVSSProtocol>(
        presign_private_output,
        session_id,
        presign_blending_index,
    )?;
    let entry = private_presign_outputs
        .into_iter()
        .find(|output| {
            output.session_id == session_id
                && output.presign_blending_index == presign_blending_index
        })
        .ok_or_else(|| {
            DwalletMPCError::InvalidInput(format!(
                "no persisted VSS presign output for session {session_id:?} blending index \
                 {presign_blending_index}"
            ))
        })?;

    Ok(
        twopc_mpc::schnorr::vss::sign::decentralized_party::PrivateInput {
            secret_key_share_first_part,
            secret_key_share_second_part,
            session_id: entry.session_id,
            presign_blending_index: entry.presign_blending_index,
            nonce_share_first_part: entry.nonce_share_first_part,
            nonce_share_second_part: entry.nonce_share_second_part,
            first_nonce_polynomial_commitments: entry
                .nonce_share_first_part_coefficient_commitments,
            second_nonce_polynomial_commitments: entry
                .nonce_share_second_part_coefficient_commitments,
        },
    )
}

pub(crate) fn build_ristretto_schnorrkel_vss_sign_private_input(
    party_id: PartyID,
    root_seed: &RootSeed,
    secret_key_shares_source: &VssSecretKeySharesVersionedSource,
    presign_private_output: Option<Vec<u8>>,
    public_input: &<SignParty<RistrettoSchnorrkelSubstrateVSSProtocol> as Party>::PublicInput,
) -> DwalletMPCResult<
    <SignParty<RistrettoSchnorrkelSubstrateVSSProtocol> as AsynchronouslyAdvanceable>::PrivateInput,
> {
    let secret_key_shares_source =
        VssSecretKeyShareSource::from_versioned(secret_key_shares_source)?;
    let validator_keys = ValidatorMPCSecrets::from_seed(root_seed);
    let (secret_key_share_first_part, secret_key_share_second_part) = secret_key_shares_source
        .ristretto_shamir_shares(
            party_id,
            validator_keys.ristretto_pvss_decryption_key(),
            validator_keys.ristretto_pvss_encryption_key_and_proof().0,
        )?;

    let session_id = public_input.presign.session_id;
    let presign_blending_index = public_input.presign.presign_blending_index;
    let private_presign_outputs = vss_presign_private_outputs::<
        RistrettoSchnorrkelSubstrateVSSProtocol,
    >(presign_private_output, session_id, presign_blending_index)?;
    let entry = private_presign_outputs
        .into_iter()
        .find(|output| {
            output.session_id == session_id
                && output.presign_blending_index == presign_blending_index
        })
        .ok_or_else(|| {
            DwalletMPCError::InvalidInput(format!(
                "no persisted VSS presign output for session {session_id:?} blending index \
                 {presign_blending_index}"
            ))
        })?;

    Ok(
        twopc_mpc::schnorr::vss::sign::decentralized_party::PrivateInput {
            secret_key_share_first_part,
            secret_key_share_second_part,
            session_id: entry.session_id,
            presign_blending_index: entry.presign_blending_index,
            nonce_share_first_part: entry.nonce_share_first_part,
            nonce_share_second_part: entry.nonce_share_second_part,
            first_nonce_polynomial_commitments: entry
                .nonce_share_first_part_coefficient_commitments,
            second_nonce_polynomial_commitments: entry
                .nonce_share_second_part_coefficient_commitments,
        },
    )
}

fn build_secp256k1_taproot_vss_sign_public_input(
    dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    hash_scheme: HashScheme,
    network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
) -> DwalletMPCResult<<SignParty<Secp256k1TaprootVSSProtocol> as Party>::PublicInput> {
    let protocol_public_parameters =
        network_encryption_key_public_data.secp256k1_protocol_public_parameters();
    let (dkg_output, presign_value) = decode_schnorr_ahe_dkg_and_presign::<
        Secp256k1AsyncDKGProtocol,
        Secp256k1TaprootVSSProtocol,
    >(dwallet_decentralized_public_output, presign)?;
    let sign_data =
        decode_schnorr_sign_data::<Secp256k1TaprootVSSProtocol>(message_centralized_signature)?;
    let secret_key_shares_source =
        VssSecretKeyShareSource::from_network_key_public_data(network_encryption_key_public_data)?;
    let (first_commitments, second_commitments) =
        secret_key_shares_source.secp256k1_polynomial_commitments();

    Ok(
        twopc_mpc::schnorr::vss::sign::decentralized_party::PublicInput {
            message,
            hash_scheme,
            dkg_output,
            presign: presign_value,
            centralized_party_partial_signature: sign_data,
            protocol_public_parameters,
            first_secret_key_polynomial_commitments: first_commitments.clone(),
            second_secret_key_polynomial_commitments: second_commitments.clone(),
        },
    )
}

fn build_curve25519_eddsa_vss_sign_public_input(
    dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    hash_scheme: HashScheme,
    network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
) -> DwalletMPCResult<<SignParty<Curve25519EdDSAVSSProtocol> as Party>::PublicInput> {
    let protocol_public_parameters =
        network_encryption_key_public_data.curve25519_protocol_public_parameters();
    let (dkg_output, presign_value) = decode_schnorr_ahe_dkg_and_presign::<
        Curve25519AsyncDKGProtocol,
        Curve25519EdDSAVSSProtocol,
    >(dwallet_decentralized_public_output, presign)?;
    let sign_data =
        decode_schnorr_sign_data::<Curve25519EdDSAVSSProtocol>(message_centralized_signature)?;
    let secret_key_shares_source =
        VssSecretKeyShareSource::from_network_key_public_data(network_encryption_key_public_data)?;
    let (first_commitments, second_commitments) =
        secret_key_shares_source.curve25519_polynomial_commitments();

    Ok(
        twopc_mpc::schnorr::vss::sign::decentralized_party::PublicInput {
            message,
            hash_scheme,
            dkg_output,
            presign: presign_value,
            centralized_party_partial_signature: sign_data,
            protocol_public_parameters,
            first_secret_key_polynomial_commitments: first_commitments.clone(),
            second_secret_key_polynomial_commitments: second_commitments.clone(),
        },
    )
}

fn build_ristretto_schnorrkel_vss_sign_public_input(
    dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    hash_scheme: HashScheme,
    network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
) -> DwalletMPCResult<<SignParty<RistrettoSchnorrkelSubstrateVSSProtocol> as Party>::PublicInput> {
    let protocol_public_parameters =
        network_encryption_key_public_data.ristretto_protocol_public_parameters();
    let (dkg_output, presign_value) = decode_schnorr_ahe_dkg_and_presign::<
        RistrettoAsyncDKGProtocol,
        RistrettoSchnorrkelSubstrateVSSProtocol,
    >(dwallet_decentralized_public_output, presign)?;
    let sign_data = decode_schnorr_sign_data::<RistrettoSchnorrkelSubstrateVSSProtocol>(
        message_centralized_signature,
    )?;
    let secret_key_shares_source =
        VssSecretKeyShareSource::from_network_key_public_data(network_encryption_key_public_data)?;
    let (first_commitments, second_commitments) =
        secret_key_shares_source.ristretto_polynomial_commitments();

    Ok(
        twopc_mpc::schnorr::vss::sign::decentralized_party::PublicInput {
            message,
            hash_scheme,
            dkg_output,
            presign: presign_value,
            centralized_party_partial_signature: sign_data,
            protocol_public_parameters,
            first_secret_key_polynomial_commitments: first_commitments.clone(),
            second_secret_key_polynomial_commitments: second_commitments.clone(),
        },
    )
}

fn build_secp256k1_ecdsa_sign_public_input(
    expected_decrypters: HashSet<PartyID>,
    dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    hash_scheme: HashScheme,
    network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
) -> DwalletMPCResult<<SignParty<Secp256k1ECDSAProtocol> as Party>::PublicInput> {
    let protocol_public_parameters =
        network_encryption_key_public_data.secp256k1_protocol_public_parameters();
    let decryption_key_share_public_parameters =
        network_encryption_key_public_data.secp256k1_decryption_key_share_public_parameters();

    // secp256k1 ECDSA is the only protocol that ever wrote presign V1 (raw concrete
    // `twopc_mpc::ecdsa::presign::Presign<...>`, no `SignMessage` wrapping). Peek at the
    // presign versioning: V1 uses the shared DKG decode + inline raw-presign conversion;
    // V2 delegates the whole pair to the combined helper.
    let presign_versioned: VersionedPresignOutput = bcs::from_bytes(presign).map_err(|e| {
        DwalletMPCError::BcsError(bcs::Error::Custom(format!(
            "Failed to deserialize presign output: {e}"
        )))
    })?;

    let (dkg_output, presign_value) = match presign_versioned {
        VersionedPresignOutput::V1(presign_bytes) => {
            let dkg_output =
                decode_ecdsa_dkg::<Secp256k1AsyncDKGProtocol>(dwallet_decentralized_public_output)?;
            let raw_presign: twopc_mpc::ecdsa::presign::Presign<
                group::secp256k1::group_element::Value,
                group::Value<CiphertextSpaceGroupElement<{ NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>>,
            > = bcs::from_bytes(&presign_bytes).map_err(|e| {
                DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                    "Failed to deserialize presign V1: {e}"
                )))
            })?;
            (dkg_output, raw_presign.into())
        }
        VersionedPresignOutput::V2(_) => decode_ecdsa_dkg_and_presign::<
            Secp256k1AsyncDKGProtocol,
            Secp256k1ECDSAProtocol,
        >(dwallet_decentralized_public_output, presign)?,
    };

    let sign_data =
        decode_ecdsa_sign_data::<Secp256k1ECDSAProtocol>(message_centralized_signature)?;

    Ok(twopc_mpc::ecdsa::sign::decentralized_party::PublicInput {
        expected_decrypters,
        message,
        hash_type: hash_scheme,
        dkg_output,
        presign: presign_value,
        sign_message: sign_data,
        decryption_key_share_public_parameters,
        protocol_public_parameters,
    })
}

fn build_secp256r1_ecdsa_sign_public_input(
    expected_decrypters: HashSet<PartyID>,
    dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    hash_scheme: HashScheme,
    network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
) -> DwalletMPCResult<<SignParty<Secp256r1ECDSAProtocol> as Party>::PublicInput> {
    let protocol_public_parameters =
        network_encryption_key_public_data.secp256r1_protocol_public_parameters();
    let decryption_key_share_public_parameters =
        network_encryption_key_public_data.secp256r1_decryption_key_share_public_parameters();
    let (dkg_output, presign_value) = decode_ecdsa_dkg_and_presign::<
        Secp256r1AsyncDKGProtocol,
        Secp256r1ECDSAProtocol,
    >(dwallet_decentralized_public_output, presign)?;
    let sign_data =
        decode_ecdsa_sign_data::<Secp256r1ECDSAProtocol>(message_centralized_signature)?;

    Ok(twopc_mpc::ecdsa::sign::decentralized_party::PublicInput {
        expected_decrypters,
        message,
        hash_type: hash_scheme,
        dkg_output,
        presign: presign_value,
        sign_message: sign_data,
        decryption_key_share_public_parameters,
        protocol_public_parameters,
    })
}

fn build_secp256k1_taproot_sign_public_input(
    expected_decrypters: HashSet<PartyID>,
    dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    hash_scheme: HashScheme,
    network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
) -> DwalletMPCResult<<SignParty<Secp256k1TaprootProtocol> as Party>::PublicInput> {
    let protocol_public_parameters =
        network_encryption_key_public_data.secp256k1_protocol_public_parameters();
    let decryption_key_share_public_parameters =
        network_encryption_key_public_data.secp256k1_decryption_key_share_public_parameters();
    let (dkg_output, presign_value) = decode_schnorr_ahe_dkg_and_presign::<
        Secp256k1AsyncDKGProtocol,
        Secp256k1TaprootProtocol,
    >(dwallet_decentralized_public_output, presign)?;
    let sign_data =
        decode_schnorr_sign_data::<Secp256k1TaprootProtocol>(message_centralized_signature)?;

    Ok(
        twopc_mpc::schnorr::ahe::sign::decentralized_party::PublicInput {
            expected_decrypters,
            message,
            hash_scheme,
            dkg_output,
            presign: presign_value,
            centralized_party_partial_signature: sign_data,
            decryption_key_share_public_parameters,
            protocol_public_parameters,
        },
    )
}

fn build_curve25519_eddsa_sign_public_input(
    expected_decrypters: HashSet<PartyID>,
    dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    hash_scheme: HashScheme,
    network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
) -> DwalletMPCResult<<SignParty<Curve25519EdDSAProtocol> as Party>::PublicInput> {
    let protocol_public_parameters =
        network_encryption_key_public_data.curve25519_protocol_public_parameters();
    let decryption_key_share_public_parameters =
        network_encryption_key_public_data.curve25519_decryption_key_share_public_parameters();
    let (dkg_output, presign_value) = decode_schnorr_ahe_dkg_and_presign::<
        Curve25519AsyncDKGProtocol,
        Curve25519EdDSAProtocol,
    >(dwallet_decentralized_public_output, presign)?;
    let sign_data =
        decode_schnorr_sign_data::<Curve25519EdDSAProtocol>(message_centralized_signature)?;

    Ok(
        twopc_mpc::schnorr::ahe::sign::decentralized_party::PublicInput {
            expected_decrypters,
            message,
            hash_scheme,
            dkg_output,
            presign: presign_value,
            centralized_party_partial_signature: sign_data,
            decryption_key_share_public_parameters,
            protocol_public_parameters,
        },
    )
}

fn build_ristretto_schnorrkel_sign_public_input(
    expected_decrypters: HashSet<PartyID>,
    dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    hash_scheme: HashScheme,
    network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
) -> DwalletMPCResult<<SignParty<RistrettoSchnorrkelSubstrateProtocol> as Party>::PublicInput> {
    let protocol_public_parameters =
        network_encryption_key_public_data.ristretto_protocol_public_parameters();
    let decryption_key_share_public_parameters =
        network_encryption_key_public_data.ristretto_decryption_key_share_public_parameters();
    let (dkg_output, presign_value) = decode_schnorr_ahe_dkg_and_presign::<
        RistrettoAsyncDKGProtocol,
        RistrettoSchnorrkelSubstrateProtocol,
    >(dwallet_decentralized_public_output, presign)?;
    let sign_data = decode_schnorr_sign_data::<RistrettoSchnorrkelSubstrateProtocol>(
        message_centralized_signature,
    )?;

    Ok(
        twopc_mpc::schnorr::ahe::sign::decentralized_party::PublicInput {
            expected_decrypters,
            message,
            hash_scheme,
            dkg_output,
            presign: presign_value,
            centralized_party_partial_signature: sign_data,
            decryption_key_share_public_parameters,
            protocol_public_parameters,
        },
    )
}

// Decode helpers shared across the per-curve builders. They are generic over (D, P) where D
// is the per-curve DKG protocol and P is the per-curve sign protocol; the body is just bcs
// deserialization through the standard versioned wrappers, no protocol-specific logic.
fn decode_ecdsa_dkg<D>(
    dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
) -> DwalletMPCResult<<D as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput>
where
    D: twopc_mpc::dkg::Protocol,
{
    let dkg_versioned: VersionedDwalletDKGPublicOutput =
        bcs::from_bytes(dwallet_decentralized_public_output).map_err(|e| {
            DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                "Failed to deserialize decentralized DKG versioned output: {e}"
            )))
        })?;
    let dkg_output = match dkg_versioned {
        VersionedDwalletDKGPublicOutput::V1(output) => bcs::from_bytes::<
            <D as twopc_mpc::dkg::Protocol>::DecentralizedPartyTargetedDKGOutput,
        >(output.as_slice())
        .map_err(|e| {
            DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                "Failed to deserialize decentralized DKG output V1: {e}"
            )))
        })?
        .into(),
        VersionedDwalletDKGPublicOutput::V2 { dkg_output, .. } => {
            bcs::from_bytes(dkg_output.as_slice()).map_err(|e| {
                DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                    "Failed to deserialize decentralized DKG output V2: {e}"
                )))
            })?
        }
    };
    Ok(dkg_output)
}

fn decode_ecdsa_dkg_and_presign<D, P>(
    dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    presign: &SerializedWrappedMPCPublicOutput,
) -> DwalletMPCResult<(
    <D as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput,
    <P as twopc_mpc::presign::Protocol>::Presign,
)>
where
    D: twopc_mpc::dkg::Protocol,
    P: twopc_mpc::presign::Protocol,
{
    let dkg_output = decode_ecdsa_dkg::<D>(dwallet_decentralized_public_output)?;

    let presign_versioned: VersionedPresignOutput = bcs::from_bytes(presign).map_err(|e| {
        DwalletMPCError::BcsError(bcs::Error::Custom(format!(
            "Failed to deserialize presign output: {e}"
        )))
    })?;
    let presign_bytes = match presign_versioned {
        VersionedPresignOutput::V1(_) => {
            unreachable!("Presign V1 only valid for Secp256k1ECDSA — handled inline there")
        }
        VersionedPresignOutput::V2(p) => p,
    };
    let presign_value: <P as twopc_mpc::presign::Protocol>::Presign =
        bcs::from_bytes(&presign_bytes).map_err(|e| {
            DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                "Failed to deserialize presign V2: {e}"
            )))
        })?;
    Ok((dkg_output, presign_value))
}

// Schnorr-AHE shares the same DKG/presign decode shape as ECDSA at this rev — the
// per-curve structs differ but the BCS wire layout is the same versioned wrapper.
fn decode_schnorr_ahe_dkg_and_presign<D, P>(
    dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    presign: &SerializedWrappedMPCPublicOutput,
) -> DwalletMPCResult<(
    <D as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput,
    <P as twopc_mpc::presign::Protocol>::Presign,
)>
where
    D: twopc_mpc::dkg::Protocol,
    P: twopc_mpc::presign::Protocol,
{
    decode_ecdsa_dkg_and_presign::<D, P>(dwallet_decentralized_public_output, presign)
}

fn decode_ecdsa_sign_data<P>(
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
) -> DwalletMPCResult<
    twopc_mpc::sign::SignData<
        <P as twopc_mpc::sign::Protocol>::SignMessage,
        <P as twopc_mpc::sign::Protocol>::VerifiedSignData,
    >,
>
where
    P: twopc_mpc::sign::Protocol,
{
    if message_centralized_signature.is_empty() {
        Ok(twopc_mpc::sign::SignData::ToBeEmulated)
    } else {
        let centralized_signed_message: VersionedUserSignedMessage =
            bcs::from_bytes(message_centralized_signature).map_err(|e| {
                DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                    "Failed to deserialize centralized signed message: {e}"
                )))
            })?;
        let VersionedUserSignedMessage::V1(centralized_signed_message) = centralized_signed_message;
        let sign_message: <P as twopc_mpc::sign::Protocol>::SignMessage =
            bcs::from_bytes(&centralized_signed_message).map_err(|e| {
                DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                    "Failed to deserialize sign message: {e}"
                )))
            })?;
        Ok(twopc_mpc::sign::SignData::Unverified(sign_message))
    }
}

// Schnorr-AHE uses the same SignData wire shape as ECDSA at this rev (the field name on
// the per-protocol PublicInput differs, not the SignData<SignMessage, VerifiedSignData>
// wrapping).
fn decode_schnorr_sign_data<P>(
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
) -> DwalletMPCResult<
    twopc_mpc::sign::SignData<
        <P as twopc_mpc::sign::Protocol>::SignMessage,
        <P as twopc_mpc::sign::Protocol>::VerifiedSignData,
    >,
>
where
    P: twopc_mpc::sign::Protocol,
{
    decode_ecdsa_sign_data::<P>(message_centralized_signature)
}

impl DKGAndSignPublicInputByProtocol {
    pub(crate) fn try_new(
        session_identifier: SessionIdentifier,
        dwallet_dkg_public_input: DWalletDKGPublicInputByCurve,
        message: Vec<u8>,
        presign: &SerializedWrappedMPCPublicOutput,
        message_centralized_signature: &SerializedWrappedMPCPublicOutput,
        hash_scheme: HashScheme,
        access_structure: &WeightedThresholdAccessStructure,
        network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
        protocol: DWalletSignatureAlgorithm,
    ) -> DwalletMPCResult<Self> {
        let expected_decrypters =
            generate_expected_decrypters(access_structure, session_identifier)?;
        match protocol {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                let DWalletDKGPublicInputByCurve::Secp256k1DWalletDKG(dkg_public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch");
                };
                Ok(DKGAndSignPublicInputByProtocol::Secp256k1ECDSA(
                    build_secp256k1_ecdsa_dkg_and_sign_public_input(
                        expected_decrypters,
                        dkg_public_input,
                        message,
                        presign,
                        message_centralized_signature,
                        hash_scheme,
                        network_encryption_key_public_data,
                    )?,
                ))
            }
            DWalletSignatureAlgorithm::Taproot => {
                let DWalletDKGPublicInputByCurve::Secp256k1DWalletDKG(dkg_public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch");
                };
                Ok(DKGAndSignPublicInputByProtocol::Secp256k1Taproot(
                    build_secp256k1_taproot_dkg_and_sign_public_input(
                        expected_decrypters,
                        dkg_public_input,
                        message,
                        presign,
                        message_centralized_signature,
                        hash_scheme,
                        network_encryption_key_public_data,
                    )?,
                ))
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                let DWalletDKGPublicInputByCurve::RistrettoDWalletDKG(dkg_public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch");
                };
                Ok(DKGAndSignPublicInputByProtocol::Ristretto(
                    build_ristretto_schnorrkel_dkg_and_sign_public_input(
                        expected_decrypters,
                        dkg_public_input,
                        message,
                        presign,
                        message_centralized_signature,
                        hash_scheme,
                        network_encryption_key_public_data,
                    )?,
                ))
            }
            DWalletSignatureAlgorithm::EdDSA => {
                let DWalletDKGPublicInputByCurve::Curve25519DWalletDKG(dkg_public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch");
                };
                Ok(DKGAndSignPublicInputByProtocol::Curve25519(
                    build_curve25519_eddsa_dkg_and_sign_public_input(
                        expected_decrypters,
                        dkg_public_input,
                        message,
                        presign,
                        message_centralized_signature,
                        hash_scheme,
                        network_encryption_key_public_data,
                    )?,
                ))
            }
            DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                let DWalletDKGPublicInputByCurve::Secp256r1DWalletDKG(dkg_public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch");
                };
                Ok(DKGAndSignPublicInputByProtocol::Secp256r1(
                    build_secp256r1_ecdsa_dkg_and_sign_public_input(
                        expected_decrypters,
                        dkg_public_input,
                        message,
                        presign,
                        message_centralized_signature,
                        hash_scheme,
                        network_encryption_key_public_data,
                    )?,
                ))
            }
            // Fast Schnorr (VSS) has no combined DKG-and-sign (deferred by decision;
            // upstream party exists but is not wired here); rejected at request
            // construction, kept exhaustive here as defense-in-depth.
            DWalletSignatureAlgorithm::TaprootVSS
            | DWalletSignatureAlgorithm::EdDSAVSS
            | DWalletSignatureAlgorithm::SchnorrkelSubstrateVSS => {
                Err(DwalletMPCError::InvalidInput(format!(
                    "Fast Schnorr (VSS) algorithm {protocol} is not supported for \
                     the combined DKG-and-sign fast path"
                )))
            }
        }
    }
}

// Per-curve concrete dkg-and-sign-public-input builders. Same shape as the sign builders
// above but produce DKGSignPublicInput (taking dkg_public_input instead of decoded
// dkg_output) and pull decryption_pp / protocol_pp from
// network_encryption_key_public_data themselves.

fn build_secp256k1_ecdsa_dkg_and_sign_public_input(
    expected_decrypters: HashSet<PartyID>,
    dkg_public_input: <Secp256k1AsyncDKGProtocol as twopc_mpc::dkg::Protocol>::DKGDecentralizedPartyPublicInput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    hash_scheme: HashScheme,
    network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
) -> DwalletMPCResult<<DKGAndSignParty<Secp256k1ECDSAProtocol> as Party>::PublicInput> {
    let protocol_public_parameters =
        network_encryption_key_public_data.secp256k1_protocol_public_parameters();
    let decryption_key_share_public_parameters =
        network_encryption_key_public_data.secp256k1_decryption_key_share_public_parameters();
    let presign_value = decode_presign_v2::<Secp256k1ECDSAProtocol>(presign)?;
    let sign_data =
        decode_ecdsa_sign_data::<Secp256k1ECDSAProtocol>(message_centralized_signature)?;

    Ok(
        twopc_mpc::ecdsa::sign::decentralized_party::DKGSignPublicInput {
            expected_decrypters,
            message,
            hash_type: hash_scheme,
            dkg_public_input,
            presign: presign_value,
            sign_message: sign_data,
            decryption_key_share_public_parameters,
            protocol_public_parameters,
        },
    )
}

fn build_secp256r1_ecdsa_dkg_and_sign_public_input(
    expected_decrypters: HashSet<PartyID>,
    dkg_public_input: <Secp256r1AsyncDKGProtocol as twopc_mpc::dkg::Protocol>::DKGDecentralizedPartyPublicInput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    hash_scheme: HashScheme,
    network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
) -> DwalletMPCResult<<DKGAndSignParty<Secp256r1ECDSAProtocol> as Party>::PublicInput> {
    let protocol_public_parameters =
        network_encryption_key_public_data.secp256r1_protocol_public_parameters();
    let decryption_key_share_public_parameters =
        network_encryption_key_public_data.secp256r1_decryption_key_share_public_parameters();
    let presign_value = decode_presign_v2::<Secp256r1ECDSAProtocol>(presign)?;
    let sign_data =
        decode_ecdsa_sign_data::<Secp256r1ECDSAProtocol>(message_centralized_signature)?;

    Ok(
        twopc_mpc::ecdsa::sign::decentralized_party::DKGSignPublicInput {
            expected_decrypters,
            message,
            hash_type: hash_scheme,
            dkg_public_input,
            presign: presign_value,
            sign_message: sign_data,
            decryption_key_share_public_parameters,
            protocol_public_parameters,
        },
    )
}

fn build_secp256k1_taproot_dkg_and_sign_public_input(
    expected_decrypters: HashSet<PartyID>,
    dkg_public_input: <Secp256k1AsyncDKGProtocol as twopc_mpc::dkg::Protocol>::DKGDecentralizedPartyPublicInput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    hash_scheme: HashScheme,
    network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
) -> DwalletMPCResult<<DKGAndSignParty<Secp256k1TaprootProtocol> as Party>::PublicInput> {
    let protocol_public_parameters =
        network_encryption_key_public_data.secp256k1_protocol_public_parameters();
    let decryption_key_share_public_parameters =
        network_encryption_key_public_data.secp256k1_decryption_key_share_public_parameters();
    let presign_value = decode_presign_v2::<Secp256k1TaprootProtocol>(presign)?;
    let sign_data =
        decode_schnorr_sign_data::<Secp256k1TaprootProtocol>(message_centralized_signature)?;

    Ok(
        twopc_mpc::schnorr::ahe::sign::decentralized_party::DKGSignPublicInput {
            expected_decrypters,
            message,
            hash_scheme,
            dkg_public_input,
            presign: presign_value,
            centralized_party_partial_signature: sign_data,
            decryption_key_share_public_parameters,
            protocol_public_parameters,
        },
    )
}

fn build_curve25519_eddsa_dkg_and_sign_public_input(
    expected_decrypters: HashSet<PartyID>,
    dkg_public_input: <Curve25519AsyncDKGProtocol as twopc_mpc::dkg::Protocol>::DKGDecentralizedPartyPublicInput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    hash_scheme: HashScheme,
    network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
) -> DwalletMPCResult<<DKGAndSignParty<Curve25519EdDSAProtocol> as Party>::PublicInput> {
    let protocol_public_parameters =
        network_encryption_key_public_data.curve25519_protocol_public_parameters();
    let decryption_key_share_public_parameters =
        network_encryption_key_public_data.curve25519_decryption_key_share_public_parameters();
    let presign_value = decode_presign_v2::<Curve25519EdDSAProtocol>(presign)?;
    let sign_data =
        decode_schnorr_sign_data::<Curve25519EdDSAProtocol>(message_centralized_signature)?;

    Ok(
        twopc_mpc::schnorr::ahe::sign::decentralized_party::DKGSignPublicInput {
            expected_decrypters,
            message,
            hash_scheme,
            dkg_public_input,
            presign: presign_value,
            centralized_party_partial_signature: sign_data,
            decryption_key_share_public_parameters,
            protocol_public_parameters,
        },
    )
}

fn build_ristretto_schnorrkel_dkg_and_sign_public_input(
    expected_decrypters: HashSet<PartyID>,
    dkg_public_input: <RistrettoAsyncDKGProtocol as twopc_mpc::dkg::Protocol>::DKGDecentralizedPartyPublicInput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    hash_scheme: HashScheme,
    network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
) -> DwalletMPCResult<<DKGAndSignParty<RistrettoSchnorrkelSubstrateProtocol> as Party>::PublicInput>
{
    let protocol_public_parameters =
        network_encryption_key_public_data.ristretto_protocol_public_parameters();
    let decryption_key_share_public_parameters =
        network_encryption_key_public_data.ristretto_decryption_key_share_public_parameters();
    let presign_value = decode_presign_v2::<RistrettoSchnorrkelSubstrateProtocol>(presign)?;
    let sign_data = decode_schnorr_sign_data::<RistrettoSchnorrkelSubstrateProtocol>(
        message_centralized_signature,
    )?;

    Ok(
        twopc_mpc::schnorr::ahe::sign::decentralized_party::DKGSignPublicInput {
            expected_decrypters,
            message,
            hash_scheme,
            dkg_public_input,
            presign: presign_value,
            centralized_party_partial_signature: sign_data,
            decryption_key_share_public_parameters,
            protocol_public_parameters,
        },
    )
}

fn decode_presign_v2<P>(
    presign: &SerializedWrappedMPCPublicOutput,
) -> DwalletMPCResult<<P as twopc_mpc::presign::Protocol>::Presign>
where
    P: twopc_mpc::presign::Protocol,
{
    let presign_versioned: VersionedPresignOutput = bcs::from_bytes(presign)?;
    let presign_bytes = match presign_versioned {
        VersionedPresignOutput::V1(_) => {
            unreachable!("Presign V1 should have been handled separately")
        }
        VersionedPresignOutput::V2(p) => p,
    };
    bcs::from_bytes(&presign_bytes).map_err(|e| {
        DwalletMPCError::BcsError(bcs::Error::Custom(format!(
            "Failed to deserialize presign V2: {e}"
        )))
    })
}

/// Update metrics on whether we are in the expected or unexpected case during threshold decryption.
/// The unexpected case is slower, but still completes successfully - we want to tune the system such that
/// there will be as little unexpected cases with minimum  delay, which makes reporting these metrics useful.
pub(crate) fn update_expected_decrypters_metrics(
    expected_decrypters: &HashSet<PartyID>,
    decrypters: HashSet<PartyID>,
    access_structure: &WeightedThresholdAccessStructure,
    dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
) {
    let participating_expected_decrypters: HashSet<PartyID> = expected_decrypters
        .iter()
        .filter(|party_id| decrypters.contains(*party_id))
        .copied()
        .collect();

    if access_structure
        .is_authorized_subset(&participating_expected_decrypters)
        .is_ok()
    {
        dwallet_mpc_metrics.number_of_expected_sign_sessions.inc();
    } else {
        dwallet_mpc_metrics.number_of_unexpected_sign_sessions.inc();
    }
}

/// Verifies a single partial signature (centralized-party-only signed message) against the
/// given dWallet DKG output and returns the post-verification compact `VerifiedSignData`.
///
/// Upstream's `verify_centralized_party_partial_signature` returns `Result<P::VerifiedSignData>`
/// — a compact form (3 ciphertext / nonce fields for ECDSA, vs. the full `SignMessage` with
/// all ZK proofs) that can be persisted / re-transmitted as `SignData::Verified(...)` for any
/// follow-up sign or rebroadcast, skipping re-verification and shrinking wire size. Callers
/// that don't yet plumb it through can discard locally.
pub(crate) fn verify_partial_signature<P, D>(
    message: &[u8],
    hash_scheme: &HashScheme,
    dwallet_decentralized_output: &SerializedWrappedMPCPublicOutput,
    presign: &SerializedWrappedMPCPublicOutput,
    partially_signed_message: &SerializedWrappedMPCPublicOutput,
    protocol_public_parameters: &D::ProtocolPublicParameters,
) -> DwalletMPCResult<<P as sign::Protocol>::VerifiedSignData>
where
    P: sign::Protocol + twopc_mpc::presign::Protocol<DKGProtocol = D>,
    D: twopc_mpc::dkg::Protocol,
{
    let presign = match bcs::from_bytes::<VersionedPresignOutput>(presign)? {
        VersionedPresignOutput::V1(_) => {
            unreachable!("Presign V1 should have been handled separately")
        }
        VersionedPresignOutput::V2(presign) => presign,
    };
    let dkg_output: VersionedDwalletDKGPublicOutput =
        bcs::from_bytes(dwallet_decentralized_output)?;
    let partially_signed_message: VersionedUserSignedMessage =
        bcs::from_bytes(partially_signed_message)?;
    let decentralized_dkg_output: D::DecentralizedPartyDKGOutput = match dkg_output {
        VersionedDwalletDKGPublicOutput::V1(output) => {
            bcs::from_bytes::<D::DecentralizedPartyTargetedDKGOutput>(output.as_slice())?.into()
        }
        VersionedDwalletDKGPublicOutput::V2 { dkg_output, .. } => {
            bcs::from_bytes::<D::DecentralizedPartyDKGOutput>(dkg_output.as_slice())?
        }
    };

    let presign: <P as twopc_mpc::presign::Protocol>::Presign = bcs::from_bytes(&presign)?;
    let VersionedUserSignedMessage::V1(partially_signed_message) = partially_signed_message;
    let partial: <P as twopc_mpc::sign::Protocol>::SignMessage =
        bcs::from_bytes(&partially_signed_message)?;

    <P as sign::Protocol>::verify_centralized_party_partial_signature(
        message,
        *hash_scheme,
        decentralized_dkg_output,
        presign,
        partial,
        protocol_public_parameters,
        &mut OsCsRng,
    )
    .map_err(DwalletMPCError::from)
}

/// `decryption_key_shares` is the sign-protocol private input.
///
/// For AHE-mode protocols (all five sign protocols ika uses at this bump) this resolves to
/// `Option<HashMap<PartyID, SecretKeyShareSizedInteger>>` and is sourced from the network
/// DKG's decryption-key-shares map (i.e. the output of `decrypt_decryption_key_shares` on
/// the network DKG output).
///
/// TODO(vss): when VSS-mode sign protocols are activated, this parameter's concrete type
/// will resolve to a different shape (containing nonce shares / HPKE blobs / etc. derived
/// from the presign protocol's `PrivateOutput`). The generic shape stays the same; only
/// the source of the value changes. The presign session must persist each validator's own
/// `<P::PresignParty as mpc::Party>::PrivateOutput` keyed by `(presign_id, validator_id)`
/// so the sign session can recover it. That storage path does not exist today. See
/// `docs/plan-bump-crypto-private-to-main.md` §4d.
pub fn compute_sign<P: twopc_mpc::sign::Protocol>(
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    session_id: CommitmentSizedNumber,
    advance_request: AdvanceRequest<<SignParty<P> as mpc::Party>::Message>,
    public_input: <SignParty<P> as mpc::Party>::PublicInput,
    decryption_key_shares: Option<<SignParty<P> as AsynchronouslyAdvanceable>::PrivateInput>,
    sign_data: &SignData,
    rng: &mut impl CsRng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let result =
        mpc::guaranteed_output_delivery::Party::<SignParty<P>>::advance_with_guaranteed_output(
            session_id,
            party_id,
            access_structure,
            advance_request,
            decryption_key_shares,
            &public_input,
            rng,
        )
        .map_err(|e| DwalletMPCError::FailedToAdvanceMPC(e.into()))?;

    match result {
        GuaranteedOutputDeliveryRoundResult::Advance { message } => {
            Ok(GuaranteedOutputDeliveryRoundResult::Advance { message })
        }
        GuaranteedOutputDeliveryRoundResult::Finalize {
            public_output_value,
            malicious_parties,
            private_output,
        } => {
            let signature = match parse_signature_from_sign_output(
                &sign_data.signature_algorithm,
                public_output_value,
            ) {
                Ok(signature) => Ok(signature),
                Err(e) => {
                    error!(
                        session_identifier=?session_id,
                        ?e,
                        ?malicious_parties,
                        signature_algorithm=?sign_data.signature_algorithm,
                        should_never_happen = true,
                        "failed to deserialize sign session result "
                    );

                    Err(e)
                }
            }?;

            // For Sign protocol, we don't need to wrap the output with version like presign does
            // since the output is already in the correct format
            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value: signature,
                malicious_parties,
                private_output,
            })
        }
    }
}

/// `decryption_key_shares` is the sign-protocol private input. See `compute_sign` for the
/// AHE-mode source and the TODO(vss) note on what changes when VSS-mode sign protocols
/// activate (the same plumbing applies to the combined DKG-and-sign path).
pub fn compute_dwallet_dkg_and_sign<P: twopc_mpc::sign::Protocol>(
    curve: DWalletCurve,
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    session_id: CommitmentSizedNumber,
    advance_request: AdvanceRequest<<DKGAndSignParty<P> as mpc::Party>::Message>,
    public_input: <DKGAndSignParty<P> as mpc::Party>::PublicInput,
    decryption_key_shares: Option<<DKGAndSignParty<P> as AsynchronouslyAdvanceable>::PrivateInput>,
    signature_algorithm: &DWalletSignatureAlgorithm,
    rng: &mut impl CsRng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let result =
        mpc::guaranteed_output_delivery::Party::<DKGAndSignParty<P>>::advance_with_guaranteed_output(
            session_id,
            party_id,
            access_structure,
            advance_request,
            decryption_key_shares,
            &public_input,
            rng,
        )
        .map_err(|e| DwalletMPCError::FailedToAdvanceMPC(e.into()))?;

    match result {
        GuaranteedOutputDeliveryRoundResult::Advance { message } => {
            Ok(GuaranteedOutputDeliveryRoundResult::Advance { message })
        }
        GuaranteedOutputDeliveryRoundResult::Finalize {
            public_output_value,
            malicious_parties,
            private_output,
        } => {
            let (dwallet_dkg_output, signature_output): <P::DKGSignDecentralizedParty as mpc::Party>::PublicOutput = bcs::from_bytes(&public_output_value)?;

            let signature = match parse_signature_from_sign_output(
                signature_algorithm,
                bcs::to_bytes(&signature_output)?,
            ) {
                Ok(signature) => Ok(signature),
                Err(e) => {
                    error!(
                        session_identifier=?session_id,
                        ?e,
                        ?malicious_parties,
                        ?signature_algorithm,
                        should_never_happen = true,
                        "failed to deserialize sign session result "
                    );

                    Err(e)
                }
            }?;

            let dwallet_dkg_output = bcs::to_bytes(&dwallet_dkg_output)?;
            let public_key_bytes =
                public_key_from_decentralized_dkg_output_by_curve_v2(curve, &dwallet_dkg_output)
                    .map_err(|e| DwalletMPCError::InternalError(e.to_string()))?;
            let dkg_public_output_value = bcs::to_bytes(&VersionedDwalletDKGPublicOutput::V2 {
                public_key_bytes,
                dkg_output: dwallet_dkg_output,
            })?;

            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value: bcs::to_bytes(&(
                    dkg_public_output_value,
                    // For Sign protocol, we don't need to wrap the output with version like presign does
                    // since the output is a standardized signature
                    signature,
                ))?,
                malicious_parties,
                private_output,
            })
        }
    }
}
