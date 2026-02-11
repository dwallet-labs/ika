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
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletSignatureAlgorithm, MPCPublicOutput, NetworkEncryptionKeyPublicData,
    SerializedWrappedMPCPublicOutput, VersionedDwalletDKGPublicOutput, VersionedPresignOutput,
    VersionedUserSignedMessage, public_key_from_decentralized_dkg_output_by_curve_v2,
};
use group::CsRng;
use group::{HashScheme, OsCsRng, PartyID};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    Curve25519EdDSAProtocol, RistrettoSchnorrkelSubstrateProtocol, Secp256k1ECDSAProtocol,
    Secp256k1TaprootProtocol, Secp256r1ECDSAProtocol, SessionIdentifier,
};
use mpc::guaranteed_output_delivery::AdvanceRequest;
use mpc::{AsynchronouslyAdvanceable, GuaranteesOutputDelivery};
use mpc::{GuaranteedOutputDeliveryRoundResult, Party, Weight, WeightedThresholdAccessStructure};
use rand_core::SeedableRng;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::error;
use twopc_mpc::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS;
use twopc_mpc::{dkg, sign};

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
            DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                let decryption_pp = network_encryption_key_public_data
                    .secp256k1_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256k1_protocol_public_parameters();

                Ok(SignPublicInputByProtocol::Secp256k1ECDSA(
                    match bcs::from_bytes(presign).map_err(|_| {
                        DwalletMPCError::BcsError(bcs::Error::Custom(
                            "Failed to deserialize presign output".to_string(),
                        ))
                    })? {
                        VersionedPresignOutput::V1(presign) => {
                            let dkg_output = bcs::from_bytes(dwallet_decentralized_public_output)
                                .map_err(|_| {
                                DwalletMPCError::BcsError(bcs::Error::Custom(
                                    "Failed to deserialize decentralized DKG versioned output v1"
                                        .to_string(),
                                ))
                            })?;

                            let centralized_signed_message =
                                bcs::from_bytes(message_centralized_signature).map_err(|_| {
                                    DwalletMPCError::BcsError(bcs::Error::Custom(
                                        "Failed to deserialize centralized signed message"
                                            .to_string(),
                                    ))
                                })?;

                            let decentralized_dkg_output = match dkg_output {
                                VersionedDwalletDKGPublicOutput::V1(output) => {
                                    bcs::from_bytes::<<Secp256k1ECDSAProtocol as dkg::Protocol>::DecentralizedPartyTargetedDKGOutput>(output.as_slice()).map_err(
                                        |_| DwalletMPCError::BcsError(bcs::Error::Custom(
                                            "Failed to deserialize decentralized DKG output V1"
                                                .to_string(),
                                        )),
                                    )?.into()
                                }
                                VersionedDwalletDKGPublicOutput::V2{dkg_output, ..} => {
                                    bcs::from_bytes::<<Secp256k1ECDSAProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput>(dkg_output.as_slice()).map_err(
                                        |_| DwalletMPCError::BcsError(bcs::Error::Custom(
                                            "Failed to deserialize decentralized DKG output V2"
                                                .to_string(),
                                        ))
                                    )?
                                }
                            };

                            let VersionedUserSignedMessage::V1(centralized_signed_message) =
                                centralized_signed_message;

                            let presign: twopc_mpc::ecdsa::presign::Presign<
                                group::secp256k1::group_element::Value,
                                group::Value<
                                    CiphertextSpaceGroupElement<
                                        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                                    >,
                                >,
                            > = bcs::from_bytes(&presign).map_err(|_| {
                                DwalletMPCError::BcsError(bcs::Error::Custom(
                                    "Failed to deserialize presign V1".to_string(),
                                ))
                            })?;

                            <SignParty<Secp256k1ECDSAProtocol> as Party>::PublicInput::from((
                                expected_decrypters,
                                protocol_public_parameters,
                                message,
                                hash_scheme,
                                decentralized_dkg_output,
                                presign.into(),
                                bcs::from_bytes::<<Secp256k1ECDSAProtocol as twopc_mpc::sign::Protocol>::SignMessage>(
                                    &centralized_signed_message,
                                ).map_err(|_| DwalletMPCError::BcsError(bcs::Error::Custom(
                                    "Failed to deserialize sign message".to_string(),
                                )))?,
                                decryption_pp,
                            ))
                        }
                        VersionedPresignOutput::V2(_) => {
                            generate_sign_public_input::<Secp256k1ECDSAProtocol>(
                                protocol_public_parameters,
                                dwallet_decentralized_public_output,
                                message,
                                presign,
                                message_centralized_signature,
                                decryption_pp,
                                expected_decrypters,
                                hash_scheme,
                            )?
                        }
                    },
                ))
            }
            DWalletSignatureAlgorithm::Taproot => {
                let decryption_pp = network_encryption_key_public_data
                    .secp256k1_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256k1_protocol_public_parameters();

                let public_input = generate_sign_public_input::<Secp256k1TaprootProtocol>(
                    protocol_public_parameters,
                    dwallet_decentralized_public_output,
                    message,
                    presign,
                    message_centralized_signature,
                    decryption_pp,
                    expected_decrypters,
                    hash_scheme,
                )?;

                Ok(SignPublicInputByProtocol::Secp256k1Taproot(public_input))
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                let decryption_pp = network_encryption_key_public_data
                    .ristretto_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.ristretto_protocol_public_parameters();

                let public_input =
                    generate_sign_public_input::<RistrettoSchnorrkelSubstrateProtocol>(
                        protocol_public_parameters,
                        dwallet_decentralized_public_output,
                        message,
                        presign,
                        message_centralized_signature,
                        decryption_pp,
                        expected_decrypters,
                        hash_scheme,
                    )?;

                Ok(SignPublicInputByProtocol::Ristretto(public_input))
            }
            DWalletSignatureAlgorithm::EdDSA => {
                let decryption_pp = network_encryption_key_public_data
                    .curve25519_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.curve25519_protocol_public_parameters();

                let public_input = generate_sign_public_input::<Curve25519EdDSAProtocol>(
                    protocol_public_parameters,
                    dwallet_decentralized_public_output,
                    message,
                    presign,
                    message_centralized_signature,
                    decryption_pp,
                    expected_decrypters,
                    hash_scheme,
                )?;

                Ok(SignPublicInputByProtocol::Curve25519(public_input))
            }
            DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                let decryption_pp = network_encryption_key_public_data
                    .secp256r1_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256r1_protocol_public_parameters();

                let public_input = generate_sign_public_input::<Secp256r1ECDSAProtocol>(
                    protocol_public_parameters,
                    dwallet_decentralized_public_output,
                    message,
                    presign,
                    message_centralized_signature,
                    decryption_pp,
                    expected_decrypters,
                    hash_scheme,
                )?;

                Ok(SignPublicInputByProtocol::Secp256r1(public_input))
            }
        }
    }
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
                let decryption_pp = network_encryption_key_public_data
                    .secp256k1_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256k1_protocol_public_parameters();

                let DWalletDKGPublicInputByCurve::Secp256k1DWalletDKG(public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch");
                };

                Ok(DKGAndSignPublicInputByProtocol::Secp256k1ECDSA(
                    generate_dkg_and_sign_public_input::<Secp256k1ECDSAProtocol>(
                        protocol_public_parameters,
                        public_input,
                        message,
                        presign,
                        message_centralized_signature,
                        decryption_pp,
                        expected_decrypters,
                        hash_scheme,
                    )?,
                ))
            }
            DWalletSignatureAlgorithm::Taproot => {
                let decryption_pp = network_encryption_key_public_data
                    .secp256k1_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256k1_protocol_public_parameters();
                let DWalletDKGPublicInputByCurve::Secp256k1DWalletDKG(public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch ");
                };

                let public_input = generate_dkg_and_sign_public_input::<Secp256k1TaprootProtocol>(
                    protocol_public_parameters,
                    public_input,
                    message,
                    presign,
                    message_centralized_signature,
                    decryption_pp,
                    expected_decrypters,
                    hash_scheme,
                )?;

                Ok(DKGAndSignPublicInputByProtocol::Secp256k1Taproot(
                    public_input,
                ))
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                let decryption_pp = network_encryption_key_public_data
                    .ristretto_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.ristretto_protocol_public_parameters();
                let DWalletDKGPublicInputByCurve::RistrettoDWalletDKG(public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch ");
                };

                let public_input =
                    generate_dkg_and_sign_public_input::<RistrettoSchnorrkelSubstrateProtocol>(
                        protocol_public_parameters,
                        public_input,
                        message,
                        presign,
                        message_centralized_signature,
                        decryption_pp,
                        expected_decrypters,
                        hash_scheme,
                    )?;

                Ok(DKGAndSignPublicInputByProtocol::Ristretto(public_input))
            }
            DWalletSignatureAlgorithm::EdDSA => {
                let decryption_pp = network_encryption_key_public_data
                    .curve25519_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.curve25519_protocol_public_parameters();
                let DWalletDKGPublicInputByCurve::Curve25519DWalletDKG(public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch ");
                };

                let public_input = generate_dkg_and_sign_public_input::<Curve25519EdDSAProtocol>(
                    protocol_public_parameters,
                    public_input,
                    message,
                    presign,
                    message_centralized_signature,
                    decryption_pp,
                    expected_decrypters,
                    hash_scheme,
                )?;

                Ok(DKGAndSignPublicInputByProtocol::Curve25519(public_input))
            }
            DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                let decryption_pp = network_encryption_key_public_data
                    .secp256r1_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256r1_protocol_public_parameters();
                let DWalletDKGPublicInputByCurve::Secp256r1DWalletDKG(public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch ");
                };

                let public_input = generate_dkg_and_sign_public_input::<Secp256r1ECDSAProtocol>(
                    protocol_public_parameters,
                    public_input,
                    message,
                    presign,
                    message_centralized_signature,
                    decryption_pp,
                    expected_decrypters,
                    hash_scheme,
                )?;

                Ok(DKGAndSignPublicInputByProtocol::Secp256r1(public_input))
            }
        }
    }
}

fn generate_sign_public_input<P: twopc_mpc::sign::Protocol>(
    protocol_public_parameters: Arc<P::ProtocolPublicParameters>,
    dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    decryption_pp: Arc<P::DecryptionKeySharePublicParameters>,
    expected_decrypters: HashSet<PartyID>,
    hash_scheme: HashScheme,
) -> DwalletMPCResult<<SignParty<P> as Party>::PublicInput> {
    <SignParty<P> as SignPartyPublicInputGenerator<P>>::generate_public_input(
        protocol_public_parameters,
        dwallet_decentralized_public_output,
        message,
        presign,
        message_centralized_signature,
        decryption_pp,
        expected_decrypters,
        hash_scheme,
    )
}

fn generate_dkg_and_sign_public_input<P: twopc_mpc::sign::Protocol>(
    protocol_public_parameters: Arc<P::ProtocolPublicParameters>,
    dwallet_dkg_public_input: P::DKGDecentralizedPartyPublicInput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    decryption_pp: Arc<P::DecryptionKeySharePublicParameters>,
    expected_decrypters: HashSet<PartyID>,
    hash_scheme: HashScheme,
) -> DwalletMPCResult<<DKGAndSignParty<P> as Party>::PublicInput> {
    <DKGAndSignParty<P> as DKGAndSignPartyPublicInputGenerator<P>>::generate_public_input(
        protocol_public_parameters,
        dwallet_dkg_public_input,
        message,
        presign,
        message_centralized_signature,
        decryption_pp,
        expected_decrypters,
        hash_scheme,
    )
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

/// A trait for generating the public input for decentralized `Sign` round in the MPC protocol.
///
/// This trait is implemented to resolve compiler type ambiguities that arise in the 2PC-MPC library
/// when accessing [`Party::PublicInput`].
pub(crate) trait SignPartyPublicInputGenerator<P: twopc_mpc::sign::Protocol>: Party {
    fn generate_public_input(
        protocol_public_parameters: Arc<P::ProtocolPublicParameters>,
        dkg_output: &SerializedWrappedMPCPublicOutput,
        message: Vec<u8>,
        presign: &SerializedWrappedMPCPublicOutput,
        centralized_signed_message: &SerializedWrappedMPCPublicOutput,
        decryption_key_share_public_parameters: Arc<P::DecryptionKeySharePublicParameters>,
        expected_decrypters: HashSet<PartyID>,
        hash_scheme: HashScheme,
    ) -> DwalletMPCResult<<SignParty<P> as Party>::PublicInput>;
}

pub(crate) trait DKGAndSignPartyPublicInputGenerator<P: twopc_mpc::sign::Protocol>:
    Party
{
    fn generate_public_input(
        protocol_public_parameters: Arc<P::ProtocolPublicParameters>,
        dwallet_dkg_public_input: P::DKGDecentralizedPartyPublicInput,
        message: Vec<u8>,
        presign: &SerializedWrappedMPCPublicOutput,
        centralized_signed_message: &SerializedWrappedMPCPublicOutput,
        decryption_key_share_public_parameters: Arc<P::DecryptionKeySharePublicParameters>,
        expected_decrypters: HashSet<PartyID>,
        hash_scheme: HashScheme,
    ) -> DwalletMPCResult<<DKGAndSignParty<P> as Party>::PublicInput>;
}

impl<P: twopc_mpc::sign::Protocol> SignPartyPublicInputGenerator<P> for SignParty<P> {
    fn generate_public_input(
        protocol_public_parameters: Arc<P::ProtocolPublicParameters>,
        dkg_output: &SerializedWrappedMPCPublicOutput,
        message: Vec<u8>,
        presign: &SerializedWrappedMPCPublicOutput,
        centralized_signed_message: &SerializedWrappedMPCPublicOutput,
        decryption_key_share_public_parameters: Arc<P::DecryptionKeySharePublicParameters>,
        expected_decrypters: HashSet<PartyID>,
        hash_scheme: HashScheme,
    ) -> DwalletMPCResult<<SignParty<P> as Party>::PublicInput> {
        let presign = match bcs::from_bytes(presign).map_err(|e| {
            DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                "Failed to deserialize presign output: {e}"
            )))
        })? {
            VersionedPresignOutput::V1(_) => {
                unreachable!("Presign V1 should have been handled separately ")
            }
            VersionedPresignOutput::V2(presign) => presign,
        };

        let dkg_output = bcs::from_bytes(dkg_output).map_err(|e| {
            DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                "Failed to deserialize decentralized DKG versioned output: {e}"
            )))
        })?;

        let centralized_signed_message =
            bcs::from_bytes(centralized_signed_message).map_err(|e| {
                DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                    "Failed to deserialize centralized signed message: {e}"
                )))
            })?;

        let decentralized_dkg_output = match dkg_output {
            VersionedDwalletDKGPublicOutput::V1(output) => {
                bcs::from_bytes::<P::DecentralizedPartyTargetedDKGOutput>(output.as_slice())
                    .map_err(|e| {
                        DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                            "Failed to deserialize decentralized DKG output V1: {e}"
                        )))
                    })?
                    .into()
            }
            VersionedDwalletDKGPublicOutput::V2 { dkg_output, .. } => {
                bcs::from_bytes::<P::DecentralizedPartyDKGOutput>(dkg_output.as_slice()).map_err(
                    |e| {
                        DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                            "Failed to deserialize decentralized DKG output V2: {e}"
                        )))
                    },
                )?
            }
        };

        let VersionedUserSignedMessage::V1(centralized_signed_message) = centralized_signed_message;

        let public_input = <SignParty<P> as Party>::PublicInput::from((
            expected_decrypters,
            protocol_public_parameters,
            message,
            hash_scheme,
            decentralized_dkg_output,
            bcs::from_bytes::<<P as twopc_mpc::presign::Protocol>::Presign>(&presign).map_err(
                |e| {
                    DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                        "Failed to deserialize presign: {e}"
                    )))
                },
            )?,
            bcs::from_bytes::<<P as twopc_mpc::sign::Protocol>::SignMessage>(
                &centralized_signed_message,
            )
            .map_err(|e| {
                DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                    "Failed to deserialize sign message: {e}"
                )))
            })?,
            decryption_key_share_public_parameters,
        ));

        Ok(public_input)
    }
}

impl<P: twopc_mpc::sign::Protocol> DKGAndSignPartyPublicInputGenerator<P> for DKGAndSignParty<P> {
    fn generate_public_input(
        protocol_public_parameters: Arc<P::ProtocolPublicParameters>,
        dwallet_dkg_public_input: P::DKGDecentralizedPartyPublicInput,
        message: Vec<u8>,
        presign: &MPCPublicOutput,
        centralized_signed_message: &SerializedWrappedMPCPublicOutput,
        decryption_key_share_public_parameters: Arc<P::DecryptionKeySharePublicParameters>,
        expected_decrypters: HashSet<PartyID>,
        hash_scheme: HashScheme,
    ) -> DwalletMPCResult<<DKGAndSignParty<P> as Party>::PublicInput> {
        let presign = match bcs::from_bytes(presign)? {
            VersionedPresignOutput::V1(_) => {
                unreachable!("Presign V1 should have been handled separately")
            }
            VersionedPresignOutput::V2(presign) => presign,
        };

        let centralized_signed_message = bcs::from_bytes(centralized_signed_message)?;
        let VersionedUserSignedMessage::V1(centralized_signed_message) = centralized_signed_message;

        let public_input = <DKGAndSignParty<P> as Party>::PublicInput::from((
            expected_decrypters,
            protocol_public_parameters,
            message,
            hash_scheme,
            dwallet_dkg_public_input,
            bcs::from_bytes::<<P as twopc_mpc::presign::Protocol>::Presign>(&presign)?,
            bcs::from_bytes::<<P as twopc_mpc::sign::Protocol>::SignMessage>(
                &centralized_signed_message,
            )?,
            decryption_key_share_public_parameters,
        ));

        Ok(public_input)
    }
}

/// Verifies that a single partial signature — i.e., a message that has only been signed by the
/// client side in the 2PC-MPC protocol — is valid regarding the given dWallet DKG output.
/// Returns Ok if the message is valid, Err otherwise.
pub(crate) fn verify_partial_signature<P: sign::Protocol>(
    message: &[u8],
    hash_scheme: &HashScheme,
    dwallet_decentralized_output: &SerializedWrappedMPCPublicOutput,
    presign: &SerializedWrappedMPCPublicOutput,
    partially_signed_message: &SerializedWrappedMPCPublicOutput,
    protocol_public_parameters: &P::ProtocolPublicParameters,
) -> DwalletMPCResult<()> {
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
    let decentralized_dkg_output = match dkg_output {
        VersionedDwalletDKGPublicOutput::V1(output) => {
            bcs::from_bytes::<P::DecentralizedPartyTargetedDKGOutput>(output.as_slice())?.into()
        }
        VersionedDwalletDKGPublicOutput::V2 { dkg_output, .. } => {
            bcs::from_bytes::<P::DecentralizedPartyDKGOutput>(dkg_output.as_slice())?
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
                        should_never_happen=true,
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
