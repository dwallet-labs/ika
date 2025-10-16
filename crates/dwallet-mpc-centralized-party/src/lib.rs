// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This crate contains the cryptographic logic for the centralized 2PC-MPC party.

// Allowed to improve code readability.
#![allow(unused_qualifications)]

use anyhow::{Context, anyhow};
use class_groups::dkg::Secp256k1Party;
use class_groups::setup::get_setup_parameters_secp256k1;
use class_groups::{
    CiphertextSpaceGroupElement, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER, DecryptionKey,
    EncryptionKey, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_SCALAR_LIMBS, Secp256k1DecryptionKey,
    setup::DeriveFromPlaintextPublicParameters,
};
use dwallet_mpc_types::dwallet_mpc::{
    DKGDecentralizedPartyOutputSecp256k1, DKGDecentralizedPartyVersionedOutputSecp256k1,
    DWalletCurve, DWalletSignatureScheme, NetworkDecryptionKeyPublicOutputType,
    NetworkEncryptionKeyPublicDataV1, NetworkEncryptionKeyPublicDataV2,
    SerializedWrappedMPCPublicOutput, VersionedCentralizedDKGPublicOutput,
    VersionedCentralizedPartyImportedDWalletPublicOutput,
    VersionedDecryptionKeyReconfigurationOutput, VersionedDwalletDKGFirstRoundPublicOutput,
    VersionedDwalletDKGSecondRoundPublicOutput, VersionedDwalletUserSecretShare,
    VersionedEncryptedUserShare, VersionedImportedDwalletOutgoingMessage,
    VersionedNetworkDkgOutput, VersionedNetworkEncryptionKeyPublicData, VersionedPresignOutput,
    VersionedPublicKeyShareAndProof, VersionedSignOutput, VersionedUserSignedMessage,
};
use group::{CyclicGroupElement, GroupElement, HashType, OsCsRng, PartyID, Samplable, secp256k1};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};
use mpc::two_party::{Round, RoundResult};
use mpc::{Party, Weight, WeightedThresholdAccessStructure};
use rand_core::SeedableRng;
use twopc_mpc::secp256k1::SCALAR_LIMBS;

use class_groups::encryption_key::public_parameters::Instantiate;
use commitment::CommitmentSizedNumber;
use twopc_mpc::class_groups::{
    DKGCentralizedPartyOutput, DKGCentralizedPartyVersionedOutput,
    DKGDecentralizedPartyVersionedOutput,
};
use twopc_mpc::decentralized_party::dkg;
use twopc_mpc::dkg::Protocol;
use twopc_mpc::ecdsa::VerifyingKey;
use twopc_mpc::secp256k1::class_groups::{
    FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, ProtocolPublicParameters,
    TaprootProtocol,
};

type Secp256K1ECDSAProtocol = twopc_mpc::secp256k1::class_groups::ECDSAProtocol;

type Secp256K1DKGProtocol = twopc_mpc::secp256k1::class_groups::DKGProtocol;
type Secp256R1DKGProtocol = twopc_mpc::secp256r1::class_groups::DKGProtocol;
type Curve25519DKGProtocol = twopc_mpc::curve25519::class_groups::DKGProtocol;
type RistrettoDKGProtocol = twopc_mpc::ristretto::class_groups::DKGProtocol;

type DKGCentralizedParty =
    <Secp256K1DKGProtocol as twopc_mpc::dkg::Protocol>::DKGCentralizedPartyRound;
type SignCentralizedPartyV1 =
    <Secp256K1DKGProtocol as twopc_mpc::sign::Protocol>::SignCentralizedParty;
type DKGDecentralizedOutput =
    <Secp256K1DKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput;

type SignedMessage = Vec<u8>;

type Secp256k1EncryptionKey = EncryptionKey<
    SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::GroupElement,
>;

pub struct CentralizedDKGWasmResult {
    pub public_key_share_and_proof: Vec<u8>,
    pub public_output: Vec<u8>,
    pub centralized_secret_output: Vec<u8>,
}

pub fn network_dkg_public_output_to_protocol_pp_inner(
    network_dkg_public_output: SerializedWrappedMPCPublicOutput,
) -> anyhow::Result<Vec<u8>> {
    let public_parameters = protocol_public_parameters(network_dkg_public_output)?;
    Ok(bcs::to_bytes(&public_parameters)?)
}

pub fn reconfiguration_public_output_to_protocol_pp_inner(
    reconfiguration_dkg_public_output: SerializedWrappedMPCPublicOutput,
    versioned_network_dkg_output: SerializedWrappedMPCPublicOutput,
) -> anyhow::Result<Vec<u8>> {
    let public_parameters = protocol_public_parameters_from_reconfiguration_output(
        reconfiguration_dkg_public_output,
        versioned_network_dkg_output,
    )?;
    Ok(bcs::to_bytes(&public_parameters)?)
}

pub type DWalletDKGFirstParty = twopc_mpc::secp256k1::class_groups::EncryptionOfSecretKeyShareParty;

/// Executes the second phase of the DKG protocol, part of a three-phase DKG flow.
///
/// This function is invoked by the centralized party to produce:
/// - A public key share and its proof.
/// - Centralized DKG output required for further protocol steps.
/// # Warning
/// The secret (private) key returned from this function should never be sent
/// and should always be kept private.
///
/// # Parameters
/// — `decentralized_first_round_output`:
///    Serialized output of the decentralized party from the first DKG round.
/// — `session_id`: Unique hexadecimal string identifying the session.
///
/// # Returns
/// A tuple containing:
/// - Serialized public key share and proof.
/// - Serialized centralized DKG output.
///
/// # Errors
/// Return an error if decoding or advancing the protocol fails.
/// This is okay since a malicious blockchain can always block a client.
pub fn create_dkg_output_by_curve_v2(
    dwallet_curve: u32,
    protocol_pp: Vec<u8>,
    session_id: Vec<u8>,
) -> anyhow::Result<CentralizedDKGWasmResult> {
    match dwallet_curve.try_into()? {
        DWalletCurve::Secp256k1 => {
            centralized_dkg_output_v2::<Secp256K1DKGProtocol>(protocol_pp, session_id)
        }
        DWalletCurve::Ristretto => {
            centralized_dkg_output_v2::<RistrettoDKGProtocol>(protocol_pp, session_id)
        }
        DWalletCurve::Curve25519 => {
            centralized_dkg_output_v2::<Curve25519DKGProtocol>(protocol_pp, session_id)
        }
        DWalletCurve::Secp256r1 => {
            centralized_dkg_output_v2::<Secp256R1DKGProtocol>(protocol_pp, session_id)
        }
    }
}

fn centralized_dkg_output_v2<P: twopc_mpc::dkg::Protocol>(
    protocol_pp: Vec<u8>,
    session_id: Vec<u8>,
) -> anyhow::Result<CentralizedDKGWasmResult> {
    let protocol_public_parameters: P::ProtocolPublicParameters = bcs::from_bytes(&protocol_pp)?;
    let session_identifier = CommitmentSizedNumber::from_le_slice(&session_id);
    let round_result = P::DKGCentralizedPartyRound::advance(
        (),
        &(),
        &(protocol_public_parameters, session_identifier).into(),
        &mut OsCsRng,
    )
    .map_err(|e| anyhow!("advance() failed on the DKGCentralizedParty: {}", e.into()))?;

    // Centralized Public Key Share and Proof.
    let public_key_share_and_proof =
        VersionedPublicKeyShareAndProof::V1(bcs::to_bytes(&round_result.outgoing_message)?);

    let public_key_share_and_proof = bcs::to_bytes(&public_key_share_and_proof)?;
    let centralized_output = round_result.public_output;

    // Public Output:
    let public_output = bcs::to_bytes(&VersionedCentralizedDKGPublicOutput::V2(bcs::to_bytes(
        &centralized_output,
    )?))?;
    // Centralized Secret Key Share.
    // Warning:
    // The secret (private)
    // key share returned from this function should never be sent
    // and should always be kept private.
    let centralized_secret_output =
        VersionedDwalletUserSecretShare::V1(bcs::to_bytes(&round_result.private_output)?);
    let centralized_secret_output = bcs::to_bytes(&centralized_secret_output)?;
    Ok(CentralizedDKGWasmResult {
        public_output,
        public_key_share_and_proof,
        centralized_secret_output,
    })
}

/// Executes the second phase of the DKG protocol, part of a three-phase DKG flow.
///
/// This function is invoked by the centralized party to produce:
/// - A public key share and its proof.
/// - Centralized DKG output required for further protocol steps.
/// # Warning
/// The secret (private) key returned from this function should never be sent
/// and should always be kept private.
///
/// # Parameters
/// — `decentralized_first_round_output`:
///    Serialized output of the decentralized party from the first DKG round.
/// — `session_id`: Unique hexadecimal string identifying the session.
///
/// # Returns
/// A tuple containing:
/// - Serialized public key share and proof.
/// - Serialized centralized DKG output.
///
/// # Errors
/// Return an error if decoding or advancing the protocol fails.
/// This is okay since a malicious blockchain can always block a client.
pub fn create_dkg_output_v1(
    protocol_pp: Vec<u8>,
    decentralized_first_round_public_output: SerializedWrappedMPCPublicOutput,
) -> anyhow::Result<CentralizedDKGWasmResult> {
    let protocol_public_parameters: ProtocolPublicParameters = bcs::from_bytes(&protocol_pp)?;
    let decentralized_first_round_public_output =
        bcs::from_bytes(&decentralized_first_round_public_output)?;
    match decentralized_first_round_public_output {
        VersionedDwalletDKGFirstRoundPublicOutput::V1(decentralized_first_round_public_output) => {
            let (output, session_identifier) =
                bcs::from_bytes::<(Vec<u8>, _)>(&decentralized_first_round_public_output)?;
            let [first_part, second_part]: <DWalletDKGFirstParty as Party>::PublicOutput =
                bcs::from_bytes(&output)
                    .context("failed to deserialize decentralized first round DKG output")?;
            let (first_first_part, first_second_part) = first_part.into();
            let (second_first_part, second_second_part) = second_part.into();
            // This is a temporary hack to keep working with the existing 2-round dWallet DKG mechanism.
            // TODO (#1470): Use one network round in the dWallet DKG flow.
            let protocol_pp_with_decentralized_dkg_output = ProtocolPublicParameters::new::<
                { group::secp256k1::SCALAR_LIMBS },
                SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::secp256k1::GroupElement,
            >(
                first_second_part,
                second_second_part,
                first_first_part,
                second_first_part,
                protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .clone(),
            );
            let round_result = DKGCentralizedParty::advance(
                (),
                &(),
                &(
                    protocol_pp_with_decentralized_dkg_output,
                    session_identifier,
                )
                    .into(),
                &mut OsCsRng,
            )
            .context("advance() failed on the DKGCentralizedParty")?;

            // Centralized Public Key Share and Proof.
            let public_key_share_and_proof =
                VersionedPublicKeyShareAndProof::V1(bcs::to_bytes(&round_result.outgoing_message)?);

            let public_key_share_and_proof = bcs::to_bytes(&public_key_share_and_proof)?;
            // TODO(#1470): Use one network round in the dWallet DKG flow.
            // This is a temporary hack to keep working with the existing 2-round dWallet DKG mechanism.
            let centralized_output = match round_result.public_output {
                DKGCentralizedPartyVersionedOutput::<
                    { group::secp256k1::SCALAR_LIMBS },
                    group::secp256k1::GroupElement,
                >::UniversalPublicDKGOutput {
                    output: dkg_output,
                    ..
                } => dkg_output,
                DKGCentralizedPartyVersionedOutput::<
                    { group::secp256k1::SCALAR_LIMBS },
                    group::secp256k1::GroupElement,
                >::TargetedPublicDKGOutput(output) => output,
            };

            // Public Output:
            // centralized_public_key_share + public_key + decentralized_party_public_key_share
            let public_output = bcs::to_bytes(&VersionedCentralizedDKGPublicOutput::V1(
                bcs::to_bytes(&centralized_output)?,
            ))?;
            // Centralized Secret Key Share.
            // Warning:
            // The secret (private)
            // key share returned from this function should never be sent
            // and should always be kept private.
            let centralized_secret_output =
                VersionedDwalletUserSecretShare::V1(bcs::to_bytes(&round_result.private_output)?);
            let centralized_secret_output = bcs::to_bytes(&centralized_secret_output)?;
            Ok(CentralizedDKGWasmResult {
                public_output,
                public_key_share_and_proof,
                centralized_secret_output,
            })
        }
    }
}

pub fn public_key_from_dwallet_output(
    curve: u32,
    dwallet_output: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match curve.try_into()? {
        DWalletCurve::Secp256k1 => {
            public_key_from_dwallet_output_inner::<Secp256K1DKGProtocol>(dwallet_output)
        }
        DWalletCurve::Ristretto => {
            public_key_from_dwallet_output_inner::<RistrettoDKGProtocol>(dwallet_output)
        }
        DWalletCurve::Curve25519 => {
            public_key_from_dwallet_output_inner::<Curve25519DKGProtocol>(dwallet_output)
        }
        DWalletCurve::Secp256r1 => {
            public_key_from_dwallet_output_inner::<Secp256R1DKGProtocol>(dwallet_output)
        }
    }
}

pub fn public_key_from_dwallet_output_inner<P: Protocol>(
    dwallet_output: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let versioned_dkg_public_output: VersionedDwalletDKGSecondRoundPublicOutput =
        bcs::from_bytes(&dwallet_output)?;
    match versioned_dkg_public_output {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(dkg_output) => {
            let output: DKGDecentralizedPartyOutputSecp256k1 = bcs::from_bytes(&dkg_output)?;
            Ok(bcs::to_bytes(&output.public_key)?)
        }
        VersionedDwalletDKGSecondRoundPublicOutput::V2(dkg_output) => {
            let dkg_output: P::DecentralizedPartyDKGOutput = bcs::from_bytes(&dkg_output)?;
            Ok(bcs::to_bytes(&dkg_output.public_key)?) // todo: missing, need for scaly.
        }
    }
}

/// Check whether the centralized party (user)'s DKG output matches the decentralized party (network)'s DKG output.
///
/// Required usage: when accepting an encrypted user share after DKG before we sign on the network's public output.
pub fn centralized_and_decentralized_parties_dkg_output_match_inner(
    centralized_dkg_output: &Vec<u8>,
    decentralized_dkg_output: &Vec<u8>,
) -> anyhow::Result<bool> {
    let versioned_centralized_dkg_output =
        bcs::from_bytes::<VersionedCentralizedDKGPublicOutput>(centralized_dkg_output)?;
    let centralized_dkg_output = match versioned_centralized_dkg_output {
        VersionedCentralizedDKGPublicOutput::V1(output) => bcs::from_bytes::<
            DKGCentralizedPartyOutput<SCALAR_LIMBS, group::secp256k1::GroupElement>,
        >(output.as_slice())?
        .into(),
        VersionedCentralizedDKGPublicOutput::V2(output) => bcs::from_bytes::<
            DKGCentralizedPartyVersionedOutput<SCALAR_LIMBS, group::secp256k1::GroupElement>,
        >(output.as_slice())?,
    };

    let versioned_decentralized_dkg_output =
        bcs::from_bytes::<VersionedDwalletDKGSecondRoundPublicOutput>(decentralized_dkg_output)?;
    let decentralized_dkg_output = match versioned_decentralized_dkg_output {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(output) => {
            bcs::from_bytes::<DKGDecentralizedPartyOutputSecp256k1>(output.as_slice())?.into()
        }
        VersionedDwalletDKGSecondRoundPublicOutput::V2(output) => {
            bcs::from_bytes::<DKGDecentralizedPartyVersionedOutputSecp256k1>(output.as_slice())?
        }
    };

    let does_centralized_and_decentralized_parties_dkg_output_match =
        decentralized_dkg_output == centralized_dkg_output;

    Ok(does_centralized_and_decentralized_parties_dkg_output_match)
}

/// Executes the centralized phase of the Sign protocol,
///  the first part of the protocol.
///
/// The [`advance_centralized_sign_party`] function is
/// called by the client (the centralized party).
pub fn advance_centralized_sign_party(
    protocol_pp: Vec<u8>,
    decentralized_party_dkg_public_output: SerializedWrappedMPCPublicOutput,
    centralized_party_secret_key_share: SerializedWrappedMPCPublicOutput,
    presign: SerializedWrappedMPCPublicOutput,
    message: Vec<u8>,
    hash_type: u32,
    signature_scheme: u32,
) -> anyhow::Result<SignedMessage> {
    let presign = bcs::from_bytes(&presign)?;
    match presign {
        VersionedPresignOutput::V1(presign) => {
            let decentralized_dkg_output =
                match bcs::from_bytes(&decentralized_party_dkg_public_output)? {
                    VersionedDwalletDKGSecondRoundPublicOutput::V1(output) => {
                        bcs::from_bytes::<DKGDecentralizedPartyOutputSecp256k1>(output.as_slice())?
                            .into()
                    }
                    VersionedDwalletDKGSecondRoundPublicOutput::V2(output) => {
                        bcs::from_bytes::<DKGDecentralizedPartyVersionedOutputSecp256k1>(
                            output.as_slice(),
                        )?
                    }
                };
            let centralized_party_secret_key_share: VersionedDwalletUserSecretShare =
                bcs::from_bytes(&centralized_party_secret_key_share)?;
            let VersionedDwalletUserSecretShare::V1(centralized_party_secret_key_share) =
                centralized_party_secret_key_share;
            let centralized_public_output = DKGCentralizedPartyVersionedOutput::<
                { group::secp256k1::SCALAR_LIMBS },
                group::secp256k1::GroupElement,
            >::from(decentralized_dkg_output);
            let presign: <Secp256K1ECDSAProtocol as twopc_mpc::presign::Protocol>::Presign =
                bcs::from_bytes(&presign)?;
            let centralized_party_public_input =
                <Secp256K1ECDSAProtocol as twopc_mpc::sign::Protocol>::SignCentralizedPartyPublicInput::from((
                    message,
                    HashType::try_from(hash_type)?,
                    centralized_public_output.clone().into(),
                    presign,
                    bcs::from_bytes(&protocol_pp)?,
                ));

            let round_result = SignCentralizedPartyV1::advance(
                (),
                &bcs::from_bytes(&centralized_party_secret_key_share)?,
                &centralized_party_public_input,
                &mut OsCsRng,
            )
            .context("advance() failed on the SignCentralizedParty")?;

            let signed_message =
                VersionedUserSignedMessage::V1(bcs::to_bytes(&round_result.outgoing_message)?);
            let signed_message = bcs::to_bytes(&signed_message)?;
            Ok(signed_message)
        }
        VersionedPresignOutput::V2(presign) => {
            let signature_scheme = DWalletSignatureScheme::try_from(signature_scheme)?;
            match signature_scheme {
                DWalletSignatureScheme::ECDSASecp256k1 => {
                    advance_sign_by_protocol::<Secp256K1ECDSAProtocol>(
                        &centralized_party_secret_key_share,
                        &presign,
                        message,
                        hash_type,
                        &decentralized_party_dkg_public_output,
                        &protocol_pp,
                    )
                }
                DWalletSignatureScheme::Taproot => advance_sign_by_protocol::<TaprootProtocol>(
                    &centralized_party_secret_key_share,
                    &presign,
                    message,
                    hash_type,
                    &decentralized_party_dkg_public_output,
                    &protocol_pp,
                ),
                DWalletSignatureScheme::ECDSASecp256r1 => {
                    advance_sign_by_protocol::<Secp256R1DKGProtocol>(
                        &centralized_party_secret_key_share,
                        &presign,
                        message,
                        hash_type,
                        &decentralized_party_dkg_public_output,
                        &protocol_pp,
                    )
                }
                DWalletSignatureScheme::EdDSA => advance_sign_by_protocol::<Curve25519DKGProtocol>(
                    &centralized_party_secret_key_share,
                    &presign,
                    message,
                    hash_type,
                    &decentralized_party_dkg_public_output,
                    &protocol_pp,
                ),
                DWalletSignatureScheme::SchnorrkelSubstrate => {
                    advance_sign_by_protocol::<RistrettoDKGProtocol>(
                        &centralized_party_secret_key_share,
                        &presign,
                        message,
                        hash_type,
                        &decentralized_party_dkg_public_output,
                        &protocol_pp,
                    )
                }
            }
        }
    }
}

fn advance_sign_by_protocol<P: twopc_mpc::sign::Protocol>(
    centralized_party_secret_key_share: &[u8],
    presign: &[u8],
    message: Vec<u8>,
    hash_type: u32,
    decentralized_party_dkg_public_output: &[u8],
    protocol_pp: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let versioned_decentralized_dkg_output: VersionedDwalletDKGSecondRoundPublicOutput =
        bcs::from_bytes(&decentralized_party_dkg_public_output)?;

    let decentralized_dkg_output = match versioned_decentralized_dkg_output {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(output) => {
            let versioned_output: P::DecentralizedPartyDKGOutput =
                bcs::from_bytes::<P::DecentralizedPartyTargetedDKGOutput>(output.as_slice())?
                    .into();
            versioned_output.into()
        }
        VersionedDwalletDKGSecondRoundPublicOutput::V2(output) => {
            bcs::from_bytes::<P::DecentralizedPartyDKGOutput>(output.as_slice())?.into()
        }
    };

    let versioned_centralized_party_secret_key_share: VersionedDwalletUserSecretShare =
        bcs::from_bytes(&centralized_party_secret_key_share)?;
    let VersionedDwalletUserSecretShare::V1(centralized_party_secret_key_share) =
        versioned_centralized_party_secret_key_share;

    let centralized_party_secret_key_share =
        bcs::from_bytes::<P::CentralizedPartySecretKeyShare>(&centralized_party_secret_key_share)?;

    let presign: <P as twopc_mpc::presign::Protocol>::Presign = bcs::from_bytes(&presign)?;
    let centralized_party_public_input =
        <P as twopc_mpc::sign::Protocol>::SignCentralizedPartyPublicInput::from((
            message,
            HashType::try_from(hash_type)?,
            decentralized_dkg_output,
            presign,
            bcs::from_bytes(&protocol_pp)?,
        ));

    let round_result = SignCentralizedParty::<P>::advance(
        (),
        &centralized_party_secret_key_share,
        &centralized_party_public_input,
        &mut OsCsRng,
    );
    match round_result {
        Ok(round_result) => {
            let signed_message =
                VersionedUserSignedMessage::V2(bcs::to_bytes(&round_result.outgoing_message)?);
            let signed_message = bcs::to_bytes(&signed_message)?;
            Ok(signed_message)
        }
        Err(_) => {
            let err_str = format!("advance() failed on the SignCentralizedPartyV2",);
            Err(anyhow!(err_str.clone()).context(err_str))
        }
    }
}

pub(crate) type SignCentralizedParty<P: twopc_mpc::sign::Protocol> =
    <P as twopc_mpc::sign::Protocol>::SignCentralizedParty;

pub fn network_key_version_inner(
    network_dkg_public_output: SerializedWrappedMPCPublicOutput,
) -> anyhow::Result<u32> {
    let network_dkg_public_output: VersionedNetworkDkgOutput =
        bcs::from_bytes(&network_dkg_public_output)?;

    match &network_dkg_public_output {
        VersionedNetworkDkgOutput::V1(_) => Ok(1),
        VersionedNetworkDkgOutput::V2(_) => Ok(2),
    }
}

pub fn dwallet_version_inner(
    dwallet_output: SerializedWrappedMPCPublicOutput,
) -> anyhow::Result<u32> {
    let dwallet_output: VersionedDwalletDKGSecondRoundPublicOutput =
        bcs::from_bytes(&dwallet_output)?;

    match &dwallet_output {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(_) => Ok(1),
        VersionedDwalletDKGSecondRoundPublicOutput::V2(_) => Ok(2),
    }
}

pub fn sample_dwallet_keypair_inner(protocol_pp: Vec<u8>) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let protocol_public_parameters: ProtocolPublicParameters = bcs::from_bytes(&protocol_pp)?;
    let secret_key = twopc_mpc::secp256k1::Scalar::sample(
        &protocol_public_parameters
            .as_ref()
            .scalar_group_public_parameters,
        &mut OsCsRng,
    )?;
    let public_parameters = group::secp256k1::group_element::PublicParameters::default();
    let generator_group_element =
        group::secp256k1::group_element::GroupElement::generator_from_public_parameters(
            &public_parameters,
        )?;

    let expected_public_key = secret_key * generator_group_element;
    let bytes_public_key = bcs::to_bytes(&expected_public_key.value())?;
    Ok((bcs::to_bytes(&secret_key)?, bytes_public_key))
}

pub fn verify_secp_signature_inner(
    public_key: Vec<u8>,
    signature: Vec<u8>,
    message: Vec<u8>,
    protocol_pp: Vec<u8>,
    hash_type: u32,
) -> anyhow::Result<bool> {
    let VersionedSignOutput::V1(signature) = bcs::from_bytes(&signature)?;
    let protocol_public_parameters: ProtocolPublicParameters = bcs::from_bytes(&protocol_pp)?;
    let public_key = twopc_mpc::secp256k1::GroupElement::new(
        bcs::from_bytes(&public_key)?,
        &protocol_public_parameters.group_public_parameters,
    )?;
    Ok(public_key
        .verify(
            &message,
            HashType::try_from(hash_type)?,
            &bcs::from_bytes(&signature)?,
        )
        .is_ok())
}

pub fn create_imported_dwallet_centralized_step_inner_v1(
    protocol_pp: &[u8],
    session_identifier: &[u8],
    secret_key: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    match create_imported_dwallet_centralized_step_inner::<Secp256K1DKGProtocol>(
        protocol_pp,
        session_identifier,
        secret_key,
    ) {
        Ok((public_output, outgoing_message, secret_share)) => {
            let public_output: <Secp256K1DKGProtocol as twopc_mpc::dkg::Protocol>::CentralizedPartyDKGOutput = bcs::from_bytes(&public_output)?;
            let public_targeted_output: <Secp256K1DKGProtocol as twopc_mpc::dkg::Protocol>::CentralizedPartyTargetedDKGOutput = public_output.into();
            Ok((
                bcs::to_bytes(&VersionedDwalletUserSecretShare::V1(secret_share))?,
                bcs::to_bytes(&VersionedCentralizedPartyImportedDWalletPublicOutput::V1(
                    bcs::to_bytes(&public_targeted_output)?,
                ))?,
                bcs::to_bytes(&VersionedImportedDwalletOutgoingMessage::V1(
                    outgoing_message,
                ))?,
            ))
        }
        Err(e) => Err(e.into()),
    }
}

pub fn create_imported_dwallet_centralized_step_inner_v2(
    curve: u32,
    protocol_pp: &[u8],
    session_identifier: &[u8],
    secret_key: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let round_result = match DWalletCurve::try_from(curve)? {
        DWalletCurve::Secp256k1 => create_imported_dwallet_centralized_step_inner::<
            Secp256K1DKGProtocol,
        >(protocol_pp, session_identifier, secret_key),
        DWalletCurve::Ristretto => create_imported_dwallet_centralized_step_inner::<
            RistrettoDKGProtocol,
        >(protocol_pp, session_identifier, secret_key),
        DWalletCurve::Curve25519 => create_imported_dwallet_centralized_step_inner::<
            Curve25519DKGProtocol,
        >(protocol_pp, session_identifier, secret_key),
        DWalletCurve::Secp256r1 => create_imported_dwallet_centralized_step_inner::<
            Secp256R1DKGProtocol,
        >(protocol_pp, session_identifier, secret_key),
    };

    match round_result {
        Ok((public_output, outgoing_message, secret_share)) => Ok((
            bcs::to_bytes(&VersionedDwalletUserSecretShare::V1(secret_share))?,
            bcs::to_bytes(&VersionedCentralizedPartyImportedDWalletPublicOutput::V2(
                public_output,
            ))?,
            bcs::to_bytes(&VersionedImportedDwalletOutgoingMessage::V1(
                outgoing_message,
            ))?,
        )),
        Err(e) => Err(e),
    }
}

fn create_imported_dwallet_centralized_step_inner<P: twopc_mpc::dkg::Protocol>(
    protocol_pp: &[u8],
    session_identifier: &[u8],
    secret_key: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let protocol_public_parameters: P::ProtocolPublicParameters = bcs::from_bytes(protocol_pp)?;
    let secret_key: P::SecretKey = bcs::from_bytes(secret_key)?;
    let session_identifier = CommitmentSizedNumber::from_le_slice(session_identifier);

    let centralized_party_public_input =
        (protocol_public_parameters.clone(), session_identifier).into();

    match P::TrustedDealerDKGCentralizedPartyRound::advance(
        (),
        &secret_key,
        &centralized_party_public_input,
        &mut OsCsRng,
    ) {
        Ok(round_result) => Ok((
            bcs::to_bytes(&round_result.public_output)?,
            bcs::to_bytes(&round_result.outgoing_message)?,
            bcs::to_bytes(&round_result.private_output)?,
        )),
        Err(e) => Err(anyhow!("{}", e.into())),
    }
}

fn protocol_public_parameters(
    network_dkg_public_output: SerializedWrappedMPCPublicOutput,
) -> anyhow::Result<ProtocolPublicParameters> {
    let network_dkg_public_output: VersionedNetworkDkgOutput =
        bcs::from_bytes(&network_dkg_public_output)?;

    match &network_dkg_public_output {
        // TODO (#1473): Add support for V2 network keys.
        VersionedNetworkDkgOutput::V1(network_dkg_public_output) => {
            let network_dkg_public_output: <Secp256k1Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(network_dkg_public_output)?;
            let encryption_scheme_public_parameters = network_dkg_public_output
                .default_encryption_scheme_public_parameters::<secp256k1::GroupElement>(
            )?;

            let setup_parameters = class_groups::setup::SetupParameters::<
                SECP256K1_SCALAR_LIMBS,
                SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::secp256k1::scalar::PublicParameters,
            >::derive_from_plaintext_parameters::<group::secp256k1::Scalar>(
                group::secp256k1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

            let neutral_group_value =
                group::secp256k1::GroupElement::neutral_from_public_parameters(
                    &group::secp256k1::group_element::PublicParameters::default(),
                )
                .map_err(twopc_mpc::Error::from)?
                .value();
            let neutral_ciphertext_value =
                ::class_groups::CiphertextSpaceGroupElement::neutral_from_public_parameters(
                    &setup_parameters.ciphertext_space_public_parameters(),
                )?
                .value();

            let protocol_public_parameters = ProtocolPublicParameters::new::<
                { secp256k1::SCALAR_LIMBS },
                { SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >(
                neutral_group_value,
                neutral_group_value,
                neutral_ciphertext_value,
                neutral_ciphertext_value,
                encryption_scheme_public_parameters.clone(),
            );
            Ok(protocol_public_parameters)
        }
        VersionedNetworkDkgOutput::V2(network_dkg_public_output) => {
            let network_dkg_public_output: <dkg::Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(network_dkg_public_output)?;
            Ok(network_dkg_public_output.secp256k1_protocol_public_parameters()?)
        }
    }
}

fn protocol_public_parameters_from_reconfiguration_output(
    reconfiguration_dkg_public_output: SerializedWrappedMPCPublicOutput,
    versioned_network_dkg_output: SerializedWrappedMPCPublicOutput,
) -> anyhow::Result<ProtocolPublicParameters> {
    let reconfiguration_dkg_public_output: VersionedDecryptionKeyReconfigurationOutput =
        bcs::from_bytes(&reconfiguration_dkg_public_output)?;

    match &reconfiguration_dkg_public_output {
        // TODO (#1487): Remove temporary support for V1 reconfiguration keys.
        VersionedDecryptionKeyReconfigurationOutput::V1(public_output_bytes) => {
            protocol_public_parameters(versioned_network_dkg_output)
        }
        VersionedDecryptionKeyReconfigurationOutput::V2(public_output_bytes) => {
            let public_output: <twopc_mpc::decentralized_party::reconfiguration::Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(public_output_bytes)?;
            // TODO (#1530): Add support for all the curves the network supports.
            let secp256k1_protocol_public_parameters =
                twopc_mpc::decentralized_party::reconfiguration::PublicOutput::secp256k1_protocol_public_parameters(
                    &public_output,
                )?;

            Ok(secp256k1_protocol_public_parameters)
        }
    }
}

/// Derives class groups keypair from a given seed, by given curve.
///
/// The class groups public encryption key being used to encrypt a Secp256k1 keypair will be
/// different from the encryption key used to encrypt a Ristretto keypair.
/// The plaintext space/fundamental group will correspond to the order
/// of the respective elliptic curve.
/// The secret decryption key may be the same in terms of correctness,
/// but to simplify security analysis,
/// and the implementation current version maintains distinct key-pairs.
/// # Warning
/// The secret (private) key returned from this function should never be sent
/// and should always be kept private.
pub fn generate_secp256k1_cg_keypair_from_seed_internal(
    seed: [u8; 32],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let setup_parameters = get_setup_parameters_secp256k1();
    let (encryption_scheme_public_parameters, decryption_key) =
        Secp256k1DecryptionKey::generate(setup_parameters, &mut rng)?;
    let decryption_key = bcs::to_bytes(&decryption_key.decryption_key)?;
    let encryption_key = bcs::to_bytes(&encryption_scheme_public_parameters.encryption_key)?;
    Ok((encryption_key, decryption_key))
}

/// Encrypts the given secret key share with the given encryption key.
/// Returns a serialized tuple containing the `proof of encryption`,
/// and an encrypted `secret key share`.
pub fn encrypt_secret_key_share_and_prove_v1(
    secret_key_share: SerializedWrappedMPCPublicOutput,
    encryption_key: Vec<u8>,
    protocol_pp: SerializedWrappedMPCPublicOutput,
) -> anyhow::Result<Vec<u8>> {
    encrypt_secret_key_share_and_prove_v2(
        DWalletCurve::Secp256k1 as u32,
        secret_key_share,
        encryption_key,
        protocol_pp,
    )
}

pub fn encrypt_secret_key_share_and_prove_v2(
    curve: u32,
    secret_key_share: SerializedWrappedMPCPublicOutput,
    encryption_key: Vec<u8>,
    protocol_pp: SerializedWrappedMPCPublicOutput,
) -> anyhow::Result<Vec<u8>> {
    match DWalletCurve::try_from(curve)? {
        DWalletCurve::Secp256k1 => {
            encrypt_secret_key_share_and_prove_inner::<Secp256K1DKGProtocol>(
                secret_key_share,
                &encryption_key,
                protocol_pp,
            )
        }
        DWalletCurve::Ristretto => {
            encrypt_secret_key_share_and_prove_inner::<RistrettoDKGProtocol>(
                secret_key_share,
                &encryption_key,
                protocol_pp,
            )
        }
        DWalletCurve::Curve25519 => {
            encrypt_secret_key_share_and_prove_inner::<Curve25519DKGProtocol>(
                secret_key_share,
                &encryption_key,
                protocol_pp,
            )
        }
        DWalletCurve::Secp256r1 => {
            encrypt_secret_key_share_and_prove_inner::<Secp256R1DKGProtocol>(
                secret_key_share,
                &encryption_key,
                protocol_pp,
            )
        }
    }
}

fn encrypt_secret_key_share_and_prove_inner<P: twopc_mpc::dkg::Protocol>(
    secret_key_share: SerializedWrappedMPCPublicOutput,
    encryption_key: &[u8],
    protocol_public_params: SerializedWrappedMPCPublicOutput,
) -> anyhow::Result<Vec<u8>> {
    let secret_key_share: VersionedDwalletUserSecretShare = bcs::from_bytes(&secret_key_share)?;
    match secret_key_share {
        VersionedDwalletUserSecretShare::V1(secret_key_share) => {
            let protocol_public_params: P::ProtocolPublicParameters =
                bcs::from_bytes(&protocol_public_params)?;
            let encryption_key: P::EncryptionKey = bcs::from_bytes(&encryption_key)?;
            let secret_key_share: P::CentralizedPartySecretKeyShare =
                bcs::from_bytes(&secret_key_share)?;
            let result = P::encrypt_and_prove_centralized_party_share(
                &protocol_public_params,
                encryption_key,
                secret_key_share,
                &mut OsCsRng,
            )?;
            Ok(bcs::to_bytes(&VersionedEncryptedUserShare::V1(
                bcs::to_bytes(&result)?,
            ))?)
        }
    }
}

/// Verifies the given secret share matches the given dWallets`
/// DKG output centralized_party_public_key_share.
pub fn verify_secret_share_v1(
    versioned_secret_share: SerializedWrappedMPCPublicOutput,
    versioned_decentralized_dkg_output: SerializedWrappedMPCPublicOutput,
    protocol_pp: &[u8],
) -> anyhow::Result<bool> {
    verify_secret_share_v2(
        DWalletCurve::Secp256k1 as u32,
        versioned_secret_share,
        versioned_decentralized_dkg_output,
        protocol_pp,
    )
}

pub fn verify_secret_share_v2(
    curve: u32,
    versioned_secret_share: SerializedWrappedMPCPublicOutput,
    versioned_decentralized_dkg_output: SerializedWrappedMPCPublicOutput,
    protocol_pp: &[u8],
) -> anyhow::Result<bool> {
    match DWalletCurve::try_from(curve)? {
        DWalletCurve::Secp256k1 => verify_secret_share_inner::<Secp256K1DKGProtocol>(
            versioned_secret_share,
            versioned_decentralized_dkg_output,
            protocol_pp,
        ),
        DWalletCurve::Ristretto => verify_secret_share_inner::<RistrettoDKGProtocol>(
            versioned_secret_share,
            versioned_decentralized_dkg_output,
            protocol_pp,
        ),
        DWalletCurve::Curve25519 => verify_secret_share_inner::<Curve25519DKGProtocol>(
            versioned_secret_share,
            versioned_decentralized_dkg_output,
            protocol_pp,
        ),
        DWalletCurve::Secp256r1 => verify_secret_share_inner::<Secp256R1DKGProtocol>(
            versioned_secret_share,
            versioned_decentralized_dkg_output,
            protocol_pp,
        ),
    }
}

fn verify_secret_share_inner<P: twopc_mpc::dkg::Protocol>(
    versioned_secret_share: SerializedWrappedMPCPublicOutput,
    versioned_decentralized_dkg_output: SerializedWrappedMPCPublicOutput,
    protocol_pp: &[u8],
) -> anyhow::Result<bool> {
    let versioned_decentralized_dkg_output: VersionedDwalletDKGSecondRoundPublicOutput =
        bcs::from_bytes(&versioned_decentralized_dkg_output)?;
    let versioned_secret_share: VersionedDwalletUserSecretShare =
        bcs::from_bytes(&versioned_secret_share)?;

    let (decentralized_dkg_output, secret_share) = match (
        versioned_decentralized_dkg_output,
        versioned_secret_share,
    ) {
        (
            VersionedDwalletDKGSecondRoundPublicOutput::V1(decentralized_dkg_output),
            VersionedDwalletUserSecretShare::V1(secret_share),
        ) => {
            let decentralized_dkg_output_targeted: <Secp256K1DKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyTargetedDKGOutput = bcs::from_bytes(&decentralized_dkg_output)?;
            let decentralized_dkg_output: <Secp256K1DKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput = decentralized_dkg_output_targeted.into();
            let decentralized_dkg_output = bcs::to_bytes(&decentralized_dkg_output)?;
            (decentralized_dkg_output, secret_share)
        }
        (
            VersionedDwalletDKGSecondRoundPublicOutput::V2(decentralized_dkg_output),
            VersionedDwalletUserSecretShare::V1(secret_share),
        ) => (decentralized_dkg_output, secret_share),
    };

    let protocol_public_params: P::ProtocolPublicParameters = bcs::from_bytes(&protocol_pp)?;
    let decentralized_dkg_output: P::DecentralizedPartyDKGOutput =
        bcs::from_bytes(&decentralized_dkg_output)?;
    let secret_share: P::CentralizedPartySecretKeyShare = bcs::from_bytes(&secret_share)?;

    Ok(P::verify_centralized_party_public_key_share(
        &protocol_public_params,
        decentralized_dkg_output,
        secret_share,
    )
    .is_ok())
}

/// Decrypts the given encrypted user share using the given decryption key.
pub fn decrypt_user_share_v1(
    decryption_key: Vec<u8>,
    _encryption_key: Vec<u8>,
    dwallet_dkg_output: Vec<u8>,
    encrypted_user_share_and_proof: Vec<u8>,
    protocol_pp: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    decrypt_user_share_v2(
        DWalletCurve::Secp256k1 as u32,
        decryption_key,
        dwallet_dkg_output,
        encrypted_user_share_and_proof,
        protocol_pp,
    )
}

pub fn decrypt_user_share_v2(
    curve: u32,
    decryption_key: Vec<u8>,
    dwallet_dkg_output: Vec<u8>,
    encrypted_user_share_and_proof: Vec<u8>,
    protocol_pp: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    match DWalletCurve::try_from(curve)? {
        DWalletCurve::Secp256k1 => decrypt_user_share_inner::<Secp256K1DKGProtocol>(
            &decryption_key,
            &dwallet_dkg_output,
            &encrypted_user_share_and_proof,
            &protocol_pp,
        ),
        DWalletCurve::Ristretto => decrypt_user_share_inner::<RistrettoDKGProtocol>(
            &decryption_key,
            &dwallet_dkg_output,
            &encrypted_user_share_and_proof,
            &protocol_pp,
        ),
        DWalletCurve::Curve25519 => decrypt_user_share_inner::<Curve25519DKGProtocol>(
            &decryption_key,
            &dwallet_dkg_output,
            &encrypted_user_share_and_proof,
            &protocol_pp,
        ),
        DWalletCurve::Secp256r1 => decrypt_user_share_inner::<Secp256R1DKGProtocol>(
            &decryption_key,
            &dwallet_dkg_output,
            &encrypted_user_share_and_proof,
            &protocol_pp,
        ),
    }
}

fn decrypt_user_share_inner<P: twopc_mpc::dkg::Protocol>(
    decryption_key: &[u8],
    dwallet_dkg_output: &[u8],
    encrypted_user_share_and_proof: &[u8],
    protocol_pp: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let protocol_public_params: P::ProtocolPublicParameters = bcs::from_bytes(&protocol_pp)?;
    let VersionedEncryptedUserShare::V1(encrypted_user_share_and_proof) =
        bcs::from_bytes(&encrypted_user_share_and_proof)?;
    let dwallet_dkg_output = match bcs::from_bytes(&dwallet_dkg_output)? {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(output) => {
            let versioned_output: P::DecentralizedPartyDKGOutput =
                bcs::from_bytes::<P::DecentralizedPartyTargetedDKGOutput>(&output)?.into();
            versioned_output
        }
        VersionedDwalletDKGSecondRoundPublicOutput::V2(output) => {
            bcs::from_bytes::<P::DecentralizedPartyDKGOutput>(&output)?
        }
    };

    let centralized_party_secret_share =
        P::verify_and_decrypt_encryption_of_centralized_party_share_proof(
            &protocol_public_params,
            dwallet_dkg_output,
            bcs::from_bytes(&encrypted_user_share_and_proof)?,
            bcs::from_bytes(&decryption_key)?,
            &mut OsCsRng,
        )?;

    let secret_share_bytes =
        VersionedDwalletUserSecretShare::V1(bcs::to_bytes(&centralized_party_secret_share)?);
    let secret_share_bytes = bcs::to_bytes(&secret_share_bytes)?;
    Ok(secret_share_bytes)
}
