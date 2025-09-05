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
    DWalletCurve, SerializedWrappedMPCPublicOutput, VersionedCentralizedDKGPublicOutput,
    VersionedDwalletDKGFirstRoundPublicOutput, VersionedDwalletDKGSecondRoundPublicOutput,
    VersionedDwalletUserSecretShare, VersionedEncryptedUserShare,
    VersionedImportedDWalletPublicOutput, VersionedImportedDwalletOutgoingMessage,
    VersionedNetworkDkgOutput, VersionedPresignOutput, VersionedPublicKeyShareAndProof,
    VersionedSignOutput, VersionedUserSignedMessage,
};
use group::{CyclicGroupElement, GroupElement, HashType, OsCsRng, Samplable, secp256k1};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};
use mpc::Party;
use mpc::two_party::Round;
use rand_core::SeedableRng;
use twopc_mpc::secp256k1::SCALAR_LIMBS;

use class_groups::encryption_key::public_parameters::Instantiate;
use commitment::CommitmentSizedNumber;
use twopc_mpc::class_groups::{
    DKGCentralizedPartyOutput, DKGCentralizedPartyVersionedOutput, DKGDecentralizedPartyOutput,
    DKGDecentralizedPartyVersionedOutput,
};
use twopc_mpc::dkg::Protocol;
use twopc_mpc::ecdsa::VerifyingKey;
use twopc_mpc::ecdsa::sign::verify_signature;
use twopc_mpc::secp256k1::class_groups::{
    FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, ProtocolPublicParameters,
};

type AsyncProtocol = twopc_mpc::secp256k1::class_groups::ECDSAProtocol;
type DKGCentralizedParty = <AsyncProtocol as twopc_mpc::dkg::Protocol>::DKGCentralizedPartyRound;
pub type SignCentralizedParty = <AsyncProtocol as twopc_mpc::sign::Protocol>::SignCentralizedParty;

pub type DKGDecentralizedOutput =
    <AsyncProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput;

type SignedMessage = Vec<u8>;

type Secp256k1EncryptionKey = EncryptionKey<
    SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::GroupElement,
>;

type ImportSecretKeyFirstStep =
    <AsyncProtocol as twopc_mpc::dkg::Protocol>::TrustedDealerDKGCentralizedPartyRound;

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
pub fn create_dkg_output_v2(
    protocol_pp: Vec<u8>,
    session_id: Vec<u8>,
) -> anyhow::Result<CentralizedDKGWasmResult> {
    let protocol_public_parameters: ProtocolPublicParameters = bcs::from_bytes(&protocol_pp)?;
    let session_identifier = CommitmentSizedNumber::from_le_slice(&session_id);
    let round_result = DKGCentralizedParty::advance(
        (),
        &(),
        &(protocol_public_parameters, session_identifier).into(),
        &mut OsCsRng,
    )
    .context("advance() failed on the DKGCentralizedParty")?;

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

pub fn public_key_from_dwallet_output_inner(dwallet_output: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let dkg_output: VersionedDwalletDKGSecondRoundPublicOutput = bcs::from_bytes(&dwallet_output)?;
    match dkg_output {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(dkg_output) => {
            let output: DKGDecentralizedPartyOutputSecp256k1 = bcs::from_bytes(&dkg_output)?;
            Ok(bcs::to_bytes(&output.public_key)?)
        }
        VersionedDwalletDKGSecondRoundPublicOutput::V2(dkg_output) => {
            let dkg_output: DKGDecentralizedOutput = bcs::from_bytes(&dkg_output)?;
            let public_key = match dkg_output {
                DKGDecentralizedPartyVersionedOutput::<
                    { group::secp256k1::SCALAR_LIMBS },
                    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    group::secp256k1::GroupElement,
                >::UniversalPublicDKGOutput {
                    output: dkg_output,
                    ..
                } => dkg_output.public_key,
                DKGDecentralizedPartyVersionedOutput::<
                    { group::secp256k1::SCALAR_LIMBS },
                    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    group::secp256k1::GroupElement,
                >::TargetedPublicDKGOutput(output) => output.public_key,
            };
            Ok(bcs::to_bytes(&public_key)?)
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
) -> anyhow::Result<SignedMessage> {
    let decentralized_dkg_output = match bcs::from_bytes(&decentralized_party_dkg_public_output)? {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(output) => {
            bcs::from_bytes::<DKGDecentralizedPartyOutputSecp256k1>(output.as_slice())?.into()
        }
        VersionedDwalletDKGSecondRoundPublicOutput::V2(output) => {
            bcs::from_bytes::<DKGDecentralizedPartyVersionedOutputSecp256k1>(output.as_slice())?
        }
    };
    let presign = bcs::from_bytes(&presign)?;
    let VersionedPresignOutput::V1(presign) = presign;
    let centralized_party_secret_key_share: VersionedDwalletUserSecretShare =
        bcs::from_bytes(&centralized_party_secret_key_share)?;
    let VersionedDwalletUserSecretShare::V1(centralized_party_secret_key_share) =
        centralized_party_secret_key_share;
    let centralized_public_output = match decentralized_dkg_output {
        DKGDecentralizedPartyVersionedOutput::<
            { group::secp256k1::SCALAR_LIMBS },
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::secp256k1::GroupElement,
        >::UniversalPublicDKGOutput {
            output: dkg_output,
            ..
        } => DKGCentralizedPartyOutput::<
            { group::secp256k1::SCALAR_LIMBS },
            group::secp256k1::GroupElement,
        >::from(dkg_output),
        DKGDecentralizedPartyVersionedOutput::<
            { group::secp256k1::SCALAR_LIMBS },
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::secp256k1::GroupElement,
        >::TargetedPublicDKGOutput(output) => DKGCentralizedPartyOutput::<
            { group::secp256k1::SCALAR_LIMBS },
            group::secp256k1::GroupElement,
        >::from(output),
    };
    let presign: <AsyncProtocol as twopc_mpc::presign::Protocol>::Presign =
        bcs::from_bytes(&presign)?;
    let centralized_party_public_input =
        <AsyncProtocol as twopc_mpc::sign::Protocol>::SignCentralizedPartyPublicInput::from((
            message,
            HashType::try_from(hash_type)?,
            centralized_public_output.clone().into(),
            presign,
            bcs::from_bytes(&protocol_pp)?,
        ));

    let round_result = SignCentralizedParty::advance(
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

pub fn create_imported_dwallet_centralized_step_inner(
    protocol_pp: Vec<u8>,
    session_identifier: Vec<u8>,
    secret_key: Vec<u8>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let protocol_public_parameters: ProtocolPublicParameters = bcs::from_bytes(&protocol_pp)?;
    let secret_key = bcs::from_bytes(&secret_key)?;
    let session_identifier = CommitmentSizedNumber::from_le_slice(&session_identifier);

    let centralized_party_public_input =
        (protocol_public_parameters.clone(), session_identifier).into();

    match ImportSecretKeyFirstStep::advance(
        (),
        &secret_key,
        &centralized_party_public_input,
        &mut OsCsRng,
    ) {
        Ok(round_result) => {
            let public_output = round_result.public_output;
            let outgoing_message = round_result.outgoing_message;
            let secret_share = round_result.private_output;
            Ok((
                bcs::to_bytes(&VersionedDwalletUserSecretShare::V1(bcs::to_bytes(
                    &secret_share,
                )?))?,
                bcs::to_bytes(&VersionedImportedDWalletPublicOutput::V1(bcs::to_bytes(
                    &public_output,
                )?))?,
                bcs::to_bytes(&VersionedImportedDwalletOutgoingMessage::V1(bcs::to_bytes(
                    &outgoing_message,
                )?))?,
            ))
        }
        Err(e) => Err(e.into()),
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
    }
}

/// Derives a Secp256k1 class groups keypair from a given seed.
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
pub fn encrypt_secret_key_share_and_prove(
    secret_key_share: SerializedWrappedMPCPublicOutput,
    encryption_key: Vec<u8>,
    protocol_pp: SerializedWrappedMPCPublicOutput,
) -> anyhow::Result<Vec<u8>> {
    let protocol_public_params: ProtocolPublicParameters = bcs::from_bytes(&protocol_pp)?;
    let secret_key_share: VersionedDwalletUserSecretShare = bcs::from_bytes(&secret_key_share)?;
    match secret_key_share {
        VersionedDwalletUserSecretShare::V1(secret_key_share) => {
            let encryption_key = bcs::from_bytes(&encryption_key)?;
            let secret_key_share = bcs::from_bytes(&secret_key_share)?;
            let result = <AsyncProtocol as twopc_mpc::dkg::Protocol>::encrypt_and_prove_centralized_party_share(&protocol_public_params, encryption_key, secret_key_share, &mut OsCsRng)?;
            Ok(bcs::to_bytes(&VersionedEncryptedUserShare::V1(
                bcs::to_bytes(&result)?,
            ))?)
        }
    }
}

/// Verifies the given secret share matches the given dWallets`
/// DKG output centralized_party_public_key_share.
pub fn verify_secret_share(
    secret_share: SerializedWrappedMPCPublicOutput,
    dkg_output: SerializedWrappedMPCPublicOutput,
    protocol_pp: Vec<u8>,
) -> anyhow::Result<bool> {
    let protocol_public_params: ProtocolPublicParameters = bcs::from_bytes(&protocol_pp)?;
    let dkg_output = bcs::from_bytes(&dkg_output)?;
    let decentralized_dkg_output = match dkg_output {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(output) => {
            bcs::from_bytes::<DKGDecentralizedPartyOutputSecp256k1>(output.as_slice())?.into()
        }
        VersionedDwalletDKGSecondRoundPublicOutput::V2(output) => {
            bcs::from_bytes::<DKGDecentralizedPartyVersionedOutputSecp256k1>(output.as_slice())?
        }
    };

    let secret_share: VersionedDwalletUserSecretShare = bcs::from_bytes(&secret_share)?;
    Ok(
        <twopc_mpc::secp256k1::class_groups::ECDSAProtocol as twopc_mpc::dkg::Protocol>::verify_centralized_party_secret_key_share(
            &protocol_public_params,
            decentralized_dkg_output,
            match secret_share {
                VersionedDwalletUserSecretShare::V1(secret_share) => bcs::from_bytes(&secret_share)?
            },
        )
            .is_ok())
}

/// Decrypts the given encrypted user share using the given decryption key.
pub fn decrypt_user_share_inner(
    decryption_key: Vec<u8>,
    encryption_key: Vec<u8>,
    dwallet_dkg_output: Vec<u8>,
    encrypted_user_share_and_proof: Vec<u8>,
    protocol_pp: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    let protocol_public_params: ProtocolPublicParameters = bcs::from_bytes(&protocol_pp)?;
    let VersionedEncryptedUserShare::V1(encrypted_user_share_and_proof) =
        bcs::from_bytes(&encrypted_user_share_and_proof)?;
    let dwallet_dkg_output = match bcs::from_bytes(&dwallet_dkg_output)? {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(output) => {
            bcs::from_bytes::<DKGDecentralizedPartyOutputSecp256k1>(output.as_slice())?.into()
        }
        VersionedDwalletDKGSecondRoundPublicOutput::V2(output) => {
            bcs::from_bytes::<DKGDecentralizedPartyVersionedOutputSecp256k1>(output.as_slice())?
        }
    };

    let (_, encryption_of_discrete_log): <AsyncProtocol as twopc_mpc::dkg::Protocol>::EncryptedSecretKeyShareMessage = bcs::from_bytes(&encrypted_user_share_and_proof)?;
    <twopc_mpc::secp256k1::class_groups::ECDSAProtocol as Protocol>::verify_encryption_of_centralized_party_share_proof(
        &protocol_public_params,
        dwallet_dkg_output,
        bcs::from_bytes(&encryption_key)?,
        bcs::from_bytes(&encrypted_user_share_and_proof)?,
        &mut OsCsRng,
    )
        .map_err(Into::<anyhow::Error>::into)?;
    let decryption_key = bcs::from_bytes(&decryption_key)?;
    let public_parameters = homomorphic_encryption::PublicParameters::<
        SCALAR_LIMBS,
        crate::Secp256k1EncryptionKey,
    >::new_from_secret_key(
        protocol_public_params
            .encryption_scheme_public_parameters
            .setup_parameters
            .clone(),
        decryption_key,
    )?;
    let ciphertext = CiphertextSpaceGroupElement::new(
        encryption_of_discrete_log,
        public_parameters.ciphertext_space_public_parameters(),
    )?;

    let decryption_key: DecryptionKey<
        SCALAR_LIMBS,
        SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        secp256k1::GroupElement,
    > = DecryptionKey::new(decryption_key, &public_parameters)?;
    let Some(plaintext): Option<<Secp256k1EncryptionKey as AdditivelyHomomorphicEncryptionKey<SCALAR_LIMBS>>::PlaintextSpaceGroupElement> = decryption_key
        .decrypt(&ciphertext, &public_parameters).into() else {
        return Err(anyhow!("Decryption failed"));
    };
    let secret_share_bytes =
        VersionedDwalletUserSecretShare::V1(bcs::to_bytes(&plaintext.value())?);
    let secret_share_bytes = bcs::to_bytes(&secret_share_bytes)?;
    Ok(secret_share_bytes)
}
