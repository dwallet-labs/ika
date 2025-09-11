// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the Sign protocol from the 2PC-MPC library.
//!
//! It integrates the Sign party (representing a round in the protocol).

use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::network_dkg::DwalletMPCNetworkKeys;
use dwallet_mpc_types::dwallet_mpc::{
    DKGDecentralizedPartyOutputSecp256k1, DKGDecentralizedPartyVersionedOutputSecp256k1,
    SerializedWrappedMPCPublicOutput, VersionedDwalletDKGSecondRoundPublicOutput,
    VersionedPresignOutput, VersionedUserSignedMessage,
};
use group::{HashType, OsCsRng, PartyID};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{Secp256K1AsyncECDSAProtocol, SessionIdentifier};
use mpc::{Party, Weight, WeightedThresholdAccessStructure};
use rand_core::SeedableRng;
use std::collections::HashSet;
use std::sync::Arc;
use sui_types::base_types::ObjectID;
use twopc_mpc::dkg::Protocol;
use twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters;
use twopc_mpc::{secp256k1, sign};

pub(crate) type SignParty =
    <Secp256K1AsyncECDSAProtocol as twopc_mpc::sign::Protocol>::SignDecentralizedParty;
pub(crate) type SignPublicInput =
    <Secp256K1AsyncECDSAProtocol as twopc_mpc::sign::Protocol>::SignDecentralizedPartyPublicInput;

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

pub(crate) fn sign_session_public_input(
    dwallet_network_encryption_key_id: &ObjectID,
    session_identifier: SessionIdentifier,
    dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    hash_scheme: HashType,
    access_structure: &WeightedThresholdAccessStructure,
    network_keys: &DwalletMPCNetworkKeys,
    protocol_public_parameters: ProtocolPublicParameters,
) -> DwalletMPCResult<<SignParty as Party>::PublicInput> {
    let decryption_pp = network_keys.get_decryption_key_share_public_parameters(
        // The `StartSignRoundEvent` is assign with a Secp256k1 dwallet.
        // Todo (#473): Support generic network key scheme
        dwallet_network_encryption_key_id,
    )?;

    let expected_decrypters = generate_expected_decrypters(access_structure, session_identifier)?;

    <SignParty as SignPartyPublicInputGenerator>::generate_public_input(
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
pub(crate) trait SignPartyPublicInputGenerator: Party {
    fn generate_public_input(
        protocol_public_parameters: ProtocolPublicParameters,
        dkg_output: &SerializedWrappedMPCPublicOutput,
        message: Vec<u8>,
        presign: &SerializedWrappedMPCPublicOutput,
        centralized_signed_message: &Vec<u8>,
        decryption_key_share_public_parameters: <Secp256K1AsyncECDSAProtocol as twopc_mpc::sign::Protocol>::DecryptionKeySharePublicParameters,
        expected_decrypters: HashSet<PartyID>,
        hash_scheme: HashType,
    ) -> DwalletMPCResult<<SignParty as Party>::PublicInput>;
}

impl SignPartyPublicInputGenerator for SignParty {
    fn generate_public_input(
        protocol_public_parameters: ProtocolPublicParameters,
        dkg_output: &SerializedWrappedMPCPublicOutput,
        message: Vec<u8>,
        presign: &SerializedWrappedMPCPublicOutput,
        centralized_signed_message: &SerializedWrappedMPCPublicOutput,
        decryption_key_share_public_parameters: <Secp256K1AsyncECDSAProtocol as twopc_mpc::sign::Protocol>::DecryptionKeySharePublicParameters,
        expected_decrypters: HashSet<PartyID>,
        hash_scheme: HashType,
    ) -> DwalletMPCResult<<SignParty as Party>::PublicInput> {
        let dkg_output = bcs::from_bytes(dkg_output)?;
        let presign = bcs::from_bytes(presign)?;
        let centralized_signed_message = bcs::from_bytes(centralized_signed_message)?;
        let decentralized_dkg_output = match dkg_output {
            VersionedDwalletDKGSecondRoundPublicOutput::V1(output) => {
                bcs::from_bytes::<DKGDecentralizedPartyOutputSecp256k1>(output.as_slice())?.into()
            }
            VersionedDwalletDKGSecondRoundPublicOutput::V2(output) => {
                bcs::from_bytes::<DKGDecentralizedPartyVersionedOutputSecp256k1>(output.as_slice())?
            }
        };

        let VersionedPresignOutput::V1(presign) = presign;
        let VersionedUserSignedMessage::V1(centralized_signed_message) = centralized_signed_message;

        let public_input = SignPublicInput::from((
            expected_decrypters,
            protocol_public_parameters,
            message,
            HashType::try_from(hash_scheme as u32)
                .map_err(|_| DwalletMPCError::InvalidHashScheme)?,
            decentralized_dkg_output,
            bcs::from_bytes::<
                <Secp256K1AsyncECDSAProtocol as twopc_mpc::presign::Protocol>::Presign,
            >(&presign)?,
            bcs::from_bytes::<
                <Secp256K1AsyncECDSAProtocol as twopc_mpc::sign::Protocol>::SignMessage,
            >(&centralized_signed_message)?,
            decryption_key_share_public_parameters,
        ));

        Ok(public_input)
    }
}

/// Verifies that a single partial signature — i.e., a message that has only been signed by the
/// client side in the 2PC-MPC protocol — is valid regarding the given dWallet DKG output.
/// Returns Ok if the message is valid, Err otherwise.
pub(crate) fn verify_partial_signature(
    message: &[u8],
    hash_type: &HashType,
    dwallet_decentralized_output: &SerializedWrappedMPCPublicOutput,
    presign: &SerializedWrappedMPCPublicOutput,
    partially_signed_message: &SerializedWrappedMPCPublicOutput,
    protocol_public_parameters: &ProtocolPublicParameters,
) -> DwalletMPCResult<()> {
    let dkg_output: VersionedDwalletDKGSecondRoundPublicOutput =
        bcs::from_bytes(dwallet_decentralized_output)?;
    let decentralized_dkg_output = match dkg_output {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(output) => {
            bcs::from_bytes::<DKGDecentralizedPartyOutputSecp256k1>(output.as_slice())?.into()
        }
        VersionedDwalletDKGSecondRoundPublicOutput::V2(output) => {
            bcs::from_bytes::<DKGDecentralizedPartyVersionedOutputSecp256k1>(output.as_slice())?
        }
    };

    let presign: VersionedPresignOutput = bcs::from_bytes(presign)?;
    let partially_signed_message: VersionedUserSignedMessage =
        bcs::from_bytes(partially_signed_message)?;
    let VersionedPresignOutput::V1(presign) = presign;
    let VersionedUserSignedMessage::V1(partially_signed_message) = partially_signed_message;
    let presign: <Secp256K1AsyncECDSAProtocol as twopc_mpc::presign::Protocol>::Presign =
        bcs::from_bytes(&presign)?;
    let partial: <Secp256K1AsyncECDSAProtocol as twopc_mpc::sign::Protocol>::SignMessage =
        bcs::from_bytes(&partially_signed_message)?;

    <Secp256K1AsyncECDSAProtocol as sign::Protocol>::verify_centralized_party_partial_signature(
        message,
        hash_type.clone(),
        decentralized_dkg_output,
        presign,
        partial,
        protocol_public_parameters,
        &mut OsCsRng,
    )
    .map_err(DwalletMPCError::from)
}
