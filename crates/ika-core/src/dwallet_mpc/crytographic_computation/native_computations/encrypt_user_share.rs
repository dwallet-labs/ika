// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::protocol_public_parameters::ProtocolPublicParametersByCurve;
use dwallet_mpc_types::dwallet_mpc::{
    MPCPublicOutput, SerializedWrappedMPCPublicOutput, VersionedDwalletDKGPublicOutput,
    VersionedEncryptedUserShare,
};
use group::OsCsRng;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    Curve25519AsyncDKGProtocol, RistrettoAsyncDKGProtocol, Secp256K1AsyncDKGProtocol,
    Secp256R1AsyncDKGProtocol,
};
use twopc_mpc::dkg;
use twopc_mpc::dkg::Protocol;
use twopc_mpc::secp256k1::class_groups::ECDSAProtocol;

/// Verifies that the given encrypted secret key share matches the encryption of the dWallet's
/// secret share, validates the signature on the dWallet's public share,
/// and ensures the signing public key matches the address that initiated this transaction.
pub(crate) fn verify_encrypted_share(
    encrypted_centralized_secret_share_and_proof: &[u8],
    decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    encryption_key: &[u8],
    protocol_public_parameters: ProtocolPublicParametersByCurve,
) -> DwalletMPCResult<()> {
    let encrypted_centralized_secret_share_and_proof: VersionedEncryptedUserShare =
        bcs::from_bytes(encrypted_centralized_secret_share_and_proof)?;
    let decentralized_public_output: VersionedDwalletDKGPublicOutput =
        bcs::from_bytes(decentralized_public_output)?;

    match (
        encrypted_centralized_secret_share_and_proof,
        decentralized_public_output,
    ) {
        (
            VersionedEncryptedUserShare::V1(encrypted_centralized_secret_share_and_proof),
            VersionedDwalletDKGPublicOutput::V1(decentralized_public_output),
        ) => verify_centralized_secret_key_share_proof_v1(
            encrypted_centralized_secret_share_and_proof,
            decentralized_public_output,
            encryption_key,
            protocol_public_parameters,
        )
        .map_err(|e| DwalletMPCError::EncryptedUserShareVerificationFailed(e.to_string())),
        (
            VersionedEncryptedUserShare::V1(encrypted_centralized_secret_share_and_proof),
            VersionedDwalletDKGPublicOutput::V2(decentralized_public_output),
        ) => verify_centralized_secret_key_share_proof_v2(
            encrypted_centralized_secret_share_and_proof,
            decentralized_public_output,
            encryption_key,
            protocol_public_parameters,
        )
        .map_err(|e| DwalletMPCError::EncryptedUserShareVerificationFailed(e.to_string())),
    }
}

fn verify_centralized_secret_key_share_proof_v1(
    encrypted_centralized_secret_share_and_proof: MPCPublicOutput,
    dkg_public_output: MPCPublicOutput,
    encryption_key: &[u8],
    protocol_public_parameters: ProtocolPublicParametersByCurve,
) -> anyhow::Result<()> {
    let ProtocolPublicParametersByCurve::Secp256k1(protocol_public_parameters) =
        protocol_public_parameters
    else {
        return anyhow::bail!(
            "Secret key share proof verification for the given curve is not implemented for v1 {}",
            protocol_public_parameters.to_string()
        );
    };

    let decentralized_output: <Secp256K1AsyncDKGProtocol as Protocol>::DecentralizedPartyTargetedDKGOutput = bcs::from_bytes(&dkg_public_output).map_err(|e| anyhow::anyhow!("Failed to deserialize dkg public output: {}", e))?;
    let decentralized_output: <Secp256K1AsyncDKGProtocol as Protocol>::DecentralizedPartyDKGOutput =
        decentralized_output.into();

    <ECDSAProtocol as Protocol>::verify_encryption_of_centralized_party_share_proof(
        &protocol_public_parameters,
        decentralized_output,
        bcs::from_bytes(encryption_key)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize encryption key: {}", e))?,
        bcs::from_bytes(&encrypted_centralized_secret_share_and_proof).map_err(|e| {
            anyhow::anyhow!(
                "Failed to deserialize encrypted centralized secret share: {}",
                e
            )
        })?,
        &mut OsCsRng,
    )
    .map_err(Into::<anyhow::Error>::into)?;

    Ok(())
}

fn verify_centralized_secret_key_share_proof_v2(
    encrypted_centralized_secret_share_and_proof: MPCPublicOutput,
    dkg_public_output: MPCPublicOutput,
    encryption_key: &[u8],
    protocol_public_parameters: ProtocolPublicParametersByCurve,
) -> anyhow::Result<()> {
    match protocol_public_parameters {
        ProtocolPublicParametersByCurve::Secp256k1(pp) => {
            verify_centralized_secret_key_share_proof::<Secp256K1AsyncDKGProtocol>(
                &encrypted_centralized_secret_share_and_proof,
                bcs::from_bytes(&dkg_public_output)?,
                encryption_key,
                pp,
            )
        }
        ProtocolPublicParametersByCurve::Secp256r1(pp) => {
            verify_centralized_secret_key_share_proof::<Secp256R1AsyncDKGProtocol>(
                &encrypted_centralized_secret_share_and_proof,
                bcs::from_bytes(&dkg_public_output)?,
                encryption_key,
                pp,
            )
        }
        ProtocolPublicParametersByCurve::Curve25519(pp) => {
            verify_centralized_secret_key_share_proof::<Curve25519AsyncDKGProtocol>(
                &encrypted_centralized_secret_share_and_proof,
                bcs::from_bytes(&dkg_public_output)?,
                encryption_key,
                pp,
            )
        }
        ProtocolPublicParametersByCurve::Ristretto(pp) => {
            verify_centralized_secret_key_share_proof::<RistrettoAsyncDKGProtocol>(
                &encrypted_centralized_secret_share_and_proof,
                bcs::from_bytes(&dkg_public_output)?,
                encryption_key,
                pp,
            )
        }
    }
}

/// Verifies that the given centralized secret key share
/// encryption is the encryption of the given dWallet's secret share.
fn verify_centralized_secret_key_share_proof<P: dkg::Protocol>(
    encrypted_centralized_secret_share_and_proof: &[u8],
    decentralized_dkg_output: P::DecentralizedPartyDKGOutput,
    encryption_key: &[u8],
    protocol_public_parameters: P::ProtocolPublicParameters,
) -> anyhow::Result<()> {
    P::verify_encryption_of_centralized_party_share_proof(
        &protocol_public_parameters,
        decentralized_dkg_output,
        bcs::from_bytes(encryption_key)?,
        bcs::from_bytes(encrypted_centralized_secret_share_and_proof)?,
        &mut OsCsRng,
    )
    .map_err(Into::<anyhow::Error>::into)?;
    Ok(())
}
