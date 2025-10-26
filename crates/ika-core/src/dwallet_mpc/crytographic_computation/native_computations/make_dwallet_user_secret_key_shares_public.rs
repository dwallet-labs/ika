// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::protocol_public_parameters::ProtocolPublicParametersByCurve;
use dwallet_mpc_types::dwallet_mpc::{
    DKGDecentralizedPartyOutputSecp256k1, MPCPublicOutput, SerializedWrappedMPCPublicOutput,
    VersionedDwalletDKGPublicOutput, VersionedImportedSecretShare,
};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    Curve25519AsyncDKGProtocol, RistrettoAsyncDKGProtocol, Secp256k1AsyncDKGProtocol,
    Secp256r1AsyncDKGProtocol,
};
use twopc_mpc::dkg;
use twopc_mpc::dkg::Protocol;
use twopc_mpc::secp256k1::class_groups::ECDSAProtocol;

/// Verifies the given secret share matches the given dWallets`
/// DKG output centralized_party_public_key_share.
pub fn verify_secret_share(
    secret_share: Vec<u8>,
    dkg_output: SerializedWrappedMPCPublicOutput,
    protocol_public_parameters: ProtocolPublicParametersByCurve,
) -> DwalletMPCResult<()> {
    let secret_share: VersionedImportedSecretShare = bcs::from_bytes(&secret_share)?;
    let dkg_output: VersionedDwalletDKGPublicOutput = bcs::from_bytes(&dkg_output)?;

    match (secret_share, dkg_output) {
        (
            VersionedImportedSecretShare::V1(secret_share),
            VersionedDwalletDKGPublicOutput::V1(dkg_output),
        ) => verify_centralized_party_secret_key_share_v1(
            secret_share,
            dkg_output,
            protocol_public_parameters,
        )
        .map_err(|e| DwalletMPCError::SecretShareVerificationFailed(e.to_string())),
        (
            VersionedImportedSecretShare::V1(secret_share),
            VersionedDwalletDKGPublicOutput::V2(dkg_output),
        ) => verify_centralized_party_secret_key_share_v2(
            secret_share,
            dkg_output,
            protocol_public_parameters,
        )
        .map_err(|e| DwalletMPCError::SecretShareVerificationFailed(e.to_string())),
    }
}

fn verify_centralized_party_secret_key_share_v1(
    secret_share: MPCPublicOutput,
    dkg_output: MPCPublicOutput,
    protocol_public_parameters: ProtocolPublicParametersByCurve,
) -> anyhow::Result<()> {
    match protocol_public_parameters {
        ProtocolPublicParametersByCurve::Secp256k1(pp) => {
            let decentralized_dkg_output =
                bcs::from_bytes::<DKGDecentralizedPartyOutputSecp256k1>(&dkg_output)?;
            <ECDSAProtocol as Protocol>::verify_centralized_party_public_key_share(
                &pp,
                decentralized_dkg_output.into(),
                bcs::from_bytes(&secret_share)?,
            )
            .map_err(Into::<anyhow::Error>::into)?;
            Ok(())
        }
        _ => {
            anyhow::bail!(
                "Secret key share verification for the given curve is not implemented for v1 {}",
                protocol_public_parameters
            );
        }
    }
}

fn verify_centralized_party_secret_key_share_v2(
    secret_share: MPCPublicOutput,
    dkg_output: MPCPublicOutput,
    protocol_public_parameters: ProtocolPublicParametersByCurve,
) -> anyhow::Result<()> {
    match protocol_public_parameters {
        ProtocolPublicParametersByCurve::Secp256k1(pp) => {
            verify_centralized_party_secret_key_share::<Secp256k1AsyncDKGProtocol>(
                &secret_share,
                bcs::from_bytes(&dkg_output)?,
                pp,
            )
        }
        ProtocolPublicParametersByCurve::Secp256r1(pp) => {
            verify_centralized_party_secret_key_share::<Secp256r1AsyncDKGProtocol>(
                &secret_share,
                bcs::from_bytes(&dkg_output)?,
                pp,
            )
        }
        ProtocolPublicParametersByCurve::Curve25519(pp) => {
            verify_centralized_party_secret_key_share::<Curve25519AsyncDKGProtocol>(
                &secret_share,
                bcs::from_bytes(&dkg_output)?,
                pp,
            )
        }
        ProtocolPublicParametersByCurve::Ristretto(pp) => {
            verify_centralized_party_secret_key_share::<RistrettoAsyncDKGProtocol>(
                &secret_share,
                bcs::from_bytes(&dkg_output)?,
                pp,
            )
        }
    }
}

/// Verifies that the given centralized secret key share
/// matches the given dWallet's secret share.
fn verify_centralized_party_secret_key_share<P: dkg::Protocol>(
    secret_share: &[u8],
    decentralized_dkg_output: P::DecentralizedPartyDKGOutput,
    protocol_public_parameters: P::ProtocolPublicParameters,
) -> anyhow::Result<()> {
    P::verify_centralized_party_public_key_share(
        &protocol_public_parameters,
        decentralized_dkg_output,
        bcs::from_bytes(secret_share)?,
    )
    .map_err(Into::<anyhow::Error>::into)?;
    Ok(())
}
