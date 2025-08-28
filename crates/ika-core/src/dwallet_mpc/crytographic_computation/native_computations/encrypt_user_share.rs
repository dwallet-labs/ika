// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use dwallet_mpc_types::dwallet_mpc::{
    SerializedWrappedMPCPublicOutput, SpecificDKGDecentralizedPartyOutput,
    SpecificDKGDecentralizedPartyVersionedOutput, VersionedDwalletDKGSecondRoundPublicOutput,
    VersionedEncryptedUserShare,
};
use group::OsCsRng;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use twopc_mpc::dkg::Protocol;
use twopc_mpc::secp256k1::class_groups::AsyncECDSAProtocol;

/// Verifies that the given encrypted secret key share matches the encryption of the dWallet's
/// secret share, validates the signature on the dWallet's public share,
/// and ensures the signing public key matches the address that initiated this transaction.
pub(crate) fn verify_encrypted_share(
    encrypted_centralized_secret_share_and_proof: &[u8],
    decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    encryption_key: &[u8],
    protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
) -> DwalletMPCResult<()> {
    let encrypted_centralized_secret_share_and_proof =
        match bcs::from_bytes(encrypted_centralized_secret_share_and_proof)? {
            VersionedEncryptedUserShare::V1(output) => output.clone(),
        };
    verify_centralized_secret_key_share_proof(
        &encrypted_centralized_secret_share_and_proof,
        decentralized_public_output,
        encryption_key,
        protocol_public_parameters,
    )
    .map_err(|_| DwalletMPCError::EncryptedUserShareVerificationFailed)
}

/// Verifies that the given centralized secret key share
/// encryption is the encryption of the given dWallet's secret share.
fn verify_centralized_secret_key_share_proof(
    encrypted_centralized_secret_share_and_proof: &[u8],
    serialized_dkg_public_output: &SerializedWrappedMPCPublicOutput,
    encryption_key: &[u8],
    protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
) -> anyhow::Result<()> {
    let dkg_public_output = bcs::from_bytes(serialized_dkg_public_output)?;
    let decentralized_dkg_output = match dkg_public_output {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(output) => {
            bcs::from_bytes::<SpecificDKGDecentralizedPartyOutput>(output.as_slice())?.into()
        }
        VersionedDwalletDKGSecondRoundPublicOutput::V2(output) => {
            bcs::from_bytes::<SpecificDKGDecentralizedPartyVersionedOutput>(output.as_slice())?
        }
    };
    <AsyncECDSAProtocol as Protocol>::verify_encryption_of_centralized_party_share_proof(
        &protocol_public_parameters,
        decentralized_dkg_output,
        bcs::from_bytes(encryption_key)?,
        bcs::from_bytes(encrypted_centralized_secret_share_and_proof)?,
        &mut OsCsRng,
    )
    .map_err(Into::<anyhow::Error>::into)?;
    Ok(())
}
