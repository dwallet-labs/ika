// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use dwallet_mpc_types::dwallet_mpc::{
    DKGDecentralizedPartyOutputSecp256k1, DKGDecentralizedPartyVersionedOutputSecp256k1,
    SerializedWrappedMPCPublicOutput, VersionedDwalletDKGSecondRoundPublicOutput,
    VersionedImportedSecretShare,
};
use twopc_mpc::secp256k1::class_groups::ECDSAProtocol;

/// Verifies the given secret share matches the given dWallets`
/// DKG output centralized_party_public_key_share.
pub fn verify_secret_share(
    protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    secret_share: Vec<u8>,
    dkg_output: SerializedWrappedMPCPublicOutput,
) -> anyhow::Result<()> {
    let secret_share: VersionedImportedSecretShare = bcs::from_bytes(&secret_share)?;
    let VersionedImportedSecretShare::V1(secret_share) = secret_share;
    let dkg_output = bcs::from_bytes(&dkg_output)?;
    let decentralized_dkg_output = match dkg_output {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(output) => {
            bcs::from_bytes::<DKGDecentralizedPartyOutputSecp256k1>(output.as_slice())?.into()
        }
        VersionedDwalletDKGSecondRoundPublicOutput::V2(output) => {
            bcs::from_bytes::<DKGDecentralizedPartyVersionedOutputSecp256k1>(output.as_slice())?
        }
    };
    <ECDSAProtocol as twopc_mpc::dkg::Protocol>::verify_centralized_party_secret_key_share(
        &protocol_public_parameters,
        decentralized_dkg_output,
        bcs::from_bytes(&secret_share)?,
    )
    .map_err(Into::into)
}
