// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use dwallet_mpc_types::dwallet_mpc::{
    SerializedWrappedMPCPublicOutput, VersionedDwalletDKGSecondRoundPublicOutput,
    VersionedImportedSecretShare,
};
use twopc_mpc::secp256k1::class_groups::AsyncECDSAProtocol;

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
    match dkg_output {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(dkg_output) => {
            <AsyncECDSAProtocol as twopc_mpc::dkg::Protocol>::verify_centralized_party_secret_key_share(
                &protocol_public_parameters,
                bcs::from_bytes(&dkg_output)?,
                bcs::from_bytes(&secret_share)?,
            )
            .map_err(Into::into)
        }
    }
}
