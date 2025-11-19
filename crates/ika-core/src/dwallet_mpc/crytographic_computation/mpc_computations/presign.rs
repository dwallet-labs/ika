// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the Presign protocol from the 2PC-MPC library.
//!
//! It integrates both Presign parties (each representing a round in the Presign protocol).

use crate::dwallet_mpc::crytographic_computation::mpc_computations;
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    DKGDecentralizedPartyOutputSecp256k1, DWalletSignatureAlgorithm, MPCPublicOutput,
    SerializedWrappedMPCPublicOutput, VersionedDwalletDKGPublicOutput,
    VersionedNetworkEncryptionKeyPublicData,
};
use dwallet_mpc_types::dwallet_mpc::{NetworkEncryptionKeyPublicDataTrait, VersionedPresignOutput};
use group::{CsRng, PartyID};
use ika_protocol_config::ProtocolVersion;
use ika_types::dwallet_mpc_error::DwalletMPCError;
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use ika_types::messages_dwallet_mpc::{
    Curve25519EdDSAProtocol, RistrettoSchnorrkelSubstrateProtocol, Secp256k1ECDSAProtocol,
    Secp256k1TaprootProtocol, Secp256r1ECDSAProtocol,
};
use mpc::guaranteed_output_delivery::AdvanceRequest;
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, WeightedThresholdAccessStructure,
};
use std::collections::HashMap;
use twopc_mpc::dkg::decentralized_party::VersionedOutput;
use twopc_mpc::presign::Protocol;
use twopc_mpc::{dkg, presign};

pub(crate) type PresignParty<P> = <P as Protocol>::PresignParty;

#[derive(Clone, Debug, Eq, PartialEq, strum_macros::Display)]
pub(crate) enum PresignPublicInputByProtocol {
    #[strum(to_string = "Presign Public Input - curve: Secp256k1, protocol: ECDSA")]
    Secp256k1ECDSA(<PresignParty<Secp256k1ECDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Presign Public Input - curve: Secp256k1, protocol: Taproot")]
    Taproot(<PresignParty<Secp256k1TaprootProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Presign Public Input - curve: Secp256r1, protocol: ECDSA")]
    Secp256r1ECDSA(<PresignParty<Secp256r1ECDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Presign Public Input - curve: Curve25519, protocol: EdDSA")]
    EdDSA(<PresignParty<Curve25519EdDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(
        to_string = "Presign Public Input - curve: Ristretto, protocol: Schnorrkel (Substrate)"
    )]
    SchnorrkelSubstrate(
        <PresignParty<RistrettoSchnorrkelSubstrateProtocol> as mpc::Party>::PublicInput,
    ),
}

#[derive(strum_macros::Display)]
pub(crate) enum PresignAdvanceRequestByProtocol {
    #[strum(to_string = "Presign Advance Request - curve: Secp256k1, protocol: ECDSA")]
    Secp256k1ECDSA(AdvanceRequest<<PresignParty<Secp256k1ECDSAProtocol> as mpc::Party>::Message>),
    #[strum(to_string = "Presign Advance Request - curve: Secp256k1, protocol: Taproot")]
    Taproot(AdvanceRequest<<PresignParty<Secp256k1TaprootProtocol> as mpc::Party>::Message>),
    #[strum(to_string = "Presign Advance Request - curve: Secp256r1, protocol: ECDSA")]
    Secp256r1ECDSA(AdvanceRequest<<PresignParty<Secp256r1ECDSAProtocol> as mpc::Party>::Message>),
    #[strum(to_string = "Presign Advance Request - curve: Curve25519, protocol: EdDSA")]
    EdDSA(AdvanceRequest<<PresignParty<Curve25519EdDSAProtocol> as mpc::Party>::Message>),
    #[strum(
        to_string = "Presign Advance Request - curve: Ristretto, protocol: Schnorrkel (Substrate)"
    )]
    SchnorrkelSubstrate(
        AdvanceRequest<<PresignParty<RistrettoSchnorrkelSubstrateProtocol> as mpc::Party>::Message>,
    ),
}

impl PresignAdvanceRequestByProtocol {
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
                    mpc_computations::try_ready_to_advance::<PresignParty<Secp256k1ECDSAProtocol>>(
                        party_id,
                        access_structure,
                        consensus_round,
                        &serialized_messages_by_consensus_round,
                    )?;

                advance_request.map(PresignAdvanceRequestByProtocol::Secp256k1ECDSA)
            }
            DWalletSignatureAlgorithm::Taproot => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    PresignParty<Secp256k1TaprootProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(PresignAdvanceRequestByProtocol::Taproot)
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    PresignParty<RistrettoSchnorrkelSubstrateProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(PresignAdvanceRequestByProtocol::SchnorrkelSubstrate)
            }
            DWalletSignatureAlgorithm::EdDSA => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    PresignParty<Curve25519EdDSAProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(PresignAdvanceRequestByProtocol::EdDSA)
            }
            DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                let advance_request =
                    mpc_computations::try_ready_to_advance::<PresignParty<Secp256r1ECDSAProtocol>>(
                        party_id,
                        access_structure,
                        consensus_round,
                        &serialized_messages_by_consensus_round,
                    )?;

                advance_request.map(PresignAdvanceRequestByProtocol::Secp256r1ECDSA)
            }
        };

        Ok(advance_request)
    }
}

impl PresignPublicInputByProtocol {
    pub(crate) fn try_new(
        protocol: DWalletSignatureAlgorithm,
        versioned_network_encryption_key_public_data: &VersionedNetworkEncryptionKeyPublicData,
        dwallet_public_output: Option<SerializedWrappedMPCPublicOutput>,
    ) -> DwalletMPCResult<Self> {
        if dwallet_public_output.is_none() {
            return Self::try_new_v2(protocol, versioned_network_encryption_key_public_data, None);
        }
        // Safe to unwrap as we checked for None above
        match bcs::from_bytes(&dwallet_public_output.unwrap())? {
            VersionedDwalletDKGPublicOutput::V1(dkg_output) => {
                Self::try_new_v1(versioned_network_encryption_key_public_data, dkg_output)
            }
            VersionedDwalletDKGPublicOutput::V2 { dkg_output, .. } => Self::try_new_v2(
                protocol,
                versioned_network_encryption_key_public_data,
                Some(dkg_output),
            ),
        }
    }
    pub(crate) fn try_new_v1(
        versioned_network_encryption_key_public_data: &VersionedNetworkEncryptionKeyPublicData,
        dwallet_public_output: MPCPublicOutput,
    ) -> DwalletMPCResult<Self> {
        let decentralized_party_dkg_output =
            bcs::from_bytes::<DKGDecentralizedPartyOutputSecp256k1>(&dwallet_public_output)?;

        let protocol_public_parameters =
            versioned_network_encryption_key_public_data.secp256k1_protocol_public_parameters();

        let public_input: <PresignParty<Secp256k1ECDSAProtocol> as mpc::Party>::PublicInput = (
            protocol_public_parameters,
            Some(decentralized_party_dkg_output),
        )
            .into();

        Ok(PresignPublicInputByProtocol::Secp256k1ECDSA(public_input))
    }

    pub(crate) fn try_new_v2(
        protocol: DWalletSignatureAlgorithm,
        versioned_network_encryption_key_public_data: &VersionedNetworkEncryptionKeyPublicData,
        dwallet_dkg_output: Option<MPCPublicOutput>,
    ) -> DwalletMPCResult<Self> {
        let input = match protocol {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .secp256k1_protocol_public_parameters();

                let public_input =
                    <PresignParty<Secp256k1ECDSAProtocol> as mpc::Party>::PublicInput::from((
                        protocol_public_parameters,
                        match dwallet_dkg_output {
                            Some(dkg_output) => {
                                let versioned_output = bcs::from_bytes::<
                                    <Secp256k1ECDSAProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput,
                                >(&dkg_output)?;

                                let output = match versioned_output {
                                    VersionedOutput::TargetedPublicDKGOutput(output) => output,
                                    VersionedOutput::UniversalPublicDKGOutput {
                                        ..
                                    } => {
                                        return Err(DwalletMPCError::InvalidInput(
                                            "Universal DKG output is not supported for v2 non-global presign".to_string(),
                                        ))
                                    }
                                };

                                Some(output)
                            }
                            None => None,
                        },
                    ));
                PresignPublicInputByProtocol::Secp256k1ECDSA(public_input)
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .ristretto_protocol_public_parameters()?;

                let pub_input =
                    <PresignParty<RistrettoSchnorrkelSubstrateProtocol> as mpc::Party>::PublicInput::from((
                        protocol_public_parameters,
                        match dwallet_dkg_output {
                            Some(dkg_output) => {
                                let versioned_output = bcs::from_bytes::<
                                    <RistrettoSchnorrkelSubstrateProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput,
                                >(&dkg_output)?;

                                let output = match versioned_output {
                                    VersionedOutput::TargetedPublicDKGOutput(output) => output,
                                    VersionedOutput::UniversalPublicDKGOutput {
                                        ..
                                    } => {
                                        return Err(DwalletMPCError::InvalidInput(
                                            "Universal DKG output is not supported for v2 non-global presign".to_string(),
                                        ))
                                    }
                                };

                                Some(output)
                            },
                            None => None,
                        },
                    ));

                PresignPublicInputByProtocol::SchnorrkelSubstrate(pub_input)
            }
            DWalletSignatureAlgorithm::EdDSA => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .curve25519_protocol_public_parameters()?;

                let pub_input =
                    <PresignParty<Curve25519EdDSAProtocol> as mpc::Party>::PublicInput::from((
                        protocol_public_parameters,
                        match dwallet_dkg_output {
                            Some(dkg_output) => {
                                let versioned_output = bcs::from_bytes::<
                                    <Curve25519EdDSAProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput,
                                >(&dkg_output)?;

                                let output = match versioned_output {
                                    VersionedOutput::TargetedPublicDKGOutput(output) => output,
                                    VersionedOutput::UniversalPublicDKGOutput {
                                        ..
                                    } => {
                                        return Err(DwalletMPCError::InvalidInput(
                                            "Universal DKG output is not supported for v2 non-global presign".to_string(),
                                        ))
                                    }
                                };

                                Some(output)
                            }
                            None => None,
                        },
                    ));

                PresignPublicInputByProtocol::EdDSA(pub_input)
            }
            DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .secp256r1_protocol_public_parameters()?;

                let pub_input =
                    <PresignParty<Secp256r1ECDSAProtocol> as mpc::Party>::PublicInput::from((
                        protocol_public_parameters,
                        match dwallet_dkg_output {
                            Some(dkg_output) => {
                                let versioned_output = bcs::from_bytes::<
                                    <Secp256r1ECDSAProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput,
                                >(&dkg_output)?;

                                let output = match versioned_output {
                                    VersionedOutput::TargetedPublicDKGOutput(output) => output,
                                    VersionedOutput::UniversalPublicDKGOutput {
                                        ..
                                    } => {
                                        return Err(DwalletMPCError::InvalidInput(
                                            "Universal DKG output is not supported for v2 non-global presign".to_string(),
                                        ))
                                    }
                                };

                                Some(output)
                            }
                            None => None,
                        },
                    ));

                PresignPublicInputByProtocol::Secp256r1ECDSA(pub_input)
            }
            DWalletSignatureAlgorithm::Taproot => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .secp256k1_protocol_public_parameters();

                let pub_input =
                    <PresignParty<Secp256k1TaprootProtocol> as mpc::Party>::PublicInput::from((
                        protocol_public_parameters,
                        match dwallet_dkg_output {
                            Some(dkg_output) => {
                                let versioned_output = bcs::from_bytes::<
                                    <Secp256k1TaprootProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput,
                                >(&dkg_output)?;

                                let output = match versioned_output {
                                    VersionedOutput::TargetedPublicDKGOutput(output) => output,
                                    VersionedOutput::UniversalPublicDKGOutput {
                                        ..
                                    } => {
                                        return Err(DwalletMPCError::InvalidInput(
                                            "Universal DKG output is not supported for v2 non-global presign".to_string(),
                                        ))
                                    }
                                };

                                Some(output)
                            }
                            None => None,
                        },
                    ));

                PresignPublicInputByProtocol::Taproot(pub_input)
            }
        };

        Ok(input)
    }
}

pub fn compute_presign<P: presign::Protocol>(
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    session_id: CommitmentSizedNumber,
    advance_request: AdvanceRequest<<P::PresignParty as mpc::Party>::Message>,
    public_input: <P::PresignParty as mpc::Party>::PublicInput,
    protocol_version: ProtocolVersion,
    rng: &mut impl CsRng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let result =
        mpc::guaranteed_output_delivery::Party::<P::PresignParty>::advance_with_guaranteed_output(
            session_id,
            party_id,
            access_structure,
            advance_request,
            None,
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
            // Wrap the public output with its version.
            let public_output_value = match protocol_version.as_u64() {
                1 => {
                    let versioned_presign: <Secp256k1ECDSAProtocol as Protocol>::Presign =
                        bcs::from_bytes(&public_output_value.clone())?;

                    let targeted_presign = match versioned_presign {
                        twopc_mpc::ecdsa::presign::VersionedPresign::TargetedPresign(presign) => {
                            presign
                        }
                        twopc_mpc::ecdsa::presign::VersionedPresign::UniversalPresign(_) => {
                            // In protocol version 1, we never generate universal presigns
                            unreachable!()
                        }
                    };

                    bcs::to_bytes(&VersionedPresignOutput::V1(bcs::to_bytes(
                        &targeted_presign,
                    )?))?
                }
                2 => bcs::to_bytes(&VersionedPresignOutput::V2(public_output_value))?,
                _ => {
                    return Err(DwalletMPCError::UnsupportedProtocolVersion(
                        protocol_version.as_u64(),
                    ));
                }
            };

            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value,
                malicious_parties,
                private_output,
            })
        }
    }
}
