// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the Presign protocol from the 2PC-MPC library.
//!
//! It integrates both Presign parties (each representing a round in the Presign protocol).

use crate::dwallet_mpc::ValidatorMpcKeysByPartyId;
use crate::dwallet_mpc::crytographic_computation::mpc_computations;
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::VersionedPresignOutput;
use dwallet_mpc_types::dwallet_mpc::{
    DKGDecentralizedPartyOutputSecp256k1, DWalletSignatureAlgorithm, MPCPublicOutput,
    NetworkEncryptionKeyPublicData, SerializedWrappedMPCPublicOutput,
    VersionedDwalletDKGPublicOutput,
};
use group::{CsRng, PartyID};
use ika_types::dwallet_mpc_error::DwalletMPCError;
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use ika_types::messages_dwallet_mpc::{
    Curve25519EdDSAProtocol, Curve25519EdDSAVSSProtocol, RistrettoSchnorrkelSubstrateProtocol,
    RistrettoSchnorrkelSubstrateVSSProtocol, Secp256k1AsyncDKGProtocol, Secp256k1ECDSAProtocol,
    Secp256k1TaprootProtocol, Secp256k1TaprootVSSProtocol, Secp256r1AsyncDKGProtocol,
    Secp256r1ECDSAProtocol,
};
use mpc::guaranteed_output_delivery::AdvanceRequest;
use mpc::hybrid_public_key_encryption::parse_and_uc_verify_encryption_keys;
use mpc::{
    AsynchronouslyAdvanceable, GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery,
    WeightedThresholdAccessStructure,
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
    #[strum(to_string = "Presign Public Input - curve: Secp256k1, protocol: TaprootVSS")]
    TaprootVSS(<PresignParty<Secp256k1TaprootVSSProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Presign Public Input - curve: Curve25519, protocol: EdDSAVSS")]
    EdDSAVSS(<PresignParty<Curve25519EdDSAVSSProtocol> as mpc::Party>::PublicInput),
    #[strum(
        to_string = "Presign Public Input - curve: Ristretto, protocol: SchnorrkelSubstrateVSS"
    )]
    SchnorrkelSubstrateVSS(
        <PresignParty<RistrettoSchnorrkelSubstrateVSSProtocol> as mpc::Party>::PublicInput,
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
    #[strum(to_string = "Presign Advance Request - curve: Secp256k1, protocol: TaprootVSS")]
    TaprootVSS(AdvanceRequest<<PresignParty<Secp256k1TaprootVSSProtocol> as mpc::Party>::Message>),
    #[strum(to_string = "Presign Advance Request - curve: Curve25519, protocol: EdDSAVSS")]
    EdDSAVSS(AdvanceRequest<<PresignParty<Curve25519EdDSAVSSProtocol> as mpc::Party>::Message>),
    #[strum(
        to_string = "Presign Advance Request - curve: Ristretto, protocol: SchnorrkelSubstrateVSS"
    )]
    SchnorrkelSubstrateVSS(
        AdvanceRequest<
            <PresignParty<RistrettoSchnorrkelSubstrateVSSProtocol> as mpc::Party>::Message,
        >,
    ),
}

impl PresignAdvanceRequestByProtocol {
    pub fn try_new(
        protocol: &DWalletSignatureAlgorithm,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        consensus_round: u64,
        schnorr_presign_second_round_delay: u64,
        // Consensus-round delay for the VSS presign Aggregation round (round 3).
        // Only the VSS arms use it; AHE presign is 2 rounds and ignores it.
        schnorr_presign_third_round_delay: u64,
        serialized_messages_by_consensus_round: HashMap<u64, HashMap<PartyID, Vec<u8>>>,
    ) -> DwalletMPCResult<Option<Self>> {
        let advance_request = match protocol {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                let advance_request =
                    mpc_computations::try_ready_to_advance::<PresignParty<Secp256k1ECDSAProtocol>>(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
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
                    HashMap::from([(2, schnorr_presign_second_round_delay)]),
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
                    HashMap::from([(2, schnorr_presign_second_round_delay)]),
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
                    HashMap::from([(2, schnorr_presign_second_round_delay)]),
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
                        HashMap::new(),
                        &serialized_messages_by_consensus_round,
                    )?;

                advance_request.map(PresignAdvanceRequestByProtocol::Secp256r1ECDSA)
            }
            // VSS (Fast Schnorr) presign is 3 rounds: Dealing → Accusation (round 2)
            // → Aggregation (round 3). Round 2 reuses the schnorr second-round delay;
            // round 3 uses the dedicated third-round delay.
            DWalletSignatureAlgorithm::TaprootVSS => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    PresignParty<Secp256k1TaprootVSSProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::from([
                        (2, schnorr_presign_second_round_delay),
                        (3, schnorr_presign_third_round_delay),
                    ]),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(PresignAdvanceRequestByProtocol::TaprootVSS)
            }
            DWalletSignatureAlgorithm::EdDSAVSS => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    PresignParty<Curve25519EdDSAVSSProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::from([
                        (2, schnorr_presign_second_round_delay),
                        (3, schnorr_presign_third_round_delay),
                    ]),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(PresignAdvanceRequestByProtocol::EdDSAVSS)
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrateVSS => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    PresignParty<RistrettoSchnorrkelSubstrateVSSProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::from([
                        (2, schnorr_presign_second_round_delay),
                        (3, schnorr_presign_third_round_delay),
                    ]),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(PresignAdvanceRequestByProtocol::SchnorrkelSubstrateVSS)
            }
        };

        Ok(advance_request)
    }
}

impl PresignPublicInputByProtocol {
    pub(crate) fn try_new(
        protocol: DWalletSignatureAlgorithm,
        network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
        dwallet_public_output: Option<SerializedWrappedMPCPublicOutput>,
        validator_mpc_keys_by_party_id: &ValidatorMpcKeysByPartyId,
    ) -> DwalletMPCResult<Self> {
        if dwallet_public_output.is_none() {
            return Self::try_new_v2(
                protocol,
                network_encryption_key_public_data,
                None,
                validator_mpc_keys_by_party_id,
            );
        }
        // Safe to unwrap as we checked for None above
        match bcs::from_bytes(&dwallet_public_output.unwrap())? {
            VersionedDwalletDKGPublicOutput::V1(dkg_output) => {
                Self::try_new_v1(network_encryption_key_public_data, dkg_output)
            }
            VersionedDwalletDKGPublicOutput::V2 { dkg_output, .. } => Self::try_new_v2(
                protocol,
                network_encryption_key_public_data,
                Some(dkg_output),
                validator_mpc_keys_by_party_id,
            ),
        }
    }
    pub(crate) fn try_new_v1(
        network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
        dwallet_public_output: MPCPublicOutput,
    ) -> DwalletMPCResult<Self> {
        let decentralized_party_dkg_output =
            bcs::from_bytes::<DKGDecentralizedPartyOutputSecp256k1>(&dwallet_public_output)?;

        let protocol_public_parameters =
            network_encryption_key_public_data.secp256k1_protocol_public_parameters();

        let public_input: <PresignParty<Secp256k1ECDSAProtocol> as mpc::Party>::PublicInput =
            twopc_mpc::ecdsa::presign::decentralized_party::PublicInput {
                dkg_output: Some(decentralized_party_dkg_output),
                protocol_public_parameters,
            };

        Ok(PresignPublicInputByProtocol::Secp256k1ECDSA(public_input))
    }

    pub(crate) fn try_new_v2(
        protocol: DWalletSignatureAlgorithm,
        network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
        dwallet_dkg_output: Option<MPCPublicOutput>,
        validator_mpc_keys_by_party_id: &ValidatorMpcKeysByPartyId,
    ) -> DwalletMPCResult<Self> {
        let input = match protocol {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256k1_protocol_public_parameters();
                let dkg_output = match dwallet_dkg_output {
                    Some(dkg_output) => {
                        let versioned_output = bcs::from_bytes::<
                            <Secp256k1AsyncDKGProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput,
                        >(&dkg_output)?;
                        match versioned_output {
                            VersionedOutput::TargetedPublicDKGOutput(output) => Some(output),
                            VersionedOutput::UniversalPublicDKGOutput { .. } => None,
                        }
                    }
                    None => None,
                };
                let public_input: <PresignParty<Secp256k1ECDSAProtocol> as mpc::Party>::PublicInput =
                    twopc_mpc::ecdsa::presign::decentralized_party::PublicInput {
                        dkg_output,
                        protocol_public_parameters,
                    };
                PresignPublicInputByProtocol::Secp256k1ECDSA(public_input)
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                // Schnorr AHE presign PublicInput has no dkg_output field; ignore the optional
                // dwallet_dkg_output (the field is targeted-DKG-only and AHE-mode Schnorr
                // doesn't use it). Upstream's Schnorr AHE presign carries only
                // protocol_public_parameters.
                let _ = dwallet_dkg_output;
                let protocol_public_parameters =
                    network_encryption_key_public_data.ristretto_protocol_public_parameters();
                let pub_input: <PresignParty<RistrettoSchnorrkelSubstrateProtocol> as mpc::Party>::PublicInput =
                    twopc_mpc::schnorr::ahe::presign::decentralized_party::PublicInput {
                        protocol_public_parameters,
                    };

                PresignPublicInputByProtocol::SchnorrkelSubstrate(pub_input)
            }
            DWalletSignatureAlgorithm::EdDSA => {
                let _ = dwallet_dkg_output;
                let protocol_public_parameters =
                    network_encryption_key_public_data.curve25519_protocol_public_parameters();
                let pub_input: <PresignParty<Curve25519EdDSAProtocol> as mpc::Party>::PublicInput =
                    twopc_mpc::schnorr::ahe::presign::decentralized_party::PublicInput {
                        protocol_public_parameters,
                    };

                PresignPublicInputByProtocol::EdDSA(pub_input)
            }
            DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256r1_protocol_public_parameters();
                let dkg_output = match dwallet_dkg_output {
                    Some(dkg_output) => {
                        let versioned_output = bcs::from_bytes::<
                            <Secp256r1AsyncDKGProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput,
                        >(&dkg_output)?;
                        match versioned_output {
                            VersionedOutput::TargetedPublicDKGOutput(output) => Some(output),
                            VersionedOutput::UniversalPublicDKGOutput { .. } => None,
                        }
                    }
                    None => None,
                };
                let pub_input: <PresignParty<Secp256r1ECDSAProtocol> as mpc::Party>::PublicInput =
                    twopc_mpc::ecdsa::presign::decentralized_party::PublicInput {
                        dkg_output,
                        protocol_public_parameters,
                    };

                PresignPublicInputByProtocol::Secp256r1ECDSA(pub_input)
            }
            DWalletSignatureAlgorithm::Taproot => {
                let _ = dwallet_dkg_output;
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256k1_protocol_public_parameters();
                let pub_input: <PresignParty<Secp256k1TaprootProtocol> as mpc::Party>::PublicInput =
                    twopc_mpc::schnorr::ahe::presign::decentralized_party::PublicInput {
                        protocol_public_parameters,
                    };

                PresignPublicInputByProtocol::Taproot(pub_input)
            }
            // VSS (Fast Schnorr) presign PublicInput carries the per-party curve25519
            // HPKE encryption keys + the UC-verified party set, in addition to the
            // protocol public parameters. These are the single `vss_hpke`
            // curve25519 keys (one per validator, curve-independent) — NOT the three
            // per-curve class-groups `*_pvss` keys. `parse_and_uc_verify_encryption_keys`
            // parses the published values and verifies their UC proofs, returning only
            // the parties that pass both — so the verified set is just its keys, and a
            // single malformed/unprovable submission excludes only that party.
            DWalletSignatureAlgorithm::TaprootVSS => {
                let _ = dwallet_dkg_output;
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256k1_protocol_public_parameters();
                let party_encryption_keys =
                    parse_and_uc_verify_encryption_keys(&validator_mpc_keys_by_party_id.vss_hpke)
                        .map_err(|e| {
                        DwalletMPCError::InvalidInput(format!(
                            "failed to parse/verify VSS HPKE encryption keys: {e:?}"
                        ))
                    })?;
                let parties_with_uc_verified_public_keys =
                    party_encryption_keys.keys().copied().collect();
                let pub_input: <PresignParty<Secp256k1TaprootVSSProtocol> as mpc::Party>::PublicInput =
                    twopc_mpc::schnorr::vss::presign::decentralized_party::PublicInput {
                        protocol_public_parameters,
                        party_encryption_keys,
                        parties_with_uc_verified_public_keys,
                    };
                PresignPublicInputByProtocol::TaprootVSS(pub_input)
            }
            DWalletSignatureAlgorithm::EdDSAVSS => {
                let _ = dwallet_dkg_output;
                let protocol_public_parameters =
                    network_encryption_key_public_data.curve25519_protocol_public_parameters();
                let party_encryption_keys =
                    parse_and_uc_verify_encryption_keys(&validator_mpc_keys_by_party_id.vss_hpke)
                        .map_err(|e| {
                        DwalletMPCError::InvalidInput(format!(
                            "failed to parse/verify VSS HPKE encryption keys: {e:?}"
                        ))
                    })?;
                let parties_with_uc_verified_public_keys =
                    party_encryption_keys.keys().copied().collect();
                let pub_input: <PresignParty<Curve25519EdDSAVSSProtocol> as mpc::Party>::PublicInput =
                    twopc_mpc::schnorr::vss::presign::decentralized_party::PublicInput {
                        protocol_public_parameters,
                        party_encryption_keys,
                        parties_with_uc_verified_public_keys,
                    };
                PresignPublicInputByProtocol::EdDSAVSS(pub_input)
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrateVSS => {
                let _ = dwallet_dkg_output;
                let protocol_public_parameters =
                    network_encryption_key_public_data.ristretto_protocol_public_parameters();
                let party_encryption_keys =
                    parse_and_uc_verify_encryption_keys(&validator_mpc_keys_by_party_id.vss_hpke)
                        .map_err(|e| {
                        DwalletMPCError::InvalidInput(format!(
                            "failed to parse/verify VSS HPKE encryption keys: {e:?}"
                        ))
                    })?;
                let parties_with_uc_verified_public_keys =
                    party_encryption_keys.keys().copied().collect();
                let pub_input: <PresignParty<RistrettoSchnorrkelSubstrateVSSProtocol> as mpc::Party>::PublicInput =
                    twopc_mpc::schnorr::vss::presign::decentralized_party::PublicInput {
                        protocol_public_parameters,
                        party_encryption_keys,
                        parties_with_uc_verified_public_keys,
                    };
                PresignPublicInputByProtocol::SchnorrkelSubstrateVSS(pub_input)
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
    // AHE Schnorr / ECDSA presign has a `()` private input (`None`). VSS presign
    // needs the validator's curve25519 HPKE secret as `PrivateInput`, constructed
    // at the compute layer (it is deliberately non-serializable, so it can't ride
    // the serialized `MPCPrivateInput` seam).
    private_input: Option<<P::PresignParty as AsynchronouslyAdvanceable>::PrivateInput>,
    is_internal: bool,
    rng: &mut impl CsRng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let result =
        mpc::guaranteed_output_delivery::Party::<P::PresignParty>::advance_with_guaranteed_output(
            session_id,
            party_id,
            access_structure,
            advance_request,
            private_input,
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
            let public_output_value = if is_internal {
                // No need to wrap with version as it is only used internally.
                public_output_value
            } else {
                // For backward compatibility, we take the first presign only, which is identical to the one computed in the non-blending aggregation method.
                // Only case where after upgrade we will have an external presign protocol is for ECDSA imported dWallet,
                // as Schnorr protocols are always global, and so are zero-trust dWallets, and global dWallets always gets presigns from the internal presign pool (and no dedicated external presign protocol is computed for them).
                // As there are no presign blending for ECDSA anyways, this logic isn't a performance hit.
                let presigns: Vec<P::Presign> = bcs::from_bytes(&public_output_value)?;
                let presign = presigns.first().ok_or(DwalletMPCError::InternalError(
                    "at least one presign must be generated".to_string(),
                ))?;

                bcs::to_bytes(&VersionedPresignOutput::V2(bcs::to_bytes(&presign)?))?
            };

            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value,
                malicious_parties,
                private_output,
            })
        }
    }
}
