// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::MPC_SIGN_SECOND_ROUND;
use crate::dwallet_mpc::crytographic_computation::protocol_public_parameters::ProtocolPublicParametersByCurve;
use crate::dwallet_mpc::dwallet_dkg::{
    DWalletDKGAdvanceRequestByCurve, DWalletDKGFirstParty, DWalletDKGPublicInputByCurve,
    DWalletImportedKeyVerificationAdvanceRequestByCurve,
    DWalletImportedKeyVerificationPublicInputByCurve, Secp256k1DWalletDKGParty,
    compute_dwallet_dkg, compute_imported_key_verification,
};
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::encrypt_user_share::verify_encrypted_share;
use crate::dwallet_mpc::mpc_session::PublicInput;
use crate::dwallet_mpc::network_dkg::{
    DwalletMPCNetworkKeys, advance_network_dkg_v1, advance_network_dkg_v2,
};
use crate::dwallet_mpc::presign::{
    PresignAdvanceRequestByProtocol, PresignPublicInputByProtocol, compute_presign,
};
use crate::dwallet_mpc::protocol_cryptographic_data::ProtocolCryptographicData;
use crate::dwallet_mpc::reconfiguration::ReconfigurationV1toV2Party;
use crate::dwallet_mpc::sign::{
    DKGAndSignPublicInputByProtocol, DWalletDKGAndSignAdvanceRequestByProtocol,
    SignAdvanceRequestByProtocol, SignPublicInputByProtocol, compute_dwallet_dkg_and_sign,
    compute_sign, update_expected_decrypters_metrics,
};
use crate::dwallet_session_request::DWalletSessionRequestMetricData;
use crate::request_protocol_data::{
    NetworkEncryptionKeyDkgData, NetworkEncryptionKeyV1ToV2ReconfigurationData,
    NetworkEncryptionKeyV2ReconfigurationData, ProtocolData,
};
use class_groups::dkg::Secp256k1Party;
use commitment::CommitmentSizedNumber;
use dwallet_classgroups_types::ClassGroupsDecryptionKey;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletSignatureAlgorithm, ReconfigurationParty, ReconfigurationV2Party,
    VersionedDecryptionKeyReconfigurationOutput, VersionedDwalletDKGFirstRoundPublicOutput,
    VersionedDwalletDKGPublicOutput,
};
use dwallet_rng::RootSeed;
use group::PartyID;
use ika_protocol_config::ProtocolVersion;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    Curve25519AsyncDKGProtocol, Curve25519EdDSAProtocol, RistrettoAsyncDKGProtocol,
    RistrettoSchnorrkelSubstrateProtocol, Secp256k1AsyncDKGProtocol, Secp256k1TaprootProtocol,
    Secp256r1AsyncDKGProtocol, Secp256r1ECDSAProtocol,
};
use ika_types::messages_dwallet_mpc::{Secp256k1ECDSAProtocol, SessionIdentifier};
use mpc::guaranteed_output_delivery::{AdvanceRequest, Party, ReadyToAdvanceResult};
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, WeightedThresholdAccessStructure,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::error;
use twopc_mpc::ecdsa::{ECDSASecp256k1Signature, ECDSASecp256r1Signature};
use twopc_mpc::schnorr::{EdDSASignature, SchnorrkelSubstrateSignature, TaprootSignature};
use twopc_mpc::sign::EncodableSignature;

pub(crate) mod dwallet_dkg;
pub(crate) mod network_dkg;
pub(crate) mod presign;
pub(crate) mod reconfiguration;
pub(crate) mod sign;

impl ProtocolCryptographicData {
    pub fn try_new_mpc(
        protocol_specific_data: &ProtocolData,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        consensus_round: u64,
        serialized_messages_by_consensus_round: HashMap<u64, HashMap<PartyID, Vec<u8>>>,
        public_input: PublicInput,
        network_dkg_third_round_delay: u64,
        decryption_key_reconfiguration_third_round_delay: u64,
        class_groups_decryption_key: ClassGroupsDecryptionKey,
        decryption_key_shares: &DwalletMPCNetworkKeys,
        protocol_version: &ProtocolVersion,
    ) -> Result<Option<Self>, DwalletMPCError> {
        let res = match protocol_specific_data {
            ProtocolData::ImportedKeyVerification { data, .. } => {
                let PublicInput::DWalletImportedKeyVerificationRequest(public_input) = public_input
                else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request = DWalletImportedKeyVerificationAdvanceRequestByCurve::try_new(
                    &data.curve,
                    party_id,
                    access_structure,
                    consensus_round,
                    serialized_messages_by_consensus_round,
                )?;

                let Some(advance_request) = advance_request else {
                    return Ok(None);
                };

                ProtocolCryptographicData::ImportedKeyVerification {
                    data: data.clone(),
                    public_input,
                    advance_request,
                    protocol_version: *protocol_version,
                }
            }
            ProtocolData::DWalletDKG { data, .. } => {
                let PublicInput::DWalletDKG(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request = DWalletDKGAdvanceRequestByCurve::try_new(
                    &data.curve,
                    party_id,
                    access_structure,
                    consensus_round,
                    serialized_messages_by_consensus_round,
                )?;

                let Some(advance_request) = advance_request else {
                    return Ok(None);
                };

                ProtocolCryptographicData::DWalletDKG {
                    data: data.clone(),
                    public_input: public_input.clone(),
                    advance_request,
                }
            }
            ProtocolData::DKGFirst { data, .. } => {
                let PublicInput::DKGFirst(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result = Party::<DWalletDKGFirstParty>::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };

                ProtocolCryptographicData::DKGFirst {
                    data: data.clone(),
                    public_input: public_input.clone(),
                    advance_request,
                }
            }
            ProtocolData::DKGSecond {
                data,
                first_round_output,
                ..
            } => {
                let PublicInput::Secp256k1DWalletDKG(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result = Party::<Secp256k1DWalletDKGParty>::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };

                ProtocolCryptographicData::DKGSecond {
                    data: data.clone(),
                    public_input: public_input.clone(),
                    advance_request,
                    first_round_output: first_round_output.clone(),
                }
            }
            ProtocolData::Presign { data, .. } => {
                let PublicInput::Presign(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result = presign::PresignAdvanceRequestByProtocol::try_new(
                    &data.signature_algorithm,
                    party_id,
                    access_structure,
                    consensus_round,
                    serialized_messages_by_consensus_round,
                )?;

                let Some(advance_request) = advance_request_result else {
                    return Ok(None);
                };

                ProtocolCryptographicData::Presign {
                    data: data.clone(),
                    public_input: public_input.clone(),
                    advance_request,
                    protocol_version: *protocol_version,
                }
            }
            ProtocolData::Sign {
                data,
                dwallet_network_encryption_key_id,
                ..
            } => {
                let PublicInput::Sign(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result = SignAdvanceRequestByProtocol::try_new(
                    &data.signature_algorithm,
                    party_id,
                    access_structure,
                    consensus_round,
                    serialized_messages_by_consensus_round,
                )?;

                let Some(advance_request) = advance_request_result else {
                    return Ok(None);
                };

                let decryption_key_shares = decryption_key_shares
                    .decryption_key_shares(dwallet_network_encryption_key_id)?;

                ProtocolCryptographicData::Sign {
                    data: data.clone(),
                    public_input: public_input.clone(),
                    advance_request,
                    decryption_key_shares: decryption_key_shares.clone(),
                    protocol_version: *protocol_version,
                }
            }
            ProtocolData::DWalletDKGAndSign {
                data,
                dwallet_network_encryption_key_id,
                ..
            } => {
                let PublicInput::DWalletDKGAndSign(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result = DWalletDKGAndSignAdvanceRequestByProtocol::try_new(
                    &data.signature_algorithm,
                    party_id,
                    access_structure,
                    consensus_round,
                    serialized_messages_by_consensus_round,
                )?;

                let Some(advance_request) = advance_request_result else {
                    return Ok(None);
                };

                let decryption_key_shares = decryption_key_shares
                    .decryption_key_shares(dwallet_network_encryption_key_id)?;

                ProtocolCryptographicData::DWalletDKGAndSign {
                    data: data.clone(),
                    public_input: public_input.clone(),
                    advance_request,
                    decryption_key_shares: decryption_key_shares.clone(),
                }
            }
            ProtocolData::NetworkEncryptionKeyDkg {
                data: NetworkEncryptionKeyDkgData {},
                ..
            } => match public_input {
                PublicInput::NetworkEncryptionKeyDkgV1(public_input) => {
                    let advance_request_result = Party::<Secp256k1Party>::ready_to_advance(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::from([(3, network_dkg_third_round_delay)]),
                        &serialized_messages_by_consensus_round,
                    )?;

                    let ReadyToAdvanceResult::ReadyToAdvance(advance_request) =
                        advance_request_result
                    else {
                        return Ok(None);
                    };

                    ProtocolCryptographicData::NetworkEncryptionKeyDkgV1 {
                        data: NetworkEncryptionKeyDkgData {},
                        public_input: public_input.clone(),
                        advance_request,
                        class_groups_decryption_key,
                    }
                }
                PublicInput::NetworkEncryptionKeyDkgV2(public_input) => {
                    let advance_request_result =
                        Party::<twopc_mpc::decentralized_party::dkg::Party>::ready_to_advance(
                            party_id,
                            access_structure,
                            consensus_round,
                            HashMap::from([(3, network_dkg_third_round_delay)]),
                            &serialized_messages_by_consensus_round,
                        )?;

                    let ReadyToAdvanceResult::ReadyToAdvance(advance_request) =
                        advance_request_result
                    else {
                        return Ok(None);
                    };
                    ProtocolCryptographicData::NetworkEncryptionKeyDkgV2 {
                        public_input: public_input.clone(),
                        advance_request,
                        class_groups_decryption_key,
                    }
                }
                _ => {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            },
            ProtocolData::NetworkEncryptionKeyReconfiguration {
                data,
                dwallet_network_encryption_key_id,
            } => match public_input {
                PublicInput::NetworkEncryptionKeyReconfigurationV1(public_input) => {
                    let advance_request_result = Party::<ReconfigurationParty>::ready_to_advance(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::from([(3, decryption_key_reconfiguration_third_round_delay)]),
                        &serialized_messages_by_consensus_round,
                    )?;

                    let ReadyToAdvanceResult::ReadyToAdvance(advance_request) =
                        advance_request_result
                    else {
                        return Ok(None);
                    };

                    let decryption_key_shares = decryption_key_shares
                        .decryption_key_shares(dwallet_network_encryption_key_id)?;

                    ProtocolCryptographicData::NetworkEncryptionKeyV1Reconfiguration {
                        data: data.clone(),
                        public_input: public_input.clone(),
                        advance_request,
                        decryption_key_shares: decryption_key_shares.clone(),
                    }
                }
                PublicInput::NetworkEncryptionKeyReconfigurationV1ToV2(public_input) => {
                    let advance_request_result =
                        Party::<ReconfigurationV1toV2Party>::ready_to_advance(
                            party_id,
                            access_structure,
                            consensus_round,
                            HashMap::from([(3, decryption_key_reconfiguration_third_round_delay)]),
                            &serialized_messages_by_consensus_round,
                        )?;

                    let ReadyToAdvanceResult::ReadyToAdvance(advance_request) =
                        advance_request_result
                    else {
                        return Ok(None);
                    };

                    let decryption_key_shares = decryption_key_shares
                        .decryption_key_shares(dwallet_network_encryption_key_id)?;

                    ProtocolCryptographicData::NetworkEncryptionKeyV1ToV2Reconfiguration {
                        data: NetworkEncryptionKeyV1ToV2ReconfigurationData {},
                        public_input: public_input.clone(),
                        advance_request,
                        decryption_key_shares: decryption_key_shares.clone(),
                    }
                }
                PublicInput::NetworkEncryptionKeyReconfigurationV2(public_input) => {
                    let advance_request_result = Party::<ReconfigurationV2Party>::ready_to_advance(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::from([(3, decryption_key_reconfiguration_third_round_delay)]),
                        &serialized_messages_by_consensus_round,
                    )?;

                    let ReadyToAdvanceResult::ReadyToAdvance(advance_request) =
                        advance_request_result
                    else {
                        return Ok(None);
                    };

                    let decryption_key_shares = decryption_key_shares
                        .decryption_key_shares(dwallet_network_encryption_key_id)?;

                    ProtocolCryptographicData::NetworkEncryptionKeyV2Reconfiguration {
                        data: NetworkEncryptionKeyV2ReconfigurationData {},
                        public_input: public_input.clone(),
                        advance_request,
                        decryption_key_shares: decryption_key_shares.clone(),
                    }
                }
                _ => {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            },
            _ => {
                return Err(DwalletMPCError::InvalidDWalletProtocolType);
            }
        };
        Ok(Some(res))
    }

    pub(crate) fn compute_mpc(
        self,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        mpc_round: u64,
        consensus_round: u64,
        session_identifier: SessionIdentifier,
        root_seed: RootSeed,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
    ) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
        let protocol_metadata: DWalletSessionRequestMetricData = (&self).into();

        dwallet_mpc_metrics.add_advance_mpc_call(&protocol_metadata, &mpc_round.to_string());

        let session_id = CommitmentSizedNumber::from_le_slice(&session_identifier.into_bytes());

        // Derive a one-time use, MPC protocol and round specific, deterministic random generator
        // from the private seed.
        // This should only be used to `advance()` this specific round, and is guaranteed to be
        // deterministic — if we attempt to run the round twice, the same message will be generated.
        // SECURITY NOTICE: don't use for anything else other than (this particular) `advance()`,
        // and keep private!
        let mut rng = root_seed.mpc_round_rng(session_id, mpc_round, consensus_round);

        match self {
            ProtocolCryptographicData::ImportedKeyVerification {
                public_input:
                    DWalletImportedKeyVerificationPublicInputByCurve::Secp256k1(public_input),
                advance_request:
                    DWalletImportedKeyVerificationAdvanceRequestByCurve::Secp256k1(advance_request),
                protocol_version,
                data,
                ..
            } => compute_imported_key_verification::<Secp256k1AsyncDKGProtocol>(
                data.curve,
                session_id,
                party_id,
                access_structure,
                advance_request,
                &public_input.clone(),
                protocol_version,
                &mut rng,
            ),
            ProtocolCryptographicData::ImportedKeyVerification {
                public_input:
                    DWalletImportedKeyVerificationPublicInputByCurve::Secp256r1(public_input),
                advance_request:
                    DWalletImportedKeyVerificationAdvanceRequestByCurve::Secp256r1(advance_request),
                protocol_version,
                data,
                ..
            } => compute_imported_key_verification::<Secp256r1AsyncDKGProtocol>(
                data.curve,
                session_id,
                party_id,
                access_structure,
                advance_request,
                &public_input.clone(),
                protocol_version,
                &mut rng,
            ),
            ProtocolCryptographicData::ImportedKeyVerification {
                public_input:
                    DWalletImportedKeyVerificationPublicInputByCurve::Curve25519(public_input),
                advance_request:
                    DWalletImportedKeyVerificationAdvanceRequestByCurve::Curve25519(advance_request),
                protocol_version,
                data,
                ..
            } => compute_imported_key_verification::<Curve25519AsyncDKGProtocol>(
                data.curve,
                session_id,
                party_id,
                access_structure,
                advance_request,
                &public_input.clone(),
                protocol_version,
                &mut rng,
            ),
            ProtocolCryptographicData::ImportedKeyVerification {
                public_input:
                    DWalletImportedKeyVerificationPublicInputByCurve::Ristretto(public_input),
                advance_request:
                    DWalletImportedKeyVerificationAdvanceRequestByCurve::Ristretto(advance_request),
                protocol_version,
                data,
                ..
            } => compute_imported_key_verification::<RistrettoAsyncDKGProtocol>(
                data.curve,
                session_id,
                party_id,
                access_structure,
                advance_request,
                &public_input.clone(),
                protocol_version,
                &mut rng,
            ),
            ProtocolCryptographicData::ImportedKeyVerification {
                public_input,
                advance_request,
                ..
            } => Err(DwalletMPCError::MPCParametersMissmatchInputToRequest(
                public_input.to_string(),
                advance_request.to_string(),
            )),
            ProtocolCryptographicData::DKGFirst {
                public_input,
                advance_request,
                ..
            } => {
                let result = Party::<DWalletDKGFirstParty>::advance_with_guaranteed_output(
                    session_id,
                    party_id,
                    access_structure,
                    advance_request,
                    None,
                    &public_input,
                    &mut rng,
                )?;

                match result {
                    GuaranteedOutputDeliveryRoundResult::Advance { message } => {
                        Ok(GuaranteedOutputDeliveryRoundResult::Advance { message })
                    }
                    GuaranteedOutputDeliveryRoundResult::Finalize {
                        public_output_value,
                        malicious_parties,
                        private_output,
                    } => {
                        let output: <DWalletDKGFirstParty as mpc::Party>::PublicOutputValue =
                            bcs::from_bytes(&public_output_value)?;
                        let output_with_session_id = bcs::to_bytes(&(output, session_id))?;
                        // Wrap the public output with its version.
                        let public_output_value = bcs::to_bytes(
                            &VersionedDwalletDKGFirstRoundPublicOutput::V1(output_with_session_id),
                        )?;

                        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                            public_output_value,
                            malicious_parties,
                            private_output,
                        })
                    }
                }
            }

            ProtocolCryptographicData::DKGSecond {
                public_input,
                data,
                advance_request,
                first_round_output,
                ..
            } => {
                let session_id = match bcs::from_bytes(&first_round_output)? {
                    VersionedDwalletDKGFirstRoundPublicOutput::V1(output) => {
                        let (_, session_id): (
                            <DWalletDKGFirstParty as mpc::Party>::PublicOutputValue,
                            CommitmentSizedNumber,
                        ) = bcs::from_bytes(&output)?;

                        session_id
                    }
                };
                let result = Party::<Secp256k1DWalletDKGParty>::advance_with_guaranteed_output(
                    session_id,
                    party_id,
                    access_structure,
                    advance_request,
                    None,
                    &public_input.clone(),
                    &mut rng,
                )?;

                match result {
                    GuaranteedOutputDeliveryRoundResult::Advance { message } => {
                        Ok(GuaranteedOutputDeliveryRoundResult::Advance { message })
                    }
                    GuaranteedOutputDeliveryRoundResult::Finalize {
                        public_output_value,
                        malicious_parties,
                        private_output,
                    } => {
                        let decentralized_output: <Secp256k1AsyncDKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput = bcs::from_bytes(&public_output_value)?;
                        let decentralized_output: <Secp256k1AsyncDKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyTargetedDKGOutput = decentralized_output.into();

                        let public_output_value =
                            bcs::to_bytes(&VersionedDwalletDKGPublicOutput::V1(bcs::to_bytes(
                                &decentralized_output,
                            )?))?;

                        verify_encrypted_share(
                            &data.encrypted_centralized_secret_share_and_proof,
                            // TODO (#1482): Check the protocol config and use this hack only for V1
                            // DWallets.
                            &public_output_value,
                            &data.encryption_key,
                            // DKG second is supported only for secp256k1.
                            ProtocolPublicParametersByCurve::Secp256k1(
                                public_input.protocol_public_parameters.clone(),
                            ),
                            ProtocolVersion::from(1),
                        )?;

                        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                            public_output_value,
                            malicious_parties,
                            private_output,
                        })
                    }
                }
            }
            ProtocolCryptographicData::DWalletDKG {
                public_input: DWalletDKGPublicInputByCurve::Secp256k1DWalletDKG(public_input),
                advance_request:
                    DWalletDKGAdvanceRequestByCurve::Secp256k1DWalletDKG(advance_request),
                data,
                ..
            } => Ok(compute_dwallet_dkg::<Secp256k1AsyncDKGProtocol>(
                data.curve,
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                &mut rng,
            )?),
            ProtocolCryptographicData::DWalletDKG {
                public_input: DWalletDKGPublicInputByCurve::Secp256r1DWalletDKG(public_input),
                advance_request:
                    DWalletDKGAdvanceRequestByCurve::Secp256r1DWalletDKG(advance_request),
                data,
                ..
            } => Ok(compute_dwallet_dkg::<Secp256r1AsyncDKGProtocol>(
                data.curve,
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                &mut rng,
            )?),
            ProtocolCryptographicData::DWalletDKG {
                public_input: DWalletDKGPublicInputByCurve::Curve25519DWalletDKG(public_input),
                advance_request:
                    DWalletDKGAdvanceRequestByCurve::Curve25519DWalletDKG(advance_request),
                data,
                ..
            } => Ok(compute_dwallet_dkg::<Curve25519AsyncDKGProtocol>(
                data.curve,
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                &mut rng,
            )?),
            ProtocolCryptographicData::DWalletDKG {
                public_input: DWalletDKGPublicInputByCurve::RistrettoDWalletDKG(public_input),
                advance_request:
                    DWalletDKGAdvanceRequestByCurve::RistrettoDWalletDKG(advance_request),
                data,
                ..
            } => Ok(compute_dwallet_dkg::<RistrettoAsyncDKGProtocol>(
                data.curve,
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                &mut rng,
            )?),
            ProtocolCryptographicData::DWalletDKG {
                public_input,
                advance_request,
                ..
            } => Err(DwalletMPCError::MPCParametersMissmatchInputToRequest(
                public_input.to_string(),
                advance_request.to_string(),
            )),
            ProtocolCryptographicData::Presign {
                public_input: PresignPublicInputByProtocol::Secp256k1ECDSA(public_input),
                advance_request: PresignAdvanceRequestByProtocol::Secp256k1ECDSA(advance_request),
                protocol_version,
                ..
            } => Ok(compute_presign::<Secp256k1ECDSAProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                protocol_version,
                &mut rng,
            )?),
            ProtocolCryptographicData::Presign {
                public_input: PresignPublicInputByProtocol::Taproot(public_input),
                advance_request: PresignAdvanceRequestByProtocol::Taproot(advance_request),
                protocol_version,
                ..
            } => Ok(compute_presign::<Secp256k1TaprootProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                protocol_version,
                &mut rng,
            )?),
            ProtocolCryptographicData::Presign {
                public_input: PresignPublicInputByProtocol::Secp256r1ECDSA(public_input),
                advance_request: PresignAdvanceRequestByProtocol::Secp256r1ECDSA(advance_request),
                protocol_version,
                ..
            } => Ok(compute_presign::<Secp256r1ECDSAProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                protocol_version,
                &mut rng,
            )?),
            ProtocolCryptographicData::Presign {
                public_input: PresignPublicInputByProtocol::EdDSA(public_input),
                advance_request: PresignAdvanceRequestByProtocol::EdDSA(advance_request),
                protocol_version,
                ..
            } => Ok(compute_presign::<Curve25519EdDSAProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                protocol_version,
                &mut rng,
            )?),
            ProtocolCryptographicData::Presign {
                public_input: PresignPublicInputByProtocol::SchnorrkelSubstrate(public_input),
                advance_request:
                    PresignAdvanceRequestByProtocol::SchnorrkelSubstrate(advance_request),
                protocol_version,
                ..
            } => Ok(compute_presign::<RistrettoSchnorrkelSubstrateProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                protocol_version,
                &mut rng,
            )?),
            ProtocolCryptographicData::Sign {
                public_input: SignPublicInputByProtocol::Secp256k1ECDSA(public_input),
                advance_request: SignAdvanceRequestByProtocol::Secp256k1ECDSA(advance_request),
                decryption_key_shares,
                data,
                protocol_version,
                ..
            } => {
                if mpc_round == MPC_SIGN_SECOND_ROUND {
                    let decrypters = advance_request.senders_for_round(1)?;
                    update_expected_decrypters_metrics(
                        &public_input.expected_decrypters,
                        decrypters,
                        access_structure,
                        dwallet_mpc_metrics,
                    );
                }

                compute_sign::<Secp256k1ECDSAProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &data,
                    protocol_version,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::Sign {
                public_input: SignPublicInputByProtocol::Secp256k1Taproot(public_input),
                advance_request: SignAdvanceRequestByProtocol::Secp256k1Taproot(advance_request),
                decryption_key_shares,
                data,
                protocol_version,
                ..
            } => {
                if mpc_round == MPC_SIGN_SECOND_ROUND {
                    let decrypters = advance_request.senders_for_round(1)?;
                    update_expected_decrypters_metrics(
                        &public_input.expected_decrypters,
                        decrypters,
                        access_structure,
                        dwallet_mpc_metrics,
                    );
                }

                compute_sign::<Secp256k1TaprootProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &data,
                    protocol_version,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::Sign {
                public_input: SignPublicInputByProtocol::Secp256r1(public_input),
                advance_request: SignAdvanceRequestByProtocol::Secp256r1(advance_request),
                decryption_key_shares,
                data,
                protocol_version,
                ..
            } => {
                if mpc_round == MPC_SIGN_SECOND_ROUND {
                    let decrypters = advance_request.senders_for_round(1)?;
                    update_expected_decrypters_metrics(
                        &public_input.expected_decrypters,
                        decrypters,
                        access_structure,
                        dwallet_mpc_metrics,
                    );
                }

                compute_sign::<Secp256r1ECDSAProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &data,
                    protocol_version,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::Sign {
                public_input: SignPublicInputByProtocol::Curve25519(public_input),
                advance_request: SignAdvanceRequestByProtocol::Curve25519(advance_request),
                decryption_key_shares,
                data,
                protocol_version,
                ..
            } => {
                if mpc_round == MPC_SIGN_SECOND_ROUND {
                    let decrypters = advance_request.senders_for_round(1)?;
                    update_expected_decrypters_metrics(
                        &public_input.expected_decrypters,
                        decrypters,
                        access_structure,
                        dwallet_mpc_metrics,
                    );
                }

                compute_sign::<Curve25519EdDSAProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &data,
                    protocol_version,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::Sign {
                public_input: SignPublicInputByProtocol::Ristretto(public_input),
                advance_request: SignAdvanceRequestByProtocol::Ristretto(advance_request),
                decryption_key_shares,
                data,
                protocol_version,
                ..
            } => {
                if mpc_round == MPC_SIGN_SECOND_ROUND {
                    let decrypters = advance_request.senders_for_round(1)?;
                    update_expected_decrypters_metrics(
                        &public_input.expected_decrypters,
                        decrypters,
                        access_structure,
                        dwallet_mpc_metrics,
                    );
                }

                compute_sign::<RistrettoSchnorrkelSubstrateProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &data,
                    protocol_version,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::Sign {
                public_input,
                advance_request,
                ..
            } => Err(DwalletMPCError::MPCParametersMissmatchInputToRequest(
                public_input.to_string(),
                advance_request.to_string(),
            )),
            ProtocolCryptographicData::DWalletDKGAndSign {
                public_input: DKGAndSignPublicInputByProtocol::Secp256k1ECDSA(public_input),
                advance_request:
                    DWalletDKGAndSignAdvanceRequestByProtocol::Secp256k1ECDSA(advance_request),
                decryption_key_shares,
                data,
                ..
            } => {
                if mpc_round == MPC_SIGN_SECOND_ROUND {
                    let decrypters = advance_request.senders_for_round(1)?;
                    update_expected_decrypters_metrics(
                        &public_input.expected_decrypters,
                        decrypters,
                        access_structure,
                        dwallet_mpc_metrics,
                    );
                }

                compute_dwallet_dkg_and_sign::<Secp256k1ECDSAProtocol>(
                    data.curve,
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &data,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::DWalletDKGAndSign {
                public_input: DKGAndSignPublicInputByProtocol::Secp256k1Taproot(public_input),
                advance_request:
                    DWalletDKGAndSignAdvanceRequestByProtocol::Secp256k1Taproot(advance_request),
                decryption_key_shares,
                data,
                ..
            } => {
                if mpc_round == MPC_SIGN_SECOND_ROUND {
                    let decrypters = advance_request.senders_for_round(1)?;
                    update_expected_decrypters_metrics(
                        &public_input.expected_decrypters,
                        decrypters,
                        access_structure,
                        dwallet_mpc_metrics,
                    );
                }

                compute_dwallet_dkg_and_sign::<Secp256k1TaprootProtocol>(
                    data.curve,
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &data,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::DWalletDKGAndSign {
                public_input: DKGAndSignPublicInputByProtocol::Secp256r1(public_input),
                advance_request:
                    DWalletDKGAndSignAdvanceRequestByProtocol::Secp256r1(advance_request),
                decryption_key_shares,
                data,
                ..
            } => {
                if mpc_round == MPC_SIGN_SECOND_ROUND {
                    let decrypters = advance_request.senders_for_round(1)?;
                    update_expected_decrypters_metrics(
                        &public_input.expected_decrypters,
                        decrypters,
                        access_structure,
                        dwallet_mpc_metrics,
                    );
                }

                compute_dwallet_dkg_and_sign::<Secp256r1ECDSAProtocol>(
                    data.curve,
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &data,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::DWalletDKGAndSign {
                public_input: DKGAndSignPublicInputByProtocol::Curve25519(public_input),
                advance_request:
                    DWalletDKGAndSignAdvanceRequestByProtocol::Curve25519(advance_request),
                decryption_key_shares,
                data,
                ..
            } => {
                if mpc_round == MPC_SIGN_SECOND_ROUND {
                    let decrypters = advance_request.senders_for_round(1)?;
                    update_expected_decrypters_metrics(
                        &public_input.expected_decrypters,
                        decrypters,
                        access_structure,
                        dwallet_mpc_metrics,
                    );
                }

                compute_dwallet_dkg_and_sign::<Curve25519EdDSAProtocol>(
                    data.curve,
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &data,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::DWalletDKGAndSign {
                public_input: DKGAndSignPublicInputByProtocol::Ristretto(public_input),
                advance_request:
                    DWalletDKGAndSignAdvanceRequestByProtocol::Ristretto(advance_request),
                decryption_key_shares,
                data,
                ..
            } => {
                if mpc_round == MPC_SIGN_SECOND_ROUND {
                    let decrypters = advance_request.senders_for_round(1)?;
                    update_expected_decrypters_metrics(
                        &public_input.expected_decrypters,
                        decrypters,
                        access_structure,
                        dwallet_mpc_metrics,
                    );
                }

                compute_dwallet_dkg_and_sign::<RistrettoSchnorrkelSubstrateProtocol>(
                    data.curve,
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &data,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::DWalletDKGAndSign {
                public_input,
                advance_request,
                ..
            } => Err(DwalletMPCError::MPCParametersMissmatchInputToRequest(
                public_input.to_string(),
                advance_request.to_string(),
            )),
            ProtocolCryptographicData::NetworkEncryptionKeyDkgV1 {
                public_input,
                advance_request,
                class_groups_decryption_key,
                ..
            } => advance_network_dkg_v1(
                session_id,
                access_structure,
                public_input,
                party_id,
                advance_request,
                class_groups_decryption_key,
                &mut rng,
            ),
            ProtocolCryptographicData::NetworkEncryptionKeyDkgV2 {
                public_input,
                advance_request,
                class_groups_decryption_key,
                ..
            } => advance_network_dkg_v2(
                session_id,
                access_structure,
                public_input,
                party_id,
                advance_request,
                class_groups_decryption_key,
                &mut rng,
            ),
            ProtocolCryptographicData::NetworkEncryptionKeyV1Reconfiguration {
                public_input,
                advance_request,
                decryption_key_shares,
                ..
            } => {
                let result = Party::<ReconfigurationParty>::advance_with_guaranteed_output(
                    session_id,
                    party_id,
                    access_structure,
                    advance_request,
                    Some(decryption_key_shares.clone()),
                    &public_input,
                    &mut rng,
                )?;

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
                        let public_output_value = bcs::to_bytes(
                            &VersionedDecryptionKeyReconfigurationOutput::V1(public_output_value),
                        )?;

                        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                            public_output_value,
                            malicious_parties,
                            private_output,
                        })
                    }
                }
            }
            ProtocolCryptographicData::NetworkEncryptionKeyV1ToV2Reconfiguration {
                public_input,
                advance_request,
                decryption_key_shares,
                ..
            } => {
                let result = Party::<ReconfigurationV1toV2Party>::advance_with_guaranteed_output(
                    session_id,
                    party_id,
                    access_structure,
                    advance_request,
                    Some(decryption_key_shares.clone()),
                    &public_input,
                    &mut rng,
                )?;

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
                        let public_output_value = bcs::to_bytes(
                            &VersionedDecryptionKeyReconfigurationOutput::V2(public_output_value),
                        )?;

                        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                            public_output_value,
                            malicious_parties,
                            private_output,
                        })
                    }
                }
            }
            ProtocolCryptographicData::NetworkEncryptionKeyV2Reconfiguration {
                public_input,
                advance_request,
                decryption_key_shares,
                ..
            } => {
                let result = Party::<ReconfigurationV2Party>::advance_with_guaranteed_output(
                    session_id,
                    party_id,
                    access_structure,
                    advance_request,
                    Some(decryption_key_shares.clone()),
                    &public_input,
                    &mut rng,
                )?;

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
                        let public_output_value = bcs::to_bytes(
                            &VersionedDecryptionKeyReconfigurationOutput::V2(public_output_value),
                        )?;

                        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                            public_output_value,
                            malicious_parties,
                            private_output,
                        })
                    }
                }
            }
            _ => {
                error!(
                    session_type=?protocol_metadata,
                    session_identifier=?session_identifier,
                    "Invalid session type for mpc computation");
                Err(DwalletMPCError::InvalidDWalletProtocolType)
            }
        }
    }
}

fn parse_signature_from_sign_output(
    signature_algorithm: &DWalletSignatureAlgorithm,
    public_output_value: Vec<u8>,
) -> DwalletMPCResult<Vec<u8>> {
    match signature_algorithm {
        DWalletSignatureAlgorithm::ECDSASecp256k1 => {
            let signature: ECDSASecp256k1Signature = bcs::from_bytes(&public_output_value)?;

            Ok(signature.to_bytes().to_vec())
        }
        DWalletSignatureAlgorithm::ECDSASecp256r1 => {
            let signature: ECDSASecp256r1Signature = bcs::from_bytes(&public_output_value)?;

            Ok(signature.to_bytes().to_vec())
        }
        DWalletSignatureAlgorithm::EdDSA => {
            let signature: EdDSASignature = bcs::from_bytes(&public_output_value)?;

            Ok(signature.to_bytes().to_vec())
        }
        DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
            let signature: SchnorrkelSubstrateSignature = bcs::from_bytes(&public_output_value)?;

            Ok(signature.to_bytes().to_vec())
        }
        DWalletSignatureAlgorithm::Taproot => {
            let signature: TaprootSignature = bcs::from_bytes(&public_output_value)?;

            Ok(signature.to_bytes().to_vec())
        }
    }
}

fn try_ready_to_advance<P: mpc::Party + mpc::AsynchronouslyAdvanceable>(
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    consensus_round: u64,
    serialized_messages_by_consensus_round: &HashMap<u64, HashMap<PartyID, Vec<u8>>>,
) -> DwalletMPCResult<Option<AdvanceRequest<<P>::Message>>> {
    let advance_request_result = mpc::guaranteed_output_delivery::Party::<P>::ready_to_advance(
        party_id,
        access_structure,
        consensus_round,
        HashMap::new(),
        serialized_messages_by_consensus_round,
    )
    .map_err(|e| DwalletMPCError::FailedToAdvanceMPC(e.into()))?;

    match advance_request_result {
        ReadyToAdvanceResult::ReadyToAdvance(advance_request) => Ok(Some(advance_request)),
        _ => Ok(None),
    }
}
