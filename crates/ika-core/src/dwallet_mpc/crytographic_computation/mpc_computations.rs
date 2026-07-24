// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::MPC_SIGN_SECOND_ROUND;
use crate::dwallet_mpc::dwallet_dkg::{
    DWalletDKGAdvanceRequestByCurve, DWalletDKGPublicInputByCurve,
    DWalletImportedKeyVerificationAdvanceRequestByCurve,
    DWalletImportedKeyVerificationPublicInputByCurve, compute_dwallet_dkg,
    compute_imported_key_verification,
};
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::mpc_session::PublicInput;
use crate::dwallet_mpc::network_dkg::{DwalletMPCNetworkKeys, advance_network_dkg_v2};
use crate::dwallet_mpc::presign::{
    PresignAdvanceRequestByProtocol, PresignPublicInputByProtocol, compute_presign,
};
use crate::dwallet_mpc::protocol_cryptographic_data::ProtocolCryptographicData;
use crate::dwallet_mpc::sign::{
    DKGAndSignPublicInputByProtocol, DWalletDKGAndSignAdvanceRequestByProtocol,
    SignAdvanceRequestByProtocol, SignPublicInputByProtocol,
    build_curve25519_eddsa_vss_sign_private_input,
    build_ristretto_schnorrkel_vss_sign_private_input,
    build_secp256k1_taproot_vss_sign_private_input, compute_dwallet_dkg_and_sign, compute_sign,
    update_expected_decrypters_metrics,
};
use crate::dwallet_session_request::DWalletSessionRequestMetricData;
use crate::request_protocol_data::{
    NetworkEncryptionKeyDkgData, NetworkEncryptionKeyReconfigurationData, ProtocolData, SignData,
};
use commitment::CommitmentSizedNumber;
use dwallet_classgroups_types::ClassGroupsDecryptionKey;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletSignatureAlgorithm, ReconfigurationParty, VersionedDecryptionKeyReconfigurationOutput,
};
use dwallet_rng::RootSeed;
use group::PartyID;
use ika_protocol_config::ProtocolConfig;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    Curve25519AsyncDKGProtocol, Curve25519EdDSAProtocol, Curve25519EdDSAVSSProtocol,
    RistrettoAsyncDKGProtocol, RistrettoSchnorrkelProtocol, RistrettoSchnorrkelVSSProtocol,
    Secp256k1AsyncDKGProtocol, Secp256k1TaprootProtocol, Secp256k1TaprootVSSProtocol,
    Secp256r1AsyncDKGProtocol, Secp256r1ECDSAProtocol,
};
use ika_types::messages_dwallet_mpc::{Secp256k1ECDSAProtocol, SessionIdentifier};
use mpc::guaranteed_output_delivery::{AdvanceRequest, Party, ReadyToAdvanceResult};
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, WeightedThresholdAccessStructure,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info};
use twopc_mpc::ecdsa::{ECDSASecp256k1Signature, ECDSASecp256r1Signature};
use twopc_mpc::schnorr::{EdDSASignature, SchnorrkelSignature, TaprootSignature};
use twopc_mpc::sign::EncodableSignature;

pub(crate) mod dwallet_dkg;
pub(crate) mod network_dkg;
pub(crate) mod network_owned_address_sign_dkg_emulation;
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
        schnorr_presign_second_round_delay: u64,
        class_groups_decryption_key: ClassGroupsDecryptionKey,
        decryption_key_shares: &DwalletMPCNetworkKeys,
        // Persisted VSS presign `PrivateOutput` (`bcs(Vec<PrivatePresignOutput>)`)
        // for this sign's presign session, read by the manager (which has the
        // epoch store). Only populated for Fast Schnorr (VSS) sign requests.
        presign_private_output: Option<Vec<u8>>,
        protocol_config: &ProtocolConfig,
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
            ProtocolData::Presign { data, .. } => {
                let PublicInput::Presign(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result = presign::PresignAdvanceRequestByProtocol::try_new(
                    &data.signature_algorithm,
                    party_id,
                    access_structure,
                    consensus_round,
                    schnorr_presign_second_round_delay,
                    protocol_config
                        .schnorr_presign_third_round_delay_as_option()
                        .unwrap_or(0),
                    serialized_messages_by_consensus_round,
                )?;

                let Some(advance_request) = advance_request_result else {
                    return Ok(None);
                };

                ProtocolCryptographicData::Presign {
                    data: data.clone(),
                    public_input: public_input.clone(),
                    advance_request,
                }
            }
            ProtocolData::InternalPresign { data, .. } => {
                let PublicInput::Presign(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result = presign::PresignAdvanceRequestByProtocol::try_new(
                    &data.signature_algorithm,
                    party_id,
                    access_structure,
                    consensus_round,
                    schnorr_presign_second_round_delay,
                    protocol_config
                        .schnorr_presign_third_round_delay_as_option()
                        .unwrap_or(0),
                    serialized_messages_by_consensus_round,
                )?;

                let Some(advance_request) = advance_request_result else {
                    return Ok(None);
                };

                ProtocolCryptographicData::InternalPresign {
                    data: data.clone(),
                    public_input: public_input.clone(),
                    advance_request,
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

                if data.signature_algorithm.is_vss() {
                    // Fast Schnorr (VSS): carry the secret-key-share source (the
                    // reconfiguration output if the key reconfigured, else the network
                    // DKG output) for secret-key-share recovery at compute time, plus
                    // the persisted presign nonce data, instead of the AHE decryption
                    // key shares.
                    let vss_shamir_cache = decryption_key_shares
                        .vss_shamir_cache(dwallet_network_encryption_key_id)?
                        .clone();
                    ProtocolCryptographicData::SignVSS {
                        data: data.clone(),
                        public_input: public_input.clone(),
                        advance_request,
                        vss_shamir_cache,
                        presign_private_output,
                    }
                } else {
                    let decryption_key_shares = decryption_key_shares
                        .decryption_key_shares(dwallet_network_encryption_key_id)?;

                    ProtocolCryptographicData::Sign {
                        data: data.clone(),
                        public_input: public_input.clone(),
                        advance_request,
                        decryption_key_shares: decryption_key_shares.clone(),
                    }
                }
            }
            ProtocolData::NetworkOwnedAddressSign {
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
                    serialized_messages_by_consensus_round.clone(),
                )?;

                let Some(advance_request) = advance_request_result else {
                    return Ok(None);
                };

                if data.signature_algorithm.is_vss() {
                    // Fast Schnorr (VSS) NOA sign reuses the external-sign compute path
                    // (`SignVSS`): VSS has no AHE decryption-key shares / decrypters, so
                    // the NOA-vs-external compute distinction collapses. Output is still
                    // routed to the NOA channel by the request's session type. The
                    // presign (popped from the internal VSS pool) carries the private
                    // nonce output, read by the manager as for external VSS sign.
                    let vss_shamir_cache = decryption_key_shares
                        .vss_shamir_cache(dwallet_network_encryption_key_id)?
                        .clone();
                    ProtocolCryptographicData::NetworkOwnedAddressSignVSS {
                        data: data.clone(),
                        public_input: public_input.clone(),
                        advance_request,
                        vss_shamir_cache,
                        presign_private_output,
                    }
                } else {
                    let decryption_key_shares = decryption_key_shares
                        .decryption_key_shares(dwallet_network_encryption_key_id)?;

                    ProtocolCryptographicData::NetworkOwnedAddressSign {
                        data: data.clone(),
                        public_input: public_input.clone(),
                        advance_request,
                        decryption_key_shares: decryption_key_shares.clone(),
                    }
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

                if data.signature_algorithm.is_vss() {
                    // Fast Schnorr (VSS) combined DKG-and-sign: as for `SignVSS`, carry the
                    // secret-key-share source (reconfiguration output if the key
                    // reconfigured, else the network DKG output) for secret-key-share
                    // recovery at compute time, plus the persisted presign nonce data,
                    // instead of the AHE decryption key shares.
                    let vss_shamir_cache = decryption_key_shares
                        .vss_shamir_cache(dwallet_network_encryption_key_id)?
                        .clone();
                    ProtocolCryptographicData::DWalletDKGAndSignVSS {
                        data: data.clone(),
                        public_input: public_input.clone(),
                        advance_request,
                        vss_shamir_cache,
                        presign_private_output,
                    }
                } else {
                    let decryption_key_shares = decryption_key_shares
                        .decryption_key_shares(dwallet_network_encryption_key_id)?;

                    ProtocolCryptographicData::DWalletDKGAndSign {
                        data: data.clone(),
                        public_input: public_input.clone(),
                        advance_request,
                        decryption_key_shares: decryption_key_shares.clone(),
                    }
                }
            }
            ProtocolData::NetworkEncryptionKeyDkg {
                data: NetworkEncryptionKeyDkgData {},
                ..
            } => match public_input {
                PublicInput::NetworkEncryptionKeyDkg(public_input) => {
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

                    ProtocolCryptographicData::NetworkEncryptionKeyDkg {
                        public_input: public_input.clone(),
                        advance_request,
                        class_groups_decryption_key,
                    }
                }
                _ => return Err(DwalletMPCError::InvalidSessionPublicInput),
            },
            ProtocolData::NetworkEncryptionKeyReconfiguration {
                dwallet_network_encryption_key_id,
                ..
            } => {
                let decryption_key_shares = decryption_key_shares
                    .decryption_key_shares(dwallet_network_encryption_key_id)?;

                match public_input {
                    PublicInput::NetworkEncryptionKeyReconfiguration(public_input) => {
                        let advance_request_result =
                            Party::<ReconfigurationParty>::ready_to_advance(
                                party_id,
                                access_structure,
                                consensus_round,
                                HashMap::from([(
                                    3,
                                    decryption_key_reconfiguration_third_round_delay,
                                )]),
                                &serialized_messages_by_consensus_round,
                            )?;

                        let ReadyToAdvanceResult::ReadyToAdvance(advance_request) =
                            advance_request_result
                        else {
                            return Ok(None);
                        };

                        ProtocolCryptographicData::NetworkEncryptionKeyReconfiguration {
                            data: NetworkEncryptionKeyReconfigurationData {},
                            public_input: public_input.clone(),
                            advance_request,
                            decryption_key_shares: decryption_key_shares.clone(),
                        }
                    }
                    _ => return Err(DwalletMPCError::InvalidSessionPublicInput),
                }
            }
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
        vss_hpke_secret_key: group::curve25519::Scalar,
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
                data,
                ..
            } => compute_imported_key_verification::<Secp256k1AsyncDKGProtocol>(
                data.curve,
                session_id,
                party_id,
                access_structure,
                advance_request,
                &public_input.clone(),
                &mut rng,
            ),
            ProtocolCryptographicData::ImportedKeyVerification {
                public_input:
                    DWalletImportedKeyVerificationPublicInputByCurve::Secp256r1(public_input),
                advance_request:
                    DWalletImportedKeyVerificationAdvanceRequestByCurve::Secp256r1(advance_request),
                data,
                ..
            } => compute_imported_key_verification::<Secp256r1AsyncDKGProtocol>(
                data.curve,
                session_id,
                party_id,
                access_structure,
                advance_request,
                &public_input.clone(),
                &mut rng,
            ),
            ProtocolCryptographicData::ImportedKeyVerification {
                public_input:
                    DWalletImportedKeyVerificationPublicInputByCurve::Curve25519(public_input),
                advance_request:
                    DWalletImportedKeyVerificationAdvanceRequestByCurve::Curve25519(advance_request),
                data,
                ..
            } => compute_imported_key_verification::<Curve25519AsyncDKGProtocol>(
                data.curve,
                session_id,
                party_id,
                access_structure,
                advance_request,
                &public_input.clone(),
                &mut rng,
            ),
            ProtocolCryptographicData::ImportedKeyVerification {
                public_input:
                    DWalletImportedKeyVerificationPublicInputByCurve::Ristretto(public_input),
                advance_request:
                    DWalletImportedKeyVerificationAdvanceRequestByCurve::Ristretto(advance_request),
                data,
                ..
            } => compute_imported_key_verification::<RistrettoAsyncDKGProtocol>(
                data.curve,
                session_id,
                party_id,
                access_structure,
                advance_request,
                &public_input.clone(),
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
                ..
            } => Ok(compute_presign::<Secp256k1ECDSAProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                None,
                false,
                &mut rng,
            )?),
            ProtocolCryptographicData::Presign {
                public_input: PresignPublicInputByProtocol::Taproot(public_input),
                advance_request: PresignAdvanceRequestByProtocol::Taproot(advance_request),
                ..
            } => Ok(compute_presign::<Secp256k1TaprootProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                None,
                false,
                &mut rng,
            )?),
            ProtocolCryptographicData::Presign {
                public_input: PresignPublicInputByProtocol::Secp256r1ECDSA(public_input),
                advance_request: PresignAdvanceRequestByProtocol::Secp256r1ECDSA(advance_request),
                ..
            } => Ok(compute_presign::<Secp256r1ECDSAProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                None,
                false,
                &mut rng,
            )?),
            ProtocolCryptographicData::Presign {
                public_input: PresignPublicInputByProtocol::EdDSA(public_input),
                advance_request: PresignAdvanceRequestByProtocol::EdDSA(advance_request),
                ..
            } => Ok(compute_presign::<Curve25519EdDSAProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                None,
                false,
                &mut rng,
            )?),
            ProtocolCryptographicData::Presign {
                public_input: PresignPublicInputByProtocol::Schnorrkel(public_input),
                advance_request: PresignAdvanceRequestByProtocol::Schnorrkel(advance_request),
                ..
            } => Ok(compute_presign::<RistrettoSchnorrkelProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                None,
                false,
                &mut rng,
            )?),
            ProtocolCryptographicData::InternalPresign {
                public_input: PresignPublicInputByProtocol::Secp256k1ECDSA(public_input),
                advance_request: PresignAdvanceRequestByProtocol::Secp256k1ECDSA(advance_request),
                ..
            } => Ok(compute_presign::<Secp256k1ECDSAProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                None,
                true,
                &mut rng,
            )?),
            ProtocolCryptographicData::InternalPresign {
                public_input: PresignPublicInputByProtocol::Taproot(public_input),
                advance_request: PresignAdvanceRequestByProtocol::Taproot(advance_request),
                ..
            } => Ok(compute_presign::<Secp256k1TaprootProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                None,
                true,
                &mut rng,
            )?),
            ProtocolCryptographicData::InternalPresign {
                public_input: PresignPublicInputByProtocol::Secp256r1ECDSA(public_input),
                advance_request: PresignAdvanceRequestByProtocol::Secp256r1ECDSA(advance_request),
                ..
            } => Ok(compute_presign::<Secp256r1ECDSAProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                None,
                true,
                &mut rng,
            )?),
            ProtocolCryptographicData::InternalPresign {
                public_input: PresignPublicInputByProtocol::EdDSA(public_input),
                advance_request: PresignAdvanceRequestByProtocol::EdDSA(advance_request),
                ..
            } => Ok(compute_presign::<Curve25519EdDSAProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                None,
                true,
                &mut rng,
            )?),
            ProtocolCryptographicData::InternalPresign {
                public_input: PresignPublicInputByProtocol::Schnorrkel(public_input),
                advance_request: PresignAdvanceRequestByProtocol::Schnorrkel(advance_request),
                ..
            } => Ok(compute_presign::<RistrettoSchnorrkelProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                None,
                true,
                &mut rng,
            )?),
            // Fast Schnorr (VSS) presign: the `PrivateInput` is the validator's
            // curve25519 HPKE secret (one keypair serves all VSS curves), derived
            // locally from `root_seed`. It is deliberately non-serializable, so it
            // is constructed here rather than threaded through the serialized seam.
            ProtocolCryptographicData::Presign {
                public_input: PresignPublicInputByProtocol::TaprootVSS(public_input),
                advance_request: PresignAdvanceRequestByProtocol::TaprootVSS(advance_request),
                ..
            } => Ok(compute_presign::<Secp256k1TaprootVSSProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                Some(vss_presign_private_input(vss_hpke_secret_key)),
                false,
                &mut rng,
            )?),
            ProtocolCryptographicData::Presign {
                public_input: PresignPublicInputByProtocol::EdDSAVSS(public_input),
                advance_request: PresignAdvanceRequestByProtocol::EdDSAVSS(advance_request),
                ..
            } => Ok(compute_presign::<Curve25519EdDSAVSSProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                Some(vss_presign_private_input(vss_hpke_secret_key)),
                false,
                &mut rng,
            )?),
            ProtocolCryptographicData::Presign {
                public_input: PresignPublicInputByProtocol::SchnorrkelVSS(public_input),
                advance_request: PresignAdvanceRequestByProtocol::SchnorrkelVSS(advance_request),
                ..
            } => Ok(compute_presign::<RistrettoSchnorrkelVSSProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                Some(vss_presign_private_input(vss_hpke_secret_key)),
                false,
                &mut rng,
            )?),
            ProtocolCryptographicData::InternalPresign {
                public_input: PresignPublicInputByProtocol::TaprootVSS(public_input),
                advance_request: PresignAdvanceRequestByProtocol::TaprootVSS(advance_request),
                ..
            } => Ok(compute_presign::<Secp256k1TaprootVSSProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                Some(vss_presign_private_input(vss_hpke_secret_key)),
                true,
                &mut rng,
            )?),
            ProtocolCryptographicData::InternalPresign {
                public_input: PresignPublicInputByProtocol::EdDSAVSS(public_input),
                advance_request: PresignAdvanceRequestByProtocol::EdDSAVSS(advance_request),
                ..
            } => Ok(compute_presign::<Curve25519EdDSAVSSProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                Some(vss_presign_private_input(vss_hpke_secret_key)),
                true,
                &mut rng,
            )?),
            ProtocolCryptographicData::InternalPresign {
                public_input: PresignPublicInputByProtocol::SchnorrkelVSS(public_input),
                advance_request: PresignAdvanceRequestByProtocol::SchnorrkelVSS(advance_request),
                ..
            } => Ok(compute_presign::<RistrettoSchnorrkelVSSProtocol>(
                party_id,
                access_structure,
                session_id,
                advance_request,
                public_input,
                Some(vss_presign_private_input(vss_hpke_secret_key)),
                true,
                &mut rng,
            )?),
            ProtocolCryptographicData::Sign {
                public_input: SignPublicInputByProtocol::Secp256k1ECDSA(public_input),
                advance_request: SignAdvanceRequestByProtocol::Secp256k1ECDSA(advance_request),
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

                compute_sign::<Secp256k1ECDSAProtocol>(
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
            ProtocolCryptographicData::Sign {
                public_input: SignPublicInputByProtocol::Secp256k1Taproot(public_input),
                advance_request: SignAdvanceRequestByProtocol::Secp256k1Taproot(advance_request),
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

                compute_sign::<Secp256k1TaprootProtocol>(
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
            ProtocolCryptographicData::Sign {
                public_input: SignPublicInputByProtocol::Secp256r1(public_input),
                advance_request: SignAdvanceRequestByProtocol::Secp256r1(advance_request),
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

                compute_sign::<Secp256r1ECDSAProtocol>(
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
            ProtocolCryptographicData::Sign {
                public_input: SignPublicInputByProtocol::Curve25519(public_input),
                advance_request: SignAdvanceRequestByProtocol::Curve25519(advance_request),
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

                compute_sign::<Curve25519EdDSAProtocol>(
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
            ProtocolCryptographicData::Sign {
                public_input: SignPublicInputByProtocol::Ristretto(public_input),
                advance_request: SignAdvanceRequestByProtocol::Ristretto(advance_request),
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

                compute_sign::<RistrettoSchnorrkelProtocol>(
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
            ProtocolCryptographicData::Sign {
                public_input,
                advance_request,
                ..
            } => Err(DwalletMPCError::MPCParametersMissmatchInputToRequest(
                public_input.to_string(),
                advance_request.to_string(),
            )),
            // Fast Schnorr (VSS) sign: assemble the 8-field VSS PrivateInput here
            // (root_seed is available) — secret-key Shamir shares recovered from the
            // reconfiguration output + the persisted presign nonce data — then run
            // the generic sign. VSS has no expected_decrypters metrics.
            ProtocolCryptographicData::SignVSS {
                public_input: SignPublicInputByProtocol::TaprootVSS(public_input),
                advance_request: SignAdvanceRequestByProtocol::TaprootVSS(advance_request),
                vss_shamir_cache,
                presign_private_output,
                data,
                ..
            } => {
                let private_input = build_secp256k1_taproot_vss_sign_private_input(
                    &vss_shamir_cache,
                    presign_private_output,
                    public_input.presign.session_id,
                    public_input.presign.presign_blending_index,
                )?;
                compute_sign::<Secp256k1TaprootVSSProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(private_input),
                    &data,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::SignVSS {
                public_input: SignPublicInputByProtocol::EdDSAVSS(public_input),
                advance_request: SignAdvanceRequestByProtocol::EdDSAVSS(advance_request),
                vss_shamir_cache,
                presign_private_output,
                data,
                ..
            } => {
                let private_input = build_curve25519_eddsa_vss_sign_private_input(
                    &vss_shamir_cache,
                    presign_private_output,
                    public_input.presign.session_id,
                    public_input.presign.presign_blending_index,
                )?;
                compute_sign::<Curve25519EdDSAVSSProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(private_input),
                    &data,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::SignVSS {
                public_input: SignPublicInputByProtocol::SchnorrkelVSS(public_input),
                advance_request: SignAdvanceRequestByProtocol::SchnorrkelVSS(advance_request),
                vss_shamir_cache,
                presign_private_output,
                data,
                ..
            } => {
                let private_input = build_ristretto_schnorrkel_vss_sign_private_input(
                    &vss_shamir_cache,
                    presign_private_output,
                    public_input.presign.session_id,
                    public_input.presign.presign_blending_index,
                )?;
                compute_sign::<RistrettoSchnorrkelVSSProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(private_input),
                    &data,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::SignVSS {
                public_input,
                advance_request,
                ..
            } => Err(DwalletMPCError::MPCParametersMissmatchInputToRequest(
                public_input.to_string(),
                advance_request.to_string(),
            )),
            // NOA Fast Schnorr (VSS) sign: identical compute to `SignVSS`, but `data`
            // is the native `NetworkOwnedAddressSignData`, coerced to `SignData` only
            // here (mirroring the AHE `NetworkOwnedAddressSign` compute arms).
            ProtocolCryptographicData::NetworkOwnedAddressSignVSS {
                public_input: SignPublicInputByProtocol::TaprootVSS(public_input),
                advance_request: SignAdvanceRequestByProtocol::TaprootVSS(advance_request),
                vss_shamir_cache,
                presign_private_output,
                data,
                ..
            } => {
                let private_input = build_secp256k1_taproot_vss_sign_private_input(
                    &vss_shamir_cache,
                    presign_private_output,
                    public_input.presign.session_id,
                    public_input.presign.presign_blending_index,
                )?;
                compute_sign::<Secp256k1TaprootVSSProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(private_input),
                    &SignData::from(&data),
                    &mut rng,
                )
            }
            ProtocolCryptographicData::NetworkOwnedAddressSignVSS {
                public_input: SignPublicInputByProtocol::EdDSAVSS(public_input),
                advance_request: SignAdvanceRequestByProtocol::EdDSAVSS(advance_request),
                vss_shamir_cache,
                presign_private_output,
                data,
                ..
            } => {
                let private_input = build_curve25519_eddsa_vss_sign_private_input(
                    &vss_shamir_cache,
                    presign_private_output,
                    public_input.presign.session_id,
                    public_input.presign.presign_blending_index,
                )?;
                compute_sign::<Curve25519EdDSAVSSProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(private_input),
                    &SignData::from(&data),
                    &mut rng,
                )
            }
            ProtocolCryptographicData::NetworkOwnedAddressSignVSS {
                public_input: SignPublicInputByProtocol::SchnorrkelVSS(public_input),
                advance_request: SignAdvanceRequestByProtocol::SchnorrkelVSS(advance_request),
                vss_shamir_cache,
                presign_private_output,
                data,
                ..
            } => {
                let private_input = build_ristretto_schnorrkel_vss_sign_private_input(
                    &vss_shamir_cache,
                    presign_private_output,
                    public_input.presign.session_id,
                    public_input.presign.presign_blending_index,
                )?;
                compute_sign::<RistrettoSchnorrkelVSSProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(private_input),
                    &SignData::from(&data),
                    &mut rng,
                )
            }
            ProtocolCryptographicData::NetworkOwnedAddressSignVSS {
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
                    &data.signature_algorithm,
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
                    &data.signature_algorithm,
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
                    &data.signature_algorithm,
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
                    &data.signature_algorithm,
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

                compute_dwallet_dkg_and_sign::<RistrettoSchnorrkelProtocol>(
                    data.curve,
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &data.signature_algorithm,
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
            // Fast Schnorr (VSS) combined DKG-and-sign: assemble the VSS `PrivateInput`
            // from the secret-key-share source + persisted presign nonce data (the
            // builder is shared verbatim with standalone VSS sign — the private-input
            // type is identical), reading the presign id/index from
            // `public_input.presign`. VSS has no AHE decrypters, so there is no
            // `update_expected_decrypters_metrics` here (as in the `SignVSS` arms).
            ProtocolCryptographicData::DWalletDKGAndSignVSS {
                public_input: DKGAndSignPublicInputByProtocol::TaprootVSS(public_input),
                advance_request:
                    DWalletDKGAndSignAdvanceRequestByProtocol::TaprootVSS(advance_request),
                vss_shamir_cache,
                presign_private_output,
                data,
                ..
            } => {
                let private_input = build_secp256k1_taproot_vss_sign_private_input(
                    &vss_shamir_cache,
                    presign_private_output,
                    public_input.presign.session_id,
                    public_input.presign.presign_blending_index,
                )?;
                compute_dwallet_dkg_and_sign::<Secp256k1TaprootVSSProtocol>(
                    data.curve,
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(private_input),
                    &data.signature_algorithm,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::DWalletDKGAndSignVSS {
                public_input: DKGAndSignPublicInputByProtocol::EdDSAVSS(public_input),
                advance_request:
                    DWalletDKGAndSignAdvanceRequestByProtocol::EdDSAVSS(advance_request),
                vss_shamir_cache,
                presign_private_output,
                data,
                ..
            } => {
                let private_input = build_curve25519_eddsa_vss_sign_private_input(
                    &vss_shamir_cache,
                    presign_private_output,
                    public_input.presign.session_id,
                    public_input.presign.presign_blending_index,
                )?;
                compute_dwallet_dkg_and_sign::<Curve25519EdDSAVSSProtocol>(
                    data.curve,
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(private_input),
                    &data.signature_algorithm,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::DWalletDKGAndSignVSS {
                public_input: DKGAndSignPublicInputByProtocol::SchnorrkelVSS(public_input),
                advance_request:
                    DWalletDKGAndSignAdvanceRequestByProtocol::SchnorrkelVSS(advance_request),
                vss_shamir_cache,
                presign_private_output,
                data,
                ..
            } => {
                let private_input = build_ristretto_schnorrkel_vss_sign_private_input(
                    &vss_shamir_cache,
                    presign_private_output,
                    public_input.presign.session_id,
                    public_input.presign.presign_blending_index,
                )?;
                compute_dwallet_dkg_and_sign::<RistrettoSchnorrkelVSSProtocol>(
                    data.curve,
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(private_input),
                    &data.signature_algorithm,
                    &mut rng,
                )
            }
            ProtocolCryptographicData::DWalletDKGAndSignVSS {
                public_input,
                advance_request,
                ..
            } => Err(DwalletMPCError::MPCParametersMissmatchInputToRequest(
                public_input.to_string(),
                advance_request.to_string(),
            )),
            ProtocolCryptographicData::NetworkOwnedAddressSign {
                public_input: SignPublicInputByProtocol::Secp256k1ECDSA(public_input),
                advance_request: SignAdvanceRequestByProtocol::Secp256k1ECDSA(advance_request),
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

                compute_sign::<Secp256k1ECDSAProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &SignData::from(&data),
                    &mut rng,
                )
            }
            ProtocolCryptographicData::NetworkOwnedAddressSign {
                public_input: SignPublicInputByProtocol::Secp256k1Taproot(public_input),
                advance_request: SignAdvanceRequestByProtocol::Secp256k1Taproot(advance_request),
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

                compute_sign::<Secp256k1TaprootProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &SignData::from(&data),
                    &mut rng,
                )
            }
            ProtocolCryptographicData::NetworkOwnedAddressSign {
                public_input: SignPublicInputByProtocol::Secp256r1(public_input),
                advance_request: SignAdvanceRequestByProtocol::Secp256r1(advance_request),
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

                compute_sign::<Secp256r1ECDSAProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &SignData::from(&data),
                    &mut rng,
                )
            }
            ProtocolCryptographicData::NetworkOwnedAddressSign {
                public_input: SignPublicInputByProtocol::Curve25519(public_input),
                advance_request: SignAdvanceRequestByProtocol::Curve25519(advance_request),
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

                compute_sign::<Curve25519EdDSAProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &SignData::from(&data),
                    &mut rng,
                )
            }
            ProtocolCryptographicData::NetworkOwnedAddressSign {
                public_input: SignPublicInputByProtocol::Ristretto(public_input),
                advance_request: SignAdvanceRequestByProtocol::Ristretto(advance_request),
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

                compute_sign::<RistrettoSchnorrkelProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input,
                    Some(decryption_key_shares),
                    &SignData::from(&data),
                    &mut rng,
                )
            }
            ProtocolCryptographicData::NetworkOwnedAddressSign {
                public_input,
                advance_request,
                ..
            } => Err(DwalletMPCError::MPCParametersMissmatchInputToRequest(
                public_input.to_string(),
                advance_request.to_string(),
            )),
            ProtocolCryptographicData::NetworkEncryptionKeyDkg {
                public_input,
                advance_request,
                class_groups_decryption_key,
            } => advance_network_dkg_v2(
                session_id,
                access_structure,
                public_input,
                party_id,
                advance_request,
                class_groups_decryption_key,
                &mut rng,
            ),
            ProtocolCryptographicData::NetworkEncryptionKeyReconfiguration {
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
                        // Wrap the public output with its version: always the
                        // aggregated (V4) shape — pre-aggregation (V3) output
                        // production was removed with protocol v4 support.
                        //
                        // Deliberately the CONCRETE non-aggregated type, not the
                        // Party's associated output type: this decode-and-upgrade
                        // is correct only while the reconfiguration Party's wire
                        // output is the non-aggregated shape. When the Party
                        // migrates to the aggregated output post-upgrade, this
                        // site must be revisited — a hardcoded type makes that a
                        // loud failure instead of a silent misinterpretation.
                        let public_output: twopc_mpc::decentralized_party::reconfiguration::NonAggregatedPublicOutput =
                            bcs::from_bytes(&public_output_value)?;
                        info!(
                            session_identifier=?session_identifier,
                            "persisting aggregated (V4) network-key reconfiguration output"
                        );
                        let public_output_value =
                            bcs::to_bytes(&VersionedDecryptionKeyReconfigurationOutput::V4(
                                bcs::to_bytes(&public_output.upgrade()?)?,
                            ))?;

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

/// Constructs the Fast Schnorr (VSS) presign `PrivateInput` — the validator's
/// curve25519 HPKE secret — from its `RootSeed`. One curve25519 keypair serves
/// all VSS signing curves, so the same `PrivateInput` type is used for every VSS
/// presign protocol. The secret is non-serializable and so is built here at the
/// compute layer rather than threaded through the serialized `MPCPrivateInput`.
fn vss_presign_private_input(
    vss_hpke_secret_key: group::curve25519::Scalar,
) -> twopc_mpc::schnorr::vss::presign::decentralized_party::PrivateInput {
    twopc_mpc::schnorr::vss::presign::decentralized_party::PrivateInput::new(vss_hpke_secret_key)
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
        DWalletSignatureAlgorithm::Schnorrkel => {
            let signature: SchnorrkelSignature = bcs::from_bytes(&public_output_value)?;

            Ok(signature.to_bytes().to_vec())
        }
        DWalletSignatureAlgorithm::Taproot => {
            let signature: TaprootSignature = bcs::from_bytes(&public_output_value)?;

            Ok(signature.to_bytes().to_vec())
        }
        // Fast Schnorr (VSS) produces the same signature object as its AHE sibling.
        DWalletSignatureAlgorithm::TaprootVSS => {
            let signature: TaprootSignature = bcs::from_bytes(&public_output_value)?;

            Ok(signature.to_bytes().to_vec())
        }
        DWalletSignatureAlgorithm::EdDSAVSS => {
            let signature: EdDSASignature = bcs::from_bytes(&public_output_value)?;

            Ok(signature.to_bytes().to_vec())
        }
        DWalletSignatureAlgorithm::SchnorrkelVSS => {
            let signature: SchnorrkelSignature = bcs::from_bytes(&public_output_value)?;

            Ok(signature.to_bytes().to_vec())
        }
    }
}

fn try_ready_to_advance<P: mpc::Party + mpc::AsynchronouslyAdvanceable>(
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    consensus_round: u64,
    mpc_round_to_consensus_rounds_delay: HashMap<u64, u64>,
    serialized_messages_by_consensus_round: &HashMap<u64, HashMap<PartyID, Vec<u8>>>,
) -> DwalletMPCResult<Option<AdvanceRequest<<P>::Message>>> {
    let advance_request_result = mpc::guaranteed_output_delivery::Party::<P>::ready_to_advance(
        party_id,
        access_structure,
        consensus_round,
        mpc_round_to_consensus_rounds_delay,
        serialized_messages_by_consensus_round,
    )
    .map_err(|e| DwalletMPCError::FailedToAdvanceMPC(e.into()))?;

    match advance_request_result {
        ReadyToAdvanceResult::ReadyToAdvance(advance_request) => Ok(Some(advance_request)),
        _ => Ok(None),
    }
}
