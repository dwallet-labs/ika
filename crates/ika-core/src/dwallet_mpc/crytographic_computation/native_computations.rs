// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::protocol_public_parameters::ProtocolPublicParametersByCurve;
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::encrypt_user_share::verify_encrypted_share;
use crate::dwallet_mpc::make_dwallet_user_secret_key_shares_public::verify_secret_share;
use crate::dwallet_mpc::mpc_session::PublicInput;
use crate::dwallet_mpc::protocol_cryptographic_data::ProtocolCryptographicData;
use crate::dwallet_mpc::sign::verify_partial_signature;
use crate::dwallet_session_request::DWalletSessionRequestMetricData;
use crate::request_protocol_data::ProtocolData;
use class_groups::CiphertextSpaceGroupElement;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletSignatureAlgorithm, VersionedDwalletDKGPublicOutput, VersionedPresignOutput,
    VersionedUserSignedMessage,
};
use group::OsCsRng;
use ika_protocol_config::ProtocolVersion;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    Curve25519EdDSAProtocol, RistrettoSchnorrkelSubstrateProtocol, Secp256k1ECDSAProtocol,
    Secp256r1ECDSAProtocol, SessionIdentifier,
};
use mpc::GuaranteedOutputDeliveryRoundResult;
use std::sync::Arc;
use tracing::error;
use twopc_mpc::secp256k1::class_groups::{NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, TaprootProtocol};
use twopc_mpc::sign;

pub(crate) mod encrypt_user_share;
pub(crate) mod make_dwallet_user_secret_key_shares_public;

impl ProtocolCryptographicData {
    pub fn try_new_native(
        protocol_specific_data: &ProtocolData,
        public_input: PublicInput,
        protocol_version: ProtocolVersion,
    ) -> Result<Option<Self>, DwalletMPCError> {
        let res = match protocol_specific_data {
            ProtocolData::MakeDWalletUserSecretKeySharesPublic { data, .. } => {
                let PublicInput::MakeDWalletUserSecretKeySharesPublic(public_input) = public_input
                else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };
                ProtocolCryptographicData::MakeDWalletUserSecretKeySharesPublic {
                    data: data.clone(),
                    protocol_public_parameters: public_input.clone(),
                }
            }
            ProtocolData::PartialSignatureVerification { data, .. } => {
                let PublicInput::PartialSignatureVerification(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                ProtocolCryptographicData::PartialSignatureVerification {
                    data: data.clone(),
                    protocol_public_parameters: public_input.clone(),
                }
            }
            ProtocolData::EncryptedShareVerification { data, .. } => {
                let PublicInput::EncryptedShareVerification(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                ProtocolCryptographicData::EncryptedShareVerification {
                    data: data.clone(),
                    protocol_public_parameters: public_input.clone(),
                    protocol_version,
                }
            }
            _ => {
                return Err(DwalletMPCError::InvalidDWalletProtocolType);
            }
        };

        Ok(Some(res))
    }

    pub(crate) fn compute_native(
        &self,
        session_identifier: SessionIdentifier,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
    ) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
        let protocol_metadata: DWalletSessionRequestMetricData = self.into();
        dwallet_mpc_metrics.add_compute_native_call(&protocol_metadata);

        let public_output_value = match self {
            ProtocolCryptographicData::EncryptedShareVerification {
                data,
                protocol_public_parameters,
                protocol_version,
                ..
            } => {
                match verify_encrypted_share(
                    &data.encrypted_centralized_secret_share_and_proof,
                    &data.decentralized_public_output,
                    &data.encryption_key,
                    protocol_public_parameters.clone(),
                    *protocol_version,
                ) {
                    Ok(_) => Vec::new(),
                    Err(err) => return Err(err),
                }
            }
            ProtocolCryptographicData::PartialSignatureVerification {
                data,
                protocol_public_parameters:
                    ProtocolPublicParametersByCurve::Secp256k1(protocol_public_parameters),
                ..
            } => match bcs::from_bytes(&data.presign)? {
                VersionedPresignOutput::V1(presign) => {
                    let dkg_output = bcs::from_bytes(&data.dwallet_decentralized_output)?;
                    let partially_signed_message = bcs::from_bytes(&data.partially_signed_message)?;
                    let message = &data.message;
                    let hash_scheme = data.hash_scheme;
                    let decentralized_dkg_output = match dkg_output {
                            VersionedDwalletDKGPublicOutput::V1(output) => {
                                bcs::from_bytes::<<Secp256k1ECDSAProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyTargetedDKGOutput>(output.as_slice())?.into()
                            }
                            VersionedDwalletDKGPublicOutput::V2{dkg_output, ..} => {
                                bcs::from_bytes::<<Secp256k1ECDSAProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput>(dkg_output.as_slice())?
                            }
                        };

                    let presign: twopc_mpc::ecdsa::presign::Presign<
                        group::secp256k1::group_element::Value,
                        group::Value<
                            CiphertextSpaceGroupElement<{ NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
                        >,
                    > = bcs::from_bytes(&presign)?;
                    let VersionedUserSignedMessage::V1(partially_signed_message) =
                        partially_signed_message;
                    let partial: <Secp256k1ECDSAProtocol as twopc_mpc::sign::Protocol>::SignMessage =
                            bcs::from_bytes(&partially_signed_message)?;

                    <Secp256k1ECDSAProtocol as sign::Protocol>::verify_centralized_party_partial_signature(
                        message,
                        hash_scheme,
                        decentralized_dkg_output,
                        presign.into(),
                        partial,
                        protocol_public_parameters,
                        &mut OsCsRng,
                        )
                            .map_err(DwalletMPCError::from)?;
                    Vec::new()
                }
                VersionedPresignOutput::V2(_) => {
                    match data.signature_algorithm {
                        DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                            verify_partial_signature::<Secp256k1ECDSAProtocol>(
                                &data.message,
                                &data.hash_scheme,
                                &data.dwallet_decentralized_output,
                                &data.presign,
                                &data.partially_signed_message,
                                protocol_public_parameters,
                            )?;
                        }
                        DWalletSignatureAlgorithm::Taproot => {
                            verify_partial_signature::<TaprootProtocol>(
                                &data.message,
                                &data.hash_scheme,
                                &data.dwallet_decentralized_output,
                                &data.presign,
                                &data.partially_signed_message,
                                protocol_public_parameters,
                            )?;
                        }
                        _ => {
                            return Err(DwalletMPCError::CurveToProtocolMismatch {
                                curve: data.curve,
                                protocol: data.signature_algorithm,
                            });
                        }
                    }
                    Vec::new()
                }
            },
            ProtocolCryptographicData::PartialSignatureVerification {
                data,
                protocol_public_parameters:
                    ProtocolPublicParametersByCurve::Secp256r1(protocol_public_parameters),
                ..
            } => {
                if data.signature_algorithm != DWalletSignatureAlgorithm::ECDSASecp256r1 {
                    return Err(DwalletMPCError::CurveToProtocolMismatch {
                        curve: data.curve,
                        protocol: data.signature_algorithm,
                    });
                }

                verify_partial_signature::<Secp256r1ECDSAProtocol>(
                    &data.message,
                    &data.hash_scheme,
                    &data.dwallet_decentralized_output,
                    &data.presign,
                    &data.partially_signed_message,
                    protocol_public_parameters,
                )?;
                Vec::new()
            }
            ProtocolCryptographicData::PartialSignatureVerification {
                data,
                protocol_public_parameters:
                    ProtocolPublicParametersByCurve::Curve25519(protocol_public_parameters),
                ..
            } => {
                if data.signature_algorithm != DWalletSignatureAlgorithm::EdDSA {
                    return Err(DwalletMPCError::CurveToProtocolMismatch {
                        curve: data.curve,
                        protocol: data.signature_algorithm,
                    });
                }

                verify_partial_signature::<Curve25519EdDSAProtocol>(
                    &data.message,
                    &data.hash_scheme,
                    &data.dwallet_decentralized_output,
                    &data.presign,
                    &data.partially_signed_message,
                    protocol_public_parameters,
                )?;
                Vec::new()
            }
            ProtocolCryptographicData::PartialSignatureVerification {
                data,
                protocol_public_parameters:
                    ProtocolPublicParametersByCurve::Ristretto(protocol_public_parameters),
                ..
            } => {
                if data.signature_algorithm != DWalletSignatureAlgorithm::SchnorrkelSubstrate {
                    return Err(DwalletMPCError::CurveToProtocolMismatch {
                        curve: data.curve,
                        protocol: data.signature_algorithm,
                    });
                }

                verify_partial_signature::<RistrettoSchnorrkelSubstrateProtocol>(
                    &data.message,
                    &data.hash_scheme,
                    &data.dwallet_decentralized_output,
                    &data.presign,
                    &data.partially_signed_message,
                    protocol_public_parameters,
                )?;
                Vec::new()
            }
            ProtocolCryptographicData::MakeDWalletUserSecretKeySharesPublic {
                protocol_public_parameters,
                data,
                ..
            } => {
                match verify_secret_share(
                    data.public_user_secret_key_shares.clone(),
                    data.dwallet_decentralized_output.clone(),
                    protocol_public_parameters.clone(),
                ) {
                    Ok(..) => data.public_user_secret_key_shares.clone(),
                    Err(err) => {
                        error!(
                            error=?err,
                            session_identifier=?session_identifier,
                            "failed to verify secret share"
                        );
                        return Err(DwalletMPCError::DWalletSecretNotMatchedDWalletOutput);
                    }
                }
            }
            _ => {
                error!(
                    session_type=?protocol_metadata,
                    session_identifier=?session_identifier,
                    "Invalid session type for native computation");
                return Err(DwalletMPCError::InvalidDWalletProtocolType);
            }
        };

        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
            public_output_value,
            private_output: vec![],
            malicious_parties: vec![],
        })
    }
}
