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
use group::HashType;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    Curve25519EdDSAProtocol, RistrettoSchnorrkelSubstrateProtocol, Secp256K1ECDSAProtocol,
    Secp256K1TaprootProtocol, Secp256R1ECDSAProtocol, SessionIdentifier,
};
use mpc::GuaranteedOutputDeliveryRoundResult;
use std::sync::Arc;
use tracing::error;

pub(crate) mod encrypt_user_share;
pub(crate) mod make_dwallet_user_secret_key_shares_public;

impl ProtocolCryptographicData {
    pub fn try_new_native(
        protocol_specific_data: &ProtocolData,
        public_input: PublicInput,
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
                ..
            } => {
                match verify_encrypted_share(
                    &data.encrypted_centralized_secret_share_and_proof,
                    &data.decentralized_public_output,
                    &data.encryption_key,
                    protocol_public_parameters.clone(),
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
            } => {
                verify_partial_signature::<Secp256K1ECDSAProtocol>(
                    &data.message,
                    &HashType::try_from(data.hash_type.clone() as u32)
                        .map_err(|err| DwalletMPCError::InternalError(err.to_string()))?,
                    &data.dwallet_decentralized_output,
                    &data.presign,
                    &data.partially_signed_message,
                    &protocol_public_parameters,
                )?;
                Vec::new()
            }
            ProtocolCryptographicData::PartialSignatureVerification {
                data,
                protocol_public_parameters:
                    ProtocolPublicParametersByCurve::Secp256r1(protocol_public_parameters),
                ..
            } => {
                verify_partial_signature::<Secp256R1ECDSAProtocol>(
                    &data.message,
                    &HashType::try_from(data.hash_type.clone() as u32)
                        .map_err(|err| DwalletMPCError::InternalError(err.to_string()))?,
                    &data.dwallet_decentralized_output,
                    &data.presign,
                    &data.partially_signed_message,
                    &protocol_public_parameters,
                )?;
                Vec::new()
            }
            ProtocolCryptographicData::PartialSignatureVerification {
                data,
                protocol_public_parameters:
                    ProtocolPublicParametersByCurve::Curve25519(protocol_public_parameters),
                ..
            } => {
                verify_partial_signature::<Curve25519EdDSAProtocol>(
                    &data.message,
                    &HashType::try_from(data.hash_type.clone() as u32)
                        .map_err(|err| DwalletMPCError::InternalError(err.to_string()))?,
                    &data.dwallet_decentralized_output,
                    &data.presign,
                    &data.partially_signed_message,
                    &protocol_public_parameters,
                )?;
                Vec::new()
            }
            ProtocolCryptographicData::PartialSignatureVerification {
                data,
                protocol_public_parameters:
                    ProtocolPublicParametersByCurve::Ristretto(protocol_public_parameters),
                ..
            } => {
                verify_partial_signature::<RistrettoSchnorrkelSubstrateProtocol>(
                    &data.message,
                    &HashType::try_from(data.hash_type.clone() as u32)
                        .map_err(|err| DwalletMPCError::InternalError(err.to_string()))?,
                    &data.dwallet_decentralized_output,
                    &data.presign,
                    &data.partially_signed_message,
                    &protocol_public_parameters,
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
