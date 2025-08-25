// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::encrypt_user_share::verify_encrypted_share;
use crate::dwallet_mpc::make_dwallet_user_secret_key_shares_public::verify_secret_share;
use crate::dwallet_mpc::mpc_session::PublicInput;
use crate::dwallet_mpc::protocol_cryptographic_data::ProtocolCryptographicData;
use crate::dwallet_mpc::sign::verify_partial_signature;
use crate::dwallet_session_request::DWalletSessionRequestMetricData;
use crate::request_protocol_data::ProtocolData;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::SessionIdentifier;
use message_digest::message_digest::message_digest;
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
                return Err(DwalletMPCError::InvalidSessionType);
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
                protocol_public_parameters,
                ..
            } => {
                let hashed_message = bcs::to_bytes(
                    &message_digest(&data.message, &data.hash_type)
                        .map_err(|err| DwalletMPCError::MessageDigest(err.to_string()))?,
                )?;

                verify_partial_signature(
                    &hashed_message,
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
                    protocol_public_parameters.clone(),
                    data.public_user_secret_key_shares.clone(),
                    data.dwallet_decentralized_output.clone(),
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
                return Err(DwalletMPCError::InvalidSessionType);
            }
        };

        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
            public_output_value,
            private_output: vec![],
            malicious_parties: vec![],
        })
    }
}
