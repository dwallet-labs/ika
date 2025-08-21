// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::protocol_cryptographic_data::ProtocolCryptographicData;
use crate::dwallet_mpc::crytographic_computation::{ComputationId, MPC_SIGN_SECOND_ROUND};
use crate::dwallet_mpc::dwallet_dkg::{
    DWalletDKGFirstParty, DWalletDKGSecondParty, DWalletImportedKeyVerificationParty,
};
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::encrypt_user_share::verify_encrypted_share;
use crate::dwallet_mpc::make_dwallet_user_secret_key_shares_public::verify_secret_share;
use crate::dwallet_mpc::mpc_session::PublicInput;
use crate::dwallet_mpc::network_dkg::advance_network_dkg;
use crate::dwallet_mpc::presign::PresignParty;
use crate::dwallet_mpc::reconfiguration::ReconfigurationSecp256k1Party;
use crate::dwallet_mpc::sign::{SignParty, verify_partial_signature};
use crate::dwallet_session_request::DWalletSessionRequestMetricData;
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    VersionedDWalletImportedKeyVerificationOutput, VersionedDecryptionKeyReconfigurationOutput,
    VersionedDwalletDKGFirstRoundPublicOutput, VersionedDwalletDKGSecondRoundPublicOutput,
    VersionedPresignOutput, VersionedSignOutput,
};
use dwallet_rng::RootSeed;
use group::PartyID;
use ika_types::crypto::AuthorityPublicKeyBytes;
use ika_types::dwallet_mpc_error::{DwalletError, DwalletResult};
use message_digest::message_digest::message_digest;
use mpc::guaranteed_output_delivery::Party;
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, WeightedThresholdAccessStructure,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info};

pub(crate) struct Request {
    pub(crate) party_id: PartyID,
    pub(crate) protocol_data: DWalletSessionRequestMetricData,
    pub(crate) validator_name: AuthorityPublicKeyBytes,
    pub(crate) access_structure: WeightedThresholdAccessStructure,
    pub(crate) protocol_cryptographic_data: ProtocolCryptographicData,
}

impl Request {
    /// Perform a cryptographic computation.
    /// Notice: `root_seed` must be kept private!
    pub(crate) fn compute(
        self,
        computation_id: ComputationId,
        root_seed: RootSeed,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
    ) -> DwalletResult<GuaranteedOutputDeliveryRoundResult> {
        info!(
            mpc_protocol=?self.protocol_data.to_string(),
            validator=?self.validator_name,
            session_identifier=?computation_id.session_identifier,
            mpc_round=?computation_id.current_round,
            access_structure=?self.access_structure,
            "Advancing an MPC session"
        );
        let session_id =
            CommitmentSizedNumber::from_le_slice(&computation_id.session_identifier.into_bytes());

        // Derive a one-time use, MPC protocol and round specific, deterministic random generator
        // from the private seed.
        // This should only be used to `advance()` this specific round, and is guaranteed to be
        // deterministic — if we attempt to run the round twice, the same message will be generated.
        // SECURITY NOTICE: don't use for anything else other than (this particular) `advance()`,
        // and keep private!
        let mut rng = root_seed.mpc_round_rng(
            session_id,
            computation_id.current_round,
            computation_id.consensus_round,
        );

        match self.protocol_cryptographic_data {
            ProtocolCryptographicData::ImportedKeyVerification {
                public_input,
                data,
                advance_request,
                ..
            } => {
                let result =
                    Party::<DWalletImportedKeyVerificationParty>::advance_with_guaranteed_output(
                        session_id,
                        self.party_id,
                        &self.access_structure,
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
                        // Verify the encrypted share before finalizing, guaranteeing a two-for-one
                        // computation of both that the key import was successful, and
                        // the encrypted user share is valid.
                        verify_encrypted_share(
                            &data.encrypted_centralized_secret_share_and_proof,
                            &bcs::to_bytes(&VersionedDwalletDKGSecondRoundPublicOutput::V1(
                                public_output_value.clone(),
                            ))?,
                            &data.encryption_key,
                            public_input.protocol_public_parameters.clone(),
                        )?;

                        // Wrap the public output with its version.
                        let public_output_value = bcs::to_bytes(
                            &VersionedDWalletImportedKeyVerificationOutput::V1(public_output_value),
                        )?;

                        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                            public_output_value,
                            malicious_parties,
                            private_output,
                        })
                    }
                }
            }
            ProtocolCryptographicData::DKGFirst {
                public_input,
                advance_request,
                ..
            } => {
                let result = Party::<DWalletDKGFirstParty>::advance_with_guaranteed_output(
                    session_id,
                    self.party_id,
                    &self.access_structure,
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
                        // Wrap the public output with its version.
                        let public_output_value = bcs::to_bytes(
                            &VersionedDwalletDKGFirstRoundPublicOutput::V1(public_output_value),
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
                ..
            } => {
                let result = Party::<DWalletDKGSecondParty>::advance_with_guaranteed_output(
                    session_id,
                    self.party_id,
                    &self.access_structure,
                    advance_request,
                    None,
                    &public_input.clone(),
                    &mut rng,
                )?;

                if let GuaranteedOutputDeliveryRoundResult::Finalize {
                    public_output_value,
                    ..
                } = &result
                {
                    // Verify the encrypted share before finalizing, guaranteeing a two-for-one
                    // computation of both that the dkg was successful, and the encrypted user share is valid.
                    verify_encrypted_share(
                        &data.encrypted_centralized_secret_share_and_proof,
                        &bcs::to_bytes(&VersionedDwalletDKGSecondRoundPublicOutput::V1(
                            public_output_value.clone(),
                        ))?,
                        &data.encryption_key,
                        public_input.protocol_public_parameters.clone(),
                    )?;
                }

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
                            &VersionedDwalletDKGSecondRoundPublicOutput::V1(public_output_value),
                        )?;
                        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                            public_output_value,
                            malicious_parties,
                            private_output,
                        })
                    }
                }
            }
            ProtocolCryptographicData::Presign {
                public_input,
                advance_request,
                ..
            } => {
                let result = Party::<PresignParty>::advance_with_guaranteed_output(
                    session_id,
                    self.party_id,
                    &self.access_structure,
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
                        // Wrap the public output with its version.
                        let public_output_value =
                            bcs::to_bytes(&VersionedPresignOutput::V1(public_output_value))?;
                        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                            public_output_value,
                            malicious_parties,
                            private_output,
                        })
                    }
                }
            }
            ProtocolCryptographicData::Sign {
                public_input,
                advance_request,
                decryption_key_shares,
                ..
            } => {
                if computation_id.current_round == MPC_SIGN_SECOND_ROUND {
                    // Todo (#1408): Return update_expected_decrypters_metrics
                }

                let result = Party::<SignParty>::advance_with_guaranteed_output(
                    session_id,
                    self.party_id,
                    &self.access_structure,
                    advance_request,
                    Some(decryption_key_shares),
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
                        let public_output_value =
                            bcs::to_bytes(&VersionedSignOutput::V1(public_output_value))?;

                        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                            public_output_value,
                            malicious_parties,
                            private_output,
                        })
                    }
                }
            }
            ProtocolCryptographicData::NetworkEncryptionKeyDkg {
                data,
                public_input,
                advance_request,
                class_groups_decryption_key,
                ..
            } => advance_network_dkg(
                session_id,
                &self.access_structure,
                &PublicInput::NetworkEncryptionKeyDkg(public_input),
                self.party_id,
                &data.key_scheme,
                advance_request,
                class_groups_decryption_key,
                &mut rng,
            ),
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
                    Ok(_) => Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                        public_output_value: vec![],
                        private_output: vec![],
                        malicious_parties: vec![],
                    }),
                    Err(err) => Err(err),
                }
            }
            ProtocolCryptographicData::PartialSignatureVerification {
                data,
                protocol_public_parameters,
                ..
            } => {
                let hashed_message = bcs::to_bytes(
                    &message_digest(&data.message, &data.hash_type)
                        .map_err(|err| DwalletError::MessageDigest(err.to_string()))?,
                )?;

                verify_partial_signature(
                    &hashed_message,
                    &data.dwallet_decentralized_output,
                    &data.presign,
                    &data.partially_signed_message,
                    &protocol_public_parameters,
                )?;

                Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                    public_output_value: vec![],
                    private_output: vec![],
                    malicious_parties: vec![],
                })
            }
            ProtocolCryptographicData::NetworkEncryptionKeyReconfiguration {
                public_input,
                advance_request,
                decryption_key_shares,
                ..
            } => {
                let decryption_key_shares = decryption_key_shares
                    .iter()
                    .map(|(party_id, share)| (*party_id, share.decryption_key_share))
                    .collect::<HashMap<_, _>>();

                let result =
                    Party::<ReconfigurationSecp256k1Party>::advance_with_guaranteed_output(
                        session_id,
                        self.party_id,
                        &self.access_structure,
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
                    Ok(..) => Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                        public_output_value: data.public_user_secret_key_shares.clone(),
                        private_output: vec![],
                        malicious_parties: vec![],
                    }),
                    Err(err) => {
                        error!(
                            error=?err,
                            session_identifier=?computation_id.session_identifier,
                            validator=?self.validator_name,
                            mpc_round=?computation_id.current_round,
                            "failed to verify secret share"
                        );
                        Err(DwalletError::DWalletSecretNotMatchedDWalletOutput)
                    }
                }
            }
        }
    }
}
