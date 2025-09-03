// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::MPC_SIGN_SECOND_ROUND;
use crate::dwallet_mpc::dwallet_dkg::{
    DWalletDKGFirstParty, DWalletDKGSecondParty, DWalletImportedKeyVerificationParty,
};
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::encrypt_user_share::verify_encrypted_share;
use crate::dwallet_mpc::mpc_session::PublicInput;
use crate::dwallet_mpc::network_dkg::{DwalletMPCNetworkKeys, advance_network_dkg};
use crate::dwallet_mpc::presign::PresignParty;
use crate::dwallet_mpc::protocol_cryptographic_data::ProtocolCryptographicData;
use crate::dwallet_mpc::reconfiguration::{
    ReconfigurationSecp256k1Party, ReconfigurationV1toV2Secp256k1Party,
};
use crate::dwallet_mpc::sign::SignParty;
use crate::dwallet_session_request::DWalletSessionRequestMetricData;
use crate::request_protocol_data::{
    NetworkEncryptionKeyDkgData, NetworkEncryptionKeyV1ToV2ReconfigurationData, ProtocolData,
};
use anyhow::anyhow;
use class_groups::dkg::Secp256k1Party;
use commitment::CommitmentSizedNumber;
use dwallet_classgroups_types::ClassGroupsDecryptionKey;
use dwallet_mpc_types::dwallet_mpc::{
    DKGDecentralizedPartyOutputSecp256k1, DKGDecentralizedPartyVersionedOutputSecp256k1,
    VersionedDWalletImportedKeyVerificationOutput, VersionedDecryptionKeyReconfigurationOutput,
    VersionedDwalletDKGFirstRoundPublicOutput, VersionedDwalletDKGSecondRoundPublicOutput,
    VersionedPresignOutput, VersionedSignOutput,
};
use dwallet_rng::RootSeed;
use group::PartyID;
use ika_protocol_config::ProtocolConfig;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{AsyncProtocol, SessionIdentifier};
use mpc::guaranteed_output_delivery::{Party, ReadyToAdvanceResult};
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, WeightedThresholdAccessStructure,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::error;
use twopc_mpc::Protocol;
use twopc_mpc::class_groups::{
    DKGCentralizedPartyVersionedOutput, DKGDecentralizedPartyVersionedOutput,
};

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
        decryption_key_shares: &Box<DwalletMPCNetworkKeys>,
    ) -> Result<Option<Self>, DwalletMPCError> {
        let res = match protocol_specific_data {
            ProtocolData::ImportedKeyVerification { data, .. } => {
                let PublicInput::DWalletImportedKeyVerificationRequest(public_input) = public_input
                else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result =
                    Party::<DWalletImportedKeyVerificationParty>::ready_to_advance(
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

                ProtocolCryptographicData::ImportedKeyVerification {
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
                let PublicInput::DKGSecond(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result = Party::<DWalletDKGSecondParty>::ready_to_advance(
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

                let advance_request_result = Party::<PresignParty>::ready_to_advance(
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

                ProtocolCryptographicData::Presign {
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

                let advance_request_result = Party::<SignParty>::ready_to_advance(
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

                let decryption_key_shares = decryption_key_shares
                    .get_decryption_key_shares(dwallet_network_encryption_key_id)?;

                ProtocolCryptographicData::Sign {
                    data: data.clone(),
                    public_input: public_input.clone(),
                    advance_request,
                    decryption_key_shares: decryption_key_shares.clone(),
                }
            }
            ProtocolData::NetworkEncryptionKeyDkg {
                data: NetworkEncryptionKeyDkgData { key_scheme },
                ..
            } => {
                let PublicInput::NetworkEncryptionKeyDkg(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result = Party::<Secp256k1Party>::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::from([(3, network_dkg_third_round_delay)]),
                    &serialized_messages_by_consensus_round,
                )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };

                ProtocolCryptographicData::NetworkEncryptionKeyDkg {
                    data: NetworkEncryptionKeyDkgData {
                        key_scheme: key_scheme.clone(),
                    },
                    public_input: public_input.clone(),
                    advance_request,
                    class_groups_decryption_key,
                }
            }
            ProtocolData::NetworkEncryptionKeyReconfiguration {
                data,
                dwallet_network_encryption_key_id,
            } => match public_input {
                PublicInput::NetworkEncryptionKeyReconfiguration(public_input) => {
                    let advance_request_result =
                        Party::<ReconfigurationSecp256k1Party>::ready_to_advance(
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
                        .get_decryption_key_shares(dwallet_network_encryption_key_id)?;

                    ProtocolCryptographicData::NetworkEncryptionKeyReconfiguration {
                        data: data.clone(),
                        public_input: public_input.clone(),
                        advance_request,
                        decryption_key_shares: decryption_key_shares.clone(),
                    }
                }
                PublicInput::NetworkEncryptionKeyReconfigurationV1ToV2(public_input) => {
                    let advance_request_result =
                        Party::<ReconfigurationV1toV2Secp256k1Party>::ready_to_advance(
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
                        .get_decryption_key_shares(dwallet_network_encryption_key_id)?;

                    ProtocolCryptographicData::NetworkEncryptionKeyV1ToV2Reconfiguration {
                        data: NetworkEncryptionKeyV1ToV2ReconfigurationData {},
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
        protocol_config: &ProtocolConfig,
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
                public_input,
                data,
                advance_request,
                ..
            } => {
                let result =
                    Party::<DWalletImportedKeyVerificationParty>::advance_with_guaranteed_output(
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
                        let output_with_session_id =
                            bcs::to_bytes(&(public_output_value, session_id))?;
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
                // TODO (#1482): Use this hack only for V1 dWallet DKG outputs
                let session_id = match bcs::from_bytes(&first_round_output)? {
                    VersionedDwalletDKGFirstRoundPublicOutput::V1(output) => {
                        let (_, session_id) =
                            bcs::from_bytes::<(Vec<u8>, CommitmentSizedNumber)>(&output)?;
                        session_id
                    }
                };
                let result = Party::<DWalletDKGSecondParty>::advance_with_guaranteed_output(
                    session_id,
                    party_id,
                    access_structure,
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
                    // TODO (#1482): Use this hack only for V1 dWallet DKG outputs
                    let decentralized_output = match bcs::from_bytes(&public_output_value)? {
                        DKGDecentralizedPartyVersionedOutput::<
                            { group::secp256k1::SCALAR_LIMBS },
                            { twopc_mpc::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                            {
                                twopc_mpc::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS
                            },
                            group::secp256k1::GroupElement,
                        >::UniversalPublicDKGOutput {
                            output: dkg_output,
                            ..
                        } => dkg_output,
                        DKGDecentralizedPartyVersionedOutput::<
                            { group::secp256k1::SCALAR_LIMBS },
                            { twopc_mpc::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                            {
                                twopc_mpc::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS
                            },
                            group::secp256k1::GroupElement,
                        >::TargetedPublicDKGOutput(output) => output,
                    };
                    verify_encrypted_share(
                        &data.encrypted_centralized_secret_share_and_proof,
                        // TODO (#1482): Check the protocol config and use this hack only for V1
                        // DWallets.
                        &bcs::to_bytes(&VersionedDwalletDKGSecondRoundPublicOutput::V1(
                            bcs::to_bytes(&decentralized_output)?,
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
                        // TODO (#1482): Use this hack only for V1 dWallet DKG outputs
                        let decentralized_output: <AsyncProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput = bcs::from_bytes(&public_output_value)?;
                        let decentralized_output = match decentralized_output {
                            DKGDecentralizedPartyVersionedOutputSecp256k1::UniversalPublicDKGOutput {
                                output, ..
                            } => output,
                            DKGDecentralizedPartyVersionedOutputSecp256k1::TargetedPublicDKGOutput (
                                output
                            ) => output,
                        };
                        let public_output_value =
                            bcs::to_bytes(&VersionedDwalletDKGSecondRoundPublicOutput::V1(
                                bcs::to_bytes(&decentralized_output).unwrap(),
                            ))?;
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
                if mpc_round == MPC_SIGN_SECOND_ROUND {
                    // Todo (#1408): Return update_expected_decrypters_metrics
                }

                let result = Party::<SignParty>::advance_with_guaranteed_output(
                    session_id,
                    party_id,
                    access_structure,
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
                    } => Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                        public_output_value,
                        malicious_parties,
                        private_output,
                    }),
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
                access_structure,
                &PublicInput::NetworkEncryptionKeyDkg(public_input),
                party_id,
                &data.key_scheme,
                advance_request,
                class_groups_decryption_key,
                &protocol_config,
                &mut rng,
            ),
            ProtocolCryptographicData::NetworkEncryptionKeyReconfiguration {
                public_input,
                advance_request,
                decryption_key_shares,
                ..
            } => {
                let decryption_key_shares = decryption_key_shares
                    .iter()
                    .map(|(party_id, share)| {
                        (
                            *party_id,
                            <AsyncProtocol as Protocol>::DecryptionKeyShare::new(share.to_limbs()),
                        )
                    })
                    .collect::<HashMap<_, _>>();

                let result =
                    Party::<ReconfigurationSecp256k1Party>::advance_with_guaranteed_output(
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
                        let public_output_value = match protocol_config
                            .network_encryption_key_version
                        {
                            Some(2) => {
                                bcs::to_bytes(&VersionedDecryptionKeyReconfigurationOutput::V2(
                                    public_output_value,
                                ))?
                            }
                            _ => bcs::to_bytes(&VersionedDecryptionKeyReconfigurationOutput::V1(
                                public_output_value,
                            ))?,
                        };

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
                let decryption_key_shares = decryption_key_shares
                    .iter()
                    .map(|(party_id, share)| {
                        (
                            *party_id,
                            <AsyncProtocol as Protocol>::DecryptionKeyShare::new(share.to_limbs()),
                        )
                    })
                    .collect::<HashMap<_, _>>();

                let result =
                    Party::<ReconfigurationV1toV2Secp256k1Party>::advance_with_guaranteed_output(
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
