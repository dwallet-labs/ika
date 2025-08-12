// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::{ComputationId, MPC_SIGN_SECOND_ROUND};
use crate::dwallet_mpc::dwallet_dkg::{
    DWalletDKGFirstParty, DWalletDKGSecondParty, DWalletImportedKeyVerificationParty,
};
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::encrypt_user_share::verify_encrypted_share;
use crate::dwallet_mpc::make_dwallet_user_secret_key_shares_public::verify_secret_share;
use crate::dwallet_mpc::mpc_session::PublicInput;
use crate::dwallet_mpc::mpc_session::{MPCEventData, MPCRoundToMessagesHashMap};
use crate::dwallet_mpc::network_dkg::advance_network_dkg;
use crate::dwallet_mpc::presign::PresignParty;
use crate::dwallet_mpc::reconfiguration::ReconfigurationSecp256k1Party;
use crate::dwallet_mpc::sign::{
    SignParty, update_expected_decrypters_metrics, verify_partial_signature,
};
use class_groups::dkg::Secp256k1Party;
use commitment::CommitmentSizedNumber;
use dwallet_classgroups_types::ClassGroupsDecryptionKey;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletMPCNetworkKeyScheme, MPCMessage, SerializedWrappedMPCPublicOutput,
    VersionedDWalletImportedKeyVerificationOutput, VersionedDecryptionKeyReconfigurationOutput,
    VersionedDwalletDKGFirstRoundPublicOutput, VersionedDwalletDKGSecondRoundPublicOutput,
    VersionedPresignOutput, VersionedSignOutput,
};
use dwallet_rng::RootSeed;
use group::PartyID;
use ika_types::crypto::AuthorityPublicKeyBytes;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{AsyncProtocol, MPCRequestInput};
use itertools::Itertools;
use message_digest::message_digest::{Hash, message_digest};
use mpc::guaranteed_output_delivery::{AdvanceRequest, Party, ReadyToAdvanceResult};
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, WeightedThresholdAccessStructure,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info};
use twopc_mpc::sign::Protocol;

pub(crate) struct Request {
    pub(crate) party_id: PartyID,
    pub(crate) protocol_name: String,
    pub(crate) validator_name: AuthorityPublicKeyBytes,
    pub(crate) access_structure: WeightedThresholdAccessStructure,
    pub(crate) protocol_specific_data: ProtocolSpecificData,
    /// Round -> Messages map.
    pub(crate) messages: MPCRoundToMessagesHashMap,
}

pub(crate) enum ProtocolSpecificData {
    ImportedKeyVerification {
        curve: u32,
        public_input: <DWalletImportedKeyVerificationParty as mpc::Party>::PublicInput,
        encrypted_centralized_secret_share_and_proof: Vec<u8>,
        encryption_key: Vec<u8>,
        advance_request: AdvanceRequest<()>,
    },

    MakeDWalletUserSecretKeySharesPublic {
        curve: u32,
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
        public_user_secret_key_shares: Vec<u8>,
        dwallet_decentralized_output: SerializedWrappedMPCPublicOutput,
    },

    DKGFirst {
        curve: u32,
        public_input: <DWalletDKGFirstParty as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<DWalletDKGFirstParty as mpc::Party>::Message>,
    },

    DKGSecond {
        curve: u32,
        public_input: <DWalletDKGSecondParty as mpc::Party>::PublicInput,
        encrypted_centralized_secret_share_and_proof: Vec<u8>,
        encryption_key: Vec<u8>,
        advance_request: AdvanceRequest<<DWalletDKGSecondParty as mpc::Party>::Message>,
    },

    Presign {
        curve: u32,
        signature_algorithm: u32,
        public_input: <PresignParty as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<PresignParty as mpc::Party>::Message>,
    },

    Sign {
        curve: u32,
        hash_scheme: Hash,
        signature_algorithm: u32,
        public_input: <SignParty as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<SignParty as mpc::Party>::Message>,
        decryption_key_shares: HashMap<PartyID, <AsyncProtocol as Protocol>::DecryptionKeyShare>,
    },

    NetworkEncryptionKeyDkg {
        key_scheme: DWalletMPCNetworkKeyScheme,
        public_input: <Secp256k1Party as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<Secp256k1Party as mpc::Party>::Message>,
        class_groups_decryption_key: ClassGroupsDecryptionKey,
    },

    NetworkEncryptionKeyReconfiguration {
        public_input: <ReconfigurationSecp256k1Party as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<ReconfigurationSecp256k1Party as mpc::Party>::Message>,
        decryption_key_shares: HashMap<PartyID, <AsyncProtocol as Protocol>::DecryptionKeyShare>,
    },

    EncryptedShareVerification {
        curve: u32,
        encrypted_centralized_secret_share_and_proof: Vec<u8>,
        decentralized_public_output: SerializedWrappedMPCPublicOutput,
        encryption_key: Vec<u8>,
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    },

    PartialSignatureVerification {
        curve: u32,
        message: Vec<u8>,
        hash_type: Hash,
        signature_algorithm: u32,
        dwallet_decentralized_output: SerializedWrappedMPCPublicOutput,
        presign: SerializedWrappedMPCPublicOutput,
        partially_signed_message: SerializedWrappedMPCPublicOutput,
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    },
}

impl ProtocolSpecificData {
    pub fn try_new_if_ready_to_advance(
        mpc_event_data: MPCEventData,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        consensus_round: u64,
        messages_by_consensus_round: HashMap<u64, HashMap<PartyID, MPCMessage>>,
        network_dkg_third_round_delay: u64,
        decryption_key_reconfiguration_third_round_delay: u64,
        class_groups_decryption_key: ClassGroupsDecryptionKey,
    ) -> Result<Option<Self>, DwalletMPCError> {
        let res = match mpc_event_data.request_input {
            MPCRequestInput::MakeDWalletUserSecretKeySharesPublicRequest(session_event) => {
                if let PublicInput::MakeDWalletUserSecretKeySharesPublic(public_input) =
                    &mpc_event_data.public_input
                {
                    ProtocolSpecificData::MakeDWalletUserSecretKeySharesPublic {
                        curve: session_event.event_data.curve,
                        protocol_public_parameters: public_input.clone(),
                        public_user_secret_key_shares: session_event
                            .event_data
                            .public_user_secret_key_shares,
                        dwallet_decentralized_output: session_event.event_data.public_output,
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
            MPCRequestInput::DWalletImportedKeyVerificationRequest(event_data) => {
                if let PublicInput::DWalletImportedKeyVerificationRequest(public_input) =
                    &mpc_event_data.public_input
                {
                    let ReadyToAdvanceResult::ReadyToAdvance(advance_request) =
                        Party::<DWalletImportedKeyVerificationParty>::ready_to_advance(
                            party_id,
                            access_structure,
                            consensus_round,
                            HashMap::new(),
                            &messages_by_consensus_round,
                        )?
                    else {
                        return Ok(None);
                    };
                    ProtocolSpecificData::ImportedKeyVerification {
                        curve: event_data.event_data.curve,
                        public_input: public_input.clone(),
                        encrypted_centralized_secret_share_and_proof: event_data
                            .event_data
                            .encrypted_centralized_secret_share_and_proof,
                        encryption_key: event_data.event_data.encryption_key,
                        advance_request,
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
            MPCRequestInput::DKGFirst(event_data) => {
                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) =
                    Party::<DWalletDKGFirstParty>::ready_to_advance(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
                        &messages_by_consensus_round,
                    )?
                else {
                    return Ok(None);
                };

                if let PublicInput::DKGFirst(public_input) = &mpc_event_data.public_input {
                    ProtocolSpecificData::DKGFirst {
                        curve: event_data.event_data.curve,
                        public_input: public_input.clone(),
                        advance_request,
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
            MPCRequestInput::DKGSecond(event_data) => {
                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) =
                    Party::<DWalletDKGSecondParty>::ready_to_advance(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
                        &messages_by_consensus_round,
                    )?
                else {
                    return Ok(None);
                };
                if let PublicInput::DKGSecond(public_input) = &mpc_event_data.public_input {
                    ProtocolSpecificData::DKGSecond {
                        curve: event_data.event_data.curve,
                        public_input: public_input.clone(),
                        encrypted_centralized_secret_share_and_proof: event_data
                            .event_data
                            .encrypted_centralized_secret_share_and_proof,
                        encryption_key: event_data.event_data.encryption_key,
                        advance_request,
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
            MPCRequestInput::Presign(session_event) => {
                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) =
                    Party::<PresignParty>::ready_to_advance(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
                        &messages_by_consensus_round,
                    )?
                else {
                    return Ok(None);
                };
                if let PublicInput::Presign(public_input) = &mpc_event_data.public_input {
                    ProtocolSpecificData::Presign {
                        curve: session_event.event_data.curve,
                        signature_algorithm: session_event.event_data.signature_algorithm,
                        public_input: public_input.clone(),
                        advance_request,
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
            MPCRequestInput::Sign(session_event) => {
                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) =
                    Party::<SignParty>::ready_to_advance(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
                        &messages_by_consensus_round,
                    )?
                else {
                    return Ok(None);
                };
                if let PublicInput::Sign(public_input) = &mpc_event_data.public_input {
                    let Some(decryption_key_shares) = mpc_event_data.decryption_key_shares else {
                        return Err(DwalletMPCError::MissingDwalletMPCDecryptionKeyShares(
                            "sign request requires decryption key shares, but none were found"
                                .to_string(),
                        ));
                    };
                    ProtocolSpecificData::Sign {
                        curve: session_event.event_data.curve,
                        hash_scheme: Hash::try_from(session_event.event_data.hash_scheme)
                            .map_err(|_| DwalletMPCError::InvalidSessionPublicInput)?,
                        signature_algorithm: session_event.event_data.signature_algorithm,
                        public_input: public_input.clone(),
                        advance_request,
                        decryption_key_shares,
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
            MPCRequestInput::NetworkEncryptionKeyDkg(key_scheme, ..) => {
                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) =
                    Party::<Secp256k1Party>::ready_to_advance(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::from([(3, network_dkg_third_round_delay)]),
                        &messages_by_consensus_round,
                    )?
                else {
                    return Ok(None);
                };
                if let PublicInput::NetworkEncryptionKeyDkg(public_input) =
                    &mpc_event_data.public_input
                {
                    ProtocolSpecificData::NetworkEncryptionKeyDkg {
                        key_scheme,
                        public_input: public_input.clone(),
                        advance_request,
                        class_groups_decryption_key,
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
            MPCRequestInput::EncryptedShareVerification(event_data) => {
                if let PublicInput::EncryptedShareVerification(public_input) =
                    &mpc_event_data.public_input
                {
                    ProtocolSpecificData::EncryptedShareVerification {
                        curve: event_data.event_data.curve,
                        encrypted_centralized_secret_share_and_proof: event_data
                            .event_data
                            .encrypted_centralized_secret_share_and_proof,
                        decentralized_public_output: event_data
                            .event_data
                            .decentralized_public_output,
                        encryption_key: event_data.event_data.encryption_key,
                        protocol_public_parameters: public_input.clone(),
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
            MPCRequestInput::PartialSignatureVerification(event_data) => {
                if let PublicInput::PartialSignatureVerification(public_input) =
                    &mpc_event_data.public_input
                {
                    ProtocolSpecificData::PartialSignatureVerification {
                        curve: event_data.event_data.curve,
                        message: event_data.event_data.message,
                        hash_type: Hash::try_from(event_data.event_data.hash_scheme).unwrap(),
                        signature_algorithm: event_data.event_data.signature_algorithm,
                        dwallet_decentralized_output: event_data.event_data.dkg_output,
                        presign: event_data.event_data.presign,
                        partially_signed_message: event_data
                            .event_data
                            .message_centralized_signature,
                        protocol_public_parameters: public_input.clone(),
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
            MPCRequestInput::NetworkEncryptionKeyReconfiguration(..) => {
                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) =
                    Party::<ReconfigurationSecp256k1Party>::ready_to_advance(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::from([(3, decryption_key_reconfiguration_third_round_delay)]),
                        &messages_by_consensus_round,
                    )?
                else {
                    return Ok(None);
                };
                let Some(decryption_key_shares) = mpc_event_data.decryption_key_shares else {
                    return Err(DwalletMPCError::MissingDwalletMPCDecryptionKeyShares("reconfiguration request requires decryption key shares, but none were found".to_string()));
                };
                if let PublicInput::NetworkEncryptionKeyReconfiguration(public_input) =
                    &mpc_event_data.public_input
                {
                    ProtocolSpecificData::NetworkEncryptionKeyReconfiguration {
                        public_input: public_input.clone(),
                        advance_request,
                        decryption_key_shares,
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
        };
        Ok(Some(res))
    }

    pub fn curve_name(&self) -> String {
        let curve = match self {
            ProtocolSpecificData::DKGFirst { curve, .. } => Some(curve),
            ProtocolSpecificData::DKGSecond { curve, .. } => Some(curve),
            ProtocolSpecificData::Presign { curve, .. } => Some(curve),
            ProtocolSpecificData::Sign { curve, .. } => Some(curve),
            ProtocolSpecificData::NetworkEncryptionKeyDkg { .. } => None,
            ProtocolSpecificData::EncryptedShareVerification { curve, .. } => Some(curve),
            ProtocolSpecificData::PartialSignatureVerification { curve, .. } => Some(curve),
            ProtocolSpecificData::NetworkEncryptionKeyReconfiguration { .. } => None,
            ProtocolSpecificData::MakeDWalletUserSecretKeySharesPublic { curve, .. } => Some(curve),
            ProtocolSpecificData::ImportedKeyVerification { curve, .. } => Some(curve),
        };
        match curve {
            None => "".to_string(),
            Some(curve) => {
                if curve == &0 {
                    "Secp256k1".to_string()
                } else {
                    "Unknown".to_string()
                }
            }
        }
    }

    pub fn hash_scheme_name(&self) -> String {
        let hash_scheme = match self {
            ProtocolSpecificData::DKGFirst { .. } => None,
            ProtocolSpecificData::DKGSecond { .. } => None,
            ProtocolSpecificData::Presign { .. } => None,
            ProtocolSpecificData::Sign { hash_scheme, .. } => Some(hash_scheme.clone() as u8),
            ProtocolSpecificData::NetworkEncryptionKeyDkg { .. } => None,
            ProtocolSpecificData::EncryptedShareVerification { .. } => None,
            ProtocolSpecificData::PartialSignatureVerification { hash_type, .. } => {
                Some(hash_type.clone() as u8)
            }
            ProtocolSpecificData::NetworkEncryptionKeyReconfiguration { .. } => None,
            ProtocolSpecificData::MakeDWalletUserSecretKeySharesPublic { .. } => None,
            ProtocolSpecificData::ImportedKeyVerification { .. } => None,
        };
        match &hash_scheme {
            None => "".to_string(),
            Some(hash_scheme) => {
                if hash_scheme == &0 {
                    "KECCAK256".to_string()
                } else if hash_scheme == &1 {
                    "SHA256".to_string()
                } else {
                    "Unknown".to_string()
                }
            }
        }
    }

    pub fn signature_algorithm_name(&self) -> String {
        let signature_alg = match self {
            ProtocolSpecificData::DKGFirst { .. } => None,
            ProtocolSpecificData::DKGSecond { .. } => None,
            ProtocolSpecificData::Presign {
                signature_algorithm,
                ..
            } => Some(signature_algorithm),
            ProtocolSpecificData::Sign {
                signature_algorithm,
                ..
            } => Some(signature_algorithm),
            ProtocolSpecificData::NetworkEncryptionKeyDkg { .. } => None,
            ProtocolSpecificData::EncryptedShareVerification { .. } => None,
            ProtocolSpecificData::PartialSignatureVerification {
                signature_algorithm,
                ..
            } => Some(signature_algorithm),
            ProtocolSpecificData::NetworkEncryptionKeyReconfiguration { .. } => None,
            ProtocolSpecificData::MakeDWalletUserSecretKeySharesPublic { .. } => None,
            ProtocolSpecificData::ImportedKeyVerification { .. } => None,
        };
        match signature_alg {
            None => "".to_string(),
            Some(curve) => {
                if curve == &0 {
                    "ECDSA".to_string()
                } else {
                    "Unknown".to_string()
                }
            }
        }
    }
}

impl Request {
    /// Perform a cryptographic computation.
    /// Notice: `root_seed` must be kept private!
    pub(crate) fn compute(
        self,
        computation_id: ComputationId,
        root_seed: RootSeed,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
    ) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
        let messages_skeleton = self
            .messages
            .iter()
            .map(|(round, messages_map)| {
                (
                    *round,
                    messages_map.keys().copied().sorted().collect::<Vec<_>>(),
                )
            })
            .collect::<HashMap<_, _>>();

        info!(
            mpc_protocol=?self.protocol_name,
            validator=?self.validator_name,
            session_identifier=?computation_id.session_identifier,
            mpc_round=?computation_id.mpc_round,
            access_structure=?self.access_structure,
            ?messages_skeleton,
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
            computation_id.mpc_round,
            computation_id.attempt_number,
        );

        match self.protocol_specific_data {
            ProtocolSpecificData::ImportedKeyVerification {
                public_input,
                encrypted_centralized_secret_share_and_proof,
                encryption_key,
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
                            &encrypted_centralized_secret_share_and_proof,
                            &bcs::to_bytes(&VersionedDwalletDKGSecondRoundPublicOutput::V1(
                                public_output_value.clone(),
                            ))?,
                            &encryption_key,
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
            ProtocolSpecificData::DKGFirst {
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
            ProtocolSpecificData::DKGSecond {
                public_input,
                encrypted_centralized_secret_share_and_proof,
                encryption_key,
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
                        &encrypted_centralized_secret_share_and_proof,
                        &bcs::to_bytes(&VersionedDwalletDKGSecondRoundPublicOutput::V1(
                            public_output_value.clone(),
                        ))?,
                        &encryption_key,
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
            ProtocolSpecificData::Presign {
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
            ProtocolSpecificData::Sign {
                public_input,
                advance_request,
                decryption_key_shares,
                ..
            } => {
                if computation_id.mpc_round == MPC_SIGN_SECOND_ROUND {
                    if let Some(sign_first_round_messages) = self.messages.get(&1) {
                        let decrypters = sign_first_round_messages.keys().copied().collect();
                        update_expected_decrypters_metrics(
                            &public_input.expected_decrypters,
                            decrypters,
                            &self.access_structure,
                            dwallet_mpc_metrics,
                        );
                    }
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
            ProtocolSpecificData::NetworkEncryptionKeyDkg {
                key_scheme,
                public_input,
                advance_request,
                class_groups_decryption_key,
            } => advance_network_dkg(
                session_id,
                &self.access_structure,
                &PublicInput::NetworkEncryptionKeyDkg(public_input),
                self.party_id,
                &key_scheme,
                class_groups_decryption_key,
                advance_request,
                &mut rng,
            ),
            ProtocolSpecificData::EncryptedShareVerification {
                encrypted_centralized_secret_share_and_proof,
                decentralized_public_output,
                encryption_key,
                protocol_public_parameters,
                ..
            } => {
                match verify_encrypted_share(
                    &encrypted_centralized_secret_share_and_proof,
                    &decentralized_public_output,
                    &encryption_key,
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
            ProtocolSpecificData::PartialSignatureVerification {
                message,
                hash_type,
                dwallet_decentralized_output,
                presign,
                partially_signed_message,
                protocol_public_parameters,
                ..
            } => {
                let hashed_message = bcs::to_bytes(
                    &message_digest(&message, &hash_type)
                        .map_err(|err| DwalletMPCError::MessageDigest(err.to_string()))?,
                )?;

                verify_partial_signature(
                    &hashed_message,
                    &dwallet_decentralized_output,
                    &presign,
                    &partially_signed_message,
                    &protocol_public_parameters,
                )?;

                Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                    public_output_value: vec![],
                    private_output: vec![],
                    malicious_parties: vec![],
                })
            }
            ProtocolSpecificData::NetworkEncryptionKeyReconfiguration {
                public_input,
                advance_request,
                decryption_key_shares,
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
            ProtocolSpecificData::MakeDWalletUserSecretKeySharesPublic {
                protocol_public_parameters,
                public_user_secret_key_shares,
                dwallet_decentralized_output,
                ..
            } => {
                match verify_secret_share(
                    protocol_public_parameters.clone(),
                    public_user_secret_key_shares.clone(),
                    dwallet_decentralized_output.clone(),
                ) {
                    Ok(..) => Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                        public_output_value: public_user_secret_key_shares.clone(),
                        private_output: vec![],
                        malicious_parties: vec![],
                    }),
                    Err(err) => {
                        error!(
                            error=?err,
                            session_identifier=?computation_id.session_identifier,
                            validator=?self.validator_name,
                            mpc_round=?computation_id.mpc_round,
                            "failed to verify secret share"
                        );
                        Err(DwalletMPCError::DWalletSecretNotMatchedDWalletOutput)
                    }
                }
            }
        }
    }
}
