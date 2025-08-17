use crate::dwallet_mpc::dwallet_dkg::{
    DWalletDKGFirstParty, DWalletDKGSecondParty, DWalletImportedKeyVerificationParty,
};
use crate::dwallet_mpc::mpc_session::{MPCEventData, MPCRoundToMessagesHashMap, PublicInput};
use crate::dwallet_mpc::presign::PresignParty;
use crate::dwallet_mpc::reconfiguration::ReconfigurationSecp256k1Party;
use crate::dwallet_mpc::sign::SignParty;
use class_groups::dkg::Secp256k1Party;
use dwallet_classgroups_types::ClassGroupsDecryptionKey;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletMPCNetworkKeyScheme, MPCMessage, SerializedWrappedMPCPublicOutput, SignatureAlgorithm,
};
use group::PartyID;
use ika_types::committee::EpochId;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    AsyncProtocol, MPCRequestInput, SessionIdentifier, SessionType,
};
use message_digest::message_digest::Hash;
use mpc::guaranteed_output_delivery::{AdvanceRequest, Party, ReadyToAdvanceResult};
use mpc::{GuaranteesOutputDelivery, WeightedThresholdAccessStructure};
use std::collections::HashMap;
use sui_types::base_types::ObjectID;
use twopc_mpc::sign::Protocol;

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct DWalletSessionRequest {
    pub session_type: SessionType,
    /// Unique identifier for the MPC session.
    pub session_identifier: SessionIdentifier,
    pub session_sequence_number: u64,
    pub protocol_specific_data: ProtocolSpecificData,
    pub epoch: u64,
    pub requires_network_key_data: bool,
    pub requires_next_active_committee: bool,
    // True when the event was pulled from the state of the object,
    // and False when it was pushed as an event.
    pub pulled: bool,
}

#[derive(strum_macros::Display, Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ProtocolSpecificData {
    #[strum(to_string = "ImportedKeyVerification")]
    ImportedKeyVerification {
        curve: DWalletMPCNetworkKeyScheme,
        encrypted_centralized_secret_share_and_proof: Vec<u8>,
        encryption_key: Vec<u8>,
        dwallet_id: ObjectID,
        encrypted_user_secret_key_share_id: ObjectID,
        dwallet_network_encryption_key_id: ObjectID,
        centralized_party_message: Vec<u8>,
    },

    #[strum(to_string = "MakeDWalletUserSecretKeySharesPublic")]
    MakeDWalletUserSecretKeySharesPublic {
        curve: DWalletMPCNetworkKeyScheme,
        public_user_secret_key_shares: Vec<u8>,
        dwallet_decentralized_output: SerializedWrappedMPCPublicOutput,
        dwallet_id: ObjectID,
        dwallet_network_encryption_key_id: ObjectID,
    },

    #[strum(to_string = "DKGFirst")]
    DKGFirst {
        curve: DWalletMPCNetworkKeyScheme,
        dwallet_id: ObjectID,
        dwallet_network_encryption_key_id: ObjectID,
    },

    #[strum(to_string = "DKGSecond")]
    DKGSecond {
        curve: DWalletMPCNetworkKeyScheme,
        encrypted_centralized_secret_share_and_proof: Vec<u8>,
        encryption_key: Vec<u8>,
        dwallet_id: ObjectID,
        encrypted_secret_share_id: ObjectID,
        dwallet_network_encryption_key_id: ObjectID,
        first_round_output: SerializedWrappedMPCPublicOutput,
        centralized_public_key_share_and_proof: SerializedWrappedMPCPublicOutput,
    },

    #[strum(to_string = "Presign")]
    Presign {
        curve: DWalletMPCNetworkKeyScheme,
        signature_algorithm: SignatureAlgorithm,
        dwallet_id: Option<ObjectID>,
        presign_id: ObjectID,
        dwallet_public_output: Option<SerializedWrappedMPCPublicOutput>,
        dwallet_network_encryption_key_id: ObjectID,
    },

    #[strum(to_string = "Sign")]
    Sign {
        curve: DWalletMPCNetworkKeyScheme,
        hash_scheme: Hash,
        signature_algorithm: SignatureAlgorithm,
        dwallet_id: ObjectID,
        sign_id: ObjectID,
        is_future_sign: bool,
        dwallet_network_encryption_key_id: ObjectID,
        dwallet_decentralized_public_output: SerializedWrappedMPCPublicOutput,
        message: Vec<u8>,
        presign: SerializedWrappedMPCPublicOutput,
        message_centralized_signature: SerializedWrappedMPCPublicOutput,
    },

    #[strum(to_string = "NetworkEncryptionKeyDkg")]
    NetworkEncryptionKeyDkg {
        key_scheme: DWalletMPCNetworkKeyScheme,
        dwallet_network_encryption_key_id: ObjectID,
    },

    #[strum(to_string = "NetworkEncryptionKeyReconfiguration")]
    NetworkEncryptionKeyReconfiguration {
        dwallet_network_encryption_key_id: ObjectID,
    },

    #[strum(to_string = "EncryptedShareVerification")]
    EncryptedShareVerification {
        curve: DWalletMPCNetworkKeyScheme,
        encrypted_centralized_secret_share_and_proof: Vec<u8>,
        decentralized_public_output: SerializedWrappedMPCPublicOutput,
        encryption_key: Vec<u8>,
        dwallet_id: ObjectID,
        encrypted_user_secret_key_share_id: ObjectID,
        dwallet_network_encryption_key_id: ObjectID,
    },

    #[strum(to_string = "PartialSignatureVerification")]
    PartialSignatureVerification {
        curve: DWalletMPCNetworkKeyScheme,
        message: Vec<u8>,
        hash_type: Hash,
        signature_algorithm: SignatureAlgorithm,
        dwallet_decentralized_output: SerializedWrappedMPCPublicOutput,
        presign: SerializedWrappedMPCPublicOutput,
        partially_signed_message: SerializedWrappedMPCPublicOutput,
        dwallet_id: ObjectID,
        partial_centralized_signed_message_id: ObjectID,
        dwallet_network_encryption_key_id: ObjectID,
    },
}

impl ProtocolSpecificData {
    pub fn try_new(request_input: MPCRequestInput) -> DwalletMPCResult<Self> {
        let protocol_data = match request_input {
            MPCRequestInput::MakeDWalletUserSecretKeySharesPublicRequest(session_event) => {
                ProtocolSpecificData::MakeDWalletUserSecretKeySharesPublic {
                    curve: session_event.event_data.curve.try_into()?,
                    public_user_secret_key_shares: session_event
                        .event_data
                        .public_user_secret_key_shares,
                    dwallet_decentralized_output: session_event.event_data.public_output,
                    dwallet_id: session_event.event_data.dwallet_id,
                    dwallet_network_encryption_key_id: session_event
                        .event_data
                        .dwallet_network_encryption_key_id,
                }
            }
            MPCRequestInput::DWalletImportedKeyVerificationRequest(event_data) => {
                ProtocolSpecificData::ImportedKeyVerification {
                    curve: event_data.event_data.curve.try_into()?,
                    encrypted_centralized_secret_share_and_proof: event_data
                        .event_data
                        .encrypted_centralized_secret_share_and_proof,
                    encryption_key: event_data.event_data.encryption_key,
                    dwallet_id: event_data.event_data.dwallet_id,
                    encrypted_user_secret_key_share_id: event_data
                        .event_data
                        .encrypted_user_secret_key_share_id,
                    dwallet_network_encryption_key_id: event_data
                        .event_data
                        .dwallet_network_encryption_key_id,
                    centralized_party_message: event_data.event_data.centralized_party_message,
                }
            }
            MPCRequestInput::DKGFirst(event_data) => ProtocolSpecificData::DKGFirst {
                curve: event_data.event_data.curve.try_into()?,
                dwallet_id: event_data.event_data.dwallet_id,
                dwallet_network_encryption_key_id: event_data
                    .event_data
                    .dwallet_network_encryption_key_id,
            },
            MPCRequestInput::DKGSecond(event_data) => ProtocolSpecificData::DKGSecond {
                curve: event_data.event_data.curve.try_into()?,
                encrypted_centralized_secret_share_and_proof: event_data
                    .event_data
                    .encrypted_centralized_secret_share_and_proof,
                encryption_key: event_data.event_data.encryption_key,
                dwallet_id: event_data.event_data.dwallet_id,
                encrypted_secret_share_id: event_data.event_data.encrypted_user_secret_key_share_id,
                dwallet_network_encryption_key_id: event_data
                    .event_data
                    .dwallet_network_encryption_key_id,
                first_round_output: event_data.event_data.first_round_output,
                centralized_public_key_share_and_proof: event_data
                    .event_data
                    .centralized_public_key_share_and_proof,
            },
            MPCRequestInput::Presign(session_event) => ProtocolSpecificData::Presign {
                curve: session_event.event_data.curve.try_into()?,
                signature_algorithm: session_event.event_data.signature_algorithm.try_into()?,
                dwallet_id: session_event.event_data.dwallet_id,
                presign_id: session_event.event_data.presign_id,
                dwallet_public_output: session_event.event_data.dwallet_public_output,
                dwallet_network_encryption_key_id: session_event
                    .event_data
                    .dwallet_network_encryption_key_id,
            },
            MPCRequestInput::Sign(session_event) => ProtocolSpecificData::Sign {
                curve: session_event.event_data.curve.try_into()?,
                hash_scheme: Hash::try_from(session_event.event_data.hash_scheme)
                    .map_err(|_| DwalletMPCError::InvalidSessionPublicInput)?,
                signature_algorithm: session_event.event_data.signature_algorithm.try_into()?,
                dwallet_id: session_event.event_data.dwallet_id,
                sign_id: session_event.event_data.sign_id,
                is_future_sign: session_event.event_data.is_future_sign,
                dwallet_network_encryption_key_id: session_event
                    .event_data
                    .dwallet_network_encryption_key_id,
                dwallet_decentralized_public_output: session_event
                    .event_data
                    .dwallet_decentralized_public_output,
                message: session_event.event_data.message,
                presign: session_event.event_data.presign,
                message_centralized_signature: session_event
                    .event_data
                    .message_centralized_signature,
            },
            MPCRequestInput::NetworkEncryptionKeyDkg(key_scheme, session_event) => {
                ProtocolSpecificData::NetworkEncryptionKeyDkg {
                    key_scheme,
                    dwallet_network_encryption_key_id: session_event
                        .event_data
                        .dwallet_network_encryption_key_id,
                }
            }
            MPCRequestInput::EncryptedShareVerification(event_data) => {
                ProtocolSpecificData::EncryptedShareVerification {
                    curve: event_data.event_data.curve.try_into()?,
                    encrypted_centralized_secret_share_and_proof: event_data
                        .event_data
                        .encrypted_centralized_secret_share_and_proof,
                    decentralized_public_output: event_data.event_data.decentralized_public_output,
                    encryption_key: event_data.event_data.encryption_key,
                    dwallet_id: event_data.event_data.dwallet_id,
                    encrypted_user_secret_key_share_id: event_data
                        .event_data
                        .encrypted_user_secret_key_share_id,
                    dwallet_network_encryption_key_id: event_data
                        .event_data
                        .dwallet_network_encryption_key_id,
                }
            }
            MPCRequestInput::PartialSignatureVerification(event_data) => {
                ProtocolSpecificData::PartialSignatureVerification {
                    curve: event_data.event_data.curve.try_into()?,
                    message: event_data.event_data.message,
                    hash_type: Hash::try_from(event_data.event_data.hash_scheme).unwrap(),
                    signature_algorithm: event_data.event_data.signature_algorithm.try_into()?,
                    dwallet_decentralized_output: event_data.event_data.dkg_output,
                    presign: event_data.event_data.presign,
                    partially_signed_message: event_data.event_data.message_centralized_signature,
                    dwallet_id: event_data.event_data.dwallet_id,
                    partial_centralized_signed_message_id: event_data
                        .event_data
                        .partial_centralized_signed_message_id,
                    dwallet_network_encryption_key_id: event_data
                        .event_data
                        .dwallet_network_encryption_key_id,
                }
            }
            MPCRequestInput::NetworkEncryptionKeyReconfiguration(session_event) => {
                ProtocolSpecificData::NetworkEncryptionKeyReconfiguration {
                    dwallet_network_encryption_key_id: session_event
                        .event_data
                        .dwallet_network_encryption_key_id,
                }
            }
        };
        Ok(protocol_data)
    }

    pub fn curve(&self) -> String {
        match self {
            ProtocolSpecificData::DKGFirst { curve, .. }
            | ProtocolSpecificData::DKGSecond { curve, .. }
            | ProtocolSpecificData::Presign { curve, .. }
            | ProtocolSpecificData::Sign { curve, .. }
            | ProtocolSpecificData::EncryptedShareVerification { curve, .. }
            | ProtocolSpecificData::PartialSignatureVerification { curve, .. }
            | ProtocolSpecificData::MakeDWalletUserSecretKeySharesPublic { curve, .. }
            | ProtocolSpecificData::ImportedKeyVerification { curve, .. } => curve.to_string(),
            ProtocolSpecificData::NetworkEncryptionKeyDkg { .. }
            | ProtocolSpecificData::NetworkEncryptionKeyReconfiguration { .. } => {
                "Unknown".to_string()
            }
        }
    }

    pub fn hash_scheme(&self) -> String {
        match self {
            ProtocolSpecificData::Sign { hash_scheme, .. }
            | ProtocolSpecificData::PartialSignatureVerification {
                hash_type: hash_scheme,
                ..
            } => hash_scheme.to_string(),
            ProtocolSpecificData::DKGFirst { .. }
            | ProtocolSpecificData::DKGSecond { .. }
            | ProtocolSpecificData::Presign { .. }
            | ProtocolSpecificData::NetworkEncryptionKeyDkg { .. }
            | ProtocolSpecificData::EncryptedShareVerification { .. }
            | ProtocolSpecificData::NetworkEncryptionKeyReconfiguration { .. }
            | ProtocolSpecificData::MakeDWalletUserSecretKeySharesPublic { .. }
            | ProtocolSpecificData::ImportedKeyVerification { .. } => "Unknown".to_string(),
        }
    }

    pub fn signature_algorithm(&self) -> String {
        match self {
            ProtocolSpecificData::Presign {
                signature_algorithm,
                ..
            }
            | ProtocolSpecificData::Sign {
                signature_algorithm,
                ..
            }
            | ProtocolSpecificData::PartialSignatureVerification {
                signature_algorithm,
                ..
            } => signature_algorithm.to_string(),
            ProtocolSpecificData::DKGFirst { .. }
            | ProtocolSpecificData::DKGSecond { .. }
            | ProtocolSpecificData::NetworkEncryptionKeyDkg { .. }
            | ProtocolSpecificData::EncryptedShareVerification { .. }
            | ProtocolSpecificData::NetworkEncryptionKeyReconfiguration { .. }
            | ProtocolSpecificData::MakeDWalletUserSecretKeySharesPublic { .. }
            | ProtocolSpecificData::ImportedKeyVerification { .. } => "Unknown".to_string(),
        }
    }

    pub fn network_encryption_key_id(&self) -> Option<ObjectID> {
        match self {
            ProtocolSpecificData::DKGFirst {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolSpecificData::DKGSecond {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolSpecificData::Presign {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolSpecificData::Sign {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolSpecificData::NetworkEncryptionKeyDkg {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolSpecificData::NetworkEncryptionKeyReconfiguration {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolSpecificData::EncryptedShareVerification {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolSpecificData::PartialSignatureVerification {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolSpecificData::MakeDWalletUserSecretKeySharesPublic {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolSpecificData::ImportedKeyVerification {
                dwallet_network_encryption_key_id,
                ..
            } => Some(*dwallet_network_encryption_key_id),
        }
    }
}

#[derive(Debug)]
pub(crate) enum AdvanceSpecificData {
    ImportedKeyVerification {
        curve: DWalletMPCNetworkKeyScheme,
        public_input: <DWalletImportedKeyVerificationParty as mpc::Party>::PublicInput,
        encrypted_centralized_secret_share_and_proof: Vec<u8>,
        encryption_key: Vec<u8>,
        advance_request: AdvanceRequest<()>,
    },

    MakeDWalletUserSecretKeySharesPublic {
        curve: DWalletMPCNetworkKeyScheme,
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
        public_user_secret_key_shares: Vec<u8>,
        dwallet_decentralized_output: SerializedWrappedMPCPublicOutput,
    },

    DKGFirst {
        curve: DWalletMPCNetworkKeyScheme,
        public_input: <DWalletDKGFirstParty as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<DWalletDKGFirstParty as mpc::Party>::Message>,
    },

    DKGSecond {
        curve: DWalletMPCNetworkKeyScheme,
        public_input: <DWalletDKGSecondParty as mpc::Party>::PublicInput,
        encrypted_centralized_secret_share_and_proof: Vec<u8>,
        encryption_key: Vec<u8>,
        advance_request: AdvanceRequest<<DWalletDKGSecondParty as mpc::Party>::Message>,
    },

    Presign {
        curve: DWalletMPCNetworkKeyScheme,
        signature_algorithm: SignatureAlgorithm,
        public_input: <PresignParty as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<PresignParty as mpc::Party>::Message>,
    },

    Sign {
        curve: DWalletMPCNetworkKeyScheme,
        hash_scheme: Hash,
        signature_algorithm: SignatureAlgorithm,
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
        curve: DWalletMPCNetworkKeyScheme,
        encrypted_centralized_secret_share_and_proof: Vec<u8>,
        decentralized_public_output: SerializedWrappedMPCPublicOutput,
        encryption_key: Vec<u8>,
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    },

    PartialSignatureVerification {
        curve: DWalletMPCNetworkKeyScheme,
        message: Vec<u8>,
        hash_type: Hash,
        signature_algorithm: SignatureAlgorithm,
        dwallet_decentralized_output: SerializedWrappedMPCPublicOutput,
        presign: SerializedWrappedMPCPublicOutput,
        partially_signed_message: SerializedWrappedMPCPublicOutput,
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    },
}

impl AdvanceSpecificData {
    pub fn try_new(
        protocol_specific_data: &ProtocolSpecificData,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        consensus_round: u64,
        serialized_messages_by_consensus_round: HashMap<u64, HashMap<PartyID, Vec<u8>>>,
        public_input: PublicInput,
        network_dkg_third_round_delay: u64,
        decryption_key_reconfiguration_third_round_delay: u64,
        class_groups_decryption_key: ClassGroupsDecryptionKey,
        decryption_key_shares: &HashMap<
            ObjectID,
            HashMap<PartyID, <AsyncProtocol as Protocol>::DecryptionKeyShare>,
        >,
    ) -> Result<Option<Self>, DwalletMPCError> {
        let res = match protocol_specific_data {
            ProtocolSpecificData::MakeDWalletUserSecretKeySharesPublic {
                curve,
                public_user_secret_key_shares,
                dwallet_decentralized_output,
                ..
            } => {
                let PublicInput::MakeDWalletUserSecretKeySharesPublic(public_input) = public_input
                else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };
                AdvanceSpecificData::MakeDWalletUserSecretKeySharesPublic {
                    curve: *curve,
                    protocol_public_parameters: public_input.clone(),
                    public_user_secret_key_shares: public_user_secret_key_shares.clone(),
                    dwallet_decentralized_output: dwallet_decentralized_output.clone(),
                }
            }
            ProtocolSpecificData::ImportedKeyVerification {
                curve,
                encrypted_centralized_secret_share_and_proof,
                encryption_key,
                ..
            } => {
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

                AdvanceSpecificData::ImportedKeyVerification {
                    curve: curve.clone(),
                    public_input: public_input.clone(),
                    encrypted_centralized_secret_share_and_proof:
                        encrypted_centralized_secret_share_and_proof.clone(),
                    encryption_key: encryption_key.clone(),
                    advance_request,
                }
            }
            ProtocolSpecificData::DKGFirst { curve, .. } => {
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

                AdvanceSpecificData::DKGFirst {
                    curve: *curve,
                    public_input: public_input.clone(),
                    advance_request,
                }
            }
            ProtocolSpecificData::DKGSecond {
                curve,
                encrypted_centralized_secret_share_and_proof,
                encryption_key,
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

                AdvanceSpecificData::DKGSecond {
                    curve: *curve,
                    public_input: public_input.clone(),
                    encrypted_centralized_secret_share_and_proof:
                        encrypted_centralized_secret_share_and_proof.clone(),
                    encryption_key: encryption_key.clone(),
                    advance_request,
                }
            }
            ProtocolSpecificData::Presign {
                curve,
                signature_algorithm,
                ..
            } => {
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

                AdvanceSpecificData::Presign {
                    curve: *curve,
                    signature_algorithm: *signature_algorithm,
                    public_input: public_input.clone(),
                    advance_request,
                }
            }
            ProtocolSpecificData::Sign {
                curve,
                hash_scheme,
                signature_algorithm,
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
                    .get(dwallet_network_encryption_key_id)
                    .cloned()
                    .ok_or(DwalletMPCError::MissingDwalletMPCDecryptionKeyShares(
                        dwallet_network_encryption_key_id.to_string(),
                    ))?;

                AdvanceSpecificData::Sign {
                    curve: *curve,
                    hash_scheme: hash_scheme.clone(),
                    signature_algorithm: *signature_algorithm,
                    public_input: public_input.clone(),
                    advance_request,
                    decryption_key_shares: decryption_key_shares.clone(),
                }
            }
            ProtocolSpecificData::NetworkEncryptionKeyDkg { key_scheme, .. } => {
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

                AdvanceSpecificData::NetworkEncryptionKeyDkg {
                    key_scheme: key_scheme.clone(),
                    public_input: public_input.clone(),
                    advance_request,
                    class_groups_decryption_key,
                }
            }
            ProtocolSpecificData::NetworkEncryptionKeyReconfiguration {
                dwallet_network_encryption_key_id,
            } => {
                let PublicInput::NetworkEncryptionKeyReconfiguration(public_input) = public_input
                else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result =
                    Party::<ReconfigurationSecp256k1Party>::ready_to_advance(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::from([(3, decryption_key_reconfiguration_third_round_delay)]),
                        &serialized_messages_by_consensus_round,
                    )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };

                let decryption_key_shares = decryption_key_shares
                    .get(dwallet_network_encryption_key_id)
                    .cloned()
                    .ok_or(DwalletMPCError::MissingDwalletMPCDecryptionKeyShares(
                        dwallet_network_encryption_key_id.to_string(),
                    ))?;

                AdvanceSpecificData::NetworkEncryptionKeyReconfiguration {
                    public_input: public_input.clone(),
                    advance_request,
                    decryption_key_shares: decryption_key_shares.clone(),
                }
            }
            ProtocolSpecificData::EncryptedShareVerification {
                curve,
                encrypted_centralized_secret_share_and_proof,
                decentralized_public_output,
                encryption_key,
                ..
            } => {
                let PublicInput::EncryptedShareVerification(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                AdvanceSpecificData::EncryptedShareVerification {
                    curve: *curve,
                    encrypted_centralized_secret_share_and_proof:
                        encrypted_centralized_secret_share_and_proof.clone(),
                    decentralized_public_output: decentralized_public_output.clone(),
                    encryption_key: encryption_key.clone(),
                    protocol_public_parameters: public_input.clone(),
                }
            }
            ProtocolSpecificData::PartialSignatureVerification {
                curve,
                message,
                hash_type,
                signature_algorithm,
                dwallet_decentralized_output,
                presign,
                partially_signed_message,
                ..
            } => {
                let PublicInput::PartialSignatureVerification(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                AdvanceSpecificData::PartialSignatureVerification {
                    curve: *curve,
                    message: message.clone(),
                    hash_type: hash_type.clone(),
                    signature_algorithm: *signature_algorithm,
                    dwallet_decentralized_output: dwallet_decentralized_output.clone(),
                    presign: presign.clone(),
                    partially_signed_message: partially_signed_message.clone(),
                    protocol_public_parameters: public_input.clone(),
                }
            }
        };
        Ok(Some(res))
    }

    pub fn curve_name(&self) -> String {
        match self {
            AdvanceSpecificData::DKGFirst { curve, .. }
            | AdvanceSpecificData::DKGSecond { curve, .. }
            | AdvanceSpecificData::Presign { curve, .. }
            | AdvanceSpecificData::Sign { curve, .. }
            | AdvanceSpecificData::EncryptedShareVerification { curve, .. }
            | AdvanceSpecificData::PartialSignatureVerification { curve, .. }
            | AdvanceSpecificData::MakeDWalletUserSecretKeySharesPublic { curve, .. }
            | AdvanceSpecificData::ImportedKeyVerification { curve, .. } => curve.to_string(),
            AdvanceSpecificData::NetworkEncryptionKeyDkg { .. }
            | AdvanceSpecificData::NetworkEncryptionKeyReconfiguration { .. } => {
                "Unknown".to_string()
            }
        }
    }

    pub fn hash_scheme_name(&self) -> String {
        match self {
            AdvanceSpecificData::Sign { hash_scheme, .. }
            | AdvanceSpecificData::PartialSignatureVerification {
                hash_type: hash_scheme,
                ..
            } => hash_scheme.to_string(),
            AdvanceSpecificData::DKGFirst { .. }
            | AdvanceSpecificData::DKGSecond { .. }
            | AdvanceSpecificData::Presign { .. }
            | AdvanceSpecificData::NetworkEncryptionKeyDkg { .. }
            | AdvanceSpecificData::EncryptedShareVerification { .. }
            | AdvanceSpecificData::NetworkEncryptionKeyReconfiguration { .. }
            | AdvanceSpecificData::MakeDWalletUserSecretKeySharesPublic { .. }
            | AdvanceSpecificData::ImportedKeyVerification { .. } => "Unknown".to_string(),
        }
    }

    pub fn signature_algorithm_name(&self) -> String {
        match self {
            AdvanceSpecificData::Presign {
                signature_algorithm,
                ..
            }
            | AdvanceSpecificData::Sign {
                signature_algorithm,
                ..
            }
            | AdvanceSpecificData::PartialSignatureVerification {
                signature_algorithm,
                ..
            } => signature_algorithm.to_string(),
            AdvanceSpecificData::DKGFirst { .. }
            | AdvanceSpecificData::DKGSecond { .. }
            | AdvanceSpecificData::NetworkEncryptionKeyDkg { .. }
            | AdvanceSpecificData::EncryptedShareVerification { .. }
            | AdvanceSpecificData::NetworkEncryptionKeyReconfiguration { .. }
            | AdvanceSpecificData::MakeDWalletUserSecretKeySharesPublic { .. }
            | AdvanceSpecificData::ImportedKeyVerification { .. } => "Unknown".to_string(),
        }
    }

    pub fn get_attempt_number(&self) -> u64 {
        match self {
            AdvanceSpecificData::DKGFirst {
                advance_request, ..
            } => advance_request.attempt_number,
            AdvanceSpecificData::DKGSecond {
                advance_request, ..
            } => advance_request.attempt_number,
            AdvanceSpecificData::Presign {
                advance_request, ..
            } => advance_request.attempt_number,
            AdvanceSpecificData::Sign {
                advance_request, ..
            } => advance_request.attempt_number,
            AdvanceSpecificData::NetworkEncryptionKeyDkg {
                advance_request, ..
            } => advance_request.attempt_number,
            AdvanceSpecificData::NetworkEncryptionKeyReconfiguration {
                advance_request, ..
            } => advance_request.attempt_number,
            AdvanceSpecificData::EncryptedShareVerification { .. } => 1,
            AdvanceSpecificData::PartialSignatureVerification { .. } => 1,
            AdvanceSpecificData::MakeDWalletUserSecretKeySharesPublic { .. } => 1,
            AdvanceSpecificData::ImportedKeyVerification {
                advance_request, ..
            } => advance_request.attempt_number,
        }
    }
}
