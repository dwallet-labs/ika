use crate::dwallet_mpc::dwallet_dkg::{
    DWalletDKGFirstParty, DWalletDKGSecondParty, DWalletImportedKeyVerificationParty,
};
use crate::dwallet_mpc::mpc_session::{MPCEventData, PublicInput};
use crate::dwallet_mpc::presign::PresignParty;
use crate::dwallet_mpc::reconfiguration::ReconfigurationSecp256k1Party;
use crate::dwallet_mpc::sign::SignParty;
use class_groups::dkg::Secp256k1Party;
use dwallet_classgroups_types::ClassGroupsDecryptionKey;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletMPCNetworkKeyScheme, MPCMessage, SerializedWrappedMPCPublicOutput,
};
use group::PartyID;
use ika_types::dwallet_mpc_error::DwalletMPCError;
use ika_types::messages_dwallet_mpc::{AsyncProtocol, MPCRequestInput};
use message_digest::message_digest::Hash;
use mpc::guaranteed_output_delivery::{AdvanceRequest, Party, ReadyToAdvanceResult};
use mpc::{GuaranteesOutputDelivery, WeightedThresholdAccessStructure};
use std::collections::HashMap;
use twopc_mpc::sign::Protocol;

#[derive(Debug, Clone)]
pub(crate) enum ProtocolSpecificData {
    ImportedKeyVerification {
        curve: u32,
        public_input: <DWalletImportedKeyVerificationParty as mpc::Party>::PublicInput,
        encrypted_centralized_secret_share_and_proof: Vec<u8>,
        encryption_key: Vec<u8>,
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
    },

    DKGSecond {
        curve: u32,
        public_input: <DWalletDKGSecondParty as mpc::Party>::PublicInput,
        encrypted_centralized_secret_share_and_proof: Vec<u8>,
        encryption_key: Vec<u8>,
    },

    Presign {
        curve: u32,
        signature_algorithm: u32,
        public_input: <PresignParty as mpc::Party>::PublicInput,
    },

    Sign {
        curve: u32,
        hash_scheme: Hash,
        signature_algorithm: u32,
        public_input: <SignParty as mpc::Party>::PublicInput,
        decryption_key_shares: HashMap<PartyID, <AsyncProtocol as Protocol>::DecryptionKeyShare>,
    },

    NetworkEncryptionKeyDkg {
        key_scheme: DWalletMPCNetworkKeyScheme,
        public_input: <Secp256k1Party as mpc::Party>::PublicInput,
        class_groups_decryption_key: ClassGroupsDecryptionKey,
        mpc_round_to_consensus_rounds_delay: HashMap<u64, u64>,
    },

    NetworkEncryptionKeyReconfiguration {
        public_input: <ReconfigurationSecp256k1Party as mpc::Party>::PublicInput,
        decryption_key_shares: HashMap<PartyID, <AsyncProtocol as Protocol>::DecryptionKeyShare>,
        mpc_round_to_consensus_rounds_delay: HashMap<u64, u64>,
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
    pub fn try_new(
        mpc_event_data: MPCEventData,
        network_dkg_third_round_delay: u64,
        decryption_key_reconfiguration_third_round_delay: u64,
        class_groups_decryption_key: ClassGroupsDecryptionKey,
    ) -> Result<Self, DwalletMPCError> {
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
                    ProtocolSpecificData::ImportedKeyVerification {
                        curve: event_data.event_data.curve,
                        public_input: public_input.clone(),
                        encrypted_centralized_secret_share_and_proof: event_data
                            .event_data
                            .encrypted_centralized_secret_share_and_proof,
                        encryption_key: event_data.event_data.encryption_key,
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
            MPCRequestInput::DKGFirst(event_data) => {
                if let PublicInput::DKGFirst(public_input) = &mpc_event_data.public_input {
                    ProtocolSpecificData::DKGFirst {
                        curve: event_data.event_data.curve,
                        public_input: public_input.clone(),
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
            MPCRequestInput::DKGSecond(event_data) => {
                if let PublicInput::DKGSecond(public_input) = &mpc_event_data.public_input {
                    ProtocolSpecificData::DKGSecond {
                        curve: event_data.event_data.curve,
                        public_input: public_input.clone(),
                        encrypted_centralized_secret_share_and_proof: event_data
                            .event_data
                            .encrypted_centralized_secret_share_and_proof,
                        encryption_key: event_data.event_data.encryption_key,
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
            MPCRequestInput::Presign(session_event) => {
                if let PublicInput::Presign(public_input) = &mpc_event_data.public_input {
                    ProtocolSpecificData::Presign {
                        curve: session_event.event_data.curve,
                        signature_algorithm: session_event.event_data.signature_algorithm,
                        public_input: public_input.clone(),
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
            MPCRequestInput::Sign(session_event) => {
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
                        decryption_key_shares,
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
            MPCRequestInput::NetworkEncryptionKeyDkg(key_scheme, ..) => {
                if let PublicInput::NetworkEncryptionKeyDkg(public_input) =
                    &mpc_event_data.public_input
                {
                    ProtocolSpecificData::NetworkEncryptionKeyDkg {
                        key_scheme,
                        public_input: public_input.clone(),
                        class_groups_decryption_key,
                        mpc_round_to_consensus_rounds_delay: HashMap::from([(
                            3,
                            network_dkg_third_round_delay,
                        )]),
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
                let Some(decryption_key_shares) = mpc_event_data.decryption_key_shares else {
                    return Err(DwalletMPCError::MissingDwalletMPCDecryptionKeyShares("reconfiguration request requires decryption key shares, but none were found".to_string()));
                };
                if let PublicInput::NetworkEncryptionKeyReconfiguration(public_input) =
                    &mpc_event_data.public_input
                {
                    ProtocolSpecificData::NetworkEncryptionKeyReconfiguration {
                        public_input: public_input.clone(),
                        decryption_key_shares,
                        mpc_round_to_consensus_rounds_delay: HashMap::from([(
                            3,
                            decryption_key_reconfiguration_third_round_delay,
                        )]),
                    }
                } else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                }
            }
        };
        Ok(res)
    }
}

#[derive(Debug)]
pub(crate) enum AdvanceSpecificData {
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
        mpc_round_to_consensus_rounds_delay: HashMap<u64, u64>,
    },

    NetworkEncryptionKeyReconfiguration {
        public_input: <ReconfigurationSecp256k1Party as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<ReconfigurationSecp256k1Party as mpc::Party>::Message>,
        decryption_key_shares: HashMap<PartyID, <AsyncProtocol as Protocol>::DecryptionKeyShare>,
        mpc_round_to_consensus_rounds_delay: HashMap<u64, u64>,
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

impl AdvanceSpecificData {
    pub fn try_from_protocol_specific_data(
        protocol_specific_data: &ProtocolSpecificData,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        consensus_round: u64,
        messages_by_consensus_round: HashMap<u64, HashMap<PartyID, MPCMessage>>,
    ) -> Result<Option<Self>, DwalletMPCError> {
        let res = match protocol_specific_data {
            ProtocolSpecificData::MakeDWalletUserSecretKeySharesPublic {
                curve,
                protocol_public_parameters,
                public_user_secret_key_shares,
                dwallet_decentralized_output,
            } => AdvanceSpecificData::MakeDWalletUserSecretKeySharesPublic {
                curve: *curve,
                protocol_public_parameters: protocol_public_parameters.clone(),
                public_user_secret_key_shares: public_user_secret_key_shares.clone(),
                dwallet_decentralized_output: dwallet_decentralized_output.clone(),
            },
            ProtocolSpecificData::ImportedKeyVerification {
                curve,
                public_input,
                encrypted_centralized_secret_share_and_proof,
                encryption_key,
            } => {
                let advance_request_result =
                    Party::<DWalletImportedKeyVerificationParty>::ready_to_advance(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
                        &messages_by_consensus_round,
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
            ProtocolSpecificData::DKGFirst {
                curve,
                public_input,
            } => {
                let advance_request_result = Party::<DWalletDKGFirstParty>::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &messages_by_consensus_round,
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
                public_input,
                encrypted_centralized_secret_share_and_proof,
                encryption_key,
            } => {
                let advance_request_result = Party::<DWalletDKGSecondParty>::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &messages_by_consensus_round,
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
                public_input,
            } => {
                let advance_request_result = Party::<PresignParty>::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &messages_by_consensus_round,
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
                public_input,
                decryption_key_shares,
            } => {
                let advance_request_result = Party::<SignParty>::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &messages_by_consensus_round,
                )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };

                AdvanceSpecificData::Sign {
                    curve: *curve,
                    hash_scheme: hash_scheme.clone(),
                    signature_algorithm: *signature_algorithm,
                    public_input: public_input.clone(),
                    advance_request,
                    decryption_key_shares: decryption_key_shares.clone(),
                }
            }
            ProtocolSpecificData::NetworkEncryptionKeyDkg {
                key_scheme,
                public_input,
                class_groups_decryption_key,
                mpc_round_to_consensus_rounds_delay,
            } => {
                let advance_request_result = Party::<Secp256k1Party>::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    mpc_round_to_consensus_rounds_delay.clone(),
                    &messages_by_consensus_round,
                )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };

                AdvanceSpecificData::NetworkEncryptionKeyDkg {
                    key_scheme: key_scheme.clone(),
                    public_input: public_input.clone(),
                    advance_request,
                    class_groups_decryption_key: class_groups_decryption_key.clone(),
                    mpc_round_to_consensus_rounds_delay: mpc_round_to_consensus_rounds_delay
                        .clone(),
                }
            }
            ProtocolSpecificData::NetworkEncryptionKeyReconfiguration {
                public_input,
                decryption_key_shares,
                mpc_round_to_consensus_rounds_delay,
            } => {
                let advance_request_result =
                    Party::<ReconfigurationSecp256k1Party>::ready_to_advance(
                        party_id,
                        access_structure,
                        consensus_round,
                        mpc_round_to_consensus_rounds_delay.clone(),
                        &messages_by_consensus_round,
                    )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };

                AdvanceSpecificData::NetworkEncryptionKeyReconfiguration {
                    public_input: public_input.clone(),
                    advance_request,
                    decryption_key_shares: decryption_key_shares.clone(),
                    mpc_round_to_consensus_rounds_delay: mpc_round_to_consensus_rounds_delay
                        .clone(),
                }
            }
            ProtocolSpecificData::EncryptedShareVerification {
                curve,
                encrypted_centralized_secret_share_and_proof,
                decentralized_public_output,
                encryption_key,
                protocol_public_parameters,
            } => AdvanceSpecificData::EncryptedShareVerification {
                curve: *curve,
                encrypted_centralized_secret_share_and_proof:
                    encrypted_centralized_secret_share_and_proof.clone(),
                decentralized_public_output: decentralized_public_output.clone(),
                encryption_key: encryption_key.clone(),
                protocol_public_parameters: protocol_public_parameters.clone(),
            },
            ProtocolSpecificData::PartialSignatureVerification {
                curve,
                message,
                hash_type,
                signature_algorithm,
                dwallet_decentralized_output,
                presign,
                partially_signed_message,
                protocol_public_parameters,
            } => AdvanceSpecificData::PartialSignatureVerification {
                curve: *curve,
                message: message.clone(),
                hash_type: hash_type.clone(),
                signature_algorithm: *signature_algorithm,
                dwallet_decentralized_output: dwallet_decentralized_output.clone(),
                presign: presign.clone(),
                partially_signed_message: partially_signed_message.clone(),
                protocol_public_parameters: protocol_public_parameters.clone(),
            },
        };
        Ok(Some(res))
    }

    pub fn curve_name(&self) -> String {
        let curve = match self {
            AdvanceSpecificData::DKGFirst { curve, .. } => Some(curve),
            AdvanceSpecificData::DKGSecond { curve, .. } => Some(curve),
            AdvanceSpecificData::Presign { curve, .. } => Some(curve),
            AdvanceSpecificData::Sign { curve, .. } => Some(curve),
            AdvanceSpecificData::NetworkEncryptionKeyDkg { .. } => None,
            AdvanceSpecificData::EncryptedShareVerification { curve, .. } => Some(curve),
            AdvanceSpecificData::PartialSignatureVerification { curve, .. } => Some(curve),
            AdvanceSpecificData::NetworkEncryptionKeyReconfiguration { .. } => None,
            AdvanceSpecificData::MakeDWalletUserSecretKeySharesPublic { curve, .. } => Some(curve),
            AdvanceSpecificData::ImportedKeyVerification { curve, .. } => Some(curve),
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
            AdvanceSpecificData::DKGFirst { .. } => None,
            AdvanceSpecificData::DKGSecond { .. } => None,
            AdvanceSpecificData::Presign { .. } => None,
            AdvanceSpecificData::Sign { hash_scheme, .. } => Some(hash_scheme.clone() as u8),
            AdvanceSpecificData::NetworkEncryptionKeyDkg { .. } => None,
            AdvanceSpecificData::EncryptedShareVerification { .. } => None,
            AdvanceSpecificData::PartialSignatureVerification { hash_type, .. } => {
                Some(hash_type.clone() as u8)
            }
            AdvanceSpecificData::NetworkEncryptionKeyReconfiguration { .. } => None,
            AdvanceSpecificData::MakeDWalletUserSecretKeySharesPublic { .. } => None,
            AdvanceSpecificData::ImportedKeyVerification { .. } => None,
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
            AdvanceSpecificData::DKGFirst { .. } => None,
            AdvanceSpecificData::DKGSecond { .. } => None,
            AdvanceSpecificData::Presign {
                signature_algorithm,
                ..
            } => Some(signature_algorithm),
            AdvanceSpecificData::Sign {
                signature_algorithm,
                ..
            } => Some(signature_algorithm),
            AdvanceSpecificData::NetworkEncryptionKeyDkg { .. } => None,
            AdvanceSpecificData::EncryptedShareVerification { .. } => None,
            AdvanceSpecificData::PartialSignatureVerification {
                signature_algorithm,
                ..
            } => Some(signature_algorithm),
            AdvanceSpecificData::NetworkEncryptionKeyReconfiguration { .. } => None,
            AdvanceSpecificData::MakeDWalletUserSecretKeySharesPublic { .. } => None,
            AdvanceSpecificData::ImportedKeyVerification { .. } => None,
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
