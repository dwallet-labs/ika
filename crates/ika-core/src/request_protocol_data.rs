use dwallet_mpc_types::dwallet_mpc::{
    DWalletMPCNetworkKeyScheme, SerializedWrappedMPCPublicOutput, SignatureAlgorithm,
};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::MPCRequestInput;
use message_digest::message_digest::Hash;
use sui_types::base_types::ObjectID;
// Common structs for shared data between ProtocolSpecificData and AdvanceSpecificData
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Imported Key Verification")]
pub(crate) struct ImportedKeyVerificationData {
    pub curve: DWalletMPCNetworkKeyScheme,
    pub encrypted_centralized_secret_share_and_proof: Vec<u8>,
    pub encryption_key: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Make DWallet User Secret Key Shares Public")]
pub(crate) struct MakeDWalletUserSecretKeySharesPublicData {
    pub curve: DWalletMPCNetworkKeyScheme,
    pub public_user_secret_key_shares: Vec<u8>,
    pub dwallet_decentralized_output: SerializedWrappedMPCPublicOutput,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("dWallet DKG First Round")]
pub(crate) struct DKGFirstData {
    pub curve: DWalletMPCNetworkKeyScheme,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("dWallet DKG Second Round")]
pub(crate) struct DKGSecondData {
    pub curve: DWalletMPCNetworkKeyScheme,
    pub encrypted_centralized_secret_share_and_proof: Vec<u8>,
    pub encryption_key: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Presign")]
pub(crate) struct PresignData {
    pub curve: DWalletMPCNetworkKeyScheme,
    pub signature_algorithm: SignatureAlgorithm,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Sign")]
pub(crate) struct SignData {
    pub curve: DWalletMPCNetworkKeyScheme,
    pub hash_scheme: Hash,
    pub signature_algorithm: SignatureAlgorithm,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Network Encryption Key DKG")]
pub(crate) struct NetworkEncryptionKeyDkgData {
    pub key_scheme: DWalletMPCNetworkKeyScheme,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Network Encryption Key Reconfiguration")]
pub(crate) struct NetworkEncryptionKeyReconfigurationData {}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Encrypted Share Verification")]
pub(crate) struct EncryptedShareVerificationData {
    pub curve: DWalletMPCNetworkKeyScheme,
    pub encrypted_centralized_secret_share_and_proof: Vec<u8>,
    pub decentralized_public_output: SerializedWrappedMPCPublicOutput,
    pub encryption_key: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Partial Signature Verification")]
pub(crate) struct PartialSignatureVerificationData {
    pub curve: DWalletMPCNetworkKeyScheme,
    pub message: Vec<u8>,
    pub hash_type: Hash,
    pub signature_algorithm: SignatureAlgorithm,
    pub dwallet_decentralized_output: SerializedWrappedMPCPublicOutput,
    pub presign: SerializedWrappedMPCPublicOutput,
    pub partially_signed_message: SerializedWrappedMPCPublicOutput,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ProtocolSpecificData {
    ImportedKeyVerification {
        data: ImportedKeyVerificationData,
        dwallet_id: ObjectID,
        encrypted_user_secret_key_share_id: ObjectID,
        dwallet_network_encryption_key_id: ObjectID,
        centralized_party_message: Vec<u8>,
    },

    MakeDWalletUserSecretKeySharesPublic {
        data: MakeDWalletUserSecretKeySharesPublicData,
        dwallet_id: ObjectID,
        dwallet_network_encryption_key_id: ObjectID,
    },

    DKGFirst {
        data: DKGFirstData,
        dwallet_id: ObjectID,
        dwallet_network_encryption_key_id: ObjectID,
    },

    DKGSecond {
        data: DKGSecondData,
        dwallet_id: ObjectID,
        encrypted_secret_share_id: ObjectID,
        dwallet_network_encryption_key_id: ObjectID,
        first_round_output: SerializedWrappedMPCPublicOutput,
        centralized_public_key_share_and_proof: SerializedWrappedMPCPublicOutput,
    },

    Presign {
        data: PresignData,
        dwallet_id: Option<ObjectID>,
        presign_id: ObjectID,
        dwallet_public_output: Option<SerializedWrappedMPCPublicOutput>,
        dwallet_network_encryption_key_id: ObjectID,
    },

    Sign {
        data: SignData,
        dwallet_id: ObjectID,
        sign_id: ObjectID,
        is_future_sign: bool,
        dwallet_network_encryption_key_id: ObjectID,
        dwallet_decentralized_public_output: SerializedWrappedMPCPublicOutput,
        message: Vec<u8>,
        presign: SerializedWrappedMPCPublicOutput,
        message_centralized_signature: SerializedWrappedMPCPublicOutput,
    },

    NetworkEncryptionKeyDkg {
        data: NetworkEncryptionKeyDkgData,
        dwallet_network_encryption_key_id: ObjectID,
    },

    NetworkEncryptionKeyReconfiguration {
        data: NetworkEncryptionKeyReconfigurationData,
        dwallet_network_encryption_key_id: ObjectID,
    },

    EncryptedShareVerification {
        data: EncryptedShareVerificationData,
        dwallet_id: ObjectID,
        encrypted_user_secret_key_share_id: ObjectID,
        dwallet_network_encryption_key_id: ObjectID,
    },

    PartialSignatureVerification {
        data: PartialSignatureVerificationData,
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
                    data: MakeDWalletUserSecretKeySharesPublicData {
                        curve: session_event.event_data.curve.try_into()?,
                        public_user_secret_key_shares: session_event
                            .event_data
                            .public_user_secret_key_shares,
                        dwallet_decentralized_output: session_event.event_data.public_output,
                    },
                    dwallet_id: session_event.event_data.dwallet_id,
                    dwallet_network_encryption_key_id: session_event
                        .event_data
                        .dwallet_network_encryption_key_id,
                }
            }
            MPCRequestInput::DWalletImportedKeyVerificationRequest(event_data) => {
                ProtocolSpecificData::ImportedKeyVerification {
                    data: ImportedKeyVerificationData {
                        curve: event_data.event_data.curve.try_into()?,
                        encrypted_centralized_secret_share_and_proof: event_data
                            .event_data
                            .encrypted_centralized_secret_share_and_proof,
                        encryption_key: event_data.event_data.encryption_key,
                    },
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
                data: DKGFirstData {
                    curve: event_data.event_data.curve.try_into()?,
                },
                dwallet_id: event_data.event_data.dwallet_id,
                dwallet_network_encryption_key_id: event_data
                    .event_data
                    .dwallet_network_encryption_key_id,
            },
            MPCRequestInput::DKGSecond(event_data) => ProtocolSpecificData::DKGSecond {
                data: DKGSecondData {
                    curve: event_data.event_data.curve.try_into()?,
                    encrypted_centralized_secret_share_and_proof: event_data
                        .event_data
                        .encrypted_centralized_secret_share_and_proof,
                    encryption_key: event_data.event_data.encryption_key,
                },
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
                data: PresignData {
                    curve: session_event.event_data.curve.try_into()?,
                    signature_algorithm: session_event.event_data.signature_algorithm.try_into()?,
                },
                dwallet_id: session_event.event_data.dwallet_id,
                presign_id: session_event.event_data.presign_id,
                dwallet_public_output: session_event.event_data.dwallet_public_output,
                dwallet_network_encryption_key_id: session_event
                    .event_data
                    .dwallet_network_encryption_key_id,
            },
            MPCRequestInput::Sign(session_event) => ProtocolSpecificData::Sign {
                data: SignData {
                    curve: session_event.event_data.curve.try_into()?,
                    hash_scheme: Hash::try_from(session_event.event_data.hash_scheme)
                        .map_err(|_| DwalletMPCError::InvalidSessionPublicInput)?,
                    signature_algorithm: session_event.event_data.signature_algorithm.try_into()?,
                },
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
                    data: NetworkEncryptionKeyDkgData {
                        key_scheme: key_scheme.clone(),
                    },
                    dwallet_network_encryption_key_id: session_event
                        .event_data
                        .dwallet_network_encryption_key_id,
                }
            }
            MPCRequestInput::EncryptedShareVerification(event_data) => {
                ProtocolSpecificData::EncryptedShareVerification {
                    data: EncryptedShareVerificationData {
                        curve: event_data.event_data.curve.try_into()?,
                        encrypted_centralized_secret_share_and_proof: event_data
                            .event_data
                            .encrypted_centralized_secret_share_and_proof,
                        decentralized_public_output: event_data
                            .event_data
                            .decentralized_public_output,
                        encryption_key: event_data.event_data.encryption_key,
                    },
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
                    data: PartialSignatureVerificationData {
                        curve: event_data.event_data.curve.try_into()?,
                        message: event_data.event_data.message,
                        hash_type: Hash::try_from(event_data.event_data.hash_scheme).unwrap(),
                        signature_algorithm: event_data
                            .event_data
                            .signature_algorithm
                            .try_into()?,
                        dwallet_decentralized_output: event_data.event_data.dkg_output,
                        presign: event_data.event_data.presign,
                        partially_signed_message: event_data
                            .event_data
                            .message_centralized_signature,
                    },
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
                    data: NetworkEncryptionKeyReconfigurationData {},
                    dwallet_network_encryption_key_id: session_event
                        .event_data
                        .dwallet_network_encryption_key_id,
                }
            }
        };
        Ok(protocol_data)
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
