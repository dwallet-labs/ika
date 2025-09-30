use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletSignatureScheme, SerializedWrappedMPCPublicOutput,
};
use group::HashType;
use ika_protocol_config::ProtocolVersion;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    DWalletDKGFirstRoundRequestEvent, DWalletDKGRequestEvent, DWalletDKGSecondRoundRequestEvent,
    DWalletEncryptionKeyReconfigurationRequestEvent, DWalletImportedKeyVerificationRequestEvent,
    DWalletNetworkDKGEncryptionKeyRequestEvent, EncryptedShareVerificationRequestEvent,
    FutureSignRequestEvent, MakeDWalletUserSecretKeySharesPublicRequestEvent, PresignRequestEvent,
    SignRequestEvent, UserSecretKeyShareEventType,
};
use sui_types::base_types::ObjectID;

// Common structs for shared data between ProtocolSpecificData and AdvanceSpecificData
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Imported Key Verification")]
pub struct ImportedKeyVerificationData {
    pub curve: DWalletCurve,
    pub encrypted_centralized_secret_share_and_proof: Vec<u8>,
    pub encryption_key: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Make DWallet User Secret Key Shares Public")]
pub struct MakeDWalletUserSecretKeySharesPublicData {
    pub curve: DWalletCurve,
    pub public_user_secret_key_shares: Vec<u8>,
    pub dwallet_decentralized_output: SerializedWrappedMPCPublicOutput,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("dWallet DKG First Round")]
pub struct DKGFirstData {
    pub curve: DWalletCurve,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("dWallet DKG Second Round")]
pub struct DKGSecondData {
    pub curve: DWalletCurve,
    pub encrypted_centralized_secret_share_and_proof: Vec<u8>,
    pub encryption_key: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("dWallet DKG Second Round")]
pub struct DWalletDKGWithEncryptedUserShareData {
    pub curve: DWalletCurve,
    pub encrypted_centralized_secret_share_and_proof: Vec<u8>,
    pub encryption_key: Vec<u8>,
    pub centralized_public_key_share_and_proof: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Presign")]
pub struct PresignData {
    pub curve: DWalletCurve,
    pub signature_algorithm: DWalletSignatureScheme,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Sign")]
pub struct SignData {
    pub curve: DWalletCurve,
    pub hash_scheme: HashType,
    pub signature_algorithm: DWalletSignatureScheme,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Network Encryption Key DKG")]
pub struct NetworkEncryptionKeyDkgData {}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Network Encryption Key Reconfiguration")]
pub struct NetworkEncryptionKeyReconfigurationData {}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Network Encryption Key V1 to V2 Reconfiguration")]
pub struct NetworkEncryptionKeyV1ToV2ReconfigurationData {}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Network Encryption Key V2 Reconfiguration")]
pub struct NetworkEncryptionKeyV2ReconfigurationData {}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Encrypted Share Verification")]
pub struct EncryptedShareVerificationData {
    pub curve: DWalletCurve,
    pub encrypted_centralized_secret_share_and_proof: Vec<u8>,
    pub decentralized_public_output: SerializedWrappedMPCPublicOutput,
    pub encryption_key: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
#[display("Partial Signature Verification")]
pub struct PartialSignatureVerificationData {
    pub curve: DWalletCurve,
    pub message: Vec<u8>,
    pub hash_type: HashType,
    pub signature_algorithm: DWalletSignatureScheme,
    pub dwallet_decentralized_output: SerializedWrappedMPCPublicOutput,
    pub presign: SerializedWrappedMPCPublicOutput,
    pub partially_signed_message: SerializedWrappedMPCPublicOutput,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProtocolData {
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

    DWalletDKGWithEncryptedUserShare {
        data: DWalletDKGWithEncryptedUserShareData,
        dwallet_id: ObjectID,
        dwallet_network_encryption_key_id: ObjectID,
        encrypted_secret_share_id: ObjectID,
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
pub fn make_dwallet_user_secret_key_shares_public_protocol_data(
    request_event_data: MakeDWalletUserSecretKeySharesPublicRequestEvent,
) -> DwalletMPCResult<ProtocolData> {
    Ok(ProtocolData::MakeDWalletUserSecretKeySharesPublic {
        data: MakeDWalletUserSecretKeySharesPublicData {
            curve: request_event_data.curve.try_into()?,
            public_user_secret_key_shares: request_event_data.public_user_secret_key_shares,
            dwallet_decentralized_output: request_event_data.public_output,
        },
        dwallet_id: request_event_data.dwallet_id,
        dwallet_network_encryption_key_id: request_event_data.dwallet_network_encryption_key_id,
    })
}

pub fn imported_key_verification_protocol_data(
    request_event_data: DWalletImportedKeyVerificationRequestEvent,
) -> DwalletMPCResult<ProtocolData> {
    Ok(ProtocolData::ImportedKeyVerification {
        data: ImportedKeyVerificationData {
            curve: request_event_data.curve.try_into()?,
            encrypted_centralized_secret_share_and_proof: request_event_data
                .encrypted_centralized_secret_share_and_proof,
            encryption_key: request_event_data.encryption_key,
        },
        dwallet_id: request_event_data.dwallet_id,
        encrypted_user_secret_key_share_id: request_event_data.encrypted_user_secret_key_share_id,
        dwallet_network_encryption_key_id: request_event_data.dwallet_network_encryption_key_id,
        centralized_party_message: request_event_data.centralized_party_message,
    })
}

pub fn dwallet_dkg_first_protocol_data(
    request_event_data: DWalletDKGFirstRoundRequestEvent,
) -> DwalletMPCResult<ProtocolData> {
    Ok(ProtocolData::DKGFirst {
        data: DKGFirstData {
            curve: request_event_data.curve.try_into()?,
        },
        dwallet_id: request_event_data.dwallet_id,
        dwallet_network_encryption_key_id: request_event_data.dwallet_network_encryption_key_id,
    })
}

pub fn dwallet_dkg_with_encrypted_secret_share_protocol_data(
    request_event_data: DWalletDKGRequestEvent,
) -> DwalletMPCResult<ProtocolData> {
    let UserSecretKeyShareEventType::Encrypted {
        encrypted_user_secret_key_share_id,
        encrypted_centralized_secret_share_and_proof,
        encryption_key,
        ..
    } = request_event_data.user_secret_key_share.clone()
    else {
        return Err(
            ika_types::dwallet_mpc_error::DwalletMPCError::InternalError(
                "Expected an encrypted user secret key share".to_string(),
            ),
        );
    };

    Ok(ProtocolData::DWalletDKGWithEncryptedUserShare {
        data: DWalletDKGWithEncryptedUserShareData {
            curve: request_event_data.curve.try_into()?,
            encrypted_centralized_secret_share_and_proof,
            encryption_key,
            centralized_public_key_share_and_proof: request_event_data
                .centralized_public_key_share_and_proof,
        },
        dwallet_id: request_event_data.dwallet_id,
        dwallet_network_encryption_key_id: request_event_data.dwallet_network_encryption_key_id,
        encrypted_secret_share_id: encrypted_user_secret_key_share_id,
    })
}

pub fn dwallet_dkg_second_protocol_data(
    request_event_data: DWalletDKGSecondRoundRequestEvent,
) -> DwalletMPCResult<ProtocolData> {
    Ok(ProtocolData::DKGSecond {
        data: DKGSecondData {
            curve: request_event_data.curve.try_into()?,
            encrypted_centralized_secret_share_and_proof: request_event_data
                .encrypted_centralized_secret_share_and_proof,
            encryption_key: request_event_data.encryption_key,
        },
        dwallet_id: request_event_data.dwallet_id,
        encrypted_secret_share_id: request_event_data.encrypted_user_secret_key_share_id,
        dwallet_network_encryption_key_id: request_event_data.dwallet_network_encryption_key_id,
        first_round_output: request_event_data.first_round_output,
        centralized_public_key_share_and_proof: request_event_data
            .centralized_public_key_share_and_proof,
    })
}

pub fn presign_protocol_data(
    request_event_data: PresignRequestEvent,
) -> DwalletMPCResult<ProtocolData> {
    Ok(ProtocolData::Presign {
        data: PresignData {
            curve: request_event_data.curve.try_into()?,
            signature_algorithm: request_event_data.signature_algorithm.try_into()?,
        },
        dwallet_id: request_event_data.dwallet_id,
        presign_id: request_event_data.presign_id,
        dwallet_public_output: request_event_data.dwallet_public_output,
        dwallet_network_encryption_key_id: request_event_data.dwallet_network_encryption_key_id,
    })
}

pub fn sign_protocol_data(request_event_data: SignRequestEvent) -> DwalletMPCResult<ProtocolData> {
    Ok(ProtocolData::Sign {
        data: SignData {
            curve: request_event_data.curve.try_into()?,
            hash_scheme: HashType::try_from(request_event_data.hash_scheme)
                .map_err(|_| DwalletMPCError::InvalidSessionPublicInput)?,
            signature_algorithm: request_event_data.signature_algorithm.try_into()?,
        },
        dwallet_id: request_event_data.dwallet_id,
        sign_id: request_event_data.sign_id,
        is_future_sign: request_event_data.is_future_sign,
        dwallet_network_encryption_key_id: request_event_data.dwallet_network_encryption_key_id,
        dwallet_decentralized_public_output: request_event_data.dwallet_decentralized_public_output,
        message: request_event_data.message,
        presign: request_event_data.presign,
        message_centralized_signature: request_event_data.message_centralized_signature,
    })
}

pub fn network_encryption_key_dkg_protocol_data(
    request_event_data: DWalletNetworkDKGEncryptionKeyRequestEvent,
) -> DwalletMPCResult<ProtocolData> {
    Ok(ProtocolData::NetworkEncryptionKeyDkg {
        data: NetworkEncryptionKeyDkgData {},
        dwallet_network_encryption_key_id: request_event_data.dwallet_network_encryption_key_id,
    })
}

pub fn network_encryption_key_reconfiguration_protocol_data(
    request_event_data: DWalletEncryptionKeyReconfigurationRequestEvent,
) -> DwalletMPCResult<ProtocolData> {
    Ok(ProtocolData::NetworkEncryptionKeyReconfiguration {
        data: NetworkEncryptionKeyReconfigurationData {},
        dwallet_network_encryption_key_id: request_event_data.dwallet_network_encryption_key_id,
    })
}

pub fn encrypted_share_verification_protocol_data(
    request_event_data: EncryptedShareVerificationRequestEvent,
) -> DwalletMPCResult<ProtocolData> {
    Ok(ProtocolData::EncryptedShareVerification {
        data: EncryptedShareVerificationData {
            curve: request_event_data.curve.try_into()?,
            encrypted_centralized_secret_share_and_proof: request_event_data
                .encrypted_centralized_secret_share_and_proof,
            decentralized_public_output: request_event_data.decentralized_public_output,
            encryption_key: request_event_data.encryption_key,
        },
        dwallet_id: request_event_data.dwallet_id,
        encrypted_user_secret_key_share_id: request_event_data.encrypted_user_secret_key_share_id,
        dwallet_network_encryption_key_id: request_event_data.dwallet_network_encryption_key_id,
    })
}

pub fn partial_signature_verification_protocol_data(
    request_event_data: FutureSignRequestEvent,
) -> DwalletMPCResult<ProtocolData> {
    Ok(ProtocolData::PartialSignatureVerification {
        data: PartialSignatureVerificationData {
            curve: request_event_data.curve.try_into()?,
            message: request_event_data.message,
            hash_type: HashType::try_from(request_event_data.hash_scheme).unwrap(),
            signature_algorithm: request_event_data.signature_algorithm.try_into()?,
            dwallet_decentralized_output: request_event_data.dkg_output,
            presign: request_event_data.presign,
            partially_signed_message: request_event_data.message_centralized_signature,
        },
        dwallet_id: request_event_data.dwallet_id,
        partial_centralized_signed_message_id: request_event_data
            .partial_centralized_signed_message_id,
        dwallet_network_encryption_key_id: request_event_data.dwallet_network_encryption_key_id,
    })
}

impl ProtocolData {
    pub fn network_encryption_key_id(&self) -> Option<ObjectID> {
        match self {
            ProtocolData::DWalletDKGWithEncryptedUserShare {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolData::DKGFirst {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolData::DKGSecond {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolData::Presign {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolData::Sign {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolData::NetworkEncryptionKeyDkg {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolData::NetworkEncryptionKeyReconfiguration {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolData::EncryptedShareVerification {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolData::PartialSignatureVerification {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolData::MakeDWalletUserSecretKeySharesPublic {
                dwallet_network_encryption_key_id,
                ..
            }
            | ProtocolData::ImportedKeyVerification {
                dwallet_network_encryption_key_id,
                ..
            } => Some(*dwallet_network_encryption_key_id),
        }
    }
}
