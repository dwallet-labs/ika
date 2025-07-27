use crate::crypto::{AuthorityName, keccak256_digest};
use crate::message::DWalletCheckpointMessageKind;
use dwallet_mpc_types::dwallet_mpc::DWalletMPCNetworkKeyScheme;
use move_core_types::account_address::AccountAddress;
use move_core_types::ident_str;
use move_core_types::identifier::IdentStr;
use move_core_types::language_storage::StructTag;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::fmt::{Debug, Display};
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::collection_types::{Table, TableVec};

// TODO (#650): Rename Move structs
pub const DWALLET_SESSION_EVENT_STRUCT_NAME: &IdentStr = ident_str!("DWalletSessionEvent");
pub const DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME: &IdentStr = ident_str!("coordinator");
pub const VALIDATOR_SET_MODULE_NAME: &IdentStr = ident_str!("validator_set");
pub const SESSIONS_MANAGER_MODULE_NAME: &IdentStr = ident_str!("sessions_manager");
pub const DWALLET_2PC_MPC_COORDINATOR_INNER_MODULE_NAME: &IdentStr =
    ident_str!("coordinator_inner");
pub const DWALLET_DKG_FIRST_ROUND_REQUEST_EVENT_STRUCT_NAME: &IdentStr =
    ident_str!("DWalletDKGFirstRoundRequestEvent");
pub const DWALLET_MAKE_DWALLET_USER_SECRET_KEY_SHARES_PUBLIC_REQUEST_EVENT: &IdentStr =
    ident_str!("MakeDWalletUserSecretKeySharePublicRequestEvent");
pub const DWALLET_IMPORTED_KEY_VERIFICATION_REQUEST_EVENT: &IdentStr =
    ident_str!("DWalletImportedKeyVerificationRequestEvent");
// TODO (#650): Rename Move structs
pub const DWALLET_DKG_SECOND_ROUND_REQUEST_EVENT_STRUCT_NAME: &IdentStr =
    ident_str!("DWalletDKGSecondRoundRequestEvent");
// TODO (#650): Rename Move structs
pub const PRESIGN_REQUEST_EVENT_STRUCT_NAME: &IdentStr = ident_str!("PresignRequestEvent");
pub const SIGN_REQUEST_EVENT_STRUCT_NAME: &IdentStr = ident_str!("SignRequestEvent");
pub const LOCKED_NEXT_COMMITTEE_EVENT_STRUCT_NAME: &IdentStr =
    ident_str!("LockedNextEpochCommitteeEvent");
pub const VALIDATOR_DATA_FOR_SECRET_SHARE_STRUCT_NAME: &IdentStr =
    ident_str!("ValidatorDataForDWalletSecretShare");
pub const START_NETWORK_DKG_EVENT_STRUCT_NAME: &IdentStr =
    ident_str!("DWalletNetworkDKGEncryptionKeyRequestEvent");
pub const NETWORK_ENCRYPTION_KEY_RECONFIGURATION_STR_KEY: &str =
    "NetworkEncryptionKeyReconfiguration";
pub const NETWORK_ENCRYPTION_KEY_DKG_STR_KEY: &str = "NetworkEncryptionKeyDkg";
pub const SIGN_STR_KEY: &str = "Sign";

pub const DKG_FIRST_ROUND_PROTOCOL_FLAG: u32 = 0;
pub const DKG_SECOND_ROUND_PROTOCOL_FLAG: u32 = 1;
pub const RE_ENCRYPT_USER_SHARE_PROTOCOL_FLAG: u32 = 2;
pub const MAKE_DWALLET_USER_SECRET_KEY_SHARE_PUBLIC_PROTOCOL_FLAG: u32 = 3;
pub const IMPORTED_KEY_DWALLET_VERIFICATION_PROTOCOL_FLAG: u32 = 4;
pub const PRESIGN_PROTOCOL_FLAG: u32 = 5;
pub const SIGN_PROTOCOL_FLAG: u32 = 6;
pub const FUTURE_SIGN_PROTOCOL_FLAG: u32 = 7;
pub const SIGN_WITH_PARTIAL_USER_SIGNATURE_PROTOCOL_FLAG: u32 = 8;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MPCRequestInput {
    /// Make the dWallet user secret key shares public, so the network can control it.
    MakeDWalletUserSecretKeySharesPublicRequest(
        DWalletSessionEvent<MakeDWalletUserSecretKeySharesPublicRequestEvent>,
    ),

    /// Import a secret key to a dWallet.
    DWalletImportedKeyVerificationRequest(
        DWalletSessionEvent<DWalletImportedKeyVerificationRequestEvent>,
    ),
    /// The first round of the DKG protocol.
    DKGFirst(DWalletSessionEvent<DWalletDKGFirstRoundRequestEvent>),
    /// The second round of the DKG protocol.
    /// Contains the data of the event that triggered the round,
    /// and the network key version of the first round.
    DKGSecond(DWalletSessionEvent<DWalletDKGSecondRoundRequestEvent>),
    /// The first round of the Presign protocol for each message in the Batch.
    /// Contains the `ObjectId` of the dWallet object,
    /// the DKG decentralized output, the batch session ID (same for each message in the batch),
    /// and the dWallets network key version.
    Presign(DWalletSessionEvent<PresignRequestEvent>),
    /// The first and only round of the Sign protocol.
    /// Contains all the data needed to sign the message.
    Sign(DWalletSessionEvent<SignRequestEvent>),
    /// The only round of the network DKG protocol.
    /// Contains the network key scheme, the dWallet network decryption key object ID
    /// and at the end of the session holds the new key version.
    NetworkEncryptionKeyDkg(
        DWalletMPCNetworkKeyScheme,
        DWalletSessionEvent<DWalletNetworkDKGEncryptionKeyRequestEvent>,
    ),
    /// The round of verifying the encrypted share proof is valid and
    /// that the signature on it is valid.
    /// This is not a real MPC round,
    /// but we use it to start the verification process using the same events mechanism
    /// because the system does not support native functions.
    EncryptedShareVerification(DWalletSessionEvent<EncryptedShareVerificationRequestEvent>),
    PartialSignatureVerification(DWalletSessionEvent<FutureSignRequestEvent>),
    NetworkEncryptionKeyReconfiguration(
        DWalletSessionEvent<DWalletEncryptionKeyReconfigurationRequestEvent>,
    ),
}

impl Display for MPCRequestInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MPCRequestInput::DKGFirst(_) => write!(f, "dWalletDKGFirstRound"),
            MPCRequestInput::DKGSecond(_) => write!(f, "dWalletDKGSecondRound"),
            MPCRequestInput::Presign(_) => write!(f, "Presign"),
            MPCRequestInput::Sign(_) => write!(f, "{SIGN_STR_KEY}"),
            MPCRequestInput::NetworkEncryptionKeyDkg(_, _) => {
                write!(f, "{NETWORK_ENCRYPTION_KEY_DKG_STR_KEY}")
            }
            MPCRequestInput::EncryptedShareVerification(_) => {
                write!(f, "EncryptedShareVerification")
            }
            MPCRequestInput::PartialSignatureVerification(_) => {
                write!(f, "PartialSignatureVerification")
            }
            MPCRequestInput::NetworkEncryptionKeyReconfiguration(_) => {
                write!(f, "{NETWORK_ENCRYPTION_KEY_RECONFIGURATION_STR_KEY}")
            }
            MPCRequestInput::MakeDWalletUserSecretKeySharesPublicRequest(_) => {
                write!(f, "MakeDWalletUserSecretKeySharesPublicRequest")
            }
            MPCRequestInput::DWalletImportedKeyVerificationRequest(_) => {
                write!(f, "DWalletImportedKeyVerificationRequestEvent")
            }
        }
    }
}

impl MPCRequestInput {
    pub fn get_curve(&self) -> String {
        let curve = match self {
            MPCRequestInput::DKGFirst(event) => Some(event.event_data.curve),
            MPCRequestInput::DKGSecond(event) => Some(event.event_data.curve),
            MPCRequestInput::Presign(event) => Some(event.event_data.curve),
            MPCRequestInput::Sign(event) => Some(event.event_data.curve),
            MPCRequestInput::NetworkEncryptionKeyDkg(_, _event) => None,
            MPCRequestInput::EncryptedShareVerification(event) => Some(event.event_data.curve),
            MPCRequestInput::PartialSignatureVerification(event) => Some(event.event_data.curve),
            MPCRequestInput::NetworkEncryptionKeyReconfiguration(_event) => None,
            MPCRequestInput::MakeDWalletUserSecretKeySharesPublicRequest(event) => {
                Some(event.event_data.curve)
            }

            MPCRequestInput::DWalletImportedKeyVerificationRequest(event) => {
                Some(event.event_data.curve)
            }
        };
        match &curve {
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

    pub fn get_hash_scheme(&self) -> String {
        let hash_scheme = match self {
            MPCRequestInput::DKGFirst(_) => None,
            MPCRequestInput::DKGSecond(_) => None,
            MPCRequestInput::Presign(_) => None,
            MPCRequestInput::Sign(event) => Some(event.event_data.hash_scheme),
            MPCRequestInput::NetworkEncryptionKeyDkg(_, _event) => None,
            MPCRequestInput::EncryptedShareVerification(_) => None,
            MPCRequestInput::PartialSignatureVerification(event) => {
                Some(event.event_data.hash_scheme)
            }
            MPCRequestInput::NetworkEncryptionKeyReconfiguration(_event) => None,
            MPCRequestInput::MakeDWalletUserSecretKeySharesPublicRequest(_) => None,
            MPCRequestInput::DWalletImportedKeyVerificationRequest(_) => None,
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

    pub fn get_signature_algorithm(&self) -> String {
        let signature_alg = match self {
            MPCRequestInput::DKGFirst(_event) => None,
            MPCRequestInput::DKGSecond(_event) => None,
            MPCRequestInput::Presign(event) => Some(event.event_data.signature_algorithm),
            MPCRequestInput::Sign(event) => Some(event.event_data.signature_algorithm),
            MPCRequestInput::NetworkEncryptionKeyDkg(_, _event) => None,
            MPCRequestInput::EncryptedShareVerification(_) => None,
            MPCRequestInput::PartialSignatureVerification(event) => {
                Some(event.event_data.signature_algorithm)
            }
            MPCRequestInput::NetworkEncryptionKeyReconfiguration(_event) => None,
            MPCRequestInput::MakeDWalletUserSecretKeySharesPublicRequest(_) => None,
            MPCRequestInput::DWalletImportedKeyVerificationRequest(_event) => None,
        };
        match &signature_alg {
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

    pub fn get_network_encryption_key_id(&self) -> Option<ObjectID> {
        match self {
            MPCRequestInput::DKGFirst(event) => {
                Some(event.event_data.dwallet_network_encryption_key_id)
            }
            MPCRequestInput::DKGSecond(event) => {
                Some(event.event_data.dwallet_network_encryption_key_id)
            }
            MPCRequestInput::Presign(event) => {
                Some(event.event_data.dwallet_network_encryption_key_id)
            }
            MPCRequestInput::Sign(event) => {
                Some(event.event_data.dwallet_network_encryption_key_id)
            }
            MPCRequestInput::NetworkEncryptionKeyDkg(_, event) => {
                Some(event.event_data.dwallet_network_encryption_key_id)
            }
            MPCRequestInput::EncryptedShareVerification(event) => {
                Some(event.event_data.dwallet_network_encryption_key_id)
            }
            MPCRequestInput::PartialSignatureVerification(event) => {
                Some(event.event_data.dwallet_network_encryption_key_id)
            }
            MPCRequestInput::NetworkEncryptionKeyReconfiguration(event) => {
                Some(event.event_data.dwallet_network_encryption_key_id)
            }
            MPCRequestInput::MakeDWalletUserSecretKeySharesPublicRequest(event) => {
                Some(event.event_data.dwallet_network_encryption_key_id)
            }
            MPCRequestInput::DWalletImportedKeyVerificationRequest(event) => {
                Some(event.event_data.dwallet_network_encryption_key_id)
            }
        }
    }
}

impl Debug for MPCRequestInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MPCRequestInput::DKGFirst(_) => write!(f, "dWalletDKGFirstRound"),
            MPCRequestInput::DKGSecond(_) => write!(f, "dWalletDKGSecondRound"),
            MPCRequestInput::Presign(_) => write!(f, "Presign"),
            MPCRequestInput::Sign(_) => write!(f, "Sign"),
            MPCRequestInput::NetworkEncryptionKeyDkg(_, _) => write!(f, "NetworkDkg"),
            MPCRequestInput::EncryptedShareVerification(_) => {
                write!(f, "EncryptedShareVerification")
            }
            MPCRequestInput::PartialSignatureVerification(_) => {
                write!(f, "PartialSignatureVerification")
            }
            MPCRequestInput::NetworkEncryptionKeyReconfiguration(_) => {
                write!(f, "DecryptionKeyReconfiguration")
            }
            MPCRequestInput::MakeDWalletUserSecretKeySharesPublicRequest(_) => {
                write!(f, "MakeDWalletUserSecretKeySharesPublicRequest")
            }
            MPCRequestInput::DWalletImportedKeyVerificationRequest(_) => {
                write!(f, "DWalletImportedKeyVerificationRequestEvent")
            }
        }
    }
}

/// This is a wrapper type for the [`SuiEvent`] type that is being used to write it to the local RocksDB.
/// This is needed because the [`SuiEvent`] cannot be directly written to the RocksDB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBSuiEvent {
    pub type_: StructTag,
    pub contents: Vec<u8>,
    // True when the event was pulled from the state of the object,
    // and False when it was pushed as an event.
    pub pulled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DWalletMPCEvent {
    pub session_request: MPCSessionRequest,
    // True when the event was pulled from the state of the object,
    // and False when it was pushed as an event.
    pub pulled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DWalletMPCOutput {
    /// The authority that sent the output.
    pub authority: AuthorityName,
    pub session_identifier: SessionIdentifier,
    /// The final value of the MPC session.
    pub output: Vec<DWalletCheckpointMessageKind>,
    pub malicious_authorities: Vec<AuthorityName>,
}

/// The message a Validator can send to the other parties while
/// running a dWallet MPC session.
#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub struct DWalletMPCMessage {
    /// The serialized message.
    pub message: Vec<u8>,
    /// The authority (Validator) that sent the message.
    pub authority: AuthorityName,
    pub session_identifier: SessionIdentifier,
}

/// Holds information about the current MPC session.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct MPCSessionRequest {
    pub session_type: SessionType,
    /// Unique identifier for the MPC session.
    pub session_identifier: SessionIdentifier,
    pub session_sequence_number: u64,
    /// The input to the request MPC session.
    pub request_input: MPCRequestInput,
    pub epoch: u64,
    pub requires_network_key_data: bool,
    pub requires_next_active_committee: bool,
}

pub trait DWalletSessionEventTrait {
    fn type_(packages_config: &IkaPackagesConfig) -> StructTag;
}

/// The DWallet MPC session type
/// User initiated sessions have a sequence number, which is used to determine in which epoch the session will get
/// completed.
/// System sessions are guaranteed to always get completed in the epoch they were created in.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, JsonSchema, Eq, PartialEq, Hash)]
pub enum SessionType {
    User,
    System,
}

#[derive(Eq, PartialEq, Hash, Clone, Copy, Serialize, Deserialize)]
pub struct SessionIdentifier {
    session_type: SessionType,
    session_identifier: [u8; SessionIdentifier::LENGTH],
    session_identifier_preimage: [u8; SessionIdentifier::LENGTH],
}

impl SessionIdentifier {
    /// Instantiate a [`SessionIdentifier`] from the pre-image session identifier.
    /// It is hashed together with its distinguisher and the version.
    /// Guarantees same values of `session_identifier_preimage` yield different output for `User` and `System`
    pub fn new(session_type: SessionType, session_identifier_preimage: [u8; Self::LENGTH]) -> Self {
        let version = 0u64;

        // We are adding a string distinguisher between
        // the `User` and `System` sessions, so that when it is hashed, the same inner value
        // in the two different options will yield a different output, thus guaranteeing
        // user-initiated sessions can never block or reuse session IDs for system sessions.
        let session_type_unique_prefix = match session_type {
            SessionType::User => [
                version.to_be_bytes().as_slice(),
                b"USER",
                &session_identifier_preimage,
            ]
            .concat(),
            SessionType::System => [
                version.to_be_bytes().as_slice(),
                b"SYSTEM",
                &session_identifier_preimage,
            ]
            .concat(),
        };

        let session_identifier = keccak256_digest(&session_type_unique_prefix);

        Self {
            session_type,
            session_identifier,
            session_identifier_preimage,
        }
    }

    /// The number of bytes in an address.
    pub const LENGTH: usize = 32;

    pub fn to_vec(self) -> Vec<u8> {
        self.session_identifier.to_vec()
    }

    pub fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.session_identifier
    }
}

impl AsRef<[u8]> for SessionIdentifier {
    fn as_ref(&self) -> &[u8] {
        &self.session_identifier
    }
}

impl std::ops::Deref for SessionIdentifier {
    type Target = [u8; Self::LENGTH];

    fn deref(&self) -> &Self::Target {
        &self.session_identifier
    }
}

impl fmt::Display for SessionIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        let session_type = self.session_type;

        write!(
            f,
            "SessionIdentifier {{ session_type: {session_type:?}, session_identifier_preimage: 0x{}, session_identifier: 0x{} }}",
            hex::encode(self.session_identifier_preimage),
            hex::encode(self.session_identifier)
        )
    }
}

impl fmt::Debug for SessionIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let session_type = self.session_type;

        write!(
            f,
            "SessionIdentifier {{ session_type: {session_type:?}, session_identifier_preimage: 0x{}, session_identifier: 0x{} }}",
            hex::encode(self.session_identifier_preimage),
            hex::encode(self.session_identifier)
        )
    }
}

impl From<SessionIdentifier> for Vec<u8> {
    fn from(session_identifier: SessionIdentifier) -> Vec<u8> {
        session_identifier.to_vec()
    }
}

impl From<&SessionIdentifier> for Vec<u8> {
    fn from(session_identifier: &SessionIdentifier) -> Vec<u8> {
        session_identifier.to_vec()
    }
}

impl From<SessionIdentifier> for [u8; SessionIdentifier::LENGTH] {
    fn from(session_identifier: SessionIdentifier) -> Self {
        session_identifier.session_identifier
    }
}

impl From<&SessionIdentifier> for [u8; SessionIdentifier::LENGTH] {
    fn from(session_identifier: &SessionIdentifier) -> Self {
        session_identifier.session_identifier
    }
}

impl PartialOrd for SessionIdentifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SessionIdentifier {
    fn cmp(&self, other: &Self) -> Ordering {
        self.session_identifier.cmp(&other.session_identifier)
    }
}

pub type AsyncProtocol = twopc_mpc::secp256k1::class_groups::AsyncProtocol;

/// Represents the Rust version of the Move struct `ika_system::dwallet_2pc_mpc_coordinator_inner::DWalletSessionEvent`.
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq, Hash)]
pub struct DWalletSessionEvent<E: DWalletSessionEventTrait> {
    pub epoch: u64,
    pub session_object_id: ObjectID,
    pub session_type: SessionType,
    pub session_sequence_number: u64,
    // DO NOT MAKE THIS PUBLIC! ONLY CALL `session_identifier_digest`
    session_identifier_preimage: Vec<u8>,
    pub event_data: E,
}

impl<E: DWalletSessionEventTrait> DWalletSessionEventTrait for DWalletSessionEvent<E> {
    /// This function allows comparing this event with the Move event.
    /// It is used to detect [`DWalletSessionEvent`] events from the chain and initiate the MPC session.
    fn type_(packages_config: &IkaPackagesConfig) -> StructTag {
        StructTag {
            address: *packages_config.ika_dwallet_2pc_mpc_package_id,
            name: DWALLET_SESSION_EVENT_STRUCT_NAME.to_owned(),
            module: SESSIONS_MANAGER_MODULE_NAME.to_owned(),
            type_params: vec![<E as DWalletSessionEventTrait>::type_(packages_config).into()],
        }
    }
}

impl<E: DWalletSessionEventTrait> DWalletSessionEvent<E> {
    pub fn is_dwallet_mpc_event(event: StructTag, package_id: AccountAddress) -> bool {
        event.address == package_id
            && event.module == SESSIONS_MANAGER_MODULE_NAME.to_owned()
            && event.name == DWALLET_SESSION_EVENT_STRUCT_NAME.to_owned()
    }

    /// Convert the pre-image session identifier to the session ID by hashing it together with its distinguisher.
    /// Guarantees same values of `self.session_identifier_preimage` yield different output for `User` and `System`
    pub fn session_identifier_digest(&self) -> SessionIdentifier {
        let session_identifier_preimage = self
            .session_identifier_preimage
            .clone()
            .try_into()
            .expect("Session Identifier Preimage is Hardcoded to 32-bytes Length in Move");

        SessionIdentifier::new(self.session_type, session_identifier_preimage)
    }
}

/// The Rust representation of the `EncryptedShareVerificationRequestEvent` Move struct.
/// Defined here so that we can use it in the [`MPCRequestInput`] enum,
/// as the inner data of the [`MPCRequestInput::EncryptedShareVerification`].
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq, Hash)]
pub struct EncryptedShareVerificationRequestEvent {
    /// Encrypted centralized secret key share and the associated
    /// cryptographic proof of encryption.
    pub encrypted_centralized_secret_share_and_proof: Vec<u8>,
    /// The public output of the decentralized party.
    /// Belongs to the dWallet that its centralized secret share is being encrypted.
    pub decentralized_public_output: Vec<u8>,
    /// The ID of the dWallet that this encrypted secret key share belongs to.
    pub dwallet_id: ObjectID,
    /// The encryption key used to encrypt the secret key share with.
    pub encryption_key: Vec<u8>,
    /// The `EncryptionKey` Move object ID.
    pub encryption_key_id: ObjectID,
    pub encrypted_user_secret_key_share_id: ObjectID,
    pub source_encrypted_user_secret_key_share_id: ObjectID,
    pub dwallet_network_encryption_key_id: ObjectID,
    pub curve: u32,
}

impl DWalletSessionEventTrait for EncryptedShareVerificationRequestEvent {
    fn type_(packages_config: &IkaPackagesConfig) -> StructTag {
        StructTag {
            address: *packages_config.ika_dwallet_2pc_mpc_package_id,
            name: ident_str!("EncryptedShareVerificationRequestEvent").to_owned(),
            module: DWALLET_2PC_MPC_COORDINATOR_INNER_MODULE_NAME.to_owned(),
            type_params: vec![],
        }
    }
}

/// Rust representation of the Move `FutureSignRequestEvent` Event.
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq, Hash)]
pub struct FutureSignRequestEvent {
    pub dwallet_id: ObjectID,
    pub partial_centralized_signed_message_id: ObjectID,
    pub message: Vec<u8>,
    pub presign: Vec<u8>,
    pub dkg_output: Vec<u8>,
    pub curve: u32,
    pub signature_algorithm: u32,
    pub hash_scheme: u32,
    pub message_centralized_signature: Vec<u8>,
    pub dwallet_network_encryption_key_id: ObjectID,
}

impl DWalletSessionEventTrait for FutureSignRequestEvent {
    fn type_(packages_config: &IkaPackagesConfig) -> StructTag {
        StructTag {
            address: *packages_config.ika_dwallet_2pc_mpc_package_id,
            name: ident_str!("FutureSignRequestEvent").to_owned(),
            module: DWALLET_2PC_MPC_COORDINATOR_INNER_MODULE_NAME.to_owned(),
            type_params: vec![],
        }
    }
}

/// Represents the Rust version of the Move struct `ika_system::dwallet_2pc_mpc_coordinator_inner::DWalletDKGSecondRoundRequestEvent`.
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq, Hash)]
pub struct DWalletDKGSecondRoundRequestEvent {
    pub encrypted_user_secret_key_share_id: ObjectID,
    pub dwallet_id: ObjectID,
    /// The output from the first round of the DKG process.
    pub first_round_output: Vec<u8>,
    /// A serialized vector containing the centralized public key share and its proof.
    pub centralized_public_key_share_and_proof: Vec<u8>,
    /// The `DWalletCap` object's ID associated with the `DWallet`.
    pub dwallet_cap_id: ObjectID,
    /// Encrypted centralized secret key share and the associated cryptographic proof of encryption.
    pub encrypted_centralized_secret_share_and_proof: Vec<u8>,
    /// The `EncryptionKey` object used for encrypting the secret key share.
    pub encryption_key: Vec<u8>,
    /// The unique identifier of the `EncryptionKey` object.
    pub encryption_key_id: ObjectID,
    pub encryption_key_address: SuiAddress,
    pub user_public_output: Vec<u8>,
    /// The Ed25519 public key of the initiator,
    /// used to verify the signature on the centralized public output.
    pub signer_public_key: Vec<u8>,
    pub dwallet_network_encryption_key_id: ObjectID,
    pub curve: u32,
}

impl DWalletSessionEventTrait for DWalletDKGSecondRoundRequestEvent {
    /// This function allows comparing this event with the Move event.
    /// It is used to detect [`DWalletDKGSecondRoundRequestEvent`] events from the chain
    /// and initiate the MPC session.
    fn type_(packages_config: &IkaPackagesConfig) -> StructTag {
        StructTag {
            address: *packages_config.ika_dwallet_2pc_mpc_package_id,
            name: DWALLET_DKG_SECOND_ROUND_REQUEST_EVENT_STRUCT_NAME.to_owned(),
            module: DWALLET_2PC_MPC_COORDINATOR_INNER_MODULE_NAME.to_owned(),
            type_params: vec![],
        }
    }
}

/// The possible result of advancing the MPC protocol.
#[derive(PartialEq, Eq, Hash, Clone, Debug, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AdvanceResult {
    Success,
    Failure,
}

/// Represents the Rust version of the Move struct `ika_system::dwallet_2pc_mpc_coordinator_inner::PresignRequestEvent`.
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq, Hash)]
pub struct PresignRequestEvent {
    /// The `DWallet` object's ID associated with the DKG output.
    pub dwallet_id: Option<ObjectID>,
    pub presign_id: ObjectID,
    /// The DKG decentralized final output to use for the presign session.
    pub dwallet_public_output: Option<Vec<u8>>,
    pub dwallet_network_encryption_key_id: ObjectID,
    pub curve: u32,
    pub signature_algorithm: u32,
}

impl DWalletSessionEventTrait for PresignRequestEvent {
    /// This function allows comparing this event with the Move event.
    /// It is used to detect [`PresignRequestEvent`] events
    /// from the chain and initiate the MPC session.
    fn type_(packages_config: &IkaPackagesConfig) -> StructTag {
        StructTag {
            address: *packages_config.ika_dwallet_2pc_mpc_package_id,
            name: PRESIGN_REQUEST_EVENT_STRUCT_NAME.to_owned(),
            module: DWALLET_2PC_MPC_COORDINATOR_INNER_MODULE_NAME.to_owned(),
            type_params: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IkaPackagesConfig {
    /// The move package id of ika (IKA) on sui.
    pub ika_package_id: ObjectID,
    /// The move package id of ika_common on sui.
    pub ika_common_package_id: ObjectID,
    /// The move package id of ika_dwallet_2pc_mpc on sui.
    pub ika_dwallet_2pc_mpc_package_id: ObjectID,
    /// The move package id of ika_system on sui.
    pub ika_system_package_id: ObjectID,
    /// The object id of system on sui.
    pub ika_system_object_id: ObjectID,
    /// The object id of ika_dwallet_coordinator on sui.
    pub ika_dwallet_coordinator_object_id: ObjectID,
}

impl sui_config::Config for IkaPackagesConfig {}

/// Represents the Rust version of the Move struct `ika_system::dwallet_2pc_mpc_coordinator_inner::DWalletDKGFirstRoundRequestEvent`.
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq, Hash)]
pub struct DWalletDKGFirstRoundRequestEvent {
    pub dwallet_id: ObjectID,
    /// The `DWalletCap` object's ID associated with the `DWallet`.
    pub dwallet_cap_id: ObjectID,
    pub dwallet_network_encryption_key_id: ObjectID,
    pub curve: u32,
}

impl DWalletSessionEventTrait for DWalletDKGFirstRoundRequestEvent {
    /// This function allows comparing this event with the Move event.
    /// It is used to detect [`DWalletDKGFirstRoundRequestEvent`] events from the chain and initiate the MPC session.
    fn type_(packages_config: &IkaPackagesConfig) -> StructTag {
        StructTag {
            address: *packages_config.ika_dwallet_2pc_mpc_package_id,
            name: DWALLET_DKG_FIRST_ROUND_REQUEST_EVENT_STRUCT_NAME.to_owned(),
            module: DWALLET_2PC_MPC_COORDINATOR_INNER_MODULE_NAME.to_owned(),
            type_params: vec![],
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DWalletImportedKeyVerificationRequestEvent {
    /// The unique session identifier for the DWallet.
    pub dwallet_id: ObjectID,

    /// The Encrypted user secret key share object ID.
    pub encrypted_user_secret_key_share_id: ObjectID,

    /// The message delivered to the decentralized party from a centralized party.
    /// Includes the encrypted decentralized secret key share and
    /// the associated cryptographic proof of encryption.
    pub centralized_party_message: Vec<u8>,

    /// The unique identifier of the dWallet capability associated with this session.
    pub dwallet_cap_id: ObjectID,

    /// Encrypted centralized secret key share and the associated cryptographic proof of encryption.
    pub encrypted_centralized_secret_share_and_proof: Vec<u8>,

    /// The user `EncryptionKey` object used for encrypting the user secret key share.
    pub encryption_key: Vec<u8>,

    /// The unique identifier of the `EncryptionKey` object.
    pub encryption_key_id: ObjectID,

    pub encryption_key_address: SuiAddress,

    /// The public output of the centralized party in the DKG process.
    pub user_public_output: Vec<u8>,

    /// The Ed25519 public key of the initiator,
    /// used to verify the signature on the centralized public output.
    pub signer_public_key: Vec<u8>,

    /// The MPC network decryption key id that is used to decrypt associated dWallet.
    pub dwallet_network_encryption_key_id: ObjectID,

    /// The elliptic curve used for the dWallet.
    pub curve: u32,
}

/// Represents the Rust version of the Move struct `ika_system::dwallet_2pc_mpc_coordinator_inner::DWalletDKGFirstRoundRequestEvent`.
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq, Hash)]
pub struct MakeDWalletUserSecretKeySharesPublicRequestEvent {
    pub public_user_secret_key_shares: Vec<u8>,
    pub public_output: Vec<u8>,
    pub curve: u32,
    pub dwallet_id: ObjectID,
    pub dwallet_network_encryption_key_id: ObjectID,
}

impl DWalletSessionEventTrait for MakeDWalletUserSecretKeySharesPublicRequestEvent {
    /// This function allows comparing this event with the Move event.
    /// It is used to detect [`DWalletDKGFirstRoundRequestEvent`] events from the chain and initiate the MPC session.
    fn type_(packages_config: &IkaPackagesConfig) -> StructTag {
        StructTag {
            address: *packages_config.ika_dwallet_2pc_mpc_package_id,
            name: DWALLET_MAKE_DWALLET_USER_SECRET_KEY_SHARES_PUBLIC_REQUEST_EVENT.to_owned(),
            module: DWALLET_2PC_MPC_COORDINATOR_INNER_MODULE_NAME.to_owned(),
            type_params: vec![],
        }
    }
}

impl DWalletSessionEventTrait for DWalletImportedKeyVerificationRequestEvent {
    /// This function allows comparing this event with the Move event.
    /// It is used to detect [`DWalletDKGFirstRoundRequestEvent`] events from the chain and initiate the MPC session.
    fn type_(packages_config: &IkaPackagesConfig) -> StructTag {
        StructTag {
            address: *packages_config.ika_dwallet_2pc_mpc_package_id,
            name: DWALLET_IMPORTED_KEY_VERIFICATION_REQUEST_EVENT.to_owned(),
            module: DWALLET_2PC_MPC_COORDINATOR_INNER_MODULE_NAME.to_owned(),
            type_params: vec![],
        }
    }
}

/// Represents the Rust version of the Move
/// struct `ika_system::dwallet_2pc_mpc_coordinator_inner::SignRequestEvent`.
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq, Hash)]
pub struct SignRequestEvent {
    pub sign_id: ObjectID,
    /// The `DWallet` object's ObjectID associated with the DKG output.
    pub dwallet_id: ObjectID,
    /// The public output of the decentralized party in the dWallet DKG process.
    pub dwallet_decentralized_public_output: Vec<u8>,
    pub curve: u32,
    pub signature_algorithm: u32,
    pub hash_scheme: u32,
    /// Hashed messages to Sign.
    pub message: Vec<u8>,
    /// The dWallet mpc network key version
    pub dwallet_network_encryption_key_id: ObjectID,
    pub presign_id: ObjectID,

    /// The presign protocol output as bytes.
    pub presign: Vec<u8>,

    /// The centralized party signature of a message.
    pub message_centralized_signature: Vec<u8>,

    /// Indicates whether the future sign feature was used to start the session.
    pub is_future_sign: bool,
}

impl DWalletSessionEventTrait for SignRequestEvent {
    /// This function allows comparing this event with the Move event.
    /// It is used to detect [`SignRequestEvent`]
    /// events from the chain and initiate the MPC session.
    fn type_(packages_config: &IkaPackagesConfig) -> StructTag {
        StructTag {
            address: *packages_config.ika_dwallet_2pc_mpc_package_id,
            name: SIGN_REQUEST_EVENT_STRUCT_NAME.to_owned(),
            module: DWALLET_2PC_MPC_COORDINATOR_INNER_MODULE_NAME.to_owned(),
            type_params: vec![],
        }
    }
}

/// Rust version of the Move [`ika_system::dwallet_2pc_mpc_coordinator_inner::StartNetworkDKGEvent`] type.
/// It is used to trigger the start of the network DKG process.
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq, Hash)]
pub struct DWalletNetworkDKGEncryptionKeyRequestEvent {
    pub dwallet_network_encryption_key_id: ObjectID,
    pub params_for_network: Vec<u8>,
}

impl DWalletSessionEventTrait for DWalletNetworkDKGEncryptionKeyRequestEvent {
    /// This function allows comparing this event with the Move event.
    /// It is used to detect [`DWalletNetworkDKGEncryptionKeyRequestEvent`] events from the chain and initiate the MPC session.
    /// It is used to trigger the start of the network DKG process.
    fn type_(packages_config: &IkaPackagesConfig) -> StructTag {
        StructTag {
            address: *packages_config.ika_dwallet_2pc_mpc_package_id,
            name: START_NETWORK_DKG_EVENT_STRUCT_NAME.to_owned(),
            module: DWALLET_2PC_MPC_COORDINATOR_INNER_MODULE_NAME.to_owned(),
            type_params: vec![],
        }
    }
}

/// Represents the Rust version of the Move struct `ika_system::dwallet_2pc_mpc_coordinator_inner::DWalletNetworkEncryptionKey`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DWalletNetworkEncryptionKey {
    pub id: ObjectID,
    pub dkg_at_epoch: u64,
    pub network_dkg_public_output: TableVec,
    /// key -> epoch, value -> reconfiguration public output (TableVec).
    pub reconfiguration_public_outputs: Table,
    pub dkg_params_for_network: Vec<u8>,
    pub supported_curves: Vec<u32>,
    pub state: DWalletNetworkEncryptionKeyState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DWalletNetworkEncryptionKeyData {
    pub id: ObjectID,
    pub current_epoch: u64,
    pub current_reconfiguration_public_output: Vec<u8>,
    pub network_dkg_public_output: Vec<u8>,
    pub state: DWalletNetworkEncryptionKeyState,
}

/// Represents the Rust version of the Move enum `ika_system::dwallet_2pc_mpc_coordinator_inner::DWalletNetworkEncryptionKeyState`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DWalletNetworkEncryptionKeyState {
    AwaitingNetworkDKG,
    NetworkDKGCompleted,
    AwaitingNetworkReconfiguration,
    NetworkReconfigurationCompleted,
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq, Hash)]
pub struct DWalletEncryptionKeyReconfigurationRequestEvent {
    pub dwallet_network_encryption_key_id: ObjectID,
}

impl DWalletSessionEventTrait for DWalletEncryptionKeyReconfigurationRequestEvent {
    fn type_(packages_config: &IkaPackagesConfig) -> StructTag {
        StructTag {
            address: *packages_config.ika_dwallet_2pc_mpc_package_id,
            name: ident_str!("DWalletEncryptionKeyReconfigurationRequestEvent").to_owned(),
            module: DWALLET_2PC_MPC_COORDINATOR_INNER_MODULE_NAME.to_owned(),
            type_params: vec![],
        }
    }
}

// Since exporting rust `#[cfg(test)]` is impossible, these test helpers exist in a dedicated feature-gated
// module.
#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use super::*;
    use sui_types::base_types::ObjectID;

    pub fn mock_dwallet_session_event<E: DWalletSessionEventTrait>(
        is_system: bool,
        session_sequence_number: u64,
        event_data: E,
    ) -> DWalletSessionEvent<E> {
        let session_type = if is_system {
            SessionType::System
        } else {
            SessionType::User
        };

        DWalletSessionEvent {
            epoch: 1,
            session_object_id: ObjectID::random(),
            session_type,
            session_sequence_number,
            session_identifier_preimage: vec![42u8],
            event_data,
        }
    }
}
