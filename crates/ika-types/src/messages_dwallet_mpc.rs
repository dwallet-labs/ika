use crate::crypto::{AuthorityName, keccak256_digest};
use crate::message::DWalletCheckpointMessageKind;
use anyhow::anyhow;
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletSignatureAlgorithm};
use group::HashScheme;
use move_core_types::account_address::AccountAddress;
use move_core_types::ident_str;
use move_core_types::identifier::IdentStr;
use move_core_types::language_storage::StructTag;
use move_core_types::u256::U256;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::fmt::Debug;
use std::hash::Hash;
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DWalletMPCOutput {
    /// The authority that sent the output.
    pub authority: AuthorityName,
    pub session_identifier: SessionIdentifier,
    /// The output of the MPC session, potentially split into chunks if large.
    pub output: Vec<DWalletCheckpointMessageKind>,
    pub malicious_authorities: Vec<AuthorityName>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DWalletInternalMPCOutput {
    /// The authority that sent the output.
    pub authority: AuthorityName,
    pub session_identifier: SessionIdentifier,
    /// The final value of the MPC session.
    pub output: DWalletInternalMPCOutputKind,
    pub malicious_authorities: Vec<AuthorityName>,
}

#[derive(PartialEq, Eq, Hash, Clone, Ord, PartialOrd, Debug, Serialize, Deserialize)]
pub enum DWalletInternalMPCOutputKind {
    InternalPresign {
        output: Vec<u8>,
        curve: DWalletCurve,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_sequence_number: u64,
    },
    InternalSign {
        output: Vec<u8>,
        curve: DWalletCurve,
        signature_algorithm: DWalletSignatureAlgorithm,
        hash_scheme: HashScheme,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum DWalletMPCOutputReport {
    Internal(DWalletInternalMPCOutput),
    External(DWalletMPCOutput),
}

/// A request for a global presign, to be fetched from the corresponding internal pool when available.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd, Copy)]
pub struct GlobalPresignRequest {
    pub session_identifier: SessionIdentifier,
    pub session_sequence_number: u64,
    pub presign_id: ObjectID,
    pub curve: DWalletCurve,
    pub signature_algorithm: DWalletSignatureAlgorithm,
}

/// Status update sent by each validator on each consensus round.
/// Contains information about whether the validator is idle and
/// which presign sessions it wants to request.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InternalSessionsStatusUpdate {
    /// The authority that sent this status update.
    pub authority: AuthorityName,
    // TODO: delete
    /// The consensus round this update is for.
    pub consensus_round: u64,
    /// Whether this validator is idle (has fewer sessions ready to execute
    /// than the idle session count threshold).
    pub is_idle: bool,
    /// The global presign requests this validator received.
    pub global_presign_requests: Vec<GlobalPresignRequest>,
}

#[derive(PartialEq, Eq, Hash, Clone, Ord, PartialOrd, Debug, Serialize, Deserialize)]
pub enum DWalletMPCOutputKind {
    Internal {
        output: DWalletInternalMPCOutputKind,
    },
    External {
        output: Vec<DWalletCheckpointMessageKind>,
    },
}

impl DWalletMPCOutput {
    // TODO: delete
    pub fn rejected(&self) -> Option<bool> {
        if let [output] = &self.output[..] {
            output.rejected()
        } else {
            None
        }
    }
}

impl DWalletMPCOutputKind {
    /// Instantiates a new internal MPC output.
    pub fn new_internal(output: DWalletInternalMPCOutputKind) -> Self {
        Self::Internal { output }
    }

    /// Attempts to instantiate a new internal MPC output.
    /// Performs sanity checks on the output, and fails on any error.
    pub fn new_external(output: Vec<DWalletCheckpointMessageKind>) -> anyhow::Result<Self> {
        if output.is_empty() {
            return Err(anyhow!("MPC output is empty"));
        }

        // Assure split output of an MPC session have same metadata.
        let first_output = &output[0];
        let rejected = first_output.rejected();
        let kind = std::mem::discriminant(first_output);

        if output.iter().any(|output| output.rejected() != rejected) {
            return Err(anyhow!(
                "Split MPC output is inconsistent regards rejection"
            ));
        }

        if output
            .iter()
            .any(|output| std::mem::discriminant(output) != kind)
        {
            return Err(anyhow!("Split MPC output is inconsistent in kind"));
        }

        Ok(Self::External { output })
    }
}

impl DWalletMPCOutputReport {
    /// Returns the authority that reported this output.
    pub fn authority(&self) -> AuthorityName {
        match self {
            DWalletMPCOutputReport::Internal(output) => output.authority,
            DWalletMPCOutputReport::External(output) => output.authority,
        }
    }

    /// Returns session id of the MPC session.
    pub fn session_identifier(&self) -> SessionIdentifier {
        match self {
            DWalletMPCOutputReport::Internal(output) => output.session_identifier,
            DWalletMPCOutputReport::External(output) => output.session_identifier,
        }
    }

    /// Returns the output of the MPC session.
    /// Performs sanity checks on the output, and fails on any error.
    pub fn output(&self) -> anyhow::Result<DWalletMPCOutputKind> {
        match self {
            DWalletMPCOutputReport::Internal(output) => {
                Ok(DWalletMPCOutputKind::new_internal(output.output.clone()))
            }
            DWalletMPCOutputReport::External(output) => {
                let output = output.output.clone();

                DWalletMPCOutputKind::new_external(output)
            }
        }
    }

    /// Returns the authorities that behaved maliciously in this MPC session.
    pub fn malicious_authorities(&self) -> Vec<AuthorityName> {
        match self {
            DWalletMPCOutputReport::Internal(output) => output.malicious_authorities.clone(),
            DWalletMPCOutputReport::External(output) => output.malicious_authorities.clone(),
        }
    }

    /// Returns true if this is an internal MPC session.
    pub fn is_internal(&self) -> bool {
        match self {
            DWalletMPCOutputReport::Internal(_) => true,
            DWalletMPCOutputReport::External(_) => false,
        }
    }

    /// Returns true if this is a native computation session.
    /// Otherwise, this is an MPC session.
    pub fn is_native(&self) -> anyhow::Result<bool> {
        match self.output()? {
            DWalletMPCOutputKind::Internal { .. } => {
                // All internal MPC sessions are MPC sessions, no native ones.
                Ok(false)
            }
            DWalletMPCOutputKind::External { output } => {
                // All outputs of a MPC session must be of the same kind
                // We validated the output is non-empty.
                let first_output = &output[0];
                match first_output {
                        DWalletCheckpointMessageKind::RespondMakeDWalletUserSecretKeySharesPublic(_)
                        | DWalletCheckpointMessageKind::RespondDWalletPartialSignatureVerificationOutput(_) => {
                            Ok(true)
                        }

                        DWalletCheckpointMessageKind::RespondDWalletDKGFirstRoundOutput(_)
                        | DWalletCheckpointMessageKind::RespondDWalletDKGSecondRoundOutput(_)
                        | DWalletCheckpointMessageKind::RespondDWalletEncryptedUserShare(_)
                        | DWalletCheckpointMessageKind::RespondDWalletImportedKeyVerificationOutput(_)
                        | DWalletCheckpointMessageKind::RespondDWalletPresign(_)
                        | DWalletCheckpointMessageKind::RespondDWalletSign(_)
                        | DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput(_)
                        | DWalletCheckpointMessageKind::RespondDWalletDKGOutput(_)
                        | DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(_) => {
                            Ok(false)
                        },

                        DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(_)
                        | DWalletCheckpointMessageKind::SetGasFeeReimbursementSuiSystemCallValue(_)
                        | DWalletCheckpointMessageKind::EndOfPublish => Err(anyhow!("MPC output is not a cryptographic computation")),
                    }
            }
        }
    }

    /// Returns true if this output was rejected.
    pub fn rejected(&self) -> bool {
        if let Ok(output) = self.output() {
            match output {
                DWalletMPCOutputKind::Internal { .. } => false,
                DWalletMPCOutputKind::External { output } => {
                    // Safe to dereference, validated non-empty.
                    output[0].rejected().unwrap_or(false)
                }
            }
        } else {
            false
        }
    }
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

pub trait DWalletSessionEventTrait {
    fn type_(packages_config: &IkaNetworkConfig) -> StructTag;
}

/// The DWallet MPC session type
/// User initiated sessions have a sequence number, which is used to determine in which epoch the session will get
/// completed.
/// System sessions are guaranteed to always get completed in the epoch they were created in.
#[derive(
    Debug, Serialize, Deserialize, Clone, Copy, JsonSchema, Eq, PartialEq, Hash, Ord, PartialOrd,
)]
pub enum SessionType {
    User,
    System,
    InternalPresign,
    InternalSign,
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
            SessionType::InternalPresign => [
                version.to_be_bytes().as_slice(),
                b"INTERNAL_PRESIGN",
                &session_identifier_preimage,
            ]
            .concat(),
            SessionType::InternalSign => [
                version.to_be_bytes().as_slice(),
                b"INTERNAL_SIGN",
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

    pub fn into_uint(self) -> U256 {
        U256::from_le_bytes(&self.session_identifier)
    }

    /// Returns the session type for this identifier.
    pub fn session_type(&self) -> SessionType {
        self.session_type
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

pub type Secp256k1ECDSAProtocol = twopc_mpc::secp256k1::class_groups::ECDSAProtocol;
pub type Secp256k1TaprootProtocol = twopc_mpc::secp256k1::class_groups::TaprootProtocol;
pub type Secp256r1ECDSAProtocol = twopc_mpc::secp256r1::class_groups::ECDSAProtocol;
pub type Curve25519EdDSAProtocol = twopc_mpc::curve25519::class_groups::EdDSAProtocol;
pub type RistrettoSchnorrkelSubstrateProtocol =
    twopc_mpc::ristretto::class_groups::SchnorrkelSubstrateProtocol;

pub type Secp256k1AsyncDKGProtocol = twopc_mpc::secp256k1::class_groups::DKGProtocol;
pub type Secp256r1AsyncDKGProtocol = twopc_mpc::secp256r1::class_groups::DKGProtocol;
pub type Curve25519AsyncDKGProtocol = twopc_mpc::curve25519::class_groups::DKGProtocol;
pub type RistrettoAsyncDKGProtocol = twopc_mpc::ristretto::class_groups::DKGProtocol;

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
    fn type_(packages_config: &IkaNetworkConfig) -> StructTag {
        StructTag {
            address: *packages_config.packages.ika_dwallet_2pc_mpc_package_id,
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
    fn type_(packages_config: &IkaNetworkConfig) -> StructTag {
        StructTag {
            address: *packages_config.packages.ika_dwallet_2pc_mpc_package_id,
            name: ident_str!("EncryptedShareVerificationRequestEvent").to_owned(),
            module: DWALLET_2PC_MPC_COORDINATOR_INNER_MODULE_NAME.to_owned(),
            type_params: vec![],
        }
    }
}

impl DWalletSessionEventTrait for DWalletDKGRequestEvent {
    fn type_(packages_config: &IkaNetworkConfig) -> StructTag {
        StructTag {
            address: *packages_config.packages.ika_dwallet_2pc_mpc_package_id,
            name: ident_str!("DWalletDKGRequestEvent").to_owned(),
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
    fn type_(packages_config: &IkaNetworkConfig) -> StructTag {
        StructTag {
            address: *packages_config.packages.ika_dwallet_2pc_mpc_package_id,
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
    fn type_(packages_config: &IkaNetworkConfig) -> StructTag {
        StructTag {
            address: *packages_config.packages.ika_dwallet_2pc_mpc_package_id,
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
    fn type_(packages_config: &IkaNetworkConfig) -> StructTag {
        StructTag {
            address: *packages_config.packages.ika_dwallet_2pc_mpc_package_id,
            name: PRESIGN_REQUEST_EVENT_STRUCT_NAME.to_owned(),
            module: DWALLET_2PC_MPC_COORDINATOR_INNER_MODULE_NAME.to_owned(),
            type_params: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IkaNetworkConfig {
    pub packages: IkaPackageConfig,
    pub objects: IkaObjectsConfig,
}

impl sui_config::Config for IkaNetworkConfig {}

impl IkaNetworkConfig {
    pub fn new(
        ika_package_id: ObjectID,
        ika_common_package_id: ObjectID,
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        ika_dwallet_2pc_mpc_package_id_v2: Option<ObjectID>,
        ika_system_package_id: ObjectID,
        ika_system_object_id: ObjectID,
        ika_dwallet_coordinator_object_id: ObjectID,
    ) -> Self {
        Self {
            packages: IkaPackageConfig {
                ika_package_id,
                ika_common_package_id,
                ika_dwallet_2pc_mpc_package_id,
                ika_dwallet_2pc_mpc_package_id_v2,
                ika_system_package_id,
            },
            objects: IkaObjectsConfig {
                ika_system_object_id,
                ika_dwallet_coordinator_object_id,
            },
        }
    }

    #[cfg(feature = "test_helpers")]
    pub fn new_for_testing() -> Self {
        Self::new(
            ObjectID::from_single_byte(1),
            ObjectID::from_single_byte(1),
            ObjectID::from_single_byte(1),
            None,
            ObjectID::from_single_byte(1),
            ObjectID::from_single_byte(1),
            ObjectID::from_single_byte(1),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IkaPackageConfig {
    /// The move package id of ika (IKA) on sui.
    pub ika_package_id: ObjectID,
    /// The move package id of ika_common on sui.
    pub ika_common_package_id: ObjectID,
    /// The move package id of ika_dwallet_2pc_mpc on sui.
    pub ika_dwallet_2pc_mpc_package_id: ObjectID,
    /// The move package id of ika_dwallet_2pc_mpc on sui.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ika_dwallet_2pc_mpc_package_id_v2: Option<ObjectID>,
    /// The move package id of ika_system on sui.
    pub ika_system_package_id: ObjectID,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IkaObjectsConfig {
    /// The object id of system on sui.
    pub ika_system_object_id: ObjectID,
    /// The object id of ika_dwallet_coordinator on sui.
    pub ika_dwallet_coordinator_object_id: ObjectID,
}

/// Represents the Rust version of the Move struct `ika_system::dwallet_2pc_mpc_coordinator_inner::DWalletDKGFirstRoundRequestEvent`.
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq, Hash)]
pub struct DWalletDKGFirstRoundRequestEvent {
    pub dwallet_id: ObjectID,
    /// The `DWalletCap` object's ID associated with the `DWallet`.
    pub dwallet_cap_id: ObjectID,
    pub dwallet_network_encryption_key_id: ObjectID,
    pub curve: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq, Hash)]
pub struct SignDuringDKGRequestEvent {
    pub sign_id: ObjectID,
    pub presign_id: ObjectID,
    pub presign: Vec<u8>,
    pub signature_algorithm: u32,
    pub hash_scheme: u32,
    pub message: Vec<u8>,
    pub message_centralized_signature: Vec<u8>,
}

#[derive(
    Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq, Hash, Ord, PartialOrd,
)]
pub enum UserSecretKeyShareEventType {
    Encrypted {
        /// ID of the encrypted user secret key share being created
        encrypted_user_secret_key_share_id: ObjectID,
        /// User's encrypted secret key share with zero-knowledge proof
        encrypted_centralized_secret_share_and_proof: Vec<u8>,
        /// Serialized encryption key used to encrypt the user's secret share
        encryption_key: Vec<u8>,
        /// ObjectID of the encryption key object
        encryption_key_id: ObjectID,
        /// Address of the encryption key owner
        encryption_key_address: SuiAddress,
        /// Ed25519 public key for verifying the user's signature
        signer_public_key: Vec<u8>,
    },
    Public {
        public_user_secret_key_share: Vec<u8>,
    },
}

/// Represents the Rust version of the Move struct `ika_system::dwallet_2pc_mpc_coordinator_inner::DWalletDKGFirstRoundRequestEvent`.
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq, Hash)]
pub struct DWalletDKGRequestEvent {
    pub dwallet_id: ObjectID,
    pub centralized_public_key_share_and_proof: Vec<u8>,
    pub user_public_output: Vec<u8>,
    pub dwallet_cap_id: ObjectID,
    pub dwallet_network_encryption_key_id: ObjectID,
    pub curve: u32,
    pub user_secret_key_share: UserSecretKeyShareEventType,
    pub sign_during_dkg_request: Option<SignDuringDKGRequestEvent>,
}

impl DWalletSessionEventTrait for DWalletDKGFirstRoundRequestEvent {
    /// This function allows comparing this event with the Move event.
    /// It is used to detect [`DWalletDKGFirstRoundRequestEvent`] events from the chain and initiate the MPC session.
    fn type_(packages_config: &IkaNetworkConfig) -> StructTag {
        StructTag {
            address: *packages_config.packages.ika_dwallet_2pc_mpc_package_id,
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
    fn type_(packages_config: &IkaNetworkConfig) -> StructTag {
        StructTag {
            address: *packages_config.packages.ika_dwallet_2pc_mpc_package_id,
            name: DWALLET_MAKE_DWALLET_USER_SECRET_KEY_SHARES_PUBLIC_REQUEST_EVENT.to_owned(),
            module: DWALLET_2PC_MPC_COORDINATOR_INNER_MODULE_NAME.to_owned(),
            type_params: vec![],
        }
    }
}

impl DWalletSessionEventTrait for DWalletImportedKeyVerificationRequestEvent {
    /// This function allows comparing this event with the Move event.
    /// It is used to detect [`DWalletDKGFirstRoundRequestEvent`] events from the chain and initiate the MPC session.
    fn type_(packages_config: &IkaNetworkConfig) -> StructTag {
        StructTag {
            address: *packages_config.packages.ika_dwallet_2pc_mpc_package_id,
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
    fn type_(packages_config: &IkaNetworkConfig) -> StructTag {
        StructTag {
            address: *packages_config.packages.ika_dwallet_2pc_mpc_package_id,
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
    fn type_(packages_config: &IkaNetworkConfig) -> StructTag {
        StructTag {
            address: *packages_config.packages.ika_dwallet_2pc_mpc_package_id,
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
    pub dkg_at_epoch: u64,
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
    fn type_(packages_config: &IkaNetworkConfig) -> StructTag {
        StructTag {
            address: *packages_config.packages.ika_dwallet_2pc_mpc_package_id,
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

    pub fn new_dwallet_session_event<E: DWalletSessionEventTrait>(
        is_system: bool,
        session_sequence_number: u64,
        session_identifier_preimage: Vec<u8>,
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
            session_identifier_preimage,
            event_data,
        }
    }
}
