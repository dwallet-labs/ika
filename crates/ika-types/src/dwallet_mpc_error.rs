use crate::messages_dwallet_mpc::SessionIdentifier;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletSignatureAlgorithm, DwalletNetworkMPCError,
};
use group::PartyID;
use sui_types::base_types::{EpochId, ObjectID};

#[derive(thiserror::Error, Debug, Clone)]
pub enum DwalletMPCError {
    #[error("mpc session with ID `{session_id:?}` was not found")]
    MPCSessionNotFound { session_id: ObjectID },

    #[error("sign state for the session with ID `{session_id:?}` was not found")]
    AggregatedSignStateNotFound { session_id: ObjectID },

    #[error("mpc session with ID `{session_identifier:?}`, failed: {error}")]
    MPCSessionError {
        session_identifier: SessionIdentifier,
        error: String,
    },

    #[error("Operations for the epoch {0} have ended")]
    EpochEnded(EpochId),

    #[error("authority with a name: `{0}` not found")]
    AuthorityNameNotFound(crate::crypto::AuthorityName),

    #[error("authority with a name: `{0}` not found")]
    AuthorityIndexNotFound(PartyID),

    #[error("message de/serialization error occurred in the dWallet MPC process: {0}")]
    BcsError(#[from] bcs::Error),

    #[error("received an invalid/unknown MPC party type: {0}")]
    InvalidMPCPartyType(String),

    #[error("malicious parties have been detected: {0:?}")]
    MaliciousParties(Vec<PartyID>),

    #[error("message digest error: {0}")]
    MessageDigest(String),

    #[error("dWallet MPC Manager error: {0}")]
    MPCManagerError(String),

    #[error("missing MPC class groups decryption shares in config")]
    MissingDwalletMPCClassGroupsDecryptionShares,

    #[error("missing DWallet MPC outputs verifier")]
    MissingDwalletMPCOutputsVerifier,

    #[error("missing DWallet MPC batches manager")]
    MissingDWalletMPCBatchesManager,

    #[error("missing dWallet MPC Sender")]
    MissingDWalletMPCSender,

    #[error("missing Root Seed")]
    MissingRootSeed,

    #[error("dwallet MPC Sender failed: {0}")]
    DWalletMPCSenderSendFailed(String),

    #[error("the MPC class groups decryption share missing for the party ID: {0}")]
    DwalletMPCClassGroupsDecryptionShareMissing(PartyID),

    #[error("missing MPC public parameters in config")]
    MissingDwalletMPCDecryptionSharesPublicParameters,

    #[error("2PC-MPC error")]
    TwoPCMPCError(#[from] twopc_mpc::Error),

    #[error("mpc error")]
    MPCError(#[from] mpc::Error),

    #[error("failed to find a message in batch: {0:?}")]
    MissingMessageInBatch(Vec<u8>),

    #[error("missing dwallet mpc decryption key shares: {0}")]
    MissingDwalletMPCDecryptionKeyShares(String),

    #[error("network decryption key is not ready for use")]
    NetworkDecryptionKeyNotReady,

    #[error("failed to lock the mutex")]
    LockError,

    #[error("verification of the encrypted user share failed: {0}")]
    EncryptedUserShareVerificationFailed(String),

    #[error("verification of the secret share failed: {0}")]
    SecretShareVerificationFailed(String),

    #[error("the sent public key does not match the sender's address")]
    EncryptedUserSharePublicKeyDoesNotMatchAddress,

    #[error(transparent)]
    DwalletNetworkMPCError(#[from] DwalletNetworkMPCError),

    #[error("class_groups error")]
    ClassGroups(#[from] class_groups::Error),

    #[error("failed to read seed from file: {0}")]
    FailedToReadSeed(String),

    #[error("failed to write seed to file: {0}")]
    FailedToWriteSeed(String),

    #[error("missing MPC private session input")]
    MissingMPCPrivateInput,

    #[error("failed to deserialize party public key: {0}")]
    InvalidPartyPublicKey(#[from] fastcrypto::error::FastCryptoError),

    #[error("failed to read the network decryption key shares")]
    DwalletMPCNetworkKeysNotFound,

    #[error("failed to verify signature: {0}")]
    SignatureVerificationFailed(String),

    #[error("failed to get available parallelism: {0}")]
    FailedToGetAvailableParallelism(String),

    #[error("the local machine has insufficient CPU cores to run a node")]
    InsufficientCPUCores,

    #[error("failed de/serialize json: {0:?}")]
    SerdeError(serde_json::error::Category),

    #[error("failed to find the presign round data")]
    PresignRoundDataNotFound,

    #[error("unsupported network DKG key scheme")]
    UnsupportedNetworkDKGKeyScheme,

    #[error("the first MPC step should not not receive any messages from the other parties")]
    MessageForFirstMPCStep,

    #[error("no next active committee for an event (SID ({0:?})) that required it: BUG")]
    MissingNextActiveCommittee(Vec<u8>),

    #[error("failed to find the event driven data")]
    MissingEventDrivenData,

    #[error("class groups key pair not found")]
    ClassGroupsKeyPairNotFound,

    #[error("network DKG key has not been completed yet")]
    NetworkDKGNotCompleted,

    #[error("failed to find the validator with ID: {0}")]
    ValidatorIDNotFound(ObjectID),

    #[error("{0}")]
    IkaError(#[from] crate::error::IkaError),

    #[error("waiting for network key with ID: {0}")]
    WaitingForNetworkKey(ObjectID),

    #[error("the dwallet secret does not match the dwallet output")]
    DWalletSecretNotMatchedDWalletOutput,

    #[error(
        "decryption key epoch out of sync: {key_id:?} expected epoch: {expected_epoch} but got: {actual_epoch}"
    )]
    DecryptionKeyEpochMismatch {
        key_id: ObjectID,
        expected_epoch: u64,
        actual_epoch: u64,
    },
    #[error("invalid session public input")]
    InvalidSessionPublicInput,

    #[error("tokio recv error")]
    TokioRecv,

    #[error("checkpoint message is empty")]
    CheckpointMessageIsEmpty,

    #[error("Invalid dWallet protocol type")]
    InvalidDWalletProtocolType,

    #[error("Invalid hash scheme")]
    InvalidHashScheme,

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("missing protocol public parameters for curve: {0:?}")]
    MissingProtocolPublicParametersForCurve(DWalletCurve),

    #[error("centralized secret key share proof verification failed: {0}")]
    CentralizedSecretKeyShareProofVerificationFailed(String),

    #[error("failed to advance MPC step: {0}")]
    FailedToAdvanceMPC(mpc::Error),

    #[error("public input mismatch")]
    PublicInputMismatch,

    #[error("dWallet DKG parameters missmatch: curve {0}, advance request {1}")]
    MPCParametersMissmatchInputToRequest(String, String),

    #[error("dWallet curve and protocol mismatch: curve {curve:?}, protocol {protocol:?}")]
    CurveToProtocolMismatch {
        curve: DWalletCurve,
        protocol: DWalletSignatureAlgorithm,
    },
    #[error("unsupported protocol version: {0}")]
    UnsupportedProtocolVersion(u64),

    #[error("invalid partially signed message version")]
    InvalidPartiallySignedMessageVersion,

    #[error("invalid centralized party imported dWallet public output version")]
    InvalidCentralizedPartyImportedDWalletPublicOutputVersion,
}

impl DwalletMPCError {
    /// Returns a short, stable label suitable for use as a Prometheus metric label value.
    /// Cardinality is bounded: one variant ⇒ one label. Keep these strings stable —
    /// alerts depend on them.
    pub fn kind(&self) -> &'static str {
        match self {
            DwalletMPCError::MPCSessionNotFound { .. } => "mpc_session_not_found",
            DwalletMPCError::AggregatedSignStateNotFound { .. } => "aggregated_sign_state_not_found",
            DwalletMPCError::MPCSessionError { .. } => "mpc_session_error",
            DwalletMPCError::EpochEnded(_) => "epoch_ended",
            DwalletMPCError::AuthorityNameNotFound(_) => "authority_name_not_found",
            DwalletMPCError::AuthorityIndexNotFound(_) => "authority_index_not_found",
            DwalletMPCError::BcsError(_) => "bcs_error",
            DwalletMPCError::InvalidMPCPartyType(_) => "invalid_mpc_party_type",
            DwalletMPCError::MaliciousParties(_) => "malicious_parties",
            DwalletMPCError::MessageDigest(_) => "message_digest",
            DwalletMPCError::MPCManagerError(_) => "mpc_manager_error",
            DwalletMPCError::MissingDwalletMPCClassGroupsDecryptionShares => {
                "missing_class_groups_decryption_shares"
            }
            DwalletMPCError::MissingDwalletMPCOutputsVerifier => "missing_outputs_verifier",
            DwalletMPCError::MissingDWalletMPCBatchesManager => "missing_batches_manager",
            DwalletMPCError::MissingDWalletMPCSender => "missing_mpc_sender",
            DwalletMPCError::MissingRootSeed => "missing_root_seed",
            DwalletMPCError::DWalletMPCSenderSendFailed(_) => "mpc_sender_send_failed",
            DwalletMPCError::DwalletMPCClassGroupsDecryptionShareMissing(_) => {
                "class_groups_decryption_share_missing"
            }
            DwalletMPCError::MissingDwalletMPCDecryptionSharesPublicParameters => {
                "missing_decryption_shares_public_parameters"
            }
            DwalletMPCError::TwoPCMPCError(_) => "twopc_mpc_error",
            DwalletMPCError::MPCError(_) => "mpc_error",
            DwalletMPCError::MissingMessageInBatch(_) => "missing_message_in_batch",
            DwalletMPCError::MissingDwalletMPCDecryptionKeyShares(_) => {
                "missing_decryption_key_shares"
            }
            DwalletMPCError::NetworkDecryptionKeyNotReady => "network_decryption_key_not_ready",
            DwalletMPCError::LockError => "lock_error",
            DwalletMPCError::EncryptedUserShareVerificationFailed(_) => {
                "encrypted_user_share_verification_failed"
            }
            DwalletMPCError::SecretShareVerificationFailed(_) => "secret_share_verification_failed",
            DwalletMPCError::EncryptedUserSharePublicKeyDoesNotMatchAddress => {
                "encrypted_user_share_pubkey_mismatch"
            }
            DwalletMPCError::DwalletNetworkMPCError(_) => "network_mpc_error",
            DwalletMPCError::ClassGroups(_) => "class_groups",
            DwalletMPCError::FailedToReadSeed(_) => "failed_to_read_seed",
            DwalletMPCError::FailedToWriteSeed(_) => "failed_to_write_seed",
            DwalletMPCError::MissingMPCPrivateInput => "missing_mpc_private_input",
            DwalletMPCError::InvalidPartyPublicKey(_) => "invalid_party_public_key",
            DwalletMPCError::DwalletMPCNetworkKeysNotFound => "network_keys_not_found",
            DwalletMPCError::SignatureVerificationFailed(_) => "signature_verification_failed",
            DwalletMPCError::FailedToGetAvailableParallelism(_) => {
                "failed_to_get_available_parallelism"
            }
            DwalletMPCError::InsufficientCPUCores => "insufficient_cpu_cores",
            DwalletMPCError::SerdeError(_) => "serde_error",
            DwalletMPCError::PresignRoundDataNotFound => "presign_round_data_not_found",
            DwalletMPCError::UnsupportedNetworkDKGKeyScheme => "unsupported_network_dkg_key_scheme",
            DwalletMPCError::MessageForFirstMPCStep => "message_for_first_mpc_step",
            DwalletMPCError::MissingNextActiveCommittee(_) => "missing_next_active_committee",
            DwalletMPCError::MissingEventDrivenData => "missing_event_driven_data",
            DwalletMPCError::ClassGroupsKeyPairNotFound => "class_groups_keypair_not_found",
            DwalletMPCError::NetworkDKGNotCompleted => "network_dkg_not_completed",
            DwalletMPCError::ValidatorIDNotFound(_) => "validator_id_not_found",
            DwalletMPCError::IkaError(_) => "ika_error",
            DwalletMPCError::WaitingForNetworkKey(_) => "waiting_for_network_key",
            DwalletMPCError::DWalletSecretNotMatchedDWalletOutput => {
                "dwallet_secret_not_matched_output"
            }
            DwalletMPCError::DecryptionKeyEpochMismatch { .. } => "decryption_key_epoch_mismatch",
            DwalletMPCError::InvalidSessionPublicInput => "invalid_session_public_input",
            DwalletMPCError::TokioRecv => "tokio_recv",
            DwalletMPCError::CheckpointMessageIsEmpty => "checkpoint_message_is_empty",
            DwalletMPCError::InvalidDWalletProtocolType => "invalid_dwallet_protocol_type",
            DwalletMPCError::InvalidHashScheme => "invalid_hash_scheme",
            DwalletMPCError::InternalError(_) => "internal_error",
            DwalletMPCError::InvalidInput(_) => "invalid_input",
            DwalletMPCError::MissingProtocolPublicParametersForCurve(_) => {
                "missing_protocol_public_parameters_for_curve"
            }
            DwalletMPCError::CentralizedSecretKeyShareProofVerificationFailed(_) => {
                "centralized_secret_key_share_proof_verification_failed"
            }
            DwalletMPCError::FailedToAdvanceMPC(_) => "failed_to_advance_mpc",
            DwalletMPCError::PublicInputMismatch => "public_input_mismatch",
            DwalletMPCError::MPCParametersMissmatchInputToRequest(_, _) => {
                "mpc_parameters_mismatch_input_to_request"
            }
            DwalletMPCError::CurveToProtocolMismatch { .. } => "curve_to_protocol_mismatch",
            DwalletMPCError::UnsupportedProtocolVersion(_) => "unsupported_protocol_version",
            DwalletMPCError::InvalidPartiallySignedMessageVersion => {
                "invalid_partially_signed_message_version"
            }
            DwalletMPCError::InvalidCentralizedPartyImportedDWalletPublicOutputVersion => {
                "invalid_centralized_party_imported_dwallet_public_output_version"
            }
        }
    }
}

/// A wrapper type for the result of a runtime operation.
pub type DwalletMPCResult<T> = Result<T, DwalletMPCError>;

impl From<serde_json::Error> for DwalletMPCError {
    fn from(err: serde_json::Error) -> Self {
        DwalletMPCError::SerdeError(err.classify())
    }
}
