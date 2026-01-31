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

    #[error("Presign {0:?} has already been used")]
    PresignAlreadyUsed(SessionIdentifier),
}

/// A wrapper type for the result of a runtime operation.
pub type DwalletMPCResult<T> = Result<T, DwalletMPCError>;

impl From<serde_json::Error> for DwalletMPCError {
    fn from(err: serde_json::Error) -> Self {
        DwalletMPCError::SerdeError(err.classify())
    }
}
