// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::{
    committee::{Committee, EpochId},
    crypto::AuthorityName,
};

use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use strum_macros::{AsRefStr, IntoStaticStr};
use thiserror::Error;
use tonic::Status;
use typed_store_error::TypedStoreError;

#[macro_export]
macro_rules! fp_bail {
    ($e:expr) => {
        return Err($e)
    };
}

#[macro_export(local_inner_macros)]
macro_rules! fp_ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            fp_bail!($e);
        }
    };
}
use crate::dwallet_mpc_error::DwalletMPCError;
use sui_types::error::SuiError;

#[macro_export]
macro_rules! exit_main {
    ($result:expr_2021) => {
        match $result {
            Ok(_) => (),
            Err(err) => {
                let err = format!("{:?}", err);
                println!("{}", err.bold().red());
                std::process::exit(1);
            }
        }
    };
}

#[macro_export]
macro_rules! make_invariant_violation {
    ($($args:expr_2021),* $(,)?) => {{
        if cfg!(debug_assertions) {
            panic!($($args),*)
        }
        ExecutionError::invariant_violation(format!($($args),*))
    }}
}

#[macro_export]
macro_rules! invariant_violation {
    ($($args:expr_2021),* $(,)?) => {
        return Err(make_invariant_violation!($($args),*).into())
    };
}

#[macro_export]
macro_rules! assert_invariant {
    ($cond:expr_2021, $($args:expr_2021),* $(,)?) => {{
        if !$cond {
            invariant_violation!($($args),*)
        }
    }};
}

/// Custom error type for Ika.
#[derive(
    Eq, PartialEq, Clone, Debug, Serialize, Deserialize, Error, Hash, AsRefStr, IntoStaticStr,
)]
pub enum IkaError {
    #[error("SuiError: {:?}", error)]
    SuiError { error: Box<SuiError> },

    #[error("Sui SDK Error")]
    SuiSDKError,

    #[error("There are too many transactions pending in consensus")]
    TooManyTransactionsPendingConsensus,

    #[error("Soft bundle must only contain transactions of UserTransaction kind")]
    InvalidTxKindInSoftBundle,

    // Signature verification
    #[error("Signature is not valid: {}", error)]
    InvalidSignature { error: String },
    #[error("Required Signature from {expected} is absent {:?}", actual)]
    SignerSignatureAbsent {
        expected: String,
        actual: Vec<String>,
    },
    #[error("Expect {expected} signer signatures but got {actual}")]
    SignerSignatureNumberMismatch { expected: usize, actual: usize },
    #[error("Value was not signed by the correct sender: {}", error)]
    IncorrectSigner { error: String },
    #[error(
        "Value was not signed by a known authority. signer: {:?}, index: {:?}, committee: {committee}",
        signer,
        index
    )]
    UnknownSigner {
        signer: Option<String>,
        index: Option<u32>,
        committee: Box<Committee>,
    },
    #[error(
        "Validator {:?} responded multiple signatures for the same message, conflicting: {:?}",
        signer,
        conflicting_sig
    )]
    StakeAggregatorRepeatedSigner {
        signer: AuthorityName,
        conflicting_sig: bool,
    },
    // TODO: Used for distinguishing between different occurrences of invalid signatures, to allow retries in some cases.
    #[error(
        "Signature is not valid, but a retry may result in a valid one: {}",
        error
    )]
    PotentiallyTemporarilyInvalidSignature { error: String },

    // Certificate verification and execution
    #[error(
        "Signature or certificate from wrong epoch, expected {expected_epoch}, got {actual_epoch}"
    )]
    WrongEpoch {
        expected_epoch: EpochId,
        actual_epoch: EpochId,
    },
    #[error("Signatures in a certificate must form a quorum")]
    CertificateRequiresQuorum,

    // Account access
    #[error("Invalid authenticator")]
    InvalidAuthenticator,
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Invalid transaction digest.")]
    InvalidMessageDigest,

    #[error("Invalid digest length. Expected {expected}, got {actual}")]
    InvalidDigestLength { expected: usize, actual: usize },

    #[error("Validator {authority:?} is faulty in a Byzantine manner: {reason:?}")]
    ByzantineAuthoritySuspicion {
        authority: AuthorityName,
        reason: String,
    },

    #[error("Authority Error: {error:?}")]
    GenericAuthorityError { error: String },

    #[error("Generic Error: {error:?}")]
    Generic { error: String },

    // Errors related to the authority-consensus interface.
    #[error("Failed to submit transaction to consensus: {0}")]
    FailedToSubmitToConsensus(String),
    #[error("Failed to connect with consensus node: {0}")]
    ConsensusConnectionBroken(String),
    #[error("Failed to execute handle_consensus_transaction on Ika: {0}")]
    HandleConsensusTransactionFailure(String),

    // Cryptography errors.
    #[error("Signature key generation error: {0}")]
    SignatureKeyGenError(String),
    #[error("Key Conversion Error: {0}")]
    KeyConversionError(String),
    #[error("Invalid Private Key provided")]
    InvalidPrivateKey,

    // Epoch related errors.
    #[error("Validator temporarily stopped processing transactions due to epoch change")]
    ValidatorHaltedAtEpochEnd,
    #[error("Operations for epoch {0} have ended")]
    EpochEnded(EpochId),
    #[error("Error when advancing epoch: {:?}", error)]
    AdvanceEpochError { error: String },

    #[error("Invalid committee composition")]
    InvalidCommittee(String),

    #[error("Missing committee information for epoch {0}")]
    MissingCommitteeAtEpoch(EpochId),

    #[error("Failed to read or deserialize system state related data structures on-chain: {0}")]
    IkaSystemStateReadError(String),

    #[error("Unexpected version error: {0}")]
    UnexpectedVersion(String),

    #[error("Message version is not supported at the current protocol version: {error}")]
    WrongMessageVersion { error: String },

    #[error("unknown error: {0}")]
    Unknown(String),

    #[error("Failed to perform file operation: {0}")]
    FileIOError(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error(
        "Validator cannot handle the request at the moment. Please retry after at least {retry_after_secs} seconds."
    )]
    ValidatorOverloadedRetryAfter { retry_after_secs: u64 },

    #[error("Too many requests")]
    TooManyRequests,

    // Sui Client
    #[error("Sui Client failure to serialize: {0}")]
    SuiClientSerializationError(String),

    #[error("Sui Client internal error: {0}")]
    SuiClientInternalError(String),

    #[error("Sui Client sui transaction failure due to generic error: {0}")]
    SuiClientTxFailureGeneric(String),

    // Sui Connector
    #[error("Sui Connector failure to serialize: {0}")]
    SuiConnectorSerializationError(String),

    #[error("Sui Connector internal error: {0}")]
    SuiConnectorInternalError(String),

    // This is a string because the encapsulating error has too many derives.
    #[error("dWallet MPC Error: {0}")]
    DwalletMPCError(String),

    #[error("BCS serialization error: {0}")]
    BCSError(String),

    #[error("failed to receive data: {0}")]
    ReceiverError(String),

    #[error("dry run error failed: {0}")]
    DryRunFailed(String),
}

pub type IkaResult<T = ()> = Result<T, IkaError>;

impl From<DwalletMPCError> for IkaError {
    fn from(error: DwalletMPCError) -> Self {
        IkaError::DwalletMPCError(error.to_string())
    }
}

impl From<ika_protocol_config::Error> for IkaError {
    fn from(error: ika_protocol_config::Error) -> Self {
        IkaError::WrongMessageVersion { error: error.0 }
    }
}

impl From<TypedStoreError> for IkaError {
    fn from(e: TypedStoreError) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<sui_types::storage::error::Error> for IkaError {
    fn from(e: sui_types::storage::error::Error) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<IkaError> for Status {
    fn from(error: IkaError) -> Self {
        let bytes = bcs::to_bytes(&error).unwrap();
        Status::with_details(tonic::Code::Internal, error.to_string(), bytes.into())
    }
}

impl From<&str> for IkaError {
    fn from(error: &str) -> Self {
        IkaError::GenericAuthorityError {
            error: error.to_string(),
        }
    }
}

impl From<String> for IkaError {
    fn from(error: String) -> Self {
        IkaError::GenericAuthorityError { error }
    }
}

impl From<SuiError> for IkaError {
    fn from(error: SuiError) -> Self {
        IkaError::SuiError {
            error: Box::new(error),
        }
    }
}

impl IkaError {
    pub fn individual_error_indicates_epoch_change(&self) -> bool {
        matches!(
            self,
            IkaError::ValidatorHaltedAtEpochEnd | IkaError::MissingCommitteeAtEpoch(_)
        )
    }

    /// Returns if the error is retryable and if the error's retryability is
    /// explicitly categorized.
    /// There should be only a handful of retryable errors. For now we list common
    /// non-retryable error below to help us find more retryable errors in logs.
    pub fn is_retryable(&self) -> (bool, bool) {
        let retryable = match self {
            // Reconfig error
            IkaError::ValidatorHaltedAtEpochEnd => true,
            IkaError::MissingCommitteeAtEpoch(..) => true,
            IkaError::WrongEpoch { .. } => true,
            IkaError::EpochEnded(..) => true,

            IkaError::PotentiallyTemporarilyInvalidSignature { .. } => true,

            // Overload errors
            IkaError::TooManyTransactionsPendingConsensus => true,
            IkaError::ValidatorOverloadedRetryAfter { .. } => true,

            // Non retryable error
            IkaError::ByzantineAuthoritySuspicion { .. } => false,

            // NB: This is not an internal overload, but instead an imposed rate
            // limit / blocking of a client. It must be non-retryable otherwise
            // we will make the threat worse through automatic retries.
            IkaError::TooManyRequests => false,

            // For all un-categorized errors, return here with categorized = false.
            _ => return (false, false),
        };

        (retryable, true)
    }

    pub fn is_overload(&self) -> bool {
        matches!(self, IkaError::TooManyTransactionsPendingConsensus)
    }

    pub fn is_retryable_overload(&self) -> bool {
        matches!(self, IkaError::ValidatorOverloadedRetryAfter { .. })
    }

    pub fn retry_after_secs(&self) -> u64 {
        match self {
            IkaError::ValidatorOverloadedRetryAfter { retry_after_secs } => *retry_after_secs,
            _ => 0,
        }
    }
}

impl Ord for IkaError {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        Ord::cmp(self.as_ref(), other.as_ref())
    }
}

impl PartialOrd for IkaError {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[allow(dead_code)]
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
