// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::crypto::AuthorityName;
use crate::message::DWalletCheckpointMessageKind;
use crate::messages_dwallet_checkpoint::{
    DWalletCheckpointSequenceNumber, DWalletCheckpointSignatureMessage,
};
use crate::messages_dwallet_mpc::{
    DWalletInternalMPCOutput, DWalletInternalMPCOutputKind, DWalletMPCMessage, DWalletMPCOutput,
    InternalSessionsStatusUpdate, SessionIdentifier,
};
use crate::messages_system_checkpoints::{
    SystemCheckpointSequenceNumber, SystemCheckpointSignatureMessage,
};
use crate::supported_protocol_versions::{
    SupportedProtocolVersions, SupportedProtocolVersionsWithHashes,
};
use byteorder::{BigEndian, ReadBytesExt};
use consensus_types::block::BlockRef;
pub use consensus_types::block::TransactionIndex;
use ika_protocol_config::Chain;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};
use sui_types::base_types::{ConciseableName, ObjectID};
pub use sui_types::messages_consensus::{AuthorityIndex, Round, TimestampMs};

/// The position of a transaction in consensus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConsensusPosition {
    // Block containing a transaction.
    pub block: BlockRef,
    // Index of the transaction in the block.
    pub index: TransactionIndex,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConsensusTransaction {
    /// Encodes an u64 unique tracking ID to allow us to trace a message between Ika and consensus.
    /// Use a byte array instead of u64 to ensure stable serialization.
    pub tracking_id: [u8; 8],
    pub kind: ConsensusTransactionKind,
}

#[derive(Serialize, Deserialize, Clone, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub enum ConsensusTransactionKey {
    DWalletCheckpointSignature(AuthorityName, DWalletCheckpointSequenceNumber),
    CapabilityNotification(AuthorityName, u64 /* generation */),
    EndOfPublish(AuthorityName),
    /// Authority that sent the message, the session identifier, and the message itself.
    DWalletMPCMessage(AuthorityName, SessionIdentifier, Vec<u8>),
    // Placing the consensus message in the `key`, allows re-voting in case of disagreement.
    DWalletMPCOutput(
        AuthorityName,
        SessionIdentifier,
        Vec<DWalletCheckpointMessageKind>,
        Vec<AuthorityName>, // malicious authorities
    ),
    SystemCheckpointSignature(AuthorityName, SystemCheckpointSequenceNumber),
    DWalletInternalMPCOutput(
        AuthorityName,
        SessionIdentifier,
        DWalletInternalMPCOutputKind,
        Vec<AuthorityName>, // malicious authorities
    ),
    /// Internal sessions status update from a validator.
    /// The nonce ensures each update is unique.
    InternalSessionsStatusUpdate(AuthorityName, [u8; 32]),
}

impl Debug for ConsensusTransactionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DWalletCheckpointSignature(name, seq) => {
                write!(
                    f,
                    "DWalletCheckpointSignature({:?}, {:?})",
                    name.concise(),
                    seq
                )
            }
            Self::CapabilityNotification(name, generation) => write!(
                f,
                "CapabilityNotification({:?}, {:?})",
                name.concise(),
                generation
            ),
            Self::DWalletMPCMessage(authority, session_identifier, message) => {
                write!(
                    f,
                    "DWalletMPCMessage({authority:?}, {session_identifier:?}, {message:?})"
                )
            }
            Self::DWalletMPCOutput(
                authority,
                session_identifier,
                output,
                malicious_authorities,
            ) => {
                write!(
                    f,
                    "DWalletMPCOutput({authority:?}, {session_identifier:?}, {output:?}, {malicious_authorities:?})"
                )
            }
            Self::DWalletInternalMPCOutput(
                authority,
                session_identifier,
                output,
                malicious_authorities,
            ) => {
                write!(
                    f,
                    "DWalletInternalMPCOutput({authority:?}, {session_identifier:?}, {output:?}, {malicious_authorities:?})"
                )
            }
            ConsensusTransactionKey::SystemCheckpointSignature(name, seq) => {
                write!(
                    f,
                    "SystemCheckpointSignature({:?}, {:?})",
                    name.concise(),
                    seq
                )
            }
            ConsensusTransactionKey::EndOfPublish(authority) => {
                write!(f, "EndOfPublish({:?})", authority.concise())
            }
            ConsensusTransactionKey::InternalSessionsStatusUpdate(authority, nonce) => {
                write!(
                    f,
                    "InternalSessionsStatusUpdate({:?}, 0x{})",
                    authority.concise(),
                    hex::encode(nonce)
                )
            }
        }
    }
}

pub type MovePackageDigest = [u8; 32];

/// Used to advertise the capabilities of each authority via consensus.
/// This allows validators to negotiate the creation of the AdvanceEpoch transaction.
#[derive(Serialize, Deserialize, Clone, Hash)]
pub struct AuthorityCapabilitiesV1 {
    /// Originating authority — must match transaction source authority from consensus.
    pub authority: AuthorityName,
    /// Generation number set by sending authority.
    /// Used to determine which of multiple
    /// `AuthorityCapabilities` messages from the same authority is the most recent.
    pub generation: u64,

    /// ProtocolVersions that the authority supports.
    pub supported_protocol_versions: SupportedProtocolVersionsWithHashes,

    /// A list of package id to move package digest to
    /// determine whether to do a protocol upgrade on sui.
    pub move_contracts_to_upgrade: Vec<(ObjectID, MovePackageDigest)>,
}

impl AuthorityCapabilitiesV1 {
    pub fn new(
        authority: AuthorityName,
        chain: Chain,
        supported_protocol_versions: SupportedProtocolVersions,
        move_contracts_to_upgrade: Vec<(ObjectID, MovePackageDigest)>,
    ) -> Self {
        let generation = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Sui did not exist prior to 1970")
            .as_millis()
            .try_into()
            .expect("This build of sui is not supported in the year 500,000,000");
        Self {
            authority,
            generation,
            supported_protocol_versions:
                SupportedProtocolVersionsWithHashes::from_supported_versions(
                    supported_protocol_versions,
                    chain,
                ),
            move_contracts_to_upgrade,
        }
    }
}

impl Debug for AuthorityCapabilitiesV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorityCapabilities")
            .field("authority", &self.authority.concise())
            .field("generation", &self.generation)
            .field(
                "supported_protocol_versions",
                &self.supported_protocol_versions,
            )
            .field("move_contracts_to_upgrade", &self.move_contracts_to_upgrade)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ConsensusTransactionKind {
    DWalletCheckpointSignature(Box<DWalletCheckpointSignatureMessage>),
    SystemCheckpointSignature(Box<SystemCheckpointSignatureMessage>),
    CapabilityNotificationV1(AuthorityCapabilitiesV1),
    EndOfPublish(AuthorityName),
    DWalletMPCMessage(DWalletMPCMessage),
    DWalletMPCOutput(DWalletMPCOutput),
    DWalletInternalMPCOutput(DWalletInternalMPCOutput),
    InternalSessionsStatusUpdate(InternalSessionsStatusUpdate),
}

impl ConsensusTransaction {
    pub fn new_end_of_publish(authority: AuthorityName) -> Self {
        let mut hasher = DefaultHasher::new();
        authority.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::EndOfPublish(authority),
        }
    }

    /// Create a new consensus transaction with the message to be sent to the other MPC parties.
    pub fn new_dwallet_mpc_message(
        authority: AuthorityName,
        session_identifier: SessionIdentifier,
        message: Vec<u8>,
    ) -> Self {
        let mut hasher = DefaultHasher::new();
        authority.hash(&mut hasher);
        session_identifier.hash(&mut hasher);
        message.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::DWalletMPCMessage(DWalletMPCMessage {
                message,
                authority,
                session_identifier,
            }),
        }
    }

    /// Create a new consensus transaction with the output of the MPC session to be sent to the parties.
    pub fn new_dwallet_mpc_output(
        authority: AuthorityName,
        session_identifier: SessionIdentifier,
        output: Vec<DWalletCheckpointMessageKind>,
        malicious_authorities: Vec<AuthorityName>,
    ) -> Self {
        let mut hasher = DefaultHasher::new();
        authority.hash(&mut hasher);
        session_identifier.hash(&mut hasher);
        output.hash(&mut hasher);
        malicious_authorities.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::DWalletMPCOutput(DWalletMPCOutput {
                authority,
                session_identifier,
                output,
                malicious_authorities,
            }),
        }
    }

    /// Create a new consensus transaction with the output of the MPC session to be sent to the parties.
    pub fn new_dwallet_internal_mpc_output(
        authority: AuthorityName,
        session_identifier: SessionIdentifier,
        output: DWalletInternalMPCOutputKind,
        malicious_authorities: Vec<AuthorityName>,
    ) -> Self {
        let mut hasher = DefaultHasher::new();
        authority.hash(&mut hasher);
        session_identifier.hash(&mut hasher);
        output.hash(&mut hasher);
        malicious_authorities.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::DWalletInternalMPCOutput(DWalletInternalMPCOutput {
                authority,
                session_identifier,
                output,
                malicious_authorities,
            }),
        }
    }

    pub fn new_dwallet_checkpoint_signature_message(
        data: DWalletCheckpointSignatureMessage,
    ) -> Self {
        let mut hasher = DefaultHasher::new();
        data.checkpoint_message
            .auth_sig()
            .signature
            .hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::DWalletCheckpointSignature(Box::new(data)),
        }
    }

    pub fn new_system_checkpoint_signature_message(data: SystemCheckpointSignatureMessage) -> Self {
        let mut hasher = DefaultHasher::new();
        data.checkpoint_message
            .auth_sig()
            .signature
            .hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::SystemCheckpointSignature(Box::new(data)),
        }
    }

    pub fn new_capability_notification_v1(capabilities: AuthorityCapabilitiesV1) -> Self {
        let mut hasher = DefaultHasher::new();
        capabilities.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::CapabilityNotificationV1(capabilities),
        }
    }

    /// Create a new consensus transaction with the internal sessions status update.
    pub fn new_internal_sessions_status_update(
        status_update: InternalSessionsStatusUpdate,
    ) -> Self {
        let mut hasher = DefaultHasher::new();
        status_update.authority.hash(&mut hasher);
        status_update.nonce.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::InternalSessionsStatusUpdate(status_update),
        }
    }

    pub fn get_tracking_id(&self) -> u64 {
        (&self.tracking_id[..])
            .read_u64::<BigEndian>()
            .unwrap_or_default()
    }

    pub fn key(&self) -> ConsensusTransactionKey {
        match &self.kind {
            ConsensusTransactionKind::DWalletCheckpointSignature(data) => {
                ConsensusTransactionKey::DWalletCheckpointSignature(
                    data.checkpoint_message.auth_sig().authority,
                    data.checkpoint_message.sequence_number,
                )
            }
            ConsensusTransactionKind::CapabilityNotificationV1(cap) => {
                ConsensusTransactionKey::CapabilityNotification(cap.authority, cap.generation)
            }
            ConsensusTransactionKind::DWalletMPCMessage(message) => {
                ConsensusTransactionKey::DWalletMPCMessage(
                    message.authority,
                    message.session_identifier,
                    message.message.clone(),
                )
            }
            ConsensusTransactionKind::DWalletMPCOutput(output) => {
                ConsensusTransactionKey::DWalletMPCOutput(
                    output.authority,
                    output.session_identifier,
                    output.output.clone(),
                    output.malicious_authorities.clone(),
                )
            }
            ConsensusTransactionKind::DWalletInternalMPCOutput(output) => {
                ConsensusTransactionKey::DWalletInternalMPCOutput(
                    output.authority,
                    output.session_identifier,
                    output.output.clone(),
                    output.malicious_authorities.clone(),
                )
            }
            ConsensusTransactionKind::SystemCheckpointSignature(data) => {
                ConsensusTransactionKey::SystemCheckpointSignature(
                    data.checkpoint_message.auth_sig().authority,
                    data.checkpoint_message.sequence_number,
                )
            }
            ConsensusTransactionKind::EndOfPublish(origin_authority) => {
                ConsensusTransactionKey::EndOfPublish(*origin_authority)
            }
            ConsensusTransactionKind::InternalSessionsStatusUpdate(status_update) => {
                ConsensusTransactionKey::InternalSessionsStatusUpdate(
                    status_update.authority,
                    status_update.nonce,
                )
            }
        }
    }
}
