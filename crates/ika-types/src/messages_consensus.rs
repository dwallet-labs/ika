// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::crypto::AuthorityName;
use crate::handoff::HandoffSignatureMessage;
use crate::message::DWalletCheckpointMessageKind;
use crate::messages_dwallet_checkpoint::{
    DWalletCheckpointSequenceNumber, DWalletCheckpointSignatureMessage,
};
use crate::messages_dwallet_mpc::{
    ConsensusGlobalPresignRequest, ConsensusNOAObservation, ConsensusNOAPresignDemand,
    DWalletInternalMPCOutput, DWalletInternalMPCOutputKind, DWalletMPCMessage, DWalletMPCOutput,
    IdleStatusUpdate, SessionIdentifier, SuiChainObservationUpdate,
};
use crate::messages_system_checkpoints::{
    SystemCheckpointSequenceNumber, SystemCheckpointSignatureMessage,
};
use crate::supported_protocol_versions::{
    SupportedProtocolVersions, SupportedProtocolVersionsWithHashes,
};
use crate::validator_metadata::{
    EpochMpcDataReadySignal, SignedValidatorMpcDataAnnouncement, ValidatorMpcDataAnnouncement,
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
    /// Key of a decode-only V1 `EndOfPublish` (see
    /// [`ConsensusTransactionKind::EndOfPublish`]). Still reached, because a
    /// received V1 is keyed before it is dropped. Distinct from
    /// [`Self::EndOfPublishV2`] so the consensus dedupe layer never conflates
    /// the two. BCS index is wire/DB format — do not reorder.
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
    /// Idle status update from a validator.
    /// The nonce ensures each update is unique.
    IdleStatusUpdate(AuthorityName, [u8; 32]),
    /// Sui chain observation update from a validator.
    /// The nonce ensures each update is unique.
    SuiChainObservationUpdate(AuthorityName, [u8; 32]),
    /// A global presign request, keyed by authority + session_sequence_number.
    GlobalPresignRequest(AuthorityName, u64),
    /// An NOA checkpoint observation, keyed by authority + nonce.
    NOAObservation(AuthorityName, [u8; 32]),
    /// A current-committee validator's self-submitted MPC data
    /// announcement, keyed by validator + epoch + timestamp_ms. The
    /// timestamp is the version within (validator, epoch); the
    /// consensus handler keeps the latest-by-timestamp entry. The
    /// consensus block author authenticates the validator, so this
    /// kind carries no payload signature.
    ValidatorMpcDataAnnouncement(
        AuthorityName,
        u64, /* epoch */
        u64, /* timestamp_ms */
    ),
    /// A next-epoch joiner's MPC data announcement relayed by a
    /// current-committee validator. Keyed by the joiner (not the
    /// relayer) + epoch + timestamp_ms, so two honest relayers
    /// forwarding the same joiner announcement dedupe. The relayer
    /// is unauthenticated for the payload (any current-committee
    /// validator may relay), so the joiner's Ed25519 consensus-key
    /// signature is verified against its next-epoch consensus pubkey
    /// before the relay forwards it.
    RelayedValidatorMpcDataAnnouncement(
        AuthorityName,
        u64, /* epoch */
        u64, /* timestamp_ms */
    ),
    /// A validator's "I'm ready for this epoch's MPC sessions" vote,
    /// keyed by signer + epoch + sequence_number. The sequence
    /// number lets a signer re-emit with a wider `validated_peers`
    /// set as P2P blob propagation converges; without it, the
    /// generic same-key dedup at `verify_consensus_transaction`
    /// would silently drop every emit after the first.
    EpochMpcDataReadySignal(
        AuthorityName,
        u64, /* epoch */
        u64, /* sequence_number */
    ),
    /// V2 of `EndOfPublish`, keyed only by `AuthorityName` (like V1).
    /// V1 and V2 are *distinct* keys (different enum variants), so
    /// they do not dedupe against each other — but they never need
    /// to: V2 is the only form any supported binary emits, so a given
    /// authority submits exactly one form per epoch. The bundled handoff
    /// signature inside V2 is not separately keyed; the consumer
    /// routes it through the handoff aggregator after extraction.
    EndOfPublishV2(AuthorityName),
    // WIRE/DB-FORMAT DISCIPLINE: BCS-serialized as part of the key of the
    // persisted `consensus_message_processed` DBMap and rebuilt across
    // binary upgrades - variants are APPEND-ONLY, same as
    // ConsensusTransactionKind above.
    /// A NOA sign presign demand, keyed by its `demand_id` digest ONLY (not
    /// authority), so redundant announcements of the same demand from different
    /// validators collapse to a single consensus transaction.
    NOAPresignDemand([u8; 32]),
}

impl ConsensusTransactionKey {
    /// Whether this key embeds an unbounded payload rather than being a
    /// digest or a small tuple.
    ///
    /// Most variants are a digest or an `(authority, u64)`-shaped tuple —
    /// tens of bytes. Three carry their whole MPC payload (a message body,
    /// an output's checkpoint-message kinds, or an internal output's
    /// `Vec<u8>`s), so anything that budgets by ENTRY COUNT rather than by
    /// bytes is really budgeting `count * unbounded`.
    ///
    /// The match is deliberately EXHAUSTIVE, no wildcard: a new variant
    /// fails to compile until it is classified here, which is what keeps a
    /// future payload-carrying key from silently re-entering the
    /// count-budgeted dedup LRU. (`DWalletInternalMPCOutput` did exactly
    /// that — it postdated the original two-variant list and was admitted
    /// unbounded until this classification was made exhaustive.)
    pub fn embeds_payload(&self) -> bool {
        match self {
            Self::DWalletMPCMessage(..)
            | Self::DWalletMPCOutput(..)
            | Self::DWalletInternalMPCOutput(..) => true,
            Self::DWalletCheckpointSignature(..)
            | Self::CapabilityNotification(..)
            | Self::EndOfPublish(..)
            | Self::SystemCheckpointSignature(..)
            | Self::IdleStatusUpdate(..)
            | Self::SuiChainObservationUpdate(..)
            | Self::GlobalPresignRequest(..)
            | Self::NOAObservation(..)
            | Self::ValidatorMpcDataAnnouncement(..)
            | Self::RelayedValidatorMpcDataAnnouncement(..)
            | Self::EpochMpcDataReadySignal(..)
            | Self::EndOfPublishV2(..)
            | Self::NOAPresignDemand(..) => false,
        }
    }
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
            ConsensusTransactionKey::IdleStatusUpdate(authority, nonce) => {
                write!(
                    f,
                    "IdleStatusUpdate({:?}, 0x{})",
                    authority.concise(),
                    hex::encode(nonce)
                )
            }
            ConsensusTransactionKey::SuiChainObservationUpdate(authority, nonce) => {
                write!(
                    f,
                    "SuiChainObservationUpdate({:?}, 0x{})",
                    authority.concise(),
                    hex::encode(nonce)
                )
            }
            ConsensusTransactionKey::GlobalPresignRequest(authority, seq) => {
                write!(
                    f,
                    "GlobalPresignRequest({:?}, {})",
                    authority.concise(),
                    seq
                )
            }
            ConsensusTransactionKey::NOAObservation(authority, nonce) => {
                write!(
                    f,
                    "NOAObservation({:?}, 0x{})",
                    authority.concise(),
                    hex::encode(nonce)
                )
            }
            ConsensusTransactionKey::NOAPresignDemand(demand_id_digest) => {
                write!(f, "NOAPresignDemand(0x{})", hex::encode(demand_id_digest))
            }
            ConsensusTransactionKey::ValidatorMpcDataAnnouncement(authority, epoch, ts) => {
                write!(
                    f,
                    "ValidatorMpcDataAnnouncement({:?}, epoch={}, ts={})",
                    authority.concise(),
                    epoch,
                    ts
                )
            }
            ConsensusTransactionKey::RelayedValidatorMpcDataAnnouncement(joiner, epoch, ts) => {
                write!(
                    f,
                    "RelayedValidatorMpcDataAnnouncement({:?}, epoch={}, ts={})",
                    joiner.concise(),
                    epoch,
                    ts
                )
            }
            ConsensusTransactionKey::EpochMpcDataReadySignal(authority, epoch, seq) => {
                write!(
                    f,
                    "EpochMpcDataReadySignal({:?}, epoch={}, seq={})",
                    authority.concise(),
                    epoch,
                    seq
                )
            }
            ConsensusTransactionKey::EndOfPublishV2(authority) => {
                write!(f, "EndOfPublishV2({:?})", authority.concise())
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
    /// DECODE-ONLY since `MIN_PROTOCOL_VERSION = 5`. No supported binary
    /// emits this — `EndOfPublishV2` is the only form produced, and the
    /// consumer drops any V1 it receives (a peer sending one is
    /// misconfigured). The variant itself must stay: its BCS index is wire
    /// format, and removing it would renumber every variant below.
    ///
    /// Not `#[deprecated]` on purpose — receiving and dropping V1 is live,
    /// required behavior, so the attribute would only force
    /// `#[allow(deprecated)]` onto every decode site and stop meaning
    /// anything. The dead half is *production*, which is marked on
    /// [`ConsensusTransaction::new_end_of_publish`].
    EndOfPublish(AuthorityName),
    DWalletMPCMessage(DWalletMPCMessage),
    DWalletMPCOutput(DWalletMPCOutput),
    DWalletInternalMPCOutput(DWalletInternalMPCOutput),
    IdleStatusUpdate(IdleStatusUpdate),
    SuiChainObservationUpdate(SuiChainObservationUpdate),
    GlobalPresignRequest(ConsensusGlobalPresignRequest),
    NOAObservation(ConsensusNOAObservation),
    /// Self-submission by a current-committee validator: the
    /// announcement (digest + metadata) plus the full mpc_data blob
    /// carried in-band. No payload signature (the consensus block
    /// author authenticates the sender). The receiver hash-verifies
    /// the blob against `announcement.blob_hash` and writes it to the
    /// local blob store, so every node obtains the bytes via consensus
    /// replication rather than an out-of-band P2P fetch.
    ValidatorMpcDataAnnouncement(ValidatorMpcDataAnnouncement, Vec<u8>),
    /// Relay of a next-epoch joiner's announcement by a
    /// current-committee validator: carries the joiner's Ed25519
    /// consensus-key signature (verified against the joiner's
    /// next-epoch consensus pubkey before the relay forwards it) plus
    /// the joiner's full mpc_data blob in-band, hash-verified against
    /// the signed digest. The joiner — not a consensus participant —
    /// fans its blob out over P2P to current-committee receivers; each
    /// receiver relays it into consensus here so the bytes reach the
    /// whole committee via consensus replication.
    RelayedValidatorMpcDataAnnouncement(SignedValidatorMpcDataAnnouncement, Vec<u8>),
    EpochMpcDataReadySignal(EpochMpcDataReadySignal),
    // WIRE-FORMAT DISCIPLINE: this enum is BCS-serialized into consensus
    // blocks and decoded by every binary version in a mixed committee.
    // Variants are APPEND-ONLY - inserting mid-enum shifts every later
    // tag, so old binaries' transactions decode as the WRONG variant on
    // new binaries (caught live in v121_rollout: v1.2.1 announcements,
    // tag 10, decoded as NOAPresignDemand when it was inserted at index
    // 10, crash-looping the upgraded validator mid-rollout).
    /// V2 of `EndOfPublish` that bundles the validator's signed
    /// handoff attestation into the same consensus message.
    ///
    /// Why a new variant rather than a field on `EndOfPublish`:
    /// the existing variant has shipped — older peers won't decode
    /// the extra field. A new variant is wire-additive (older peers
    /// reject as unknown rather than mis-decoding existing data).
    ///
    /// Routing on the consumer side:
    /// 1. Treat the `authority` as the EndOfPublish sender — same
    ///    semantics as `EndOfPublish(authority)` for epoch-advance
    ///    accounting.
    /// 2. Extract `handoff_signature` and route through the existing
    ///    `record_handoff_signature` aggregator.
    ///
    /// Bundling the handoff signature into the EndOfPublish message
    /// (rather than sending it as its own consensus transaction)
    /// ensures it is observed at exactly the consensus point where
    /// EndOfPublish fires — a standalone handoff message could arrive
    /// out of order relative to `EndOfPublish` and lead to inconsistent
    /// aggregator state across the committee.
    EndOfPublishV2 {
        authority: AuthorityName,
        handoff_signature: Box<HandoffSignatureMessage>,
    },
    NOAPresignDemand(ConsensusNOAPresignDemand),
}

impl ConsensusTransaction {
    /// Builds a standalone V1 `EndOfPublish`.
    ///
    /// No supported binary emits this: `EndOfPublishV2` — which bundles the
    /// vote with the sender's handoff signature — is the only form produced
    /// since the off-chain validator-metadata pipeline became unconditional
    /// at `MIN_PROTOCOL_VERSION = 5`, and the consumer side drops any V1 it
    /// receives. The DECODE path for V1 is still live and must stay (the
    /// enum variant is BCS wire format); only production is dead, which is
    /// what this marker forbids.
    #[deprecated(note = "V1 EndOfPublish is never emitted; use new_end_of_publish_v2. \
                Kept only so the wire variant has a constructor for tests.")]
    pub fn new_end_of_publish(authority: AuthorityName) -> Self {
        let mut hasher = DefaultHasher::new();
        authority.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::EndOfPublish(authority),
        }
    }

    /// V2 of [`Self::new_end_of_publish`] — bundles the validator's
    /// signed handoff attestation alongside its EndOfPublish vote in a
    /// single consensus message, so the two always arrive together and
    /// can't be reordered at peers. This is the only form producers
    /// emit; the consumer side splits the message back into its two
    /// parts and routes each through the existing v1 processing paths.
    pub fn new_end_of_publish_v2(
        authority: AuthorityName,
        handoff_signature: HandoffSignatureMessage,
    ) -> Self {
        let mut hasher = DefaultHasher::new();
        authority.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::EndOfPublishV2 {
                authority,
                handoff_signature: Box::new(handoff_signature),
            },
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

    /// Create a new consensus transaction with an idle status update.
    pub fn new_idle_status_update(update: IdleStatusUpdate) -> Self {
        let mut hasher = DefaultHasher::new();
        update.authority.hash(&mut hasher);
        update.nonce.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::IdleStatusUpdate(update),
        }
    }

    /// Create a new consensus transaction with a Sui chain observation update.
    pub fn new_sui_chain_observation_update(update: SuiChainObservationUpdate) -> Self {
        let mut hasher = DefaultHasher::new();
        update.authority.hash(&mut hasher);
        update.nonce.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::SuiChainObservationUpdate(update),
        }
    }

    /// Create a new consensus transaction for a global presign request.
    pub fn new_global_presign_request(
        authority: AuthorityName,
        request: crate::messages_dwallet_mpc::GlobalPresignRequest,
    ) -> Self {
        let mut hasher = DefaultHasher::new();
        authority.hash(&mut hasher);
        request.session_sequence_number.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::GlobalPresignRequest(ConsensusGlobalPresignRequest {
                authority,
                request,
            }),
        }
    }

    /// Create a new consensus transaction for an NOA checkpoint observation.
    pub fn new_noa_observation(
        authority: AuthorityName,
        observation: crate::noa_checkpoint::NOACheckpointTxObservation,
    ) -> Self {
        let msg = ConsensusNOAObservation::new(authority, observation);
        let mut hasher = DefaultHasher::new();
        msg.authority.hash(&mut hasher);
        msg.nonce.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::NOAObservation(msg),
        }
    }

    /// Create a new consensus transaction announcing a NOA sign presign demand.
    pub fn new_noa_presign_demand(
        authority: AuthorityName,
        demand_id: crate::noa_checkpoint::NOAPresignDemandId,
        network_encryption_key_id: ObjectID,
    ) -> Self {
        let msg = ConsensusNOAPresignDemand {
            authority,
            demand_id,
            network_encryption_key_id,
        };
        let mut hasher = DefaultHasher::new();
        msg.demand_id_digest().hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::NOAPresignDemand(msg),
        }
    }

    /// Self-submission by a current-committee validator: the bare
    /// announcement, no signature. The consensus block author
    /// authenticates the sender, and `verify_consensus_transaction`
    /// enforces `sender == announcement.validator`.
    pub fn new_validator_mpc_data_announcement(
        announcement: ValidatorMpcDataAnnouncement,
        blob: Vec<u8>,
    ) -> Self {
        let mut hasher = DefaultHasher::new();
        announcement.validator.hash(&mut hasher);
        announcement.epoch.hash(&mut hasher);
        announcement.timestamp_ms.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::ValidatorMpcDataAnnouncement(announcement, blob),
        }
    }

    /// Relay of a next-epoch joiner's announcement by a
    /// current-committee validator. Carries the joiner's Ed25519
    /// consensus-key signature, verified before forwarding.
    pub fn new_relayed_validator_mpc_data_announcement(
        signed: SignedValidatorMpcDataAnnouncement,
        blob: Vec<u8>,
    ) -> Self {
        let mut hasher = DefaultHasher::new();
        signed.announcement.validator.hash(&mut hasher);
        signed.announcement.epoch.hash(&mut hasher);
        signed.announcement.timestamp_ms.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::RelayedValidatorMpcDataAnnouncement(signed, blob),
        }
    }

    pub fn new_epoch_mpc_data_ready_signal(signal: EpochMpcDataReadySignal) -> Self {
        let mut hasher = DefaultHasher::new();
        signal.authority.hash(&mut hasher);
        signal.epoch.hash(&mut hasher);
        let tracking_id = hasher.finish().to_le_bytes();
        Self {
            tracking_id,
            kind: ConsensusTransactionKind::EpochMpcDataReadySignal(signal),
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
            ConsensusTransactionKind::IdleStatusUpdate(update) => {
                ConsensusTransactionKey::IdleStatusUpdate(update.authority, update.nonce)
            }
            ConsensusTransactionKind::SuiChainObservationUpdate(update) => {
                ConsensusTransactionKey::SuiChainObservationUpdate(update.authority, update.nonce)
            }
            ConsensusTransactionKind::GlobalPresignRequest(msg) => {
                ConsensusTransactionKey::GlobalPresignRequest(
                    msg.authority,
                    msg.request.session_sequence_number,
                )
            }
            ConsensusTransactionKind::NOAObservation(msg) => {
                ConsensusTransactionKey::NOAObservation(msg.authority, msg.nonce)
            }
            ConsensusTransactionKind::NOAPresignDemand(msg) => {
                ConsensusTransactionKey::NOAPresignDemand(msg.demand_id_digest())
            }
            ConsensusTransactionKind::ValidatorMpcDataAnnouncement(announcement, _) => {
                ConsensusTransactionKey::ValidatorMpcDataAnnouncement(
                    announcement.validator,
                    announcement.epoch,
                    announcement.timestamp_ms,
                )
            }
            ConsensusTransactionKind::RelayedValidatorMpcDataAnnouncement(signed, _) => {
                ConsensusTransactionKey::RelayedValidatorMpcDataAnnouncement(
                    signed.announcement.validator,
                    signed.announcement.epoch,
                    signed.announcement.timestamp_ms,
                )
            }
            ConsensusTransactionKind::EpochMpcDataReadySignal(signal) => {
                ConsensusTransactionKey::EpochMpcDataReadySignal(
                    signal.authority,
                    signal.epoch,
                    signal.sequence_number,
                )
            }
            ConsensusTransactionKind::EndOfPublishV2 { authority, .. } => {
                ConsensusTransactionKey::EndOfPublishV2(*authority)
            }
        }
    }
}

#[cfg(test)]
mod wire_format_tests {
    use super::*;
    use dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm;
    use sui_types::base_types::ObjectID;

    /// The BCS variant tag of `ConsensusTransactionKind` is a cross-version
    /// wire contract: every binary in a mixed committee decodes every other
    /// binary's transactions. Tags 0-12 are what deployed binaries
    /// (release/testnet-v1.2.1) emit and expect; they may NEVER shift.
    /// New variants append after the last pinned tag. This test pins the
    /// contract with cheap-to-construct variants bracketing the enum, plus
    /// the appended tail. If it fails, a variant was inserted mid-enum -
    /// move it to the end (see the WIRE-FORMAT DISCIPLINE comment on the
    /// enum; live incident: v1.2.1 announcements decoded as the mid-enum
    /// NOAPresignDemand, crash-looping upgraded validators mid-rollout).
    #[test]
    fn consensus_transaction_kind_wire_tags_are_append_only() {
        let tag =
            |kind: &ConsensusTransactionKind| -> u8 { bcs::to_bytes(kind).expect("bcs encode")[0] };
        assert_eq!(
            tag(&ConsensusTransactionKind::EndOfPublish(
                AuthorityName::default()
            )),
            3,
            "EndOfPublish must keep wire tag 3 (v1.2.1 contract)"
        );
        assert_eq!(
            tag(&ConsensusTransactionKind::NOAPresignDemand(
                ConsensusNOAPresignDemand {
                    authority: AuthorityName::default(),
                    demand_id: crate::noa_checkpoint::NOAPresignDemandId::GrpcAttestation {
                        session_identifier: [0u8; 32],
                        signature_algorithm: DWalletSignatureAlgorithm::ECDSASecp256k1,
                    },
                    network_encryption_key_id: ObjectID::ZERO,
                }
            )),
            15,
            "NOAPresignDemand is post-v1.2.1 and must stay APPENDED at tag 15; \
             renumbering it (or anything before it) breaks mixed-committee decoding"
        );
    }
}

#[cfg(test)]
mod consensus_key_tests {
    use super::*;
    use crate::messages_dwallet_mpc::SessionType;
    use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletSignatureAlgorithm};
    use sui_types::base_types::ObjectID;

    /// The dedup LRU budgets by ENTRY COUNT, so a key that embeds an
    /// unbounded MPC payload must be kept out of it (#1997) — otherwise the
    /// cap is `count * unbounded`. This pins which keys carry a payload.
    ///
    /// The point of `embeds_payload` being an exhaustive `match` is that a
    /// new variant is a COMPILE error until classified, so this test does
    /// not need to (and cannot) enumerate future variants — it locks the
    /// three payload-carrying ones as `true` and a representative sample of
    /// the digest/authority-shaped ones as `false`. `DWalletInternalMPCOutput`
    /// is the one this PR corrected: it postdated the original two-variant
    /// list and was silently admitted to the LRU until now.
    #[test]
    fn every_mpc_payload_key_is_excluded_from_the_dedup_lru() {
        let name = AuthorityName([9; 32]);
        let session = SessionIdentifier::new(SessionType::User, [0u8; 32]);

        // The three payload-carrying keys.
        assert!(
            ConsensusTransactionKey::DWalletMPCMessage(name, session, vec![0u8; 64])
                .embeds_payload(),
            "the MPC message variant carries its payload in the key"
        );
        assert!(
            ConsensusTransactionKey::DWalletMPCOutput(name, session, vec![], vec![])
                .embeds_payload(),
            "the MPC output variant carries its payload in the key"
        );
        let internal_kind = DWalletInternalMPCOutputKind::InternalPresign {
            output: vec![0u8; 64],
            curve: DWalletCurve::Secp256k1,
            signature_algorithm: DWalletSignatureAlgorithm::ECDSASecp256k1,
            session_sequence_number: 0,
            dwallet_network_encryption_key_id: ObjectID::ZERO,
        };
        assert!(
            ConsensusTransactionKey::DWalletInternalMPCOutput(
                name,
                session,
                internal_kind,
                vec![],
            )
            .embeds_payload(),
            "the internal MPC output variant embeds unbounded Vec<u8> in its key"
        );

        // Representative non-payload keys: a digest, a small tuple, a bare
        // authority. These must stay in the LRU.
        assert!(
            !ConsensusTransactionKey::NOAPresignDemand([0u8; 32]).embeds_payload(),
            "a digest-shaped key must not be classified as payload-embedding"
        );
        assert!(
            !ConsensusTransactionKey::GlobalPresignRequest(name, 7).embeds_payload(),
            "an (authority, u64) key must not be classified as payload-embedding"
        );
        assert!(
            !ConsensusTransactionKey::EndOfPublishV2(name).embeds_payload(),
            "an authority-shaped key must not be classified as payload-embedding"
        );
    }
}
