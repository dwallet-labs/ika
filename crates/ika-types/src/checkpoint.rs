// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::committee::{Committee, EpochId};
use crate::crypto::{
    AggregateAuthoritySignature, AuthoritySignInfo, AuthoritySignInfoTrait,
    AuthorityStrongQuorumSignInfo, default_hash,
};
use crate::digests::{
    DWalletCheckpointContentsDigest, DWalletCheckpointMessageDigest,
    SystemCheckpointContentsDigest, SystemCheckpointMessageDigest,
};
use crate::error::IkaError;
use crate::error::IkaResult;
use crate::intent::{Intent, IntentScope};
use crate::message::{DWalletCheckpointMessageKind, SystemCheckpointMessageKind};
use crate::message_envelope::{Envelope, Message, TrustedEnvelope, VerifiedEnvelope};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;

/// Trait that parameterizes checkpoint infrastructure over DWallet vs System checkpoint kinds.
/// Two zero-sized marker types implement this trait, providing type-level distinction
/// while enabling a single generic implementation for all checkpoint operations.
pub trait CheckpointKind: Clone + Debug + Send + Sync + 'static {
    /// The type of individual messages within a checkpoint (e.g. DWalletCheckpointMessageKind).
    type MessageKind: Clone
        + Debug
        + Serialize
        + DeserializeOwned
        + PartialEq
        + Eq
        + Hash
        + Send
        + Sync
        + 'static;

    /// The digest type for the checkpoint message.
    type MessageDigest: Clone
        + Copy
        + Debug
        + Display
        + Default
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Hash
        + Serialize
        + DeserializeOwned
        + Send
        + Sync
        + 'static;

    /// The digest type for checkpoint contents.
    type ContentsDigest: Clone
        + Copy
        + Debug
        + PartialEq
        + Eq
        + Hash
        + Serialize
        + DeserializeOwned
        + Send
        + Sync
        + 'static;

    /// Intent scope for cryptographic domain separation.
    const INTENT_SCOPE: IntentScope;

    /// Human-readable name for metrics, DB column families, and logging.
    const NAME: &'static str;

    /// Construct a message digest from a raw hash.
    fn message_digest_from_hash(hash: [u8; 32]) -> Self::MessageDigest;
}

/// Marker type for DWallet checkpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DWallet;

/// Marker type for System checkpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct System;

impl CheckpointKind for DWallet {
    type MessageKind = DWalletCheckpointMessageKind;
    type MessageDigest = DWalletCheckpointMessageDigest;
    type ContentsDigest = DWalletCheckpointContentsDigest;
    const INTENT_SCOPE: IntentScope = IntentScope::DWalletCheckpointMessage;
    const NAME: &'static str = "dwallet_checkpoint";

    fn message_digest_from_hash(hash: [u8; 32]) -> Self::MessageDigest {
        DWalletCheckpointMessageDigest::new(hash)
    }
}

impl CheckpointKind for System {
    type MessageKind = SystemCheckpointMessageKind;
    type MessageDigest = SystemCheckpointMessageDigest;
    type ContentsDigest = SystemCheckpointContentsDigest;
    const INTENT_SCOPE: IntentScope = IntentScope::SystemCheckpointMessage;
    const NAME: &'static str = "system_checkpoint";

    fn message_digest_from_hash(hash: [u8; 32]) -> Self::MessageDigest {
        SystemCheckpointMessageDigest::new(hash)
    }
}

// ── Generic checkpoint sequence number ──────────────────────────────────────

pub type CheckpointSequenceNumber = u64;

// ── Generic checkpoint message ──────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(
    serialize = "K::MessageKind: Serialize",
    deserialize = "K::MessageKind: DeserializeOwned"
))]
pub struct CheckpointMessage<K: CheckpointKind> {
    pub epoch: EpochId,
    pub sequence_number: CheckpointSequenceNumber,
    pub messages: Vec<K::MessageKind>,
}

impl<K: CheckpointKind> Message for CheckpointMessage<K> {
    type DigestType = K::MessageDigest;
    const SCOPE: IntentScope = K::INTENT_SCOPE;

    fn digest(&self) -> Self::DigestType {
        K::message_digest_from_hash(default_hash(self))
    }
}

impl<K: CheckpointKind> CheckpointMessage<K> {
    pub fn new(
        epoch: EpochId,
        sequence_number: CheckpointSequenceNumber,
        messages: Vec<K::MessageKind>,
    ) -> Self {
        Self {
            epoch,
            sequence_number,
            messages,
        }
    }

    pub fn verify_epoch(&self, epoch: EpochId) -> IkaResult {
        fp_ensure!(
            self.epoch == epoch,
            IkaError::WrongEpoch {
                expected_epoch: epoch,
                actual_epoch: self.epoch,
            }
        );
        Ok(())
    }

    pub fn sequence_number(&self) -> &CheckpointSequenceNumber {
        &self.sequence_number
    }
}

impl<K: CheckpointKind> Display for CheckpointMessage<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}CheckpointSummary {{ epoch: {:?}, seq: {:?}",
            K::NAME,
            self.epoch,
            self.sequence_number,
        )
    }
}

// ── Generic envelope type aliases ───────────────────────────────────────────

pub type CheckpointMessageEnvelope<K, S> = Envelope<CheckpointMessage<K>, S>;
pub type CertifiedCheckpointMessage<K> =
    CheckpointMessageEnvelope<K, AuthorityStrongQuorumSignInfo>;
pub type SignedCheckpointMessage<K> = CheckpointMessageEnvelope<K, AuthoritySignInfo>;

pub type VerifiedCheckpointMessage<K> =
    VerifiedEnvelope<CheckpointMessage<K>, AuthorityStrongQuorumSignInfo>;
pub type TrustedCheckpointMessage<K> =
    TrustedEnvelope<CheckpointMessage<K>, AuthorityStrongQuorumSignInfo>;

// ── Generic impl blocks ─────────────────────────────────────────────────────

impl<K: CheckpointKind> CertifiedCheckpointMessage<K> {
    pub fn verify_authority_signatures(&self, committee: &Committee) -> IkaResult {
        self.data().verify_epoch(self.auth_sig().epoch)?;
        self.auth_sig()
            .verify_secure(self.data(), Intent::ika_app(K::INTENT_SCOPE), committee)
    }

    pub fn try_into_verified(
        self,
        committee: &Committee,
    ) -> IkaResult<VerifiedCheckpointMessage<K>> {
        self.verify_authority_signatures(committee)?;
        Ok(VerifiedCheckpointMessage::new_from_verified(self))
    }

    pub fn into_summary_and_sequence(self) -> (CheckpointSequenceNumber, CheckpointMessage<K>) {
        let summary = self.into_data();
        (summary.sequence_number, summary)
    }

    pub fn get_validator_signature(self) -> AggregateAuthoritySignature {
        self.auth_sig().signature.clone()
    }
}

impl<K: CheckpointKind> SignedCheckpointMessage<K> {
    pub fn verify_authority_signatures(&self, committee: &Committee) -> IkaResult {
        self.data().verify_epoch(self.auth_sig().epoch)?;
        self.auth_sig()
            .verify_secure(self.data(), Intent::ika_app(K::INTENT_SCOPE), committee)
    }

    pub fn try_into_verified(
        self,
        committee: &Committee,
    ) -> IkaResult<VerifiedEnvelope<CheckpointMessage<K>, AuthoritySignInfo>> {
        self.verify_authority_signatures(committee)?;
        Ok(VerifiedEnvelope::<CheckpointMessage<K>, AuthoritySignInfo>::new_from_verified(self))
    }
}

impl<K: CheckpointKind> VerifiedCheckpointMessage<K> {
    pub fn into_summary_and_sequence(self) -> (CheckpointSequenceNumber, CheckpointMessage<K>) {
        self.into_inner().into_summary_and_sequence()
    }
}

// ── Checkpoint signature message ────────────────────────────────────────────

/// Message validators publish to consensus to sign a checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "K::MessageKind: Serialize",
    deserialize = "K::MessageKind: DeserializeOwned"
))]
pub struct CheckpointSignatureMessage<K: CheckpointKind> {
    pub checkpoint_message: SignedCheckpointMessage<K>,
}

impl<K: CheckpointKind> CheckpointSignatureMessage<K> {
    pub fn verify(&self, committee: &Committee) -> IkaResult {
        self.checkpoint_message
            .verify_authority_signatures(committee)
    }
}
