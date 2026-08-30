// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::committee::{EpochId, ProtocolVersion};
use crate::crypto::{
    AggregateAuthoritySignature, AuthoritySignInfo, AuthoritySignInfoTrait,
    AuthorityStrongQuorumSignInfo, default_hash,
};
use crate::error::IkaResult;
use crate::intent::{Intent, IntentScope};
use crate::message_envelope::{Envelope, Message, TrustedEnvelope, VerifiedEnvelope};
use crate::{committee::Committee, error::IkaError};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

pub use crate::digests::SystemCheckpointContentsDigest;
pub use crate::digests::SystemCheckpointMessageDigest;

pub type SystemCheckpointSequenceNumber = u64;

// The constituent parts of system checkpoints, signed and certified.
// Note: the order of these fields, and the number must correspond to the Move code in
// `system_inner.move`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SystemCheckpointMessageKind {
    /// Set the next protocol version for the next epoch.
    SetNextConfigVersion(ProtocolVersion),
    /// Set a new epoch duration in milliseconds.
    SetEpochDurationMs(u64),
    /// Set a new stake subsidy start epoch.
    SetStakeSubsidyStartEpoch(EpochId),
    /// Set a new stake subsidy rate in basis points (1/100th of a percent).
    /// The distribution per period will be recalculated.
    SetStakeSubsidyRate(u16),
    /// Set a new length of the stake subsidy period.
    /// The distribution per period will be recalculated.
    SetStakeSubsidyPeriodLength(u64),
    /// Set a new minimum number of validators required to be active in the system.
    SetMinValidatorCount(u64),
    /// Set a new maximum number of validators allowed in the system.
    SetMaxValidatorCount(u64),
    /// Set a new minimum stake required for a validator to join the system.
    SetMinValidatorJoiningStake(u64),
    /// Set a new maximum number of validators that can change in a single epoch.
    SetMaxValidatorChangeCount(u64),
    /// Set a new rate at which rewards are slashed in basis points (1/100th of a percent).
    SetRewardSlashingRate(u16),
    /// Marks the final checkpoint message for an epoch.
    /// Once the Sui smart contract processes this message, it recognizes that no further
    /// system checkpoints will be created in the current epoch, enabling external calls
    /// to proceed with advancing the epoch.
    EndOfPublish,
    /// Set an approved upgrade for a package.
    SetApprovedUpgrade {
        /// The ID of the package that is approved for upgrade.
        package_id: Vec<u8>,
        /// The version of the package that is approved for upgrade.
        /// if None, the upgrade approval will be deleted.
        digest: Option<Vec<u8>>,
    },
    /// Set or remove a witness approving advance epoch.
    SetOrRemoveWitnessApprovingAdvanceEpochMessageType {
        /// The type of the witness that is being set or removed.
        witness_type: String,
        /// If false, the witness is being set, if true, the witness is being removed.
        remove: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemCheckpointMessage {
    pub epoch: EpochId,
    pub sequence_number: SystemCheckpointSequenceNumber,
    /// Timestamp of the system checkpoint - number of milliseconds from the Unix epoch
    /// System checkpoint timestamps are monotonic, but not strongly monotonic - subsequent
    /// system checkpoints can have same timestamp if they originate from the same underlining consensus commit
    pub messages: Vec<SystemCheckpointMessageKind>,
}

impl Message for SystemCheckpointMessage {
    type DigestType = SystemCheckpointMessageDigest;
    const SCOPE: IntentScope = IntentScope::SystemCheckpointMessage;

    fn digest(&self) -> Self::DigestType {
        SystemCheckpointMessageDigest::new(default_hash(self))
    }
}

impl SystemCheckpointMessage {
    pub fn new(
        epoch: EpochId,
        sequence_number: SystemCheckpointSequenceNumber,
        messages: Vec<SystemCheckpointMessageKind>,
    ) -> SystemCheckpointMessage {
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

    pub fn sequence_number(&self) -> &SystemCheckpointSequenceNumber {
        &self.sequence_number
    }
}

impl Display for SystemCheckpointMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SystemCheckpointSummary {{ epoch: {:?}, seq: {:?}",
            self.epoch, self.sequence_number,
        )
    }
}

// System checkpoints are signed by an authority and 2f+1 form a
// certificate that others can use to catch up. The actual
// content of the digest must at the very least commit to
// the set of transactions contained in the certificate but
// we might extend this to contain roots of merkle trees,
// or other authenticated data structures to support light
// clients and more efficient sync protocols.

pub type SystemCheckpointMessageEnvelope<S> = Envelope<SystemCheckpointMessage, S>;
pub type CertifiedSystemCheckpointMessage =
    SystemCheckpointMessageEnvelope<AuthorityStrongQuorumSignInfo>;
pub type SignedSystemCheckpointMessage = SystemCheckpointMessageEnvelope<AuthoritySignInfo>;

pub type VerifiedSystemCheckpointMessage =
    VerifiedEnvelope<SystemCheckpointMessage, AuthorityStrongQuorumSignInfo>;
pub type TrustedSystemCheckpointMessage =
    TrustedEnvelope<SystemCheckpointMessage, AuthorityStrongQuorumSignInfo>;

impl CertifiedSystemCheckpointMessage {
    pub fn verify_authority_signatures(&self, committee: &Committee) -> IkaResult {
        self.data().verify_epoch(self.auth_sig().epoch)?;
        self.auth_sig().verify_secure(
            self.data(),
            Intent::ika_app(IntentScope::SystemCheckpointMessage),
            committee,
        )
    }

    pub fn try_into_verified(
        self,
        committee: &Committee,
    ) -> IkaResult<VerifiedSystemCheckpointMessage> {
        self.verify_authority_signatures(committee)?;
        Ok(VerifiedSystemCheckpointMessage::new_from_verified(self))
    }

    pub fn into_summary_and_sequence(
        self,
    ) -> (SystemCheckpointSequenceNumber, SystemCheckpointMessage) {
        let summary = self.into_data();
        (summary.sequence_number, summary)
    }

    pub fn get_validator_signature(self) -> AggregateAuthoritySignature {
        self.auth_sig().signature.clone()
    }
}

impl SignedSystemCheckpointMessage {
    pub fn verify_authority_signatures(&self, committee: &Committee) -> IkaResult {
        self.data().verify_epoch(self.auth_sig().epoch)?;
        self.auth_sig().verify_secure(
            self.data(),
            Intent::ika_app(IntentScope::SystemCheckpointMessage),
            committee,
        )
    }

    pub fn try_into_verified(
        self,
        committee: &Committee,
    ) -> IkaResult<VerifiedEnvelope<SystemCheckpointMessage, AuthoritySignInfo>> {
        self.verify_authority_signatures(committee)?;
        Ok(VerifiedEnvelope::<SystemCheckpointMessage, AuthoritySignInfo>::new_from_verified(self))
    }
}

impl VerifiedSystemCheckpointMessage {
    pub fn into_summary_and_sequence(
        self,
    ) -> (SystemCheckpointSequenceNumber, SystemCheckpointMessage) {
        self.into_inner().into_summary_and_sequence()
    }
}

/// This is a message validators publish to consensus in order to sign system checkpoint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemCheckpointSignatureMessage {
    pub checkpoint_message: SignedSystemCheckpointMessage,
}

impl SystemCheckpointSignatureMessage {
    pub fn verify(&self, committee: &Committee) -> IkaResult {
        self.checkpoint_message
            .verify_authority_signatures(committee)
    }
}

#[cfg(test)]
mod tests {
    use super::SystemCheckpointMessageKind::*;
    use super::*;

    /// Compile-time guard: a new variant of the enum has to be named here, which
    /// is the reminder that it also needs a row in the table below and an arm in
    /// the Move dispatch.
    fn assert_variant_is_covered(kind: &SystemCheckpointMessageKind) {
        match kind {
            SetNextConfigVersion(_)
            | SetEpochDurationMs(_)
            | SetStakeSubsidyStartEpoch(_)
            | SetStakeSubsidyRate(_)
            | SetStakeSubsidyPeriodLength(_)
            | SetMinValidatorCount(_)
            | SetMaxValidatorCount(_)
            | SetMinValidatorJoiningStake(_)
            | SetMaxValidatorChangeCount(_)
            | SetRewardSlashingRate(_)
            | EndOfPublish
            | SetApprovedUpgrade { .. }
            | SetOrRemoveWitnessApprovingAdvanceEpochMessageType { .. } => {}
        }
    }

    /// Move reads a checkpoint's whole message vector as one flat BCS stream: per
    /// element it peels the enum tag and then peels exactly the fields that tag's
    /// arm names, with no per-message length prefix to resynchronize on. So a Rust
    /// payload wider or narrower than the matching `peel_*` call does not merely
    /// corrupt its own message — it leaves the reader mid-value, and every message
    /// after it in the same checkpoint is decoded from the wrong offset.
    ///
    /// Each row pins one variant's complete BCS encoding against the arm that
    /// consumes it in the `message_data_enum_tag` match of
    /// `process_checkpoint_message_by_quorum`
    /// (`contracts/ika_system/sources/system/system_inner.move`): the leading byte
    /// is the tag the arm's `*_MESSAGE_TYPE` constant matches, and the remaining
    /// bytes are what that arm's `peel_*` sequence consumes.
    #[test]
    fn variant_encodings_are_pinned_to_the_move_peel_widths() {
        // Payloads chosen so the encoded width is legible in the expected bytes:
        // little-endian 0x0807060504030201 is `01..08`, and 0x0201 is `01 02`.
        let eight_bytes = 0x0807_0605_0403_0201u64;
        let two_bytes = 0x0201u16;

        for (kind, move_peels, expected) in [
            (
                SetNextConfigVersion(ProtocolVersion::new(eight_bytes)),
                "peel_u64",
                vec![0, 1, 2, 3, 4, 5, 6, 7, 8],
            ),
            (
                SetEpochDurationMs(eight_bytes),
                "peel_u64",
                vec![1, 1, 2, 3, 4, 5, 6, 7, 8],
            ),
            (
                SetStakeSubsidyStartEpoch(eight_bytes),
                "peel_u64",
                vec![2, 1, 2, 3, 4, 5, 6, 7, 8],
            ),
            (SetStakeSubsidyRate(two_bytes), "peel_u16", vec![3, 1, 2]),
            (
                SetStakeSubsidyPeriodLength(eight_bytes),
                "peel_u64",
                vec![4, 1, 2, 3, 4, 5, 6, 7, 8],
            ),
            (
                SetMinValidatorCount(eight_bytes),
                "peel_u64",
                vec![5, 1, 2, 3, 4, 5, 6, 7, 8],
            ),
            (
                SetMaxValidatorCount(eight_bytes),
                "peel_u64",
                vec![6, 1, 2, 3, 4, 5, 6, 7, 8],
            ),
            (
                SetMinValidatorJoiningStake(eight_bytes),
                "peel_u64",
                vec![7, 1, 2, 3, 4, 5, 6, 7, 8],
            ),
            (
                SetMaxValidatorChangeCount(eight_bytes),
                "peel_u64",
                vec![8, 1, 2, 3, 4, 5, 6, 7, 8],
            ),
            (SetRewardSlashingRate(two_bytes), "peel_u16", vec![9, 1, 2]),
            (EndOfPublish, "(no payload)", vec![10]),
            (
                SetApprovedUpgrade {
                    package_id: vec![1, 2, 3],
                    digest: Some(vec![4, 5]),
                },
                "peel_vec_u8, peel_option!(peel_vec_u8)",
                vec![11, 3, 1, 2, 3, 1, 2, 4, 5],
            ),
            (
                SetOrRemoveWitnessApprovingAdvanceEpochMessageType {
                    witness_type: "ab".to_string(),
                    remove: true,
                },
                "peel_vec_u8, peel_bool",
                vec![12, 2, b'a', b'b', 1],
            ),
        ] {
            assert_variant_is_covered(&kind);
            assert_eq!(
                bcs::to_bytes(&kind).unwrap(),
                expected,
                "{kind:?} no longer encodes as the Move dispatch reads it (tag {} then {move_peels}, \
                 in `process_checkpoint_message_by_quorum` in \
                 contracts/ika_system/sources/system/system_inner.move). Move peels the \
                 checkpoint's messages as one flat stream, so a width or tag change here \
                 desynchronizes every message that follows it in the same checkpoint. Change the \
                 Move arm in the same commit, or restore the encoding.",
                expected[0],
            );
        }
    }
}
