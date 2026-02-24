// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::committee::EpochId;
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

pub use crate::digests::DWalletCheckpointContentsDigest;
pub use crate::digests::DWalletCheckpointMessageDigest;
use crate::message::DWalletCheckpointMessageKind;

pub type DWalletCheckpointSequenceNumber = u64;

// The constituent parts of checkpoints, signed and certified

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DWalletCheckpointMessage {
    pub epoch: EpochId,
    pub sequence_number: DWalletCheckpointSequenceNumber,
    /// Timestamp of the dwallet checkpoint - number of milliseconds from the Unix epoch
    /// DWallet checkpoint timestamps are monotonic, but not strongly monotonic - subsequent
    /// dwallet checkpoints can have same timestamp if they originate from the same underlining consensus commit
    pub messages: Vec<DWalletCheckpointMessageKind>,
}

impl Message for DWalletCheckpointMessage {
    type DigestType = DWalletCheckpointMessageDigest;
    const SCOPE: IntentScope = IntentScope::DWalletCheckpointMessage;

    fn digest(&self) -> Self::DigestType {
        DWalletCheckpointMessageDigest::new(default_hash(self))
    }
}

impl DWalletCheckpointMessage {
    pub fn new(
        epoch: EpochId,
        sequence_number: DWalletCheckpointSequenceNumber,
        messages: Vec<DWalletCheckpointMessageKind>,
    ) -> DWalletCheckpointMessage {
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

    pub fn sequence_number(&self) -> &DWalletCheckpointSequenceNumber {
        &self.sequence_number
    }
}

impl Display for DWalletCheckpointMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DWalletCheckpointSummary {{ epoch: {:?}, seq: {:?}",
            self.epoch, self.sequence_number,
        )
    }
}

// DWallet checkpoints are signed by an authority and 2f+1 form a
// certificate that others can use to catch up. The actual
// content of the digest must at the very least commit to
// the set of transactions contained in the certificate but
// we might extend this to contain roots of merkle trees,
// or other authenticated data structures to support light
// clients and more efficient sync protocols.

pub type DWalletCheckpointMessageEnvelope<S> = Envelope<DWalletCheckpointMessage, S>;
pub type CertifiedDWalletCheckpointMessage =
    DWalletCheckpointMessageEnvelope<AuthorityStrongQuorumSignInfo>;
pub type SignedDWalletCheckpointMessage = DWalletCheckpointMessageEnvelope<AuthoritySignInfo>;

pub type VerifiedDWalletCheckpointMessage =
    VerifiedEnvelope<DWalletCheckpointMessage, AuthorityStrongQuorumSignInfo>;
pub type TrustedDWalletCheckpointMessage =
    TrustedEnvelope<DWalletCheckpointMessage, AuthorityStrongQuorumSignInfo>;

impl CertifiedDWalletCheckpointMessage {
    pub fn verify_authority_signatures(&self, committee: &Committee) -> IkaResult {
        self.data().verify_epoch(self.auth_sig().epoch)?;
        self.auth_sig().verify_secure(
            self.data(),
            Intent::ika_app(IntentScope::DWalletCheckpointMessage),
            committee,
        )
    }

    pub fn try_into_verified(
        self,
        committee: &Committee,
    ) -> IkaResult<VerifiedDWalletCheckpointMessage> {
        self.verify_authority_signatures(committee)?;
        Ok(VerifiedDWalletCheckpointMessage::new_from_verified(self))
    }

    pub fn into_summary_and_sequence(
        self,
    ) -> (DWalletCheckpointSequenceNumber, DWalletCheckpointMessage) {
        let summary = self.into_data();
        (summary.sequence_number, summary)
    }

    pub fn get_validator_signature(self) -> AggregateAuthoritySignature {
        self.auth_sig().signature.clone()
    }
}

impl SignedDWalletCheckpointMessage {
    pub fn verify_authority_signatures(&self, committee: &Committee) -> IkaResult {
        self.data().verify_epoch(self.auth_sig().epoch)?;
        self.auth_sig().verify_secure(
            self.data(),
            Intent::ika_app(IntentScope::DWalletCheckpointMessage),
            committee,
        )
    }

    pub fn try_into_verified(
        self,
        committee: &Committee,
    ) -> IkaResult<VerifiedEnvelope<DWalletCheckpointMessage, AuthoritySignInfo>> {
        self.verify_authority_signatures(committee)?;
        Ok(VerifiedEnvelope::<
            DWalletCheckpointMessage,
            AuthoritySignInfo,
        >::new_from_verified(self))
    }
}

impl VerifiedDWalletCheckpointMessage {
    pub fn into_summary_and_sequence(
        self,
    ) -> (DWalletCheckpointSequenceNumber, DWalletCheckpointMessage) {
        self.into_inner().into_summary_and_sequence()
    }
}

/// This is a message validators publish to consensus to sign dwallet checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DWalletCheckpointSignatureMessage {
    pub checkpoint_message: SignedDWalletCheckpointMessage,
}

impl DWalletCheckpointSignatureMessage {
    pub fn verify(&self, committee: &Committee) -> IkaResult {
        self.checkpoint_message
            .verify_authority_signatures(committee)
    }
}
