// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::consensus_adapter::SubmitToConsensus;
use fastcrypto::ed25519::Ed25519KeyPair;
use ika_types::committee::Committee;
use ika_types::crypto::AuthorityName;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_consensus::ConsensusTransaction;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::watch::Receiver;
use tracing::{error, info, warn};

/// `EndOfPublishSender` handles sending the `end of publish`
/// message to the consensus adapter, and — once per epoch, on the
/// same trigger — emits this validator's signed
/// `HandoffSignatureMessage` over consensus.
pub struct EndOfPublishSender {
    epoch_store: Weak<AuthorityPerEpochStore>,
    epoch_id: u64,
    consensus_adapter: Arc<dyn SubmitToConsensus>,
    end_of_publish_receiver: Receiver<Option<u64>>,
    consensus_keypair: Arc<Ed25519KeyPair>,
    next_epoch_committee_receiver: Receiver<Committee>,
    handoff_signature_sent: AtomicBool,
}

impl EndOfPublishSender {
    /// Creates a new instance of `EndOfPublishSender`.
    pub fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        consensus_adapter: Arc<dyn SubmitToConsensus>,
        end_of_publish_receiver: Receiver<Option<u64>>,
        epoch_id: u64,
        consensus_keypair: Arc<Ed25519KeyPair>,
        next_epoch_committee_receiver: Receiver<Committee>,
    ) -> Self {
        Self {
            epoch_store,
            consensus_adapter,
            end_of_publish_receiver,
            epoch_id,
            consensus_keypair,
            next_epoch_committee_receiver,
            handoff_signature_sent: AtomicBool::new(false),
        }
    }

    /// Runs the `end of publish` sender,
    /// which checks if the `end of publish` signal has been received
    /// and sends the `end of publish` message to the consensus adapter if it has.
    pub async fn run(&self) {
        loop {
            if *self.end_of_publish_receiver.borrow() == Some(self.epoch_id) {
                if let Err(err) = self.send_end_of_publish().await {
                    error!(error=?err, "failed to send `end of publish` message");
                }
                // Fire the handoff signature once per epoch. Errors
                // here aren't fatal — we'll retry on the next tick
                // of this loop while `end_of_publish_receiver` is
                // still asserted.
                if !self.handoff_signature_sent.load(Ordering::Acquire)
                    && let Err(err) = self.send_handoff_signature().await
                {
                    warn!(error=?err, "failed to send handoff signature; will retry");
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    fn epoch_store(&self) -> DwalletMPCResult<Arc<AuthorityPerEpochStore>> {
        self.epoch_store
            .upgrade()
            .ok_or(DwalletMPCError::EpochEnded(self.epoch_id))
    }

    async fn send_end_of_publish(&self) -> DwalletMPCResult<()> {
        let tx = ConsensusTransaction::new_end_of_publish(self.epoch_store()?.name);
        self.consensus_adapter
            .submit_to_consensus(&[tx], &self.epoch_store()?)
            .await?;
        Ok(())
    }

    async fn send_handoff_signature(&self) -> DwalletMPCResult<()> {
        let epoch_store = self.epoch_store()?;
        let next_committee = self.next_epoch_committee_receiver.borrow().clone();
        if next_committee.epoch() != self.epoch_id + 1 {
            // The committee sync task hasn't caught up with the
            // next epoch yet; defer until it has.
            return Ok(());
        }
        let next_committee_pubkeys: Vec<AuthorityName> = next_committee
            .voting_rights
            .iter()
            .map(|(name, _)| *name)
            .collect();

        // DKG / reconfig output digests are populated by step 9's
        // producer caching. Until then the attestation pins only
        // the frozen validator mpc_data set, which is still a
        // well-defined, signable attestation — every validator
        // running this version computes the same one.
        let empty: BTreeMap<sui_types::base_types::ObjectID, [u8; 32]> = BTreeMap::new();
        let attestation = epoch_store
            .build_local_handoff_attestation(next_committee_pubkeys, &empty, &empty)
            .map_err(DwalletMPCError::IkaError)?;

        let tx = epoch_store
            .build_local_handoff_signature_transaction(attestation, &self.consensus_keypair)
            .map_err(DwalletMPCError::IkaError)?;

        self.consensus_adapter
            .submit_to_consensus(&[tx], &epoch_store)
            .await?;
        self.handoff_signature_sent.store(true, Ordering::Release);
        info!(epoch = self.epoch_id, "submitted local handoff signature");
        Ok(())
    }
}
