// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Per-epoch task that emits this validator's signed
//! `HandoffSignatureMessage` exactly once, when the local
//! `EndOfPublish` signal asserts the current epoch.
//!
//! Decoupled from `EndOfPublishSender` so the handoff cert is its
//! own protocol step — the two used to share a task by accident of
//! triggering on the same condition. Wiring contributors is the
//! caller's job: pass any number of
//! `Arc<dyn HandoffItemsBuilder>` and the task will fold their
//! contributions into the attestation.

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::consensus_adapter::SubmitToConsensus;
use crate::validator_metadata::HandoffItemsBuilder;
use fastcrypto::ed25519::Ed25519KeyPair;
use ika_types::committee::Committee;
use ika_types::crypto::AuthorityName;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::watch::Receiver;
use tracing::{info, warn};

pub struct HandoffSignatureSender {
    epoch_store: Weak<AuthorityPerEpochStore>,
    epoch_id: u64,
    consensus_adapter: Arc<dyn SubmitToConsensus>,
    end_of_publish_receiver: Receiver<Option<u64>>,
    consensus_keypair: Arc<Ed25519KeyPair>,
    next_epoch_committee_receiver: Receiver<Committee>,
    builders: Vec<Arc<dyn HandoffItemsBuilder>>,
    sent: AtomicBool,
}

impl HandoffSignatureSender {
    pub fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        epoch_id: u64,
        consensus_adapter: Arc<dyn SubmitToConsensus>,
        end_of_publish_receiver: Receiver<Option<u64>>,
        consensus_keypair: Arc<Ed25519KeyPair>,
        next_epoch_committee_receiver: Receiver<Committee>,
        builders: Vec<Arc<dyn HandoffItemsBuilder>>,
    ) -> Self {
        Self {
            epoch_store,
            epoch_id,
            consensus_adapter,
            end_of_publish_receiver,
            consensus_keypair,
            next_epoch_committee_receiver,
            builders,
            sent: AtomicBool::new(false),
        }
    }

    pub async fn run(&self) {
        loop {
            if *self.end_of_publish_receiver.borrow() == Some(self.epoch_id)
                && !self.sent.load(Ordering::Acquire)
                && let Err(err) = self.send().await
            {
                warn!(error=?err, "failed to send handoff signature; will retry");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    fn epoch_store(&self) -> DwalletMPCResult<Arc<AuthorityPerEpochStore>> {
        self.epoch_store
            .upgrade()
            .ok_or(DwalletMPCError::EpochEnded(self.epoch_id))
    }

    async fn send(&self) -> DwalletMPCResult<()> {
        let epoch_store = self.epoch_store()?;
        let next_committee = self.next_epoch_committee_receiver.borrow().clone();
        if next_committee.epoch() != self.epoch_id + 1 {
            // Committee sync task hasn't caught up with the next
            // epoch yet; defer until it has.
            return Ok(());
        }
        let next_committee_pubkeys: Vec<AuthorityName> = next_committee
            .voting_rights
            .iter()
            .map(|(name, _)| *name)
            .collect();
        let attestation = epoch_store
            .build_local_handoff_attestation(next_committee_pubkeys, &self.builders)
            .map_err(DwalletMPCError::IkaError)?;
        let tx = epoch_store
            .build_local_handoff_signature_transaction(attestation, &self.consensus_keypair)
            .map_err(DwalletMPCError::IkaError)?;
        self.consensus_adapter
            .submit_to_consensus(&[tx], &epoch_store)
            .await?;
        self.sent.store(true, Ordering::Release);
        info!(epoch = self.epoch_id, "submitted local handoff signature");
        Ok(())
    }
}
