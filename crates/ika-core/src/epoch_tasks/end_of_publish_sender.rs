// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::consensus_adapter::SubmitToConsensus;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_consensus::ConsensusTransaction;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::watch::Receiver;
use tracing::{error, info};

/// `EndOfPublishSender` submits the `EndOfPublish` consensus
/// message once the local signal (the `end_of_publish_receiver`)
/// has asserted the current epoch_id. Nothing else.
///
/// The handoff-attestation signature emit used to be bundled here;
/// it now lives in [`super::handoff_signature_sender`] so the two
/// orthogonal protocol steps are wired independently.
pub struct EndOfPublishSender {
    epoch_store: Weak<AuthorityPerEpochStore>,
    epoch_id: u64,
    consensus_adapter: Arc<dyn SubmitToConsensus>,
    end_of_publish_receiver: Receiver<Option<u64>>,
}

impl EndOfPublishSender {
    pub fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        consensus_adapter: Arc<dyn SubmitToConsensus>,
        end_of_publish_receiver: Receiver<Option<u64>>,
        epoch_id: u64,
    ) -> Self {
        Self {
            epoch_store,
            consensus_adapter,
            end_of_publish_receiver,
            epoch_id,
        }
    }

    pub async fn run(&self) {
        // The off-chain validator-metadata flow uses EndOfPublishV2,
        // which carries this validator's EndOfPublish vote bundled
        // with its signed handoff attestation. The handoff sender
        // owns emitting V2; standalone V1 EndOfPublish is suppressed
        // here to avoid double-voting.
        if let Some(epoch_store) = self.epoch_store.upgrade()
            && epoch_store
                .protocol_config()
                .off_chain_validator_metadata_enabled()
        {
            info!(
                epoch = self.epoch_id,
                "EndOfPublishV2 active; standalone EndOfPublish sender exiting"
            );
            return;
        }
        loop {
            if *self.end_of_publish_receiver.borrow() == Some(self.epoch_id)
                && let Err(err) = self.send_end_of_publish().await
            {
                error!(error=?err, "failed to send `end of publish` message");
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
}
