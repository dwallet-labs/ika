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

use crate::authority::authority_per_epoch_store::{
    AuthorityPerEpochStore, AuthorityPerEpochStoreTrait,
};
use crate::consensus_adapter::SubmitToConsensus;
use crate::validator_metadata::HandoffItemsBuilder;
use fastcrypto::ed25519::Ed25519KeyPair;
use ika_types::committee::Committee;
use ika_types::crypto::AuthorityName;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use sui_types::base_types::ObjectID;
use tokio::sync::watch::Receiver;
use tracing::{info, warn};

pub struct HandoffSignatureSender {
    epoch_store: Weak<AuthorityPerEpochStore>,
    epoch_id: u64,
    consensus_adapter: Arc<dyn SubmitToConsensus>,
    end_of_publish_receiver: Receiver<Option<u64>>,
    consensus_keypair: Arc<Ed25519KeyPair>,
    next_epoch_committee_receiver: Receiver<Committee>,
    /// Chain-synced view of every `DWalletNetworkEncryptionKey` and
    /// its canonical DKG / current-reconfiguration output bytes.
    /// Updated by `sui_syncer::sync_dwallet_network_keys`. Read at
    /// signing time to hydrate the local digest cache with
    /// consensus/chain-deterministic hashes — sidestepping the race
    /// where the local MPC-driven cache may not yet contain the
    /// digest when EndOfPublish fires.
    network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
    builders: Vec<Arc<dyn HandoffItemsBuilder>>,
    sent: AtomicBool,
}

impl HandoffSignatureSender {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        epoch_id: u64,
        consensus_adapter: Arc<dyn SubmitToConsensus>,
        end_of_publish_receiver: Receiver<Option<u64>>,
        consensus_keypair: Arc<Ed25519KeyPair>,
        next_epoch_committee_receiver: Receiver<Committee>,
        network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
        builders: Vec<Arc<dyn HandoffItemsBuilder>>,
    ) -> Self {
        Self {
            epoch_store,
            epoch_id,
            consensus_adapter,
            end_of_publish_receiver,
            consensus_keypair,
            next_epoch_committee_receiver,
            network_keys_receiver,
            builders,
            sent: AtomicBool::new(false),
        }
    }

    pub async fn run(&self) {
        if let Some(epoch_store) = self.epoch_store.upgrade()
            && !epoch_store
                .protocol_config()
                .off_chain_validator_metadata_enabled()
        {
            info!(
                epoch = self.epoch_id,
                "off-chain validator metadata disabled; handoff signature sender exiting"
            );
            return;
        }
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

    /// For each network encryption key that has finished its
    /// initial DKG or current-epoch reconfiguration on chain,
    /// re-cache the canonical output bytes into the per-epoch
    /// digest tables. Idempotent — re-caching with the same bytes
    /// keeps the same digest (the cache layer is content-addressed).
    fn hydrate_protocol_output_digests_from_chain(
        &self,
        epoch_store: &Arc<AuthorityPerEpochStore>,
    ) {
        let snapshot = self.network_keys_receiver.borrow().clone();
        for (key_id, data) in snapshot.iter() {
            // DKG output: present once the key crosses out of
            // `AwaitingNetworkDKG`. Always cache if we have non-empty
            // bytes — re-caching with the same canonical bytes is a
            // no-op for the digest.
            if !data.network_dkg_public_output.is_empty()
                && !matches!(
                    data.state,
                    DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG
                )
                && let Err(e) =
                    epoch_store.cache_network_dkg_output(*key_id, &data.network_dkg_public_output)
            {
                warn!(
                    error = ?e,
                    key_id = ?key_id,
                    "failed to hydrate network DKG digest from chain bytes"
                );
            }
            // Reconfig output: present once the key reaches
            // `NetworkReconfigurationCompleted` for the current epoch.
            // The chain field carries the LATEST reconfig output, so
            // hydrating from it gives us the same value every
            // validator sees on chain — making the resulting handoff
            // item deterministic across the committee.
            if !data.current_reconfiguration_public_output.is_empty()
                && matches!(
                    data.state,
                    DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted
                )
                && let Err(e) = epoch_store.cache_network_reconfiguration_output(
                    *key_id,
                    &data.current_reconfiguration_public_output,
                )
            {
                warn!(
                    error = ?e,
                    key_id = ?key_id,
                    "failed to hydrate network reconfiguration digest from chain bytes"
                );
            }
        }
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
        // Hydrate the local digest cache from the chain-canonical
        // output bytes BEFORE building the attestation. EndOfPublish
        // gates on `all_network_encryption_keys_reconfiguration_completed`
        // on chain, so by the time we get here the chain has the
        // settled output for every key. Reading from chain (via the
        // `network_keys_receiver` published by `sui_syncer`) is the
        // only consensus-deterministic source — the original local
        // MPC-driven cache writes race with EndOfPublish (a slow
        // validator can see EndOfPublish before its own MPC
        // produces output, so the cache is empty at signing time
        // and the items list diverges from peers => signatures
        // cross-reject as `AttestationMismatch`).
        self.hydrate_protocol_output_digests_from_chain(&epoch_store);
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
