// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Producer-side task that drives the off-chain validator-metadata
//! flow at epoch start:
//! 1. Derives the local class-groups mpc_data blob from the root
//!    seed (matches the canonical BCS encoding `derive_mpc_data_blob`
//!    produces).
//! 2. Persists the blob into perpetual `mpc_artifact_blobs` so
//!    peers can fetch by hash via the existing `GetMpcDataBlob` RPC.
//! 3. Signs + submits a `ValidatorMpcDataAnnouncement` via
//!    consensus.
//! 4. Submits an `EpochMpcDataReadySignal` once its own
//!    announcement is in (which triggers the freeze on quorum).
//! 5. For every known network key currently in
//!    `AwaitingNetworkDKG`, submits a `NetworkKeyDKGReadySignal`.
//!
//! Without this task running, no validator would broadcast its
//! mpc_data — leaving `frozen_validator_mpc_data_input_set` empty
//! forever, leaving the step-14 kickoff gate permanently closed,
//! and stalling network DKG / reconfig.

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use crate::consensus_adapter::SubmitToConsensus;
use crate::validator_metadata::{
    build_epoch_mpc_data_ready_signal_transaction, build_network_key_dkg_ready_signal_transaction,
    derive_mpc_data_blob, now_ms, sign_validator_mpc_data_announcement,
};
use dwallet_rng::RootSeed;
use ika_network::mpc_artifacts::mpc_data_blob_hash;
use ika_types::committee::EpochId;
use ika_types::crypto::{AuthorityKeyPair, AuthorityName};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::messages_dwallet_mpc::DWalletNetworkEncryptionKeyData;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use sui_types::base_types::ObjectID;
use tokio::sync::watch::Receiver;
use tracing::{debug, error, info, warn};

/// Per-epoch producer task that broadcasts this validator's
/// mpc_data announcement and the corresponding ready signals.
pub struct MpcDataAnnouncementSender {
    epoch_store: Weak<AuthorityPerEpochStore>,
    epoch_id: EpochId,
    authority: AuthorityName,
    consensus_adapter: Arc<dyn SubmitToConsensus>,
    perpetual_tables: Arc<AuthorityPerpetualTables>,
    root_seed: RootSeed,
    bls_keypair: Arc<AuthorityKeyPair>,
    network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
    announcement_sent: AtomicBool,
    epoch_ready_signal_sent: AtomicBool,
    /// Per-key ready signals already submitted this epoch — keeps
    /// us from re-sending if the network-keys snapshot is observed
    /// repeatedly.
    per_key_signals_sent: Mutex<HashSet<ObjectID>>,
}

impl MpcDataAnnouncementSender {
    pub fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        epoch_id: EpochId,
        authority: AuthorityName,
        consensus_adapter: Arc<dyn SubmitToConsensus>,
        perpetual_tables: Arc<AuthorityPerpetualTables>,
        root_seed: RootSeed,
        bls_keypair: Arc<AuthorityKeyPair>,
        network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
    ) -> Self {
        Self {
            epoch_store,
            epoch_id,
            authority,
            consensus_adapter,
            perpetual_tables,
            root_seed,
            bls_keypair,
            network_keys_receiver,
            announcement_sent: AtomicBool::new(false),
            epoch_ready_signal_sent: AtomicBool::new(false),
            per_key_signals_sent: Mutex::new(HashSet::new()),
        }
    }

    pub async fn run(self: Arc<Self>) {
        // Off-chain feature gate. Read once at epoch start — the
        // protocol config is fixed for the epoch, so we don't need
        // to recheck on every loop tick.
        if let Some(epoch_store) = self.epoch_store.upgrade()
            && !epoch_store
                .protocol_config()
                .off_chain_validator_metadata_enabled()
        {
            info!(
                epoch = self.epoch_id,
                "off-chain validator metadata disabled by protocol config; task exiting"
            );
            return;
        }
        loop {
            if !self.announcement_sent.load(Ordering::Acquire)
                && let Err(err) = self.send_announcement().await
            {
                warn!(error=?err, "failed to send validator mpc data announcement; will retry");
            }

            if self.announcement_sent.load(Ordering::Acquire)
                && !self.epoch_ready_signal_sent.load(Ordering::Acquire)
                && let Err(err) = self.send_epoch_ready_signal().await
            {
                warn!(error=?err, "failed to send EpochMpcDataReadySignal; will retry");
            }

            if let Err(err) = self.send_pending_per_key_signals().await {
                warn!(error=?err, "failed to send NetworkKeyDKGReadySignal batch; will retry");
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    fn epoch_store(&self) -> DwalletMPCResult<Arc<AuthorityPerEpochStore>> {
        self.epoch_store
            .upgrade()
            .ok_or(DwalletMPCError::EpochEnded(self.epoch_id))
    }

    async fn send_announcement(&self) -> DwalletMPCResult<()> {
        let epoch_store = self.epoch_store()?;
        let blob = derive_mpc_data_blob(&self.root_seed).map_err(DwalletMPCError::IkaError)?;
        let digest = mpc_data_blob_hash(&blob);
        if let Err(e) = self
            .perpetual_tables
            .insert_mpc_artifact_blob(digest, &blob)
        {
            // Persist failure isn't fatal — the announcement still
            // goes through, but peers won't be able to fetch our
            // blob until the next restart hydrates it (or until
            // step 9's producer cache writes the same digest on
            // any future DKG/reconfig output we produce).
            warn!(error = ?e, "failed to persist validator mpc_data blob; peers won't serve it");
        }
        let signed = sign_validator_mpc_data_announcement(
            self.authority,
            self.epoch_id,
            now_ms(),
            digest,
            &self.bls_keypair,
        );
        let tx = ConsensusTransaction::new_validator_mpc_data_announcement(signed);
        self.consensus_adapter
            .submit_to_consensus(&[tx], &epoch_store)
            .await?;
        self.announcement_sent.store(true, Ordering::Release);
        info!(
            epoch = self.epoch_id,
            blob_hash = ?digest,
            "submitted validator mpc data announcement"
        );
        Ok(())
    }

    async fn send_epoch_ready_signal(&self) -> DwalletMPCResult<()> {
        let epoch_store = self.epoch_store()?;
        let tx = build_epoch_mpc_data_ready_signal_transaction(self.authority, self.epoch_id);
        self.consensus_adapter
            .submit_to_consensus(&[tx], &epoch_store)
            .await?;
        self.epoch_ready_signal_sent.store(true, Ordering::Release);
        info!(epoch = self.epoch_id, "submitted EpochMpcDataReadySignal");
        Ok(())
    }

    async fn send_pending_per_key_signals(&self) -> DwalletMPCResult<()> {
        let epoch_store = self.epoch_store()?;
        let snapshot = self.network_keys_receiver.borrow().clone();
        // For each network key, signal readiness regardless of
        // state. The chain-side state can lag (it's `AwaitingNetworkDKG`
        // until output lands), and per-key quorum is what unblocks
        // the DKG kickoff gate; suppressing readiness while waiting
        // would deadlock.
        let candidates: Vec<ObjectID> = snapshot.keys().copied().collect();
        for key_id in candidates {
            {
                let sent = self.per_key_signals_sent.lock().unwrap();
                if sent.contains(&key_id) {
                    continue;
                }
            }
            let tx = build_network_key_dkg_ready_signal_transaction(
                self.authority,
                key_id,
                self.epoch_id,
            );
            if let Err(err) = self
                .consensus_adapter
                .submit_to_consensus(&[tx], &epoch_store)
                .await
            {
                error!(error=?err, ?key_id, "failed to submit NetworkKeyDKGReadySignal");
                continue;
            }
            self.per_key_signals_sent.lock().unwrap().insert(key_id);
            info!(
                epoch = self.epoch_id,
                ?key_id,
                "submitted NetworkKeyDKGReadySignal"
            );
        }
        debug!(target: "mpc_data_announcement", epoch = self.epoch_id, "tick");
        Ok(())
    }
}
