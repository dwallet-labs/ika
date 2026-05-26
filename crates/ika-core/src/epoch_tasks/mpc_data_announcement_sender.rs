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

use crate::authority::authority_per_epoch_store::{
    AuthorityPerEpochStore, AuthorityPerEpochStoreTrait,
};
use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use crate::consensus_adapter::SubmitToConsensus;
use crate::validator_metadata::{
    build_epoch_mpc_data_ready_signal_transaction, build_network_key_dkg_ready_signal_transaction,
    derive_mpc_data_blob, now_ms, sign_validator_mpc_data_announcement,
};
use dwallet_rng::RootSeed;
use ika_network::mpc_artifacts::{InMemoryBlobStore, mpc_data_blob_hash};
use ika_types::committee::EpochId;
use ika_types::crypto::{AuthorityKeyPair, AuthorityName};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::messages_dwallet_mpc::DWalletNetworkEncryptionKeyData;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    /// In-memory blob cache backing the local Anemo
    /// `GetMpcDataBlob` server. We mirror our own blob into it on
    /// submit so peers asking us for it via P2P get an immediate hit
    /// without a node restart.
    in_memory_blob_store: Arc<InMemoryBlobStore>,
    root_seed: RootSeed,
    bls_keypair: Arc<AuthorityKeyPair>,
    network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
    announcement_sent: AtomicBool,
    /// Size of the `validated_peers` set in the most recently
    /// emitted `EpochMpcDataReadySignal`, or `0` if we haven't
    /// emitted yet this epoch. We re-emit whenever our local
    /// `compute_locally_validated_peers()` set grows past this
    /// value — without that, a validator who first emits at
    /// just-barely-quorum coverage stays pinned at that snapshot
    /// even as P2P propagation later delivers more peer blobs.
    /// The network's freeze tally then permanently under-counts
    /// attestations for those late-arriving honest peers, and
    /// they get excluded for the entire epoch. Re-emit stops once
    /// the freeze has fired locally (`is_mpc_data_frozen()`) —
    /// after that point further attestations don't change the
    /// already-snapshotted partition.
    last_emitted_validated_peers_count: AtomicUsize,
    /// Per-key ready signals already submitted this epoch — keeps
    /// us from re-sending if the network-keys snapshot is observed
    /// repeatedly.
    per_key_signals_sent: Mutex<HashSet<ObjectID>>,
}

impl MpcDataAnnouncementSender {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        epoch_id: EpochId,
        authority: AuthorityName,
        consensus_adapter: Arc<dyn SubmitToConsensus>,
        perpetual_tables: Arc<AuthorityPerpetualTables>,
        in_memory_blob_store: Arc<InMemoryBlobStore>,
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
            in_memory_blob_store,
            root_seed,
            bls_keypair,
            network_keys_receiver,
            announcement_sent: AtomicBool::new(false),
            last_emitted_validated_peers_count: AtomicUsize::new(0),
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
            // the producer-side caching path writes the same digest
            // again on a future DKG / reconfig output we produce).
            warn!(error = ?e, "failed to persist validator mpc_data blob; peers won't serve it");
        }
        // Mirror into the in-memory cache backing the local
        // `GetMpcDataBlob` Anemo server. The cache is hydrated only
        // at node startup, so without this insert peers asking for
        // our blob during this epoch's first run would miss until
        // the next restart.
        self.in_memory_blob_store.insert(digest, blob.clone());
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
        // Stop re-emitting once the network-wide freeze has fired.
        // After that point further attestations don't change the
        // already-snapshotted partition.
        if epoch_store
            .is_mpc_data_frozen()
            .map_err(DwalletMPCError::IkaError)?
        {
            return Ok(());
        }
        // Emit-gate: only signal "ready" when this validator has a
        // stake-quorum of peer mpc_data locally and decode-validated.
        // Without this gate, a fast signaler could push the network
        // into a premature freeze that excludes legitimately-slow
        // honest validators.
        if !epoch_store
            .local_blob_coverage_meets_quorum()
            .map_err(DwalletMPCError::IkaError)?
        {
            debug!(
                epoch = self.epoch_id,
                "deferring EpochMpcDataReadySignal: \
                 local blob coverage below stake-quorum"
            );
            return Ok(());
        }
        let validated_peers = epoch_store
            .compute_locally_validated_peers()
            .map_err(DwalletMPCError::IkaError)?;
        // Re-emit policy: emit if we've never emitted (count = 0)
        // OR the validated set has grown since the last emission.
        // Re-emitting with a stable set is wasted consensus
        // bandwidth; emitting with a *strictly larger* set lets
        // the freeze tally pick up later-arriving honest peers'
        // blobs that we couldn't attest to on the first emit.
        let prev_count = self
            .last_emitted_validated_peers_count
            .load(Ordering::Acquire);
        if validated_peers.len() <= prev_count {
            return Ok(());
        }
        let new_count = validated_peers.len();
        let tx = build_epoch_mpc_data_ready_signal_transaction(
            self.authority,
            self.epoch_id,
            validated_peers,
        );
        self.consensus_adapter
            .submit_to_consensus(&[tx], &epoch_store)
            .await?;
        self.last_emitted_validated_peers_count
            .store(new_count, Ordering::Release);
        info!(
            epoch = self.epoch_id,
            validated_peers_count = new_count,
            prev_count,
            "submitted EpochMpcDataReadySignal"
        );
        Ok(())
    }

    async fn send_pending_per_key_signals(&self) -> DwalletMPCResult<()> {
        let epoch_store = self.epoch_store()?;
        let snapshot = self.network_keys_receiver.borrow().clone();
        // For each network key, broadcast a per-key readiness
        // signal. These signals are currently recorded by
        // `record_network_key_dkg_ready_signal` but don't feed
        // the freeze tally (epoch-wide signal is the only freeze
        // trigger) or session kickoff (which gates only on the
        // freeze itself). They're kept on the wire so a future
        // per-key kickoff gate or operator dashboard can
        // consume them without a separate rollout. We always
        // signal — chain-side key state can lag, suppressing
        // would deadlock that future consumer.
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
