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
//! forever, blocking `is_mpc_data_frozen()`, and stalling network
//! DKG / reconfiguration kickoff for the epoch.

use crate::authority::authority_per_epoch_store::{
    AuthorityPerEpochStore, AuthorityPerEpochStoreTrait,
};
use crate::blob_cache::BlobCache;
use crate::consensus_adapter::SubmitToConsensus;
use crate::validator_metadata::{
    build_epoch_mpc_data_ready_signal_transaction, build_network_key_dkg_ready_signal_transaction,
    derive_mpc_data_blob, now_ms,
};
use dwallet_rng::RootSeed;
use ika_network::mpc_artifacts::mpc_data_blob_hash;
use ika_types::committee::{Committee, EpochId};
use ika_types::crypto::AuthorityName;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::error::IkaError;
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::messages_dwallet_mpc::DWalletNetworkEncryptionKeyData;
use ika_types::validator_metadata::ValidatorMpcDataAnnouncement;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use sui_types::base_types::ObjectID;
use tokio::sync::watch::Receiver;
use tracing::{debug, error, info, warn};

/// Pure decision for the ready-signal emit gate (see
/// `MpcDataAnnouncementSender::ready_to_finalize`). Extracted so the
/// joiner-inclusion timing rule is unit-testable without an epoch
/// store. Emit once either the epoch-clock deadline has passed
/// (liveness backstop) or the next-epoch committee is published and
/// every one of its members is locally validated (so a freeze
/// triggered by these signals captures the joiners).
fn decide_ready_to_finalize(
    now_ms: u64,
    deadline_ms: u64,
    next_committee_epoch: u64,
    expected_next_epoch: u64,
    next_members: &[AuthorityName],
    validated_peers: &[AuthorityName],
) -> bool {
    if now_ms >= deadline_ms {
        return true;
    }
    if next_committee_epoch != expected_next_epoch {
        // V_{e+1} not published yet — keep waiting.
        return false;
    }
    let validated: HashSet<&AuthorityName> = validated_peers.iter().collect();
    next_members.iter().all(|name| validated.contains(name))
}

/// Per-epoch producer task that broadcasts this validator's
/// mpc_data announcement and the corresponding ready signals.
pub struct MpcDataAnnouncementSender {
    epoch_store: Weak<AuthorityPerEpochStore>,
    epoch_id: EpochId,
    authority: AuthorityName,
    consensus_adapter: Arc<dyn SubmitToConsensus>,
    /// Write-through cache for the validator's own mpc_data blob:
    /// one `insert` persists to perpetual AND mirrors into the
    /// in-memory store backing the local Anemo `GetMpcDataBlob`
    /// server, so peers can fetch it over P2P without a restart.
    blob_cache: Arc<BlobCache>,
    root_seed: RootSeed,
    network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
    /// Next-epoch committee snapshot. The ready-signal emit gate
    /// waits until `V_{e+1}` is published and all its members are
    /// locally validated (or an epoch-clock deadline) before
    /// signalling — so the freeze, which fires on the first quorum
    /// of ready signals, includes next-epoch joiners (who can only
    /// announce after `V_{e+1}` is published, mid-epoch).
    next_epoch_committee_receiver: Receiver<Committee>,
    /// The announcement we've built for this epoch, cached after the
    /// first derivation. Re-sends reuse the SAME (validator, epoch,
    /// timestamp_ms) so the consensus key is stable and duplicate
    /// submissions dedup. `None` until the first `send_announcement`
    /// derives and persists the blob. Caching also avoids re-running
    /// the expensive class-groups derivation on every retry tick.
    cached_announcement: Mutex<Option<ValidatorMpcDataAnnouncement>>,
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
    /// Sequence number of the most recently emitted signal,
    /// starting at 0. Bumped on every re-emit and included in the
    /// consensus key so the generic same-key dedup at
    /// `verify_consensus_transaction` doesn't drop the re-emits —
    /// without this, only the first emit per (authority, epoch)
    /// would reach the strict-superset gate.
    next_sequence_number: std::sync::atomic::AtomicU64,
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
        blob_cache: Arc<BlobCache>,
        root_seed: RootSeed,
        network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
        next_epoch_committee_receiver: Receiver<Committee>,
    ) -> Self {
        Self {
            epoch_store,
            epoch_id,
            authority,
            consensus_adapter,
            blob_cache,
            root_seed,
            network_keys_receiver,
            next_epoch_committee_receiver,
            cached_announcement: Mutex::new(None),
            last_emitted_validated_peers_count: AtomicUsize::new(0),
            next_sequence_number: std::sync::atomic::AtomicU64::new(0),
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
            // (Re-)submit our announcement until it's confirmed in
            // the per-epoch table. `send_announcement` self-gates on
            // confirmation, so this is a cheap no-op once landed.
            if let Err(err) = self.send_announcement().await {
                warn!(error=?err, "failed to send validator mpc data announcement; will retry");
            }

            if let Err(err) = self.send_epoch_ready_signal().await {
                warn!(error=?err, "failed to send EpochMpcDataReadySignal; will retry");
            }

            if let Err(err) = self.send_pending_per_key_signals().await {
                warn!(error=?err, "failed to send NetworkKeyDKGReadySignal batch; will retry");
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Whether our own announcement is recorded in the per-epoch
    /// table (i.e. our submission was sequenced + processed by
    /// consensus). Compares against the cached announcement's
    /// timestamp + digest so a stale entry from a prior derivation
    /// doesn't count.
    fn announcement_confirmed(
        &self,
        epoch_store: &AuthorityPerEpochStore,
    ) -> DwalletMPCResult<bool> {
        let cached = self
            .cached_announcement
            .lock()
            .expect("mutex poisoned")
            .clone();
        let Some(cached) = cached else {
            return Ok(false);
        };
        let recorded = epoch_store
            .get_validator_mpc_data_announcement(&self.authority)
            .map_err(DwalletMPCError::IkaError)?;
        Ok(recorded
            .map(|r| r.timestamp_ms == cached.timestamp_ms && r.blob_hash == cached.blob_hash)
            .unwrap_or(false))
    }

    fn epoch_store(&self) -> DwalletMPCResult<Arc<AuthorityPerEpochStore>> {
        self.epoch_store
            .upgrade()
            .ok_or(DwalletMPCError::EpochEnded(self.epoch_id))
    }

    async fn send_announcement(&self) -> DwalletMPCResult<()> {
        let epoch_store = self.epoch_store()?;
        // Confirmation-based gate: stop once our announcement is in
        // the table. "submit returned Ok" only means handed off to a
        // background submit task — it can still fail to sequence
        // (epoch boundary, crash). Re-submitting an idempotent
        // announcement until it lands closes that gap.
        if self.announcement_confirmed(&epoch_store)? {
            return Ok(());
        }
        // Build (once) and cache an idempotent announcement. Reusing
        // the same (validator, epoch, timestamp_ms) keeps the
        // consensus key stable so re-sends dedup instead of stacking
        // up duplicate table entries, and avoids re-running the
        // expensive class-groups derivation on every retry tick.
        let announcement = self.cached_or_build_announcement()?;
        let tx = ConsensusTransaction::new_validator_mpc_data_announcement(announcement.clone());
        self.consensus_adapter
            .submit_to_consensus(&[tx], &epoch_store)
            .await?;
        info!(
            epoch = self.epoch_id,
            blob_hash = ?announcement.blob_hash,
            timestamp_ms = announcement.timestamp_ms,
            "submitted validator mpc data announcement (will re-submit until confirmed)"
        );
        Ok(())
    }

    /// Returns the cached announcement, building and caching it on
    /// first call: derive the blob, persist it write-through, and
    /// stamp it with `now_ms()`. Subsequent calls reuse the cache so
    /// re-sends are byte-identical (idempotent consensus key) and
    /// the costly derivation runs exactly once.
    fn cached_or_build_announcement(&self) -> DwalletMPCResult<ValidatorMpcDataAnnouncement> {
        {
            let cached = self.cached_announcement.lock().expect("mutex poisoned");
            if let Some(announcement) = cached.as_ref() {
                return Ok(announcement.clone());
            }
        }
        let blob = derive_mpc_data_blob(&self.root_seed).map_err(DwalletMPCError::IkaError)?;
        let digest = mpc_data_blob_hash(&blob);
        // Write-through: persists to perpetual AND mirrors into the
        // in-memory store backing the Anemo server. A persist failure
        // isn't fatal to the announcement, but peers won't be able to
        // fetch our blob until it's re-persisted.
        if let Err(e) = self.blob_cache.insert(digest, blob) {
            warn!(error = ?e, "failed to persist validator mpc_data blob; peers won't serve it");
        }
        let timestamp_ms = now_ms().map_err(DwalletMPCError::IkaError)?;
        if timestamp_ms == 0 {
            return Err(DwalletMPCError::IkaError(IkaError::Generic {
                error: "system clock returned a zero timestamp; refusing to \
                        announce with the reserved sentinel"
                    .into(),
            }));
        }
        // Self-submission: a current-committee validator submits the
        // bare announcement with no payload signature — the consensus
        // block author authenticates us, and the receiver enforces
        // `sender == validator`.
        let announcement = ValidatorMpcDataAnnouncement {
            validator: self.authority,
            epoch: self.epoch_id,
            timestamp_ms,
            blob_hash: digest,
        };
        *self.cached_announcement.lock().expect("mutex poisoned") = Some(announcement.clone());
        Ok(announcement)
    }

    /// Whether it's time to emit the ready signal — i.e. the freeze
    /// is allowed to capture our attestation set. True once either:
    /// - the next-epoch committee is published AND every one of its
    ///   members' blobs is locally validated (so a freeze triggered
    ///   by these signals includes the joiners), or
    /// - the epoch-clock deadline (3/4 of the epoch) has passed —
    ///   liveness backstop so a never-announcing joiner can't stall
    ///   the freeze forever.
    fn ready_to_finalize(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        validated_peers: &[AuthorityName],
    ) -> bool {
        use ika_types::sui::epoch_start_system::EpochStartSystemTrait;
        let epoch_start = epoch_store.epoch_start_state();
        let deadline = epoch_start
            .epoch_start_timestamp_ms()
            .saturating_add(epoch_start.epoch_duration_ms() / 4 * 3);
        // On clock failure, treat as past the deadline (emit) rather
        // than stalling the freeze.
        let now = now_ms().unwrap_or(u64::MAX);
        let next = self.next_epoch_committee_receiver.borrow();
        let next_members: Vec<AuthorityName> =
            next.voting_rights.iter().map(|(name, _)| *name).collect();
        decide_ready_to_finalize(
            now,
            deadline,
            next.epoch(),
            epoch_store.epoch() + 1,
            &next_members,
            validated_peers,
        )
    }

    async fn send_epoch_ready_signal(&self) -> DwalletMPCResult<()> {
        let epoch_store = self.epoch_store()?;
        // Don't signal "ready" before our own announcement has
        // landed in the table — otherwise we'd attest to a working
        // set we're not yet part of. (The loop calls this every tick
        // now, so the gate lives here rather than at the call site.)
        if !self.announcement_confirmed(&epoch_store)? {
            return Ok(());
        }
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
        // Defer the ready signal until the next-epoch committee is
        // known and all its members are locally validated (or the
        // epoch-clock deadline elapses). The freeze fires on the
        // first quorum of ready signals, so withholding here is what
        // lets joiners — who announce only after `V_{e+1}` is
        // published, mid-epoch — make it into the frozen set, the
        // next committee's class-groups map, and the handoff cert.
        // The deadline (wall-clock) only affects WHEN each validator
        // emits; the freeze snapshot itself is still computed
        // deterministically at the consensus-ordered quorum point.
        if !self.ready_to_finalize(&epoch_store, &validated_peers) {
            debug!(
                epoch = self.epoch_id,
                "deferring EpochMpcDataReadySignal: \
                 next-epoch committee not yet fully validated"
            );
            return Ok(());
        }
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
        // Reserve a sequence number BEFORE submit so we don't
        // collide with a concurrent producer call (the loop is
        // single-threaded today, but `fetch_add` keeps the
        // invariant local). The first emit is seq=0; re-emits are
        // 1, 2, ... — included in the consensus key so they don't
        // get deduped at verify time.
        let sequence_number = self.next_sequence_number.fetch_add(1, Ordering::AcqRel);
        let tx = build_epoch_mpc_data_ready_signal_transaction(
            self.authority,
            self.epoch_id,
            sequence_number,
            validated_peers,
        );
        self.consensus_adapter
            .submit_to_consensus(&[tx], &epoch_store)
            .await?;
        self.last_emitted_validated_peers_count
            .store(new_count, Ordering::Release);
        info!(
            epoch = self.epoch_id,
            sequence_number,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use fastcrypto::traits::KeyPair;
    use ika_network::mpc_artifacts::InMemoryBlobStore;
    use ika_types::messages_consensus::ConsensusTransaction;

    struct NoopAdapter;
    #[async_trait::async_trait]
    impl SubmitToConsensus for NoopAdapter {
        async fn submit_to_consensus(
            &self,
            _transactions: &[ConsensusTransaction],
            _epoch_store: &Arc<AuthorityPerEpochStore>,
        ) -> ika_types::error::IkaResult {
            Ok(())
        }
    }

    fn test_sender() -> MpcDataAnnouncementSender {
        let dir = tempfile::TempDir::new().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        std::mem::forget(dir); // keep the DB path alive for the test
        let blob_cache = BlobCache::new(InMemoryBlobStore::new(), perpetual);
        let (_tx, rx) = tokio::sync::watch::channel(Arc::new(HashMap::new()));
        // Minimal next-epoch committee; the idempotency test never
        // reads it (it exercises `cached_or_build_announcement`).
        // `Committee::new` validates the member pubkey, so use a real
        // test keypair rather than a synthetic AuthorityName.
        let member: AuthorityName = ika_types::crypto::random_committee_key_pairs_of_size(1)[0]
            .public()
            .into();
        let next_committee = Committee::new(
            6,
            vec![(member, 1u64)],
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            1,
            1,
        );
        let (_ntx, next_rx) = tokio::sync::watch::channel(next_committee);
        MpcDataAnnouncementSender::new(
            Weak::new(),
            5,
            AuthorityName::new([9; 48]),
            Arc::new(NoopAdapter),
            blob_cache,
            RootSeed::new([4; 32]),
            rx,
            next_rx,
        )
    }

    /// `cached_or_build_announcement` must return a byte-identical
    /// announcement on repeated calls (same timestamp + digest), so
    /// re-submissions produce a stable consensus key and dedup
    /// instead of stacking duplicate table entries.
    fn name(n: u8) -> AuthorityName {
        AuthorityName::new([n; 48])
    }

    #[test]
    fn ready_to_finalize_waits_for_next_committee_then_emits() {
        let a = name(1);
        let b = name(2);
        let joiner = name(3);
        // Before V_{e+1} is published (next epoch shows current=5,
        // not 6): not ready, even with everything validated.
        assert!(!decide_ready_to_finalize(100, 1000, 5, 6, &[a, b], &[a, b]));
        // V_{e+1} published (epoch 6) but the joiner isn't validated
        // yet: not ready.
        assert!(!decide_ready_to_finalize(
            100,
            1000,
            6,
            6,
            &[a, b, joiner],
            &[a, b]
        ));
        // V_{e+1} published AND all its members validated: ready.
        assert!(decide_ready_to_finalize(
            100,
            1000,
            6,
            6,
            &[a, b, joiner],
            &[a, b, joiner]
        ));
    }

    #[test]
    fn ready_to_finalize_deadline_forces_emit() {
        let a = name(1);
        let joiner = name(3);
        // Past the deadline: emit regardless of next-committee state
        // or joiner validation (liveness backstop).
        assert!(decide_ready_to_finalize(
            1000,
            1000,
            5,
            6,
            &[a, joiner],
            &[a]
        ));
        assert!(decide_ready_to_finalize(
            2000,
            1000,
            6,
            6,
            &[a, joiner],
            &[a]
        ));
    }

    #[tokio::test]
    async fn cached_announcement_is_idempotent_across_calls() {
        let sender = test_sender();
        let first = sender.cached_or_build_announcement().expect("build");
        let second = sender.cached_or_build_announcement().expect("cached");
        assert_eq!(
            first, second,
            "re-built announcement must equal the cached one"
        );
        // Same consensus key on both -> consensus dedup drops the
        // re-send rather than recording a second entry.
        let key_first = ConsensusTransaction::new_validator_mpc_data_announcement(first).key();
        let key_second = ConsensusTransaction::new_validator_mpc_data_announcement(second).key();
        assert_eq!(key_first, key_second);
    }
}
