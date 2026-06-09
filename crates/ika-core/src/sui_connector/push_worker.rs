// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! sui-state-direct worker that polls Sui for new checkpoints, filters to
//! Ika-relevant ones (any output object whose Move type tree touches an Ika
//! package id — see `object_touches_ika`) plus all end-of-epoch checkpoints,
//! builds OCS inclusion proofs for the Ika-modified objects, and pushes
//! `(summary, [(object, proof), ...])` to connected peers via
//! [`SuiStateMirrorClient::push_verified_objects`].
//!
//! Bandwidth: scanning every Sui checkpoint requires a raw fetch; that
//! cost is unchanged. The *push* drops every non-Ika object plus all tx /
//! effects, shipping one summary plus, per Ika-touched object, its full Move
//! `Object` bytes and one Merkle path — a few KB to tens of KB per checkpoint
//! instead of the full checkpoint contents (the object bytes, not the proofs,
//! dominate for large inner state).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anemo::{Network, PeerId, Request, types::response::StatusCode};
use ika_network::proof_provider::VerifiedObjectEntry;
use ika_network::sui_state_mirror::{PushVerifiedObjectsRequest, SuiStateMirrorClient};
use ika_sui_client::transport::SuiTransport;
use ika_types::messages_dwallet_mpc::IkaPackageConfig;
use parking_lot::Mutex;
use sui_light_client::proof::ocs::ModifiedObjectTree;
use sui_types::TypeTag;
use sui_types::base_types::ObjectID;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{CheckpointArtifacts, CheckpointSequenceNumber};
use sui_types::object::Object;
use tracing::{debug, info, warn};

use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use crate::sui_connector::ocs_metrics::OcsMetrics;
use crate::sui_connector::verified_state_cache::SharedVerifiedStateCache;

pub struct IkaCheckpointPusher {
    /// Raw Sui transport used to fetch full checkpoints for proof
    /// construction. Kept off the cached layer so this scan doesn't
    /// pollute consumer caches.
    transport: Arc<dyn SuiTransport>,
    network: Network,
    perpetual: Arc<AuthorityPerpetualTables>,
    metrics: Arc<OcsMetrics>,
    ika_packages: HashSet<ObjectID>,
    poll_interval: Duration,
    cursor: CheckpointSequenceNumber,
    /// Peers that recently returned `NotFound` on `push_verified_objects`,
    /// i.e. they don't have a `PushVerifiedObjectsHandler` installed.
    /// TTL'd so a peer upgrading mid-run heals itself.
    no_push_handler_peers: Mutex<HashMap<PeerId, Instant>>,
    /// Direct-side write target for the verified state cache. Same
    /// `(summary, entries)` we just built into a push payload is also
    /// folded here so local consumers can read it without a network
    /// round-trip. Step 1 is shadow-population only — readers do not
    /// yet hit this cache.
    cache: SharedVerifiedStateCache,
    /// Sequence number of the last push we sent (any peer). Stamped on
    /// the next push as `prev_checkpoint_seq` so receivers can detect
    /// dropped pushes by comparing against their cache's head_seq.
    /// `None` until the first push since boot.
    last_push_seq: Option<CheckpointSequenceNumber>,
}

const NO_PUSH_HANDLER_TTL: Duration = Duration::from_secs(300);

impl IkaCheckpointPusher {
    pub async fn new(
        transport: Arc<dyn SuiTransport>,
        network: Network,
        perpetual: Arc<AuthorityPerpetualTables>,
        metrics: Arc<OcsMetrics>,
        packages: &IkaPackageConfig,
        poll_interval: Duration,
        cache: SharedVerifiedStateCache,
    ) -> anyhow::Result<Self> {
        let mut ika_packages = HashSet::new();
        ika_packages.insert(packages.ika_package_id);
        ika_packages.insert(packages.ika_common_package_id);
        ika_packages.insert(packages.ika_dwallet_2pc_mpc_package_id);
        if let Some(v2) = packages.ika_dwallet_2pc_mpc_package_id_v2 {
            ika_packages.insert(v2);
        }
        ika_packages.insert(packages.ika_system_package_id);

        let cursor = match perpetual.get_sui_pusher_last_seq()? {
            Some(persisted) => {
                info!(
                    persisted,
                    "checkpoint pusher resuming from perpetual cursor"
                );
                persisted
            }
            None => {
                let latest = transport.get_latest_checkpoint().await?;
                let cursor = *latest.sequence_number();
                info!(
                    cursor,
                    "checkpoint pusher first start — initializing at upstream latest"
                );
                perpetual.put_sui_pusher_last_seq(cursor)?;
                cursor
            }
        };
        metrics.pusher_cursor_seq.set(cursor as i64);

        Ok(Self {
            transport,
            network,
            perpetual,
            metrics,
            ika_packages,
            poll_interval,
            cursor,
            no_push_handler_peers: Mutex::new(HashMap::new()),
            cache,
            last_push_seq: None,
        })
    }

    pub async fn run(mut self) {
        let mut tick = tokio::time::interval(self.poll_interval);
        loop {
            tick.tick().await;
            if let Err(e) = self.advance().await {
                warn!(error = ?e, "checkpoint pusher tick failed; will retry");
            }
        }
    }

    async fn advance(&mut self) -> anyhow::Result<()> {
        let latest = self.transport.get_latest_checkpoint().await?;
        let latest_seq = *latest.sequence_number();
        // Stall gauge: upstream advanced but we haven't caught up by more than
        // a tick's worth of checkpoints. A stalled pusher freezes the cache,
        // so direct cache-first reads fall through to the network
        // (`cache_first_stale_total`). `STALL_THRESHOLD` sits between the
        // normal per-tick lag (a handful) and the FAR_BEHIND fast-forward.
        const STALL_THRESHOLD: u64 = 100;
        let lag = latest_seq.saturating_sub(self.cursor);
        self.metrics
            .pusher_stalled
            .set((lag > STALL_THRESHOLD) as i64);
        if lag > STALL_THRESHOLD {
            warn!(
                cursor = self.cursor,
                latest_seq, lag, "pusher stalled: falling behind upstream"
            );
        }
        if latest_seq <= self.cursor {
            return Ok(());
        }

        // Fast-forward past the prune horizon if we've fallen too far behind.
        const FAR_BEHIND_THRESHOLD: u64 = 1_000;
        const CATCHUP_LOOKBACK: u64 = 100;
        if latest_seq.saturating_sub(self.cursor) > FAR_BEHIND_THRESHOLD {
            let new_cursor = latest_seq.saturating_sub(CATCHUP_LOOKBACK);
            warn!(
                old_cursor = self.cursor,
                new_cursor, latest_seq, "pusher cursor too far behind upstream — fast-forwarding"
            );
            self.cursor = new_cursor;
            self.metrics.pusher_cursor_seq.set(new_cursor as i64);
            let _ = self.perpetual.put_sui_pusher_last_seq(new_cursor);
        }

        for seq in (self.cursor + 1)..=latest_seq {
            let data = match self.transport.get_full_checkpoint(seq).await {
                Ok(d) => d,
                Err(e) => {
                    self.metrics.pusher_fetch_failures_total.inc();
                    debug!(seq, error = ?e, "fetch failed; advancing past");
                    self.cursor = seq;
                    self.metrics.pusher_cursor_seq.set(seq as i64);
                    let _ = self.perpetual.put_sui_pusher_last_seq(seq);
                    continue;
                }
            };
            if let Some(mut push) = self.build_push(&data)? {
                // Stamp the sequence of our previous push so receivers
                // can detect if any push was lost in transit (gap
                // recovery via `GetVerifiedSnapshot`).
                push.prev_checkpoint_seq = self.last_push_seq;
                // Shadow-populate the local verified state cache with the
                // same payload we're about to ship to peers. Step 1: cache
                // is written but no consumer reads from it yet.
                self.cache.absorb_push(&push);
                self.metrics.pusher_pushed_total.inc();
                self.fanout(seq, push).await;
                self.last_push_seq = Some(seq);
            } else {
                self.metrics.pusher_skipped_irrelevant_total.inc();
            }
            self.cursor = seq;
            self.metrics.pusher_cursor_seq.set(seq as i64);
            if let Err(e) = self.perpetual.put_sui_pusher_last_seq(seq) {
                warn!(seq, error = ?e, "failed to persist pusher cursor");
            }
        }
        Ok(())
    }

    /// Returns `Some(push)` for Ika-relevant or end-of-epoch checkpoints
    /// (with proofs for each Ika-modified object) and `None` otherwise.
    ///
    /// "Ika-relevant" is determined per-output, by walking the Move
    /// type of each output and checking whether any address in the
    /// type tree matches an Ika package id. This catches:
    /// - Top-level Ika types (e.g. `System`, `DWalletCoordinator`,
    ///   `DWalletCoordinatorInner`): outer struct address is Ika.
    /// - Bag/Table entries `0x2::dynamic_field::Field<K, V>` where
    ///   `V` is an Ika type: walking type-params hits the Ika
    ///   address. The outer `Field` struct address is `0x2`, so a
    ///   simple "outer address only" filter would miss them.
    ///
    /// The previous filter ("tx has any Ika event → all outputs")
    /// missed mutations performed by system txs that didn't emit
    /// Ika-namespace events (notably bag-removal during session
    /// completion via epoch advance), which left consumer caches
    /// stale and produced spurious bag-omission warnings.
    fn build_push(
        &self,
        data: &CheckpointData,
    ) -> anyhow::Result<Option<PushVerifiedObjectsRequest>> {
        let is_end_of_epoch = data.checkpoint_summary.end_of_epoch_data.is_some();
        let mut ika_object_ids: HashSet<ObjectID> = HashSet::new();
        for tx in &data.transactions {
            for output in &tx.output_objects {
                if object_touches_ika(output, &self.ika_packages) {
                    ika_object_ids.insert(output.id());
                }
            }
        }

        if !is_end_of_epoch && ika_object_ids.is_empty() {
            return Ok(None);
        }

        // Build the modified-objects tree once for the whole checkpoint;
        // each Ika-modified object's proof is then a cheap path lookup.
        let artifacts = CheckpointArtifacts::from(data);
        let tree = ModifiedObjectTree::new(&artifacts)
            .map_err(|e| anyhow::anyhow!("ModifiedObjectTree: {e}"))?;

        let mut objects_with_proofs = Vec::with_capacity(ika_object_ids.len());
        for id in &ika_object_ids {
            let Some(object_ref) = tree.get_object_state(*id).copied() else {
                // Object referenced by an Ika event but not in the
                // modified-objects set — treat as a benign mismatch and
                // skip rather than abort the push.
                debug!(?id, "ika object not in artifacts; skipping");
                continue;
            };
            let proof = match tree.get_inclusion_proof(object_ref) {
                Ok(p) => p,
                Err(e) => {
                    warn!(?id, error = ?e, "failed to build inclusion proof; skipping");
                    continue;
                }
            };
            // Find the full Object in the checkpoint's tx outputs.
            let object = data
                .transactions
                .iter()
                .flat_map(|tx| tx.output_objects.iter())
                .find(|o| o.id() == *id)
                .cloned();
            let Some(object) = object else {
                debug!(?id, "ika object id absent from output_objects; skipping");
                continue;
            };
            objects_with_proofs.push(VerifiedObjectEntry {
                object,
                checkpoint_seq: *data.checkpoint_summary.sequence_number(),
                proof,
            });
        }

        if !is_end_of_epoch && objects_with_proofs.is_empty() {
            return Ok(None);
        }

        Ok(Some(PushVerifiedObjectsRequest {
            summary: data.checkpoint_summary.clone(),
            objects_with_proofs,
            // Caller stamps this before fanout. We default to None
            // here because `build_push` doesn't track push history.
            prev_checkpoint_seq: None,
        }))
    }

    async fn fanout(&self, seq: CheckpointSequenceNumber, push: PushVerifiedObjectsRequest) {
        let peer_ids: Vec<_> = self.network.peers();
        debug!(
            seq,
            peer_count = peer_ids.len(),
            "fanning out PushVerifiedObjects"
        );
        for peer_id in peer_ids {
            if self.is_known_no_handler(&peer_id) {
                self.metrics.pusher_fanout_skipped_no_handler_total.inc();
                continue;
            }
            let Some(peer) = self.network.peer(peer_id) else {
                continue;
            };
            let mut client = SuiStateMirrorClient::new(peer);
            // PushVerifiedObjectsRequest is not Clone (proofs aren't Clone),
            // so re-encode per peer. Cheap relative to the round-trip.
            let req_value = match bcs::to_bytes(&push)
                .and_then(|bytes| bcs::from_bytes::<PushVerifiedObjectsRequest>(&bytes))
            {
                Ok(v) => v,
                Err(e) => {
                    warn!(seq, error = ?e, "failed to clone push payload");
                    return;
                }
            };
            let req = Request::new(req_value).with_timeout(Duration::from_secs(30));
            if let Err(status) = client.push_verified_objects(req).await {
                if status.status() == StatusCode::NotFound {
                    self.no_push_handler_peers
                        .lock()
                        .insert(peer_id, Instant::now());
                    self.metrics.pusher_fanout_skipped_no_handler_total.inc();
                    debug!(
                        ?peer_id,
                        seq,
                        ttl_secs = NO_PUSH_HANDLER_TTL.as_secs(),
                        "peer has no push handler; suppressing pushes"
                    );
                    continue;
                }
                let reason = format!("{:?}", status.status());
                self.metrics
                    .pusher_fanout_failures_total
                    .with_label_values(&[&reason])
                    .inc();
                warn!(?peer_id, seq, reason = %reason, "push to peer failed");
            }
        }
    }

    fn is_known_no_handler(&self, peer_id: &PeerId) -> bool {
        let mut cache = self.no_push_handler_peers.lock();
        match cache.get(peer_id) {
            Some(at) if at.elapsed() < NO_PUSH_HANDLER_TTL => true,
            Some(_) => {
                cache.remove(peer_id);
                false
            }
            None => false,
        }
    }
}

/// `true` if any address in the object's Move type tree matches an
/// Ika package id. Walks through generic parameters, so wrapper types
/// like `0x2::dynamic_field::Field<K, IkaEvent>` qualify when `K` or
/// `V` is Ika-defined.
fn object_touches_ika(o: &Object, ika: &HashSet<ObjectID>) -> bool {
    let Some(move_obj) = o.data.try_as_move() else {
        return false;
    };
    let object_type = move_obj.type_();
    if ika.contains(&ObjectID::from(object_type.address())) {
        return true;
    }
    object_type
        .type_params()
        .iter()
        .any(|t| type_touches_ika(t, ika))
}

fn type_touches_ika(t: &TypeTag, ika: &HashSet<ObjectID>) -> bool {
    match t {
        TypeTag::Struct(boxed) => {
            let st = &**boxed;
            if ika.contains(&ObjectID::from(st.address)) {
                return true;
            }
            st.type_params.iter().any(|p| type_touches_ika(p, ika))
        }
        TypeTag::Vector(inner) => type_touches_ika(inner, ika),
        _ => false,
    }
}
