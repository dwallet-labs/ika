// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! sui-state-direct worker that polls Sui for new checkpoints, filters to
//! Ika-relevant ones (any output object whose Move type tree touches an Ika
//! package id — see `object_touches_ika`) plus all end-of-epoch checkpoints,
//! builds OCS inclusion proofs for the Ika-modified objects, and folds
//! `(summary, [(object, proof), ...])` into the local verified state cache
//! that sui-state-direct consumers read cache-first.
//!
//! This is the authoritative cache populator on a direct node: it folds
//! every Ika-modified object of every checkpoint, in order, so a cache hit
//! is the object's current state up to the poll lag.
//!
//! Bandwidth: scanning every Sui checkpoint requires a raw fetch; that cost
//! is unchanged. Only Ika-touched objects (with their proofs) are kept; all
//! non-Ika objects plus tx / effects are dropped.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use ika_network::proof_provider::VerifiedObjectEntry;
use ika_sui_client::transport::SuiTransport;
use ika_types::messages_dwallet_mpc::IkaPackageConfig;
use sui_light_client::proof::ocs::ModifiedObjectTree;
use sui_types::TypeTag;
use sui_types::base_types::ObjectID;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointArtifacts, CheckpointSequenceNumber,
};
use sui_types::object::Object;
use tracing::{debug, info, warn};

use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use crate::sui_connector::committee_store::{CommitteeStore, CommitteeTransition};
use crate::sui_connector::ocs_metrics::OcsMetrics;
use crate::sui_connector::verified_state_cache::SharedVerifiedStateCache;

pub struct IkaCheckpointPusher {
    /// Raw Sui transport used to fetch full checkpoints for proof
    /// construction. Kept off the cached layer so this scan doesn't
    /// pollute consumer caches.
    transport: Arc<dyn SuiTransport>,
    perpetual: Arc<AuthorityPerpetualTables>,
    metrics: Arc<OcsMetrics>,
    ika_packages: HashSet<ObjectID>,
    poll_interval: Duration,
    cursor: CheckpointSequenceNumber,
    /// Direct-side write target for the verified state cache: each
    /// checkpoint's `(summary, entries)` is folded here so sui-state-direct
    /// consumers read it cache-first without a network round-trip.
    cache: SharedVerifiedStateCache,
    /// Committee chain. Each end-of-epoch checkpoint this worker streams past
    /// carries `committee[E+1]`, so we capture it here the moment we see it —
    /// the chain is then never forced to reach back for a (possibly-pruned)
    /// end-of-epoch checkpoint. The background ratchet remains the fallback.
    committees: Arc<CommitteeStore>,
}

impl IkaCheckpointPusher {
    pub async fn new(
        transport: Arc<dyn SuiTransport>,
        perpetual: Arc<AuthorityPerpetualTables>,
        metrics: Arc<OcsMetrics>,
        packages: &IkaPackageConfig,
        poll_interval: Duration,
        cache: SharedVerifiedStateCache,
        committees: Arc<CommitteeStore>,
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
            perpetual,
            metrics,
            ika_packages,
            poll_interval,
            cursor,
            cache,
            committees,
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
            // Object state for the skipped span is sacrificed (a cache miss
            // there falls through / degrades), but the committee chain must NOT
            // skip an epoch boundary: capture every still-available end-of-epoch
            // committee in the span we're about to jump over first.
            self.capture_committees_through(new_cursor).await;
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
            // Capture the committee transition the moment we stream past an
            // end-of-epoch checkpoint, so the chain never reaches back for it,
            // and retain the checkpoint so we can serve it to mirrored peers
            // after our own fullnode prunes it.
            self.capture_committee(&data);
            self.persist_end_of_epoch(&data, seq);
            if let Some((summary, entries)) = self.build_entries(&data)? {
                // Fold this checkpoint's Ika-modified objects into the local
                // verified state cache that sui-state-direct consumers read
                // cache-first.
                self.cache.absorb_entries(&summary, &entries);
                self.metrics.pusher_pushed_total.inc();
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

    /// Eagerly install the committee transition `data` commits to, if it is the
    /// end-of-epoch checkpoint of the current head epoch. A no-op otherwise.
    /// Best-effort: a verify failure is logged and left to the background
    /// ratchet rather than aborting the push.
    fn capture_committee(&self, data: &CheckpointData) {
        match self.committees.install_next_from_checkpoint(data) {
            Ok(CommitteeTransition::Installed(epoch)) => {
                info!(
                    epoch,
                    seq = *data.checkpoint_summary.sequence_number(),
                    "pusher captured Sui committee from streamed end-of-epoch checkpoint"
                );
            }
            Ok(CommitteeTransition::NotNextTransition) => {}
            Err(e) => {
                warn!(
                    error = ?e,
                    seq = *data.checkpoint_summary.sequence_number(),
                    "pusher committee capture failed; leaving to the background ratchet"
                );
            }
        }
    }

    /// Drive the committee chain forward over a span we are about to
    /// fast-forward the object cursor past, so no end-of-epoch committee is
    /// skipped: walk each still-available end-of-epoch checkpoint from the
    /// current head and install its committee, stopping at the first boundary
    /// beyond `through_seq` or the first unavailable (pruned) checkpoint. The
    /// latter is the accepted gap — the committee chain then falls back to the
    /// ratchet / a re-anchor rather than silently skipping a boundary.
    async fn capture_committees_through(&self, through_seq: CheckpointSequenceNumber) {
        loop {
            let head = self.committees.head_epoch();
            let eoe_seq = match self.transport.last_checkpoint_of_epoch(head).await {
                Ok(seq) => seq,
                // The head epoch hasn't ended yet (or the boundary is
                // unknowable) — nothing to capture ahead of `through_seq`.
                Err(_) => break,
            };
            if eoe_seq > through_seq {
                break;
            }
            let data = match self.transport.get_full_checkpoint(eoe_seq).await {
                Ok(data) => data,
                Err(e) => {
                    warn!(
                        head,
                        eoe_seq,
                        error = ?e,
                        "pusher catch-up: end-of-epoch checkpoint unavailable; committee \
                         chain falls back to the ratchet / re-anchor"
                    );
                    break;
                }
            };
            match self.committees.install_next_from_checkpoint(&data) {
                Ok(CommitteeTransition::Installed(epoch)) => {
                    info!(
                        epoch,
                        eoe_seq, "pusher captured Sui committee during catch-up"
                    );
                    self.persist_end_of_epoch(&data, eoe_seq);
                }
                // Not the next transition (head moved, or not end-of-epoch), or a
                // verify failure — stop and let the ratchet handle it.
                _ => break,
            }
        }
    }

    /// Retain a streamed end-of-epoch checkpoint (its epoch→seq mapping and the
    /// full checkpoint) so this node can serve a mirrored peer's ratchet the
    /// committee transition after its own fullnode prunes it
    /// (`RetainedFullnodeTransport`). A no-op for non-end-of-epoch checkpoints.
    fn persist_end_of_epoch(&self, data: &CheckpointData, seq: CheckpointSequenceNumber) {
        if data.checkpoint_summary.end_of_epoch_data.is_none() {
            return;
        }
        let epoch = data.checkpoint_summary.epoch();
        if let Err(e) = self.perpetual.put_sui_end_of_epoch_seq(epoch, seq) {
            warn!(epoch, seq, error = ?e, "failed to persist end-of-epoch seq");
        }
        if let Err(e) = self.perpetual.put_sui_end_of_epoch_checkpoint(seq, data) {
            warn!(seq, error = ?e, "failed to persist end-of-epoch checkpoint for mirrored peers");
        }
    }

    /// Returns `Some((summary, entries))` for Ika-relevant or end-of-epoch
    /// checkpoints (with a proof for each Ika-modified object) and `None`
    /// otherwise.
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
    fn build_entries(
        &self,
        data: &CheckpointData,
    ) -> anyhow::Result<Option<(CertifiedCheckpointSummary, Vec<VerifiedObjectEntry>)>> {
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
                dynamic_field_name_type: String::new(),
                dynamic_field_name_bcs: Vec::new(),
            });
        }

        if !is_end_of_epoch && objects_with_proofs.is_empty() {
            return Ok(None);
        }

        Ok(Some((data.checkpoint_summary.clone(), objects_with_proofs)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;

    use ika_sui_client::transport::{
        DynamicFieldPage, ExecutedTransaction, SubmittedTransaction, TransportError,
    };
    use sui_types::base_types::{ObjectRef, SequenceNumber, SuiAddress, TransactionDigest};
    use sui_types::committee::{Committee, ProtocolVersion};
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::digests::CheckpointDigest;
    use sui_types::gas::GasCostSummary;
    use sui_types::messages_checkpoint::{CheckpointContents, CheckpointSummary, EndOfEpochData};
    use sui_types::transaction::Transaction;

    use crate::sui_connector::committee_store::CommitteeBootstrap;
    use crate::sui_connector::verified_state_cache::VerifiedStateCache;

    /// Mock transport that serves a fixed `get_latest_checkpoint` and a
    /// configurable set of full checkpoints; a missing seq is `NotFound`
    /// (modeling an upstream prune). Only the three reads the pusher makes are
    /// implemented; the rest panic so an unexpected call is loud.
    struct MockTransport {
        latest: CertifiedCheckpointSummary,
        checkpoints: HashMap<CheckpointSequenceNumber, CheckpointData>,
    }

    #[async_trait]
    impl SuiTransport for MockTransport {
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            Ok(self.latest.clone())
        }
        async fn get_full_checkpoint(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            self.checkpoints
                .get(&seq)
                .cloned()
                .ok_or_else(|| TransportError::NotFound(format!("checkpoint {seq} pruned")))
        }

        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            unimplemented!()
        }
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            unimplemented!()
        }
        async fn get_reference_gas_price(&self) -> Result<u64, TransportError> {
            unimplemented!()
        }
        async fn get_committee(&self, _epoch: Option<u64>) -> Result<Committee, TransportError> {
            unimplemented!()
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            _digest: CheckpointDigest,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn last_checkpoint_of_epoch(
            &self,
            _epoch: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            unimplemented!()
        }
        async fn get_object(&self, _id: ObjectID) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn get_object_with_version(
            &self,
            _id: ObjectID,
            _version: SequenceNumber,
        ) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn batch_get_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<Vec<Object>, TransportError> {
            unimplemented!()
        }
        async fn list_owned_gas_coins(
            &self,
            _address: SuiAddress,
        ) -> Result<Vec<ObjectRef>, TransportError> {
            unimplemented!()
        }
        async fn list_dynamic_fields(
            &self,
            _parent: ObjectID,
            _page_size: Option<u32>,
            _page_token: Option<Vec<u8>>,
        ) -> Result<DynamicFieldPage, TransportError> {
            unimplemented!()
        }
        async fn get_transaction(
            &self,
            _tx: TransactionDigest,
        ) -> Result<ExecutedTransaction, TransportError> {
            unimplemented!()
        }
        async fn get_transaction_checkpoint(
            &self,
            _tx: TransactionDigest,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            unimplemented!()
        }
        async fn execute_transaction(
            &self,
            _tx: &Transaction,
        ) -> Result<SubmittedTransaction, TransportError> {
            unimplemented!()
        }
    }

    /// An end-of-epoch `CheckpointData` for the committee's epoch at `seq`,
    /// committee-signed and committing to the next epoch's committee (same
    /// members, epoch E+1). `verify_with_contents` passes because the summary's
    /// `content_digest` is set from the (empty) contents.
    fn end_of_epoch_checkpoint(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
    ) -> CheckpointData {
        let contents = CheckpointContents::new_with_digests_only_for_tests(vec![]);
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: *contents.digest(),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![],
            end_of_epoch_data: Some(EndOfEpochData {
                next_epoch_committee: committee.voting_rights.clone(),
                next_epoch_protocol_version: ProtocolVersion::MIN,
                epoch_commitments: vec![],
            }),
            version_specific_data: Vec::new(),
        };
        let checkpoint_summary =
            CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keys, committee);
        CheckpointData {
            checkpoint_summary,
            checkpoint_contents: contents,
            transactions: vec![],
        }
    }

    fn test_packages() -> IkaPackageConfig {
        IkaPackageConfig {
            ika_package_id: ObjectID::random(),
            ika_common_package_id: ObjectID::random(),
            ika_dwallet_2pc_mpc_package_id: ObjectID::random(),
            ika_dwallet_2pc_mpc_package_id_v2: None,
            ika_system_package_id: ObjectID::random(),
        }
    }

    async fn pusher_over(
        perpetual: Arc<AuthorityPerpetualTables>,
        committees: Arc<CommitteeStore>,
        transport: Arc<dyn SuiTransport>,
    ) -> IkaCheckpointPusher {
        let packages = test_packages();
        IkaCheckpointPusher::new(
            transport,
            perpetual,
            OcsMetrics::new_for_testing(),
            &packages,
            Duration::from_secs(2),
            Arc::new(VerifiedStateCache::new()),
            committees,
        )
        .await
        .unwrap()
    }

    /// Slice 1: the pusher installs `committee[E+1]` the moment it streams past
    /// the end-of-epoch checkpoint — the committee head advances without the
    /// ratchet ever reaching back for that (prune-prone) checkpoint.
    #[tokio::test]
    async fn pusher_eagerly_captures_end_of_epoch_committee() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::UnsafeGenesis(committee.clone())),
            )
            .unwrap(),
        );
        assert_eq!(committees.head_epoch(), 0);

        let eoe = end_of_epoch_checkpoint(&committee, &keys, 100);
        let latest = eoe.checkpoint_summary.clone();
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest,
            checkpoints: HashMap::from([(100u64, eoe)]),
        });
        // Resume from seq 99 so advance() streams exactly seq 100.
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let mut pusher = pusher_over(perpetual.clone(), committees.clone(), transport).await;
        pusher.advance().await.unwrap();

        assert_eq!(committees.head_epoch(), 1);
        // The end-of-epoch checkpoint is retained so this node can serve it to a
        // mirrored peer's ratchet after its own fullnode prunes it.
        assert!(
            perpetual
                .get_sui_end_of_epoch_checkpoint(100)
                .unwrap()
                .is_some()
        );
        assert_eq!(perpetual.get_sui_end_of_epoch_seq(0).unwrap(), Some(100));
    }

    /// Slice 4 (pusher half): a pruned (NotFound) checkpoint is skipped, not
    /// retried forever — advance returns Ok, the cursor moves past it, and the
    /// committee head is unchanged (nothing captured, but no stall).
    #[tokio::test]
    async fn pusher_skips_pruned_checkpoint_without_stalling() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::UnsafeGenesis(committee.clone())),
            )
            .unwrap(),
        );

        // latest=100, but the mock serves NO full checkpoints → every fetch is
        // NotFound (the prune horizon).
        let latest = end_of_epoch_checkpoint(&committee, &keys, 100).checkpoint_summary;
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest,
            checkpoints: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let mut pusher = pusher_over(perpetual.clone(), committees.clone(), transport).await;
        pusher.advance().await.unwrap();

        assert_eq!(committees.head_epoch(), 0);
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(100));
    }
}
