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

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ika_network::proof_provider::VerifiedObjectEntry;
use ika_sui_client::archive::CheckpointArchive;
use ika_sui_client::transport::SuiTransport;
use ika_types::messages_dwallet_mpc::IkaPackageConfig;
use sui_light_client::proof::ocs::ModifiedObjectTree;
use sui_types::TypeTag;
use sui_types::base_types::ObjectID;
use sui_types::digests::CheckpointArtifactsDigest;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointArtifacts, CheckpointSequenceNumber,
};
use sui_types::object::Object;
use tracing::{debug, error, info, warn};

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
    /// Scanned checkpoints whose full contents were not yet fetchable, keyed
    /// to when they were first seen missing. The fullnode materializes a
    /// checkpoint's contents AFTER its summary certifies — tens of seconds
    /// later under load — so the scan must not stall behind one (freezing
    /// the whole cache) nor skip it silently (a PERMANENT cache gap: an Ika
    /// object whose only mutation rode the missed checkpoint — e.g. a
    /// session_events bag entry — never enters the cache, the bag event
    /// pump never delivers the session, and the epoch-close gate pins the
    /// epoch forever). Gaps are retried every tick and folded LATE when
    /// they materialize — safe because the verified state cache is
    /// monotonic-by-version, so an out-of-order fold can only fill gaps,
    /// never regress state. A gap the fullnode keeps refusing is fetched
    /// from the checkpoint `archive` instead (same committee verification
    /// at fold time); only a gap that BOTH sources fail to serve until the
    /// retry deadline is dropped with a loud warn. In-memory only: gaps are
    /// lost on restart, where the on-chain uncompleted-session re-pull is
    /// the backstop.
    pending_gaps: BTreeMap<CheckpointSequenceNumber, PendingGap>,
    /// Verified-fallback source for gap checkpoints the fullnode pruned
    /// before the pusher could fetch them. The public Sui checkpoint stores
    /// retain ordinary checkpoints ~30 days — far beyond any fullnode
    /// pruning window — and everything fetched is committee-verified at
    /// fold time, so this is an availability source, never a trust source.
    /// `None` when no archive resolved (a localnet without one configured):
    /// gaps then behave as before — retried against the fullnode until the
    /// deadline, then dropped.
    archive: Option<Arc<dyn CheckpointArchive>>,
}

/// Retry state of one scanned-but-unfetchable checkpoint.
struct PendingGap {
    first_seen: Instant,
    /// When the archive was last consulted for this gap, so archive fetches
    /// are paced at `ARCHIVE_RETRY_INTERVAL` instead of every 250ms tick.
    last_archive_attempt: Option<Instant>,
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
        archive: Option<Arc<dyn CheckpointArchive>>,
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
                // Watermark probe, not a summary fetch: a fullnode pruning at
                // head NotFounds its own latest, which would fail node boot
                // here.
                let cursor = transport.get_latest_checkpoint_sequence().await?;
                info!(
                    cursor,
                    "checkpoint pusher first start — initializing at upstream latest"
                );
                perpetual.put_sui_pusher_last_seq(cursor)?;
                cursor
            }
        };
        metrics.pusher_cursor_seq.set(cursor as i64);
        // Seed the cache's processed head so the reader's staleness tripwire
        // doesn't spuriously fire before the first poll tick advances it.
        cache.note_processed(cursor);

        Ok(Self {
            transport,
            perpetual,
            metrics,
            ika_packages,
            poll_interval,
            cursor,
            cache,
            committees,
            pending_gaps: BTreeMap::new(),
            archive,
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
        self.retry_pending_gaps().await;

        // Watermark probe, not a summary fetch: `get_latest_checkpoint` reads
        // through the fullnode's availability window, so a fullnode pruning at
        // head NotFounds its own latest and aborts this tick — permanently,
        // while the window stays empty. The height watermark survives pruning.
        let latest_seq = self.transport.get_latest_checkpoint_sequence().await?;
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
            // Gaps inside the sacrificed span go with it (covered by the
            // fast-forward warn above) — but each is still a permanent loss,
            // so they count toward the drop alarm.
            let gaps_before_sacrifice = self.pending_gaps.len();
            self.pending_gaps.retain(|&seq, _| seq > new_cursor);
            let sacrificed = gaps_before_sacrifice - self.pending_gaps.len();
            if sacrificed > 0 {
                self.metrics
                    .pusher_gap_dropped_total
                    .inc_by(sacrificed as u64);
            }
        }

        for seq in (self.cursor + 1)..=latest_seq {
            match self.transport.get_full_checkpoint(seq).await {
                Ok(data) => {
                    self.fold_checkpoint(seq, &data)?;
                }
                Err(e) => {
                    self.metrics.pusher_fetch_failures_total.inc();
                    // Keep scanning — later checkpoints usually ARE
                    // fetchable — and queue this one as a pending gap,
                    // retried at the top of every tick (see `pending_gaps`
                    // for why neither stalling here nor skipping silently
                    // is acceptable).
                    debug!(
                        seq,
                        error = ?e,
                        "full-checkpoint fetch failed; queued as a pending gap"
                    );
                    self.pending_gaps.entry(seq).or_insert_with(|| PendingGap {
                        first_seen: Instant::now(),
                        last_archive_attempt: None,
                    });
                }
            }
            self.cursor = seq;
            self.metrics.pusher_cursor_seq.set(seq as i64);
            if let Err(e) = self.perpetual.put_sui_pusher_last_seq(seq) {
                warn!(seq, error = ?e, "failed to persist pusher cursor");
            }
        }
        // The cache reflects every checkpoint up to the cursor now — including
        // the ones with no Ika objects, which don't advance the fold head. The
        // reader's tripwire keys off this so a quiet stretch doesn't force a
        // (prune-prone) reach-back for a still-current cached object.
        self.cache.note_processed(self.cursor);
        Ok(())
    }

    /// Fold one fetched checkpoint: capture the committee transition the
    /// moment we stream past an end-of-epoch checkpoint (so the chain never
    /// reaches back for it), retain it so we can serve it to mirrored peers
    /// after our own fullnode prunes it, and absorb its Ika-modified objects
    /// into the local verified state cache that sui-state-direct consumers
    /// read cache-first. Shared by the in-order scan and the pending-gap
    /// retries (a late fold is version-safe — see `pending_gaps`).
    ///
    /// `build_entries` runs FIRST: it committee-verifies every end-of-epoch
    /// or object-folding checkpoint, so the retained end-of-epoch store is
    /// only ever written after the summary passed verification —
    /// `persist_end_of_epoch` itself does not verify, and writing before
    /// verifying would let a forged blob overwrite a genuine retained entry
    /// (an availability, not forgery, hazard for the mirrored peers served
    /// from that store — they re-verify — but a needless one).
    fn fold_checkpoint(
        &mut self,
        seq: CheckpointSequenceNumber,
        data: &CheckpointData,
    ) -> anyhow::Result<()> {
        let entries = self.build_entries(data)?;
        self.capture_committee(data);
        self.persist_end_of_epoch(data, seq);
        if let Some((summary, entries)) = entries {
            self.cache.absorb_entries(&summary, &entries);
            self.metrics.pusher_pushed_total.inc();
        } else {
            self.metrics.pusher_skipped_irrelevant_total.inc();
        }
        Ok(())
    }

    /// Verification an archive-served checkpoint must pass BEFORE it may
    /// clear a pending gap — strictly MORE than the fullnode fold path
    /// applies, because the archive is the lower-trust source (on the public
    /// chains it defaults to a third-party HTTP store) and `build_entries`
    /// verifies nothing for a checkpoint with no Ika-typed outputs — a blob
    /// that folds vacuously would silently clear the gap and suppress the
    /// `pusher_gap_dropped_total` alarm this fallback exists to feed:
    ///
    /// 1. the blob IS the requested checkpoint: `summary.sequence_number ==
    ///    seq` (the seq is inside the committee-signed summary, so a
    ///    mislabeled genuine blob fails here);
    /// 2. committee BLS on the summary, unconditionally;
    /// 3. the artifacts-digest binding over the blob's ENTIRE object set,
    ///    unconditionally — an emptied or altered object set produces a tree
    ///    root the committee never signed, so "no Ika objects on this
    ///    checkpoint" cannot be forged.
    fn verify_archive_checkpoint(
        &self,
        seq: CheckpointSequenceNumber,
        data: &CheckpointData,
    ) -> anyhow::Result<()> {
        let summary = &data.checkpoint_summary;
        if *summary.sequence_number() != seq {
            anyhow::bail!(
                "archive served checkpoint {} for requested seq {seq}",
                summary.sequence_number()
            );
        }
        let artifacts = CheckpointArtifacts::from(data);
        let tree = ModifiedObjectTree::new(&artifacts)
            .map_err(|e| anyhow::anyhow!("ModifiedObjectTree over archive blob: {e}"))?;
        self.verify_before_fold(summary, &tree, true)
    }

    /// Retry every pending gap once. A gap that materializes is folded late
    /// (version-safe) and cleared; one the fullnode keeps refusing past
    /// `ARCHIVE_FALLBACK_AFTER` is fetched from the checkpoint archive
    /// instead (paced at `ARCHIVE_RETRY_INTERVAL`, capped per tick) and
    /// folded through the same committee verification. Only a gap that BOTH
    /// sources fail to serve until the deadline is dropped with a loud warn
    /// and counted (`pusher_gap_dropped_total`) — a permanent cache gap
    /// that can pin an epoch close (issue #2018). Fold failures stay
    /// pending rather than dropping immediately because they are not all
    /// deterministic: `verify_before_fold` fails with MissingCommittee
    /// while the checkpoint's epoch committee hasn't installed yet (follower
    /// lag at a Sui epoch boundary, or a restart near one) — exactly the
    /// transient the in-order scan path retries by pinning its cursor. A
    /// genuinely deterministic failure warns once per tick and expires at
    /// the same deadline. After a drop, objects whose only mutation rode
    /// the checkpoint stay missing from the cache until a later mutation or
    /// a consumer's network fallback repairs them.
    async fn retry_pending_gaps(&mut self) {
        const GAP_RETRY_DEADLINE: Duration = Duration::from_secs(600);
        // How long to give the fullnode alone before consulting the archive.
        // Covers the common late-materialization case (contents certify
        // seconds after the summary) without taxing the archive; a gap still
        // missing after this is very likely pruned upstream, and a fast
        // archive repair is what keeps the session's SDK-side wait (~600s)
        // from expiring.
        const ARCHIVE_FALLBACK_AFTER: Duration = Duration::from_secs(5);
        const ARCHIVE_RETRY_INTERVAL: Duration = Duration::from_secs(5);
        // Bound the archive fetches of one tick so a prune burst (hundreds of
        // gaps at once under CI-grade load) rolls through the archive over a
        // few ticks instead of hammering it — and so a hung archive can stall
        // one tick by at most ATTEMPTS × FETCH_TIMEOUT (20s). The gap-retry
        // loop runs BEFORE the head scan, so an unbounded stall here would
        // hold the cursor back while the fullnode prunes more checkpoints —
        // the fallback amplifying the very loss it exists to prevent.
        const ARCHIVE_ATTEMPTS_PER_TICK: usize = 4;
        // Bound the FULLNODE retries of one tick for the same reason the
        // archive attempts are bounded above. A pruning-at-head window now
        // gets traversed rather than aborting the tick (which is the point —
        // see the watermark probe in `advance`), and every unfetchable
        // checkpoint in it becomes a pending gap: at mainnet rates that is
        // thousands by the retry deadline. Retrying all of them serially,
        // every 250ms tick, against the very fullnode that is already failing
        // to serve them is the self-amplification the archive cap exists to
        // avoid — reached through the uncapped half of the loop. Gaps are
        // retried oldest-first (`BTreeMap` order), so the ones nearest their
        // deadline keep priority and the rest roll through over later ticks.
        const FULLNODE_ATTEMPTS_PER_TICK: usize = 64;

        let mut archive_attempts_this_tick = 0usize;
        let mut fullnode_attempts_this_tick = 0usize;
        let seqs: Vec<CheckpointSequenceNumber> = self.pending_gaps.keys().copied().collect();
        for seq in seqs {
            if fullnode_attempts_this_tick >= FULLNODE_ATTEMPTS_PER_TICK {
                break;
            }
            fullnode_attempts_this_tick += 1;
            let Some((first_seen, last_archive_attempt)) = self
                .pending_gaps
                .get(&seq)
                .map(|gap| (gap.first_seen, gap.last_archive_attempt))
            else {
                continue;
            };
            let expired = first_seen.elapsed() > GAP_RETRY_DEADLINE;
            match self.transport.get_full_checkpoint(seq).await {
                Ok(data) => match self.fold_checkpoint(seq, &data) {
                    Ok(()) => {
                        info!(seq, "late-materialized checkpoint folded — gap repaired");
                        self.pending_gaps.remove(&seq);
                    }
                    Err(e) if expired => {
                        self.pending_gaps.remove(&seq);
                        self.metrics.pusher_gap_dropped_total.inc();
                        warn!(
                            seq,
                            error = ?e,
                            "gap checkpoint kept failing to fold until the retry deadline — dropping"
                        );
                    }
                    Err(e) => {
                        warn!(seq, error = ?e, "gap checkpoint fetched but failed to fold — will retry");
                    }
                },
                Err(fullnode_error) => {
                    let archive_due = self.archive.is_some()
                        && first_seen.elapsed() > ARCHIVE_FALLBACK_AFTER
                        && last_archive_attempt
                            .is_none_or(|at| at.elapsed() > ARCHIVE_RETRY_INTERVAL)
                        && archive_attempts_this_tick < ARCHIVE_ATTEMPTS_PER_TICK;
                    if archive_due {
                        archive_attempts_this_tick += 1;
                        let first_attempt = last_archive_attempt.is_none();
                        if self.try_archive_repair(seq, first_attempt, expired).await {
                            continue;
                        }
                    }
                    if expired {
                        self.pending_gaps.remove(&seq);
                        self.metrics.pusher_gap_dropped_total.inc();
                        warn!(
                            seq,
                            error = ?fullnode_error,
                            archive_configured = self.archive.is_some(),
                            "checkpoint never materialized within the gap retry deadline — dropping"
                        );
                    }
                }
            }
        }
    }

    /// Try to repair one pending gap from the checkpoint archive: fetch the
    /// full checkpoint data, pass it through `verify_archive_checkpoint`
    /// (seq binding + committee BLS + unconditional artifacts-digest
    /// binding — see there for why the archive path verifies MORE than the
    /// fullnode path), and fold it. Returns `true` when the gap was repaired
    /// and removed. On any failure the gap stays pending (the caller applies
    /// the deadline). The fetch is bounded by `ARCHIVE_FETCH_TIMEOUT`
    /// because the underlying object-store client retries internally for up
    /// to 60s on anything but NotFound (e.g. a truncated blob from a
    /// mid-write fullnode crash) — unbounded, a hung archive would stall the
    /// whole pusher loop.
    async fn try_archive_repair(
        &mut self,
        seq: CheckpointSequenceNumber,
        first_attempt: bool,
        expired: bool,
    ) -> bool {
        const ARCHIVE_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
        let Some(archive) = self.archive.clone() else {
            return false;
        };
        if let Some(gap) = self.pending_gaps.get_mut(&seq) {
            gap.last_archive_attempt = Some(Instant::now());
        }
        let fetched = tokio::time::timeout(ARCHIVE_FETCH_TIMEOUT, async {
            archive.fetch_checkpoint_data(seq).await
        })
        .await
        .map_err(|_| anyhow::anyhow!("archive fetch timed out after {ARCHIVE_FETCH_TIMEOUT:?}"))
        .and_then(|fetch_result| fetch_result.map_err(anyhow::Error::from));
        match fetched {
            Ok(data) => {
                if let Err(e) = self.verify_archive_checkpoint(seq, &data) {
                    warn!(
                        seq,
                        error = %e,
                        "archive served a checkpoint that failed verification — refusing it"
                    );
                    return false;
                }
                match self.fold_checkpoint(seq, &data) {
                    Ok(()) => {
                        info!(
                            seq,
                            "pruned checkpoint recovered from the archive and folded — gap repaired"
                        );
                        self.metrics.pusher_gap_archive_repairs_total.inc();
                        self.pending_gaps.remove(&seq);
                        true
                    }
                    Err(e) => {
                        // Same transient-vs-deterministic ambiguity as the
                        // fullnode fold path; the caller's deadline bounds it.
                        warn!(seq, error = ?e, "archive checkpoint fetched but failed to fold — will retry");
                        false
                    }
                }
            }
            Err(e) => {
                // The first failure per gap warns so a misconfigured archive
                // (a typo'd file:// path) is visible immediately at the
                // default log level, not only after gaps start dropping at
                // the 600s deadline.
                if first_attempt || expired {
                    warn!(seq, error = %e, "archive could not serve the gap checkpoint");
                } else {
                    debug!(seq, error = %e, "archive fetch for gap checkpoint failed; will retry");
                }
                false
            }
        }
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
        // One batch: the epoch→seq index and its backing CheckpointData are
        // persisted atomically, so a crash can't leave a dangling half.
        if let Err(e) = self.perpetual.put_sui_end_of_epoch(epoch, seq, data) {
            warn!(epoch, seq, error = ?e, "failed to persist end-of-epoch (seq + checkpoint) for mirrored peers");
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

        // Verify the checkpoint against its committee BEFORE folding anything
        // into the cache, so a direct node caches committee-attested state
        // rather than whatever its own fullnode served.
        let summary = &data.checkpoint_summary;
        if let Err(e) = self.verify_before_fold(summary, &tree, !objects_with_proofs.is_empty()) {
            error!(
                security_critical = true,
                seq = *summary.sequence_number(),
                epoch = summary.epoch(),
                error = %e,
                "refusing to fold a checkpoint that failed committee verification — \
                 own fullnode served state that does not verify against the committee"
            );
            return Err(e);
        }

        Ok(Some((data.checkpoint_summary.clone(), objects_with_proofs)))
    }

    /// Verify a checkpoint against its committee BEFORE its objects are folded
    /// into the cache, so a direct node trusts committee-attested state rather
    /// than whatever its own fullnode served — a compromised or buggy fullnode
    /// cannot seed the cache with forged objects. These are the same two checks
    /// [`OcsVerifiedReader`]'s network read path performs, hoisted to fold time
    /// (once per checkpoint, off the read hot path):
    ///
    ///   1. the checkpoint summary carries a valid committee quorum signature;
    ///   2. when objects are being folded, the locally-built modified-objects
    ///      tree root matches the committee-signed checkpoint-artifacts digest —
    ///      binding every inclusion proof derived from that tree to
    ///      committee-attested state (a real tree root means the proofs the
    ///      pusher built from it are over genuine objects).
    ///
    /// A failure means the fullnode served state that does not verify against
    /// the committee: the caller refuses to fold it (propagating the error, so
    /// the cursor stays put and a transient missing-committee self-heals on the
    /// next poll) rather than caching unverified state.
    fn verify_before_fold(
        &self,
        summary: &CertifiedCheckpointSummary,
        tree: &ModifiedObjectTree,
        folding_objects: bool,
    ) -> anyhow::Result<()> {
        let started = Instant::now();
        self.committees
            .verify_summary(summary.clone())
            .map_err(|e| {
                anyhow::anyhow!("checkpoint summary failed committee verification: {e}")
            })?;
        if folding_objects {
            let signed = summary.data().checkpoint_artifacts_digest().map_err(|e| {
                anyhow::anyhow!("summary carries no checkpoint-artifacts digest: {e}")
            })?;
            let local = CheckpointArtifactsDigest::from_artifact_digests(vec![tree.tree_root])
                .map_err(|e| anyhow::anyhow!("computing artifacts digest from local tree: {e}"))?;
            if local != *signed {
                anyhow::bail!(
                    "checkpoint-artifacts digest mismatch — the fullnode's modified-objects \
                     tree does not match the committee-signed digest"
                );
            }
        }
        // Record only the success path's cost: a rejection (the early returns
        // above) is a security event surfaced by the caller's log, not a
        // steady-state latency sample. `_count` then equals the checkpoints
        // committee-verified before folding, `_sum` the CPU the verify added
        // to the fold loop.
        self.metrics
            .pusher_fold_verify_seconds
            .observe(started.elapsed().as_secs_f64());
        Ok(())
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
    use std::collections::{BTreeMap, HashMap};

    use ika_sui_client::transport::{DynamicFieldPage, ExecutedTransaction, TransportError};
    use sui_types::base_types::{ObjectDigest, SequenceNumber, TransactionDigest};
    use sui_types::committee::{Committee, ProtocolVersion};
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::digests::CheckpointDigest;
    use sui_types::gas::GasCostSummary;
    use sui_types::messages_checkpoint::{
        CheckpointCommitment, CheckpointContents, CheckpointSummary, EndOfEpochData,
    };
    use sui_types::object::Owner;

    use crate::sui_connector::committee_store::CommitteeBootstrap;
    use crate::sui_connector::verified_state_cache::{
        SharedVerifiedStateCache, VerifiedStateCache,
    };

    /// Mock transport that serves a fixed `get_latest_checkpoint` and a
    /// configurable set of full checkpoints; a missing seq is `NotFound`
    /// (modeling an upstream prune). Only the three reads the pusher makes are
    /// implemented; the rest panic so an unexpected call is loud.
    struct MockTransport {
        latest: CertifiedCheckpointSummary,
        /// Emulates a fullnode pruning AT head: the availability window is
        /// empty, so summary reads NotFound even for `latest`, while the
        /// height watermark (`GetServiceInfo`) still answers.
        latest_summary_pruned: bool,
        checkpoints: HashMap<CheckpointSequenceNumber, CheckpointData>,
        /// `epoch -> last checkpoint seq of that epoch`, for
        /// `last_checkpoint_of_epoch` (the catch-up boundary walk). Empty for
        /// the slices that never reach `capture_committees_through`.
        eoe_seqs: HashMap<u64, CheckpointSequenceNumber>,
    }

    #[async_trait]
    impl SuiTransport for MockTransport {
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            if self.latest_summary_pruned {
                return Err(TransportError::NotFound(format!(
                    "Checkpoint {} not found",
                    self.latest.sequence_number()
                )));
            }
            Ok(self.latest.clone())
        }
        async fn get_latest_checkpoint_sequence(
            &self,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            // The height watermark survives pruning — mirrors the real
            // transport's `GetServiceInfo.checkpoint_height` probe.
            Ok(*self.latest.sequence_number())
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
            epoch: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            self.eoe_seqs
                .get(&epoch)
                .copied()
                .ok_or_else(|| TransportError::NotFound(format!("epoch {epoch} boundary unknown")))
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
    }

    /// The artifacts commitment matching a checkpoint with no transactions
    /// (the shape every helper below builds), so archive-path verification —
    /// which binds the artifacts digest unconditionally — passes for honest
    /// mock checkpoints.
    fn empty_artifacts_commitment() -> CheckpointCommitment {
        CheckpointCommitment::CheckpointArtifactsDigest(
            CheckpointArtifacts::from_object_states(BTreeMap::new())
                .digest()
                .unwrap(),
        )
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
            checkpoint_commitments: vec![empty_artifacts_commitment()],
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

    /// A plain (non-end-of-epoch) `CheckpointData` at `seq` with no
    /// transactions. `build_entries` returns `None` for it (nothing Ika to
    /// fold), so it advances the cursor / processed head without folding.
    fn plain_checkpoint(
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
            checkpoint_commitments: vec![empty_artifacts_commitment()],
            end_of_epoch_data: None,
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

    async fn pusher_over(
        perpetual: Arc<AuthorityPerpetualTables>,
        committees: Arc<CommitteeStore>,
        transport: Arc<dyn SuiTransport>,
    ) -> IkaCheckpointPusher {
        pusher_over_with_cache(
            perpetual,
            committees,
            transport,
            Arc::new(VerifiedStateCache::new()),
            OcsMetrics::new_for_testing(),
        )
        .await
    }

    async fn pusher_over_with_cache(
        perpetual: Arc<AuthorityPerpetualTables>,
        committees: Arc<CommitteeStore>,
        transport: Arc<dyn SuiTransport>,
        cache: SharedVerifiedStateCache,
        metrics: Arc<OcsMetrics>,
    ) -> IkaCheckpointPusher {
        let packages = test_packages();
        IkaCheckpointPusher::new(
            transport,
            perpetual,
            metrics,
            &packages,
            Duration::from_secs(2),
            cache,
            committees,
            None,
        )
        .await
        .unwrap()
    }

    /// Slice 1: the pusher installs `committee[E+1]` the moment it streams past
    /// the end-of-epoch checkpoint — the committee head advances without the
    /// ratchet ever reaching back for that (prune-prone) checkpoint.
    /// The pusher's FIRST START inside a pruned-at-head window: no persisted
    /// cursor, so `new` must take its initial cursor from the watermark. With
    /// a summary fetch there, constructing the pusher fails — and because
    /// `SuiClient` construction sits upstream of this on every node-start
    /// path, that failure surfaces as a node that does not come up at all.
    #[tokio::test]
    async fn pusher_first_start_survives_a_fullnode_pruning_at_head() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );

        let eoe = end_of_epoch_checkpoint(&committee, &keys, 100);
        let latest = eoe.checkpoint_summary.clone();
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest_summary_pruned: true,
            latest,
            checkpoints: HashMap::from([(100u64, eoe)]),
            eoe_seqs: HashMap::new(),
        });
        // No `put_sui_pusher_last_seq` — this is a first start.
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), None);

        let _pusher = pusher_over(perpetual.clone(), committees.clone(), transport).await;

        // The cursor initialized from the watermark rather than failing.
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(100));
    }

    /// A fullnode pruning AT head empties its availability window and serves
    /// NotFound for its OWN latest checkpoint — persistently, while the window
    /// stays empty. The tick must survive that (the height watermark is
    /// pruning-immune) and keep folding what IS available; before this, the
    /// summary fetch at the top of `advance` aborted the whole tick with `?`,
    /// freezing the cursor and the verified cache behind it.
    #[tokio::test]
    async fn pusher_tick_survives_a_fullnode_pruning_at_head() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );

        let eoe = end_of_epoch_checkpoint(&committee, &keys, 100);
        let latest = eoe.checkpoint_summary.clone();
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            // The summary read NotFounds — as a pruned-at-head fullnode does.
            latest_summary_pruned: true,
            latest,
            checkpoints: HashMap::from([(100u64, eoe)]),
            eoe_seqs: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let mut pusher = pusher_over(perpetual.clone(), committees.clone(), transport).await;
        pusher
            .advance()
            .await
            .expect("a pruned-at-head latest must not abort the tick");

        // The cursor advanced and the available checkpoint still folded.
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(100));
        assert_eq!(committees.head_epoch(), 1);
    }

    #[tokio::test]
    async fn pusher_eagerly_captures_end_of_epoch_committee() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );
        assert_eq!(committees.head_epoch(), 0);

        let eoe = end_of_epoch_checkpoint(&committee, &keys, 100);
        let latest = eoe.checkpoint_summary.clone();
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest_summary_pruned: false,
            latest,
            checkpoints: HashMap::from([(100u64, eoe)]),
            eoe_seqs: HashMap::new(),
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

    /// A NotFound checkpoint does not stall the scan NOR leave a permanent
    /// gap: the cursor advances past it (nothing folded), the seq is queued
    /// as a pending gap, and once the checkpoint materializes a later tick
    /// folds it late — recovering its committee capture and end-of-epoch
    /// retention.
    #[tokio::test]
    async fn unavailable_checkpoint_becomes_pending_gap_and_folds_when_it_materializes() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );

        // latest=100, but its contents haven't materialized yet → NotFound.
        let eoe = end_of_epoch_checkpoint(&committee, &keys, 100);
        let latest = eoe.checkpoint_summary.clone();
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest_summary_pruned: false,
            latest: latest.clone(),
            checkpoints: HashMap::new(),
            eoe_seqs: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let mut pusher = pusher_over(perpetual.clone(), committees.clone(), transport).await;
        pusher.advance().await.unwrap();

        // Nothing folded, but the scan did NOT stall: the cursor advanced
        // past the gap, which is now pending repair.
        assert_eq!(committees.head_epoch(), 0);
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(100));
        assert!(pusher.pending_gaps.contains_key(&100));

        // The checkpoint materializes; the next tick repairs the gap.
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest_summary_pruned: false,
            latest,
            checkpoints: HashMap::from([(100u64, eoe)]),
            eoe_seqs: HashMap::new(),
        });
        pusher.transport = transport;
        pusher.advance().await.unwrap();

        assert_eq!(committees.head_epoch(), 1);
        assert!(pusher.pending_gaps.is_empty());
        assert!(
            perpetual
                .get_sui_end_of_epoch_checkpoint(100)
                .unwrap()
                .is_some(),
            "a gap-repaired end-of-epoch checkpoint must be retained"
        );
    }

    /// Fast-forward catch-up walks the still-available end-of-epoch boundaries
    /// in order, installing each committee — but it must NOT skip a pruned
    /// boundary. With boundaries at seqs 30/60/90 and seq 60 pruned (NotFound),
    /// the walk installs epoch-0's transition (head → 1) from seq 30, then stops
    /// at the pruned seq-60 boundary: the committee head advances only to the
    /// epoch *before* the gap, never jumping past it to a later boundary.
    #[tokio::test]
    async fn fast_forward_captures_all_boundaries_then_stops_at_a_pruned_one() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );
        assert_eq!(committees.head_epoch(), 0);

        // End-of-epoch boundaries at 30, 60, 90. Seq 60 is pruned: present in the
        // epoch→seq map (so the boundary is *known*) but absent from the fetchable
        // checkpoints, so `get_full_checkpoint(60)` is NotFound.
        let eoe_30 = end_of_epoch_checkpoint(&committee, &keys, 30);
        let eoe_90 = end_of_epoch_checkpoint(&committee, &keys, 90);

        // latest far beyond FAR_BEHIND_THRESHOLD (1_000) so advance() fast-forwards
        // and runs the catch-up boundary walk. new_cursor = latest - 100 = 2_000,
        // which is > 90, so the walk's `eoe_seq > through_seq` guard never trips
        // before the prune does.
        let latest = end_of_epoch_checkpoint(&committee, &keys, 2_100).checkpoint_summary;
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest_summary_pruned: false,
            latest,
            checkpoints: HashMap::from([(30u64, eoe_30), (90u64, eoe_90)]),
            eoe_seqs: HashMap::from([(0u64, 30), (1u64, 60), (2u64, 90)]),
        });
        // Resume from seq 0 → lag 2_100 > FAR_BEHIND_THRESHOLD → fast-forward path.
        perpetual.put_sui_pusher_last_seq(0).unwrap();

        let mut pusher = pusher_over(perpetual.clone(), committees.clone(), transport).await;
        pusher.advance().await.unwrap();

        // Seq 30 installed epoch-0's transition; the pruned seq-60 boundary halted
        // the walk before epoch 1's boundary (seq 90) could be reached. The head
        // never jumps the gap to a later boundary.
        assert_eq!(committees.head_epoch(), 1);
        // Boundary actually walked-through is retained for mirrored peers.
        assert_eq!(perpetual.get_sui_end_of_epoch_seq(0).unwrap(), Some(30));
        // The boundary past the prune gap was never captured.
        assert_eq!(perpetual.get_sui_end_of_epoch_seq(2).unwrap(), None);
    }

    /// A transport that returns `NotFound` for every third checkpoint (modeling
    /// a sparse upstream prune) must not wedge: `advance()` streams to the
    /// latest, advancing the processed head all the way, incrementing the
    /// fetch-failure metric once per missing seq. No object is folded for a
    /// failed seq (a gap in the cache), and an end-of-epoch checkpoint that
    /// lands on a failed (NotFound) seq is NOT retained — the fetch fails before
    /// Fetch failures mid-stream become pending gaps while the scan folds
    /// everything else in order; when the missing checkpoints materialize,
    /// a later tick repairs them all — including an end-of-epoch checkpoint
    /// on a previously failed seq, whose committee capture and retention are
    /// RECOVERED rather than lost (under the old advance-past behavior a
    /// transient NotFound silently dropped it and every Ika object on that
    /// seq from the verified cache forever).
    #[tokio::test]
    async fn fetch_failures_become_pending_gaps_and_repair_when_checkpoints_materialize() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );

        // Stream seqs 1..=9 from cursor 0. Seqs 3, 6, 9 are OMITTED from the
        // served map at first (their fetches are NotFound); seq 6 is an
        // end-of-epoch checkpoint once it materializes.
        let latest_seq = 9u64;
        let mut checkpoints: HashMap<CheckpointSequenceNumber, CheckpointData> = HashMap::new();
        for seq in 1..=latest_seq {
            if seq % 3 == 0 {
                continue; // omit → NotFound on fetch
            }
            checkpoints.insert(seq, plain_checkpoint(&committee, &keys, seq));
        }
        let latest = plain_checkpoint(&committee, &keys, latest_seq).checkpoint_summary;
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest_summary_pruned: false,
            latest: latest.clone(),
            checkpoints: checkpoints.clone(),
            eoe_seqs: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(0).unwrap();

        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache.clone(),
            metrics.clone(),
        )
        .await;
        pusher.advance().await.unwrap();

        // The scan folded everything fetchable and advanced to the head; the
        // three missing seqs are pending gaps, not silent losses.
        assert_eq!(cache.processed_head_seq(), latest_seq);
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(latest_seq)
        );
        assert_eq!(metrics.pusher_fetch_failures_total.get(), 3);
        assert_eq!(
            pusher.pending_gaps.keys().copied().collect::<Vec<_>>(),
            vec![3, 6, 9]
        );

        // A tick with the checkpoints still missing keeps them pending (the
        // retry deadline is far away) — nothing is dropped.
        pusher.advance().await.unwrap();
        assert_eq!(pusher.pending_gaps.len(), 3);

        // The missing checkpoints materialize (6 as end-of-epoch); the next
        // tick repairs all three gaps: the committee is installed and the
        // end-of-epoch checkpoint retained.
        checkpoints.insert(3, plain_checkpoint(&committee, &keys, 3));
        checkpoints.insert(6, end_of_epoch_checkpoint(&committee, &keys, 6));
        checkpoints.insert(9, plain_checkpoint(&committee, &keys, 9));
        pusher.transport = Arc::new(MockTransport {
            latest_summary_pruned: false,
            latest,
            checkpoints,
            eoe_seqs: HashMap::new(),
        });
        pusher.advance().await.unwrap();

        assert!(pusher.pending_gaps.is_empty());
        assert_eq!(committees.head_epoch(), 1);
        assert!(
            perpetual
                .get_sui_end_of_epoch_checkpoint(6)
                .unwrap()
                .is_some(),
            "a gap-repaired end-of-epoch checkpoint must be retained"
        );
    }

    /// A mock checkpoint archive serving full checkpoint data from memory,
    /// for the pending-gap archive-fallback tests. The ratchet-facing methods
    /// are never called by the pusher and panic loudly if they ever are.
    struct MockCheckpointArchive {
        checkpoints: HashMap<CheckpointSequenceNumber, CheckpointData>,
    }

    #[async_trait]
    impl CheckpointArchive for MockCheckpointArchive {
        async fn enumerate_end_of_epoch_seqs(
            &self,
        ) -> Result<Vec<CheckpointSequenceNumber>, ika_sui_client::archive::ArchiveError> {
            unimplemented!()
        }
        async fn fetch_checkpoint(
            &self,
            _seq: CheckpointSequenceNumber,
        ) -> Result<
            (
                CertifiedCheckpointSummary,
                sui_types::messages_checkpoint::CheckpointContents,
            ),
            ika_sui_client::archive::ArchiveError,
        > {
            unimplemented!()
        }
        async fn fetch_checkpoint_data(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, ika_sui_client::archive::ArchiveError> {
            self.checkpoints.get(&seq).cloned().ok_or_else(|| {
                ika_sui_client::archive::ArchiveError::Fetch {
                    url: "mock".into(),
                    seq,
                    source: anyhow::anyhow!("seq {seq} not in mock archive"),
                }
            })
        }
    }

    /// A gap checkpoint the fullnode NEVER serves (pruned) is recovered from
    /// the checkpoint archive once the local-materialization grace passes,
    /// folded through the same committee verification (its committee capture
    /// and end-of-epoch retention land), and counted as an archive repair —
    /// instead of being dropped at the deadline (issue #2018).
    #[tokio::test]
    async fn pruned_gap_checkpoint_is_recovered_from_the_archive() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );

        // The fullnode advertises seq 100 but never serves its contents
        // (pruned); only the archive has it — as an end-of-epoch checkpoint so
        // the test can observe the fold's committee capture and retention.
        let eoe = end_of_epoch_checkpoint(&committee, &keys, 100);
        let latest = eoe.checkpoint_summary.clone();
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest_summary_pruned: false,
            latest,
            checkpoints: HashMap::new(),
            eoe_seqs: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache,
            metrics.clone(),
        )
        .await;
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(100u64, eoe)]),
        }));

        pusher.advance().await.unwrap();
        assert!(pusher.pending_gaps.contains_key(&100));

        // Within the local-materialization grace the archive is NOT consulted
        // yet — the fullnode alone is retried.
        pusher.advance().await.unwrap();
        assert!(pusher.pending_gaps.contains_key(&100));
        assert_eq!(metrics.pusher_gap_archive_repairs_total.get(), 0);

        // Age the gap past the grace; the next tick repairs it from the
        // archive.
        pusher.pending_gaps.get_mut(&100).unwrap().first_seen =
            Instant::now() - Duration::from_secs(6);
        pusher.advance().await.unwrap();

        assert!(pusher.pending_gaps.is_empty());
        assert_eq!(metrics.pusher_gap_archive_repairs_total.get(), 1);
        assert_eq!(metrics.pusher_gap_dropped_total.get(), 0);
        assert_eq!(committees.head_epoch(), 1);
        assert!(
            perpetual
                .get_sui_end_of_epoch_checkpoint(100)
                .unwrap()
                .is_some(),
            "an archive-repaired end-of-epoch checkpoint must be retained"
        );
    }

    /// An archive blob whose committee-signed summary is for a DIFFERENT
    /// sequence number than the one requested must NOT clear the gap.
    /// Gap-clearance would otherwise trust the archive's file naming: a
    /// mislabeled-but-genuine blob (or one substituted by a malicious
    /// store) would "repair" the gap vacuously, the real checkpoint's
    /// events would stay lost, and the dropped-gap alarm this fallback
    /// feeds would be suppressed — the issue #2018 loss shape, silently.
    #[tokio::test]
    async fn archive_blob_for_a_different_seq_is_refused() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );

        let latest = plain_checkpoint(&committee, &keys, 100).checkpoint_summary;
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest_summary_pruned: false,
            latest,
            checkpoints: HashMap::new(),
            eoe_seqs: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache,
            metrics.clone(),
        )
        .await;
        // The archive's entry FOR seq 100 is a genuine, correctly-signed
        // end-of-epoch checkpoint — of seq 999.
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(100u64, end_of_epoch_checkpoint(&committee, &keys, 999))]),
        }));

        pusher.advance().await.unwrap();
        assert!(pusher.pending_gaps.contains_key(&100));

        pusher.pending_gaps.get_mut(&100).unwrap().first_seen =
            Instant::now() - Duration::from_secs(6);
        pusher.advance().await.unwrap();

        assert!(
            pusher.pending_gaps.contains_key(&100),
            "a wrong-seq archive blob must not clear the gap"
        );
        assert_eq!(metrics.pusher_gap_archive_repairs_total.get(), 0);
        assert_eq!(
            committees.head_epoch(),
            0,
            "the refused blob's committee transition must not install"
        );
    }

    /// A gap that neither the fullnode nor the archive can serve is dropped
    /// at the retry deadline and counted (`pusher_gap_dropped_total`) — the
    /// loud permanent-loss signal — while a younger co-pending gap stays.
    #[tokio::test]
    async fn gap_missing_from_fullnode_and_archive_is_dropped_at_the_deadline() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );

        let latest = plain_checkpoint(&committee, &keys, 101).checkpoint_summary;
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest_summary_pruned: false,
            latest,
            checkpoints: HashMap::new(),
            eoe_seqs: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache,
            metrics.clone(),
        )
        .await;
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::new(),
        }));

        pusher.advance().await.unwrap();
        assert_eq!(
            pusher.pending_gaps.keys().copied().collect::<Vec<_>>(),
            vec![100, 101]
        );

        // Age seq 100 past the retry deadline; seq 101 stays young.
        pusher.pending_gaps.get_mut(&100).unwrap().first_seen =
            Instant::now() - Duration::from_secs(601);
        pusher.advance().await.unwrap();

        assert_eq!(
            pusher.pending_gaps.keys().copied().collect::<Vec<_>>(),
            vec![101],
            "only the expired gap is dropped"
        );
        assert_eq!(metrics.pusher_gap_dropped_total.get(), 1);
        assert_eq!(metrics.pusher_gap_archive_repairs_total.get(), 0);
    }

    /// The pusher resumes from its persisted cursor across a restart: once
    /// `advance()` has driven the cursor to N and persisted it, a fresh pusher
    /// constructed over the SAME perpetual tables boots at cursor N and, on
    /// construction, seeds the cache's processed head to N (so the reader's
    /// tripwire doesn't fire before the first tick). A second `advance()` with
    /// no new upstream checkpoints is a no-op that leaves the cursor at N.
    #[tokio::test]
    async fn restart_resumes_from_persisted_cursor() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );

        // First run: stream 1..=5 from cursor 0; the cursor lands on 5.
        let latest_seq = 5u64;
        let checkpoints: HashMap<CheckpointSequenceNumber, CheckpointData> = (1..=latest_seq)
            .map(|seq| (seq, plain_checkpoint(&committee, &keys, seq)))
            .collect();
        let latest = plain_checkpoint(&committee, &keys, latest_seq).checkpoint_summary;
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest_summary_pruned: false,
            latest: latest.clone(),
            checkpoints: checkpoints.clone(),
            eoe_seqs: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(0).unwrap();

        let mut first = pusher_over(perpetual.clone(), committees.clone(), transport).await;
        first.advance().await.unwrap();
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(latest_seq)
        );
        drop(first);

        // Restart: a fresh pusher over the SAME perpetual tables resumes at the
        // persisted cursor (5) — it does NOT re-fetch from upstream latest. Its
        // construction seeds the cache's processed head to the resumed cursor.
        let resume_cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let transport2: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest_summary_pruned: false,
            latest,
            checkpoints,
            eoe_seqs: HashMap::new(),
        });
        let mut resumed = pusher_over_with_cache(
            perpetual.clone(),
            committees,
            transport2,
            resume_cache.clone(),
            OcsMetrics::new_for_testing(),
        )
        .await;
        assert_eq!(
            resume_cache.processed_head_seq(),
            latest_seq,
            "a fresh pusher seeds the cache processed head from its resumed cursor"
        );

        // Upstream hasn't advanced past 5, so a second advance is a no-op: the
        // cursor stays at 5 (no re-stream of already-processed checkpoints).
        resumed.advance().await.unwrap();
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(latest_seq)
        );
    }

    /// A non-end-of-epoch, committee-signed summary at `seq` carrying exactly
    /// `commitment` (used to plant a correct or a deliberately-wrong
    /// checkpoint-artifacts digest).
    fn signed_summary_with_commitment(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        commitment: CheckpointCommitment,
    ) -> CertifiedCheckpointSummary {
        let contents = CheckpointContents::new_with_digests_only_for_tests(vec![]);
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: *contents.digest(),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![commitment],
            end_of_epoch_data: None,
            version_specific_data: Vec::new(),
        };
        CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keys, committee)
    }

    /// The modified-objects tree over a single object plus its
    /// `CheckpointArtifactsDigest`, mirroring what the pusher builds from a
    /// fetched checkpoint.
    fn tree_and_digest_over(object: &Object) -> (ModifiedObjectTree, CheckpointArtifactsDigest) {
        let (id, version, digest) = object.compute_object_reference();
        let states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)> =
            std::iter::once((id, (version, digest))).collect();
        let artifacts = CheckpointArtifacts::from_object_states(states);
        let tree = ModifiedObjectTree::new(&artifacts).unwrap();
        let artifacts_digest = artifacts.digest().unwrap();
        (tree, artifacts_digest)
    }

    /// A direct node must never fold state its own fullnode failed to prove
    /// against the committee. A foldable (end-of-epoch) checkpoint whose summary
    /// is signed by the WRONG committee is rejected at fold time: `advance()`
    /// surfaces the error, the committee head does not move, and nothing is
    /// cached. Without the fold-time committee check a compromised fullnode
    /// could seed the cache with forged state that cache-first reads serve
    /// unverified. (The honest counterpart is
    /// `pusher_eagerly_captures_end_of_epoch_committee`, which folds the same
    /// shape when it IS correctly signed.)
    #[tokio::test]
    async fn pusher_refuses_to_fold_a_checkpoint_that_fails_committee_verification() {
        let (committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        // A different committee at the same epoch (0): its authorities are not
        // in the store's committee[0], so any summary it signs fails
        // verification. A different size guarantees a disjoint authority set
        // (the test-committee constructor is deterministic per size).
        let (foreign_committee, foreign_keys) = Committee::new_simple_test_committee_of_size(7);

        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );
        assert_eq!(committees.head_epoch(), 0);

        // An end-of-epoch checkpoint at epoch 0 signed by the foreign committee.
        let forged = end_of_epoch_checkpoint(&foreign_committee, &foreign_keys, 100);
        let latest = forged.checkpoint_summary.clone();
        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest_summary_pruned: false,
            latest,
            checkpoints: HashMap::from([(100u64, forged)]),
            eoe_seqs: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache.clone(),
            OcsMetrics::new_for_testing(),
        )
        .await;

        // The fold-time committee check rejects it: advance() returns the error
        // rather than caching unverified state.
        assert!(
            pusher.advance().await.is_err(),
            "a checkpoint that fails committee verification must not be folded"
        );
        // The committee head never advanced past the unverifiable transition,
        // the cursor stayed put (the error halts it before the cursor write), so
        // a later honest checkpoint at the same seq is reprocessed, and nothing
        // was cached.
        assert_eq!(committees.head_epoch(), 0);
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(99));
        assert!(cache.is_empty());
    }

    /// The second fold-time check: even with a valid committee signature, the
    /// locally-built modified-objects tree must match the committee-signed
    /// checkpoint-artifacts digest before any object is folded — otherwise a
    /// fullnode could serve a genuine summary alongside a forged object tree.
    /// An honest summary (committing to THIS tree's digest) is accepted; one
    /// committing to a different tree's digest is rejected.
    #[tokio::test]
    async fn fold_verify_rejects_an_artifacts_digest_that_does_not_match_the_tree() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            latest_summary_pruned: false,
            latest: end_of_epoch_checkpoint(&committee, &keys, 1).checkpoint_summary,
            checkpoints: HashMap::new(),
            eoe_seqs: HashMap::new(),
        });
        let pusher = pusher_over(perpetual, committees, transport).await;

        // The tree the pusher would build for this checkpoint, and its digest.
        let object = Object::with_id_owner_version_for_testing(
            ObjectID::random(),
            SequenceNumber::from(1),
            Owner::AddressOwner(ObjectID::random().into()),
        );
        let (tree, artifacts_digest) = tree_and_digest_over(&object);

        // Honest: the summary commits to THIS tree's artifacts digest → folds.
        let honest = signed_summary_with_commitment(&committee, &keys, 1, artifacts_digest.into());
        assert!(
            pusher.verify_before_fold(&honest, &tree, true).is_ok(),
            "a summary committing to the matching tree digest must fold"
        );

        // Forged: a valid signature, but the summary commits to a DIFFERENT
        // tree's digest, so the binding to THIS tree fails → rejected.
        let other = Object::with_id_owner_version_for_testing(
            ObjectID::random(),
            SequenceNumber::from(7),
            Owner::AddressOwner(ObjectID::random().into()),
        );
        let (_other_tree, wrong_digest) = tree_and_digest_over(&other);
        let forged = signed_summary_with_commitment(&committee, &keys, 1, wrong_digest.into());
        assert!(
            pusher.verify_before_fold(&forged, &tree, true).is_err(),
            "a summary whose committed digest does not match the folded tree must be rejected"
        );
    }
}
