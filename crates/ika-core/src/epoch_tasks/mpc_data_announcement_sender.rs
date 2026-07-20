// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Producer-side task that drives the off-chain validator-metadata
//! flow during an epoch:
//! 1. Derives the local class-groups mpc_data blob from the root
//!    seed (matches the canonical BCS encoding `derive_mpc_data_blob`
//!    produces) and write-through-caches it via `BlobCache` (perpetual
//!    `mpc_artifact_blobs` + the in-memory store backing the
//!    `GetMpcDataBlob` RPC), so peers can fetch it by hash.
//! 2. Submits a bare (unsigned) `ValidatorMpcDataAnnouncement` for
//!    itself — a current-committee validator is authenticated by the
//!    consensus block author, so no payload signature is needed
//!    (only joiners sign; that path lives in
//!    `joiner_announcement_sender`). Re-submits the same idempotent
//!    announcement each tick until it's confirmed in the per-epoch
//!    table (submit != sequenced).
//! 3. Once the announcement is confirmed AND local blob coverage
//!    meets stake quorum AND `ready_to_finalize` holds (the
//!    next-epoch committee is published and all its members are
//!    covered — locally validated or carry-forward-covered by the
//!    prior epoch's handoff cert — or the announcement deadline
//!    elapsed), submits an `EpochMpcDataReadySignal` (the first
//!    quorum of which freezes the input set). Re-emits with an
//!    incremented `sequence_number` as `validated_peers` grows,
//!    until `is_mpc_data_frozen()`.
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
    build_epoch_mpc_data_ready_signal_transaction, derive_mpc_data_blob, now_ms,
};
use dwallet_rng::RootSeed;
use ika_network::mpc_artifacts::{MpcDataBlobStorage, mpc_data_blob_hash};
use ika_types::committee::{CommitteeMembership, EpochId};
use ika_types::crypto::AuthorityName;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::error::IkaError;
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::validator_metadata::ValidatorMpcDataAnnouncement;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::sync::watch::Receiver;
use tracing::{debug, info, warn};

/// Outcome of the ready-signal emit gate ([`decide_ready_to_finalize`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadyToFinalize {
    /// Don't emit yet — keep waiting (V_{e+1} unpublished, or some of
    /// its members neither validated nor carry-forward-covered, and
    /// the deadline hasn't passed).
    NotYet,
    /// Emit: the next-epoch committee is published and every member is
    /// covered — its blob locally validated, or its digest present in
    /// the prior epoch's handoff cert (the freeze carries such members
    /// forward, so a freeze triggered by these signals loses no one).
    Ready,
    /// Emit because the epoch-clock deadline elapsed, but some
    /// next-epoch members were neither locally validated nor covered
    /// by the prior epoch's handoff cert. They will be absent from
    /// this validator's `validated_peers`, the freeze cannot carry
    /// them forward, and they risk being dropped from the frozen set /
    /// next committee's class-groups map — i.e. a first-time joiner
    /// whose blob never propagated (or a never-alive member). The
    /// missing members are surfaced for an operator warning.
    ReadyViaDeadlineMissing(Vec<AuthorityName>),
}

/// Pure decision for the ready-signal emit gate (see
/// `MpcDataAnnouncementSender::ready_to_finalize`). Extracted so the
/// joiner-inclusion timing rule is unit-testable without an epoch
/// store. Emit once either the next-epoch committee is published and
/// every one of its members is covered — locally validated, or listed
/// in the prior epoch's handoff cert (`prior_cert_members`), which the
/// freeze carries forward deterministically, so waiting for a fresh
/// announcement from such a member buys nothing — or the epoch-clock
/// deadline has passed (liveness backstop) — the latter reports the
/// still-uncovered members so the caller can warn. Only uncovered
/// members (first-time joiners still propagating, or members that have
/// never announced in any epoch) can hold the gate open.
fn decide_ready_to_finalize(
    now_ms: u64,
    deadline_ms: u64,
    next_committee_epoch: u64,
    expected_next_epoch: u64,
    next_members: &[AuthorityName],
    validated_peers: &[AuthorityName],
    prior_cert_members: &HashSet<AuthorityName>,
) -> ReadyToFinalize {
    let validated: HashSet<&AuthorityName> = validated_peers.iter().collect();
    let next_published = next_committee_epoch == expected_next_epoch;
    let missing: Vec<AuthorityName> = if next_published {
        next_members
            .iter()
            .filter(|name| !validated.contains(name) && !prior_cert_members.contains(name))
            .copied()
            .collect()
    } else {
        // V_{e+1} not published yet — treat the whole (unknown) set
        // as missing for deadline-reporting purposes.
        Vec::new()
    };
    if next_published && missing.is_empty() {
        return ReadyToFinalize::Ready;
    }
    if now_ms >= deadline_ms {
        return ReadyToFinalize::ReadyViaDeadlineMissing(missing);
    }
    ReadyToFinalize::NotYet
}

/// Post-publication grace bounds for [`ready_signal_deadline_ms`]:
/// nominally 1/24 of the epoch, floored at 30s so latencies that don't
/// scale with epoch length (P2P round-trips, consensus sequencing,
/// poll ticks) still fit under short epochs, and capped at one hour —
/// announcement propagation takes minutes, so a longer courtesy wait
/// for a member that will never announce is pure reconfiguration-
/// runway loss.
const POST_PUBLICATION_GRACE_MIN_MS: u64 = 30_000;
const POST_PUBLICATION_GRACE_MAX_MS: u64 = 3_600_000;

/// The deadline after which the emit gate stops waiting for uncovered
/// next-epoch members, denominated in the epoch's CONSENSUS clock (max
/// processed `commit_timestamp_ms`) — never machine wall-clock. Pure
/// function so the timing rule is unit-testable.
///
/// `first_commit_ts_ms` anchors the 3/4-epoch liveness backstop at the
/// epoch's first processed consensus commit; `None` (no commit
/// processed yet) means no deadline at all — nothing can be sequenced
/// while no commits flow, so a deadline could not have produced a
/// freeze anyway (fate-sharing: the deadline pauses exactly when the
/// machinery it times is paused). Once V_{e+1} publication has been
/// observed (`next_committee_first_seen_ms`, also recorded off the
/// consensus clock), the wait shrinks to a propagation grace after
/// that observation — a member that is neither validated nor
/// prior-cert-covered by then is either a first-time joiner that
/// failed to propagate or a never-alive member, and holding every
/// validator's ready signal for it until the 3/4 mark would compress
/// the reconfiguration into the last quarter of every epoch (observed
/// live on testnet with two permanently-silent members; issue #1866).
/// The `min` keeps the backstop as a hard upper bound — under short
/// test epochs (where the clamped grace exceeds epoch/4) the deadline
/// stays exactly the 3/4 backstop.
///
/// The clock choice only affects WHEN each validator emits its signal;
/// the freeze snapshot stays a pure function of the consensus-ordered
/// signals. Commit timestamps are leader-proposed and manipulable at
/// seconds scale — immaterial against these hours-scale terms (issue
/// #1868); the epoch store's running max makes the observed clock
/// monotone locally regardless.
fn ready_signal_deadline_ms(
    first_commit_ts_ms: Option<u64>,
    epoch_duration_ms: u64,
    next_committee_first_seen_ms: Option<u64>,
) -> Option<u64> {
    let backstop = first_commit_ts_ms?.saturating_add(epoch_duration_ms / 4 * 3);
    let Some(first_seen_ms) = next_committee_first_seen_ms else {
        return Some(backstop);
    };
    let grace = (epoch_duration_ms / 24)
        .clamp(POST_PUBLICATION_GRACE_MIN_MS, POST_PUBLICATION_GRACE_MAX_MS);
    Some(backstop.min(first_seen_ms.saturating_add(grace)))
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
    /// CHAIN view of the next-epoch committee (members + stake),
    /// published as soon as Sui selects it — *before* the off-chain
    /// class-groups assembly. The ready-signal emit gate waits until
    /// `V_{e+1}` is published here and all its members are locally
    /// validated (or an epoch-clock deadline) before signalling — so
    /// the freeze, which fires on the first quorum of ready signals,
    /// includes next-epoch joiners. Must be the chain committee, NOT
    /// the assembled one: the assembled committee can't `Complete`
    /// until the joiner's mpc_data is in, and the joiner only learns
    /// it's a joiner from this same signal — gating on the assembled
    /// committee would deadlock and the freeze would exclude the joiner.
    next_epoch_committee_receiver: Receiver<CommitteeMembership>,
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
    /// Number of announcement submissions so far this epoch. Used
    /// only to bound logging: the first submission (and every 30th
    /// thereafter, so a sequencing stall still surfaces) logs at
    /// info, re-submissions in between at debug.
    announcement_submit_attempts: AtomicU64,
    /// Consensus-clock ms (the epoch store's max processed commit
    /// timestamp) at which this validator FIRST observed the
    /// next-epoch committee published on the watch channel, or `0`
    /// (sentinel: not yet observed, or observed while no commit had
    /// been processed yet — re-recorded on a later tick). Anchors the
    /// post-publication grace in [`ready_signal_deadline_ms`] —
    /// local-only emit timing, so per-validator skew (including a
    /// reset to the restart-time consensus view after a mid-epoch
    /// restart) is harmless. Making this anchor fleet-identical
    /// (consensus-sequenced publication attestations) is issue #1869.
    next_committee_first_seen_ms: AtomicU64,
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
        next_epoch_committee_receiver: Receiver<CommitteeMembership>,
    ) -> Self {
        Self {
            epoch_store,
            epoch_id,
            authority,
            consensus_adapter,
            blob_cache,
            root_seed,
            next_epoch_committee_receiver,
            cached_announcement: Mutex::new(None),
            last_emitted_validated_peers_count: AtomicUsize::new(0),
            next_sequence_number: std::sync::atomic::AtomicU64::new(0),
            announcement_submit_attempts: AtomicU64::new(0),
            next_committee_first_seen_ms: AtomicU64::new(0),
        }
    }

    pub async fn run(self: Arc<Self>) {
        // Off-chain feature gate. Read once at epoch start — the
        // protocol config is fixed for the epoch, so we don't need
        // to recheck on every loop tick.
        let mut poll_interval = Duration::from_secs(2);
        if let Some(epoch_store) = self.epoch_store.upgrade() {
            use ika_types::sui::epoch_start_system::EpochStartSystemTrait;
            if !epoch_store
                .protocol_config()
                .off_chain_validator_metadata_enabled()
            {
                info!(
                    epoch = self.epoch_id,
                    "off-chain validator metadata disabled by protocol config; task exiting"
                );
                return;
            }
            poll_interval = crate::validator_metadata::epoch_scaled_poll_interval(
                epoch_store.epoch_start_state().epoch_duration_ms(),
                poll_interval,
            );
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

            tokio::time::sleep(poll_interval).await;
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
        let Some(blob) = self.blob_cache.get(&announcement.blob_hash) else {
            // Build-time persist must have failed: the blob isn't in
            // the cache, and re-sending the announcement without its
            // bytes would defeat in-band consensus delivery. Clear the
            // cache to force a rebuild next tick, then retry.
            *self.cached_announcement.lock().expect("mutex poisoned") = None;
            warn!(
                blob_hash = ?announcement.blob_hash,
                "own mpc_data blob absent from cache; rebuilding before announcing"
            );
            return Ok(());
        };
        let tx =
            ConsensusTransaction::new_validator_mpc_data_announcement(announcement.clone(), blob);
        self.consensus_adapter
            .submit_to_consensus(&[tx], &epoch_store)
            .await?;
        // First submission (and every 30th re-submission, so a sequencing
        // stall still surfaces at info) logs at info; the expected
        // re-submit-until-confirmed ticks in between log at debug.
        let attempt = self
            .announcement_submit_attempts
            .fetch_add(1, Ordering::AcqRel);
        if attempt == 0 || attempt.is_multiple_of(30) {
            info!(
                epoch = self.epoch_id,
                blob_hash = ?announcement.blob_hash,
                timestamp_ms = announcement.timestamp_ms,
                attempt,
                "submitted validator mpc data announcement (will re-submit until confirmed)"
            );
        } else {
            debug!(
                epoch = self.epoch_id,
                blob_hash = ?announcement.blob_hash,
                timestamp_ms = announcement.timestamp_ms,
                attempt,
                "re-submitted validator mpc data announcement (not yet confirmed)"
            );
        }
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
        // Restart-safe: if this epoch's table already holds OUR announcement
        // for the same blob (the blob is seed-deterministic, so the digest
        // matching means it's the same announcement), reuse it — timestamp
        // included. Stamping a fresh `now_ms()` after a restart breaks
        // confirmation if the clock regressed (NTP step across the reboot):
        // the table keeps only strictly-newer timestamps, so every
        // re-submission would drop and `announcement_confirmed` (which
        // compares for equality against the cached timestamp) would stay
        // false for the rest of the epoch — withholding our ready signal and
        // re-submitting the full blob to consensus every tick.
        if let Some(epoch_store) = self.epoch_store.upgrade()
            && let Ok(Some(stored)) =
                epoch_store.get_validator_mpc_data_announcement(&self.authority)
            && stored.blob_hash == digest
            && stored.epoch == self.epoch_id
        {
            *self.cached_announcement.lock().expect("mutex poisoned") = Some(stored.clone());
            return Ok(stored);
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
    /// is allowed to capture our attestation set. Ready once either:
    /// - the next-epoch committee is published AND every one of its
    ///   members is covered — blob locally validated, or digest
    ///   present in the prior epoch's handoff cert (the freeze
    ///   carries such members forward, so waiting for them buys
    ///   nothing) — or
    /// - the consensus-clock deadline has passed: the 3/4-epoch
    ///   liveness backstop anchored at the epoch's first consensus
    ///   commit, tightened to a propagation grace after this
    ///   validator first observes V_{e+1} published (see
    ///   `ready_signal_deadline_ms`) — so an uncovered member that
    ///   never announces can't hold every epoch's freeze to the 3/4
    ///   mark (the still-uncovered members are surfaced so the
    ///   caller can warn).
    ///
    /// Every time term is read off the epoch's consensus clock (max
    /// processed commit timestamp) — machine wall-clock is never
    /// consulted, so an NTP-skewed or partitioned validator's gate
    /// pauses with its consensus view instead of deadline-emitting a
    /// stale attestation set mid-catch-up (issue #1868, Part A).
    fn ready_to_finalize(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        validated_peers: &[AuthorityName],
    ) -> ReadyToFinalize {
        use ika_types::sui::epoch_start_system::EpochStartSystemTrait;
        let epoch_start = epoch_store.epoch_start_state();
        // The epoch's consensus clock. `None` (no commit processed yet)
        // disables the deadline terms below; the coverage-based `Ready`
        // path needs no clock at all.
        let consensus_now = epoch_store.max_processed_commit_timestamp_ms();
        // Copy out of the watch borrow before the DB reads below, so
        // the channel's read guard isn't held across them.
        let (next_committee_epoch, next_members) = {
            let next = self.next_epoch_committee_receiver.borrow();
            let members: Vec<AuthorityName> =
                next.voting_rights.iter().map(|(name, _)| *name).collect();
            (next.epoch(), members)
        };
        let next_published = next_committee_epoch == epoch_store.epoch() + 1;
        if next_published && let Some(now) = consensus_now {
            // Record the FIRST observation only (compare-and-swap from
            // the 0 sentinel), so later ticks don't slide the grace
            // anchor forward. Skipped while the consensus clock is
            // unknown (`now` would be the 0 sentinel) — a later tick
            // records it once commits flow.
            let _ = self.next_committee_first_seen_ms.compare_exchange(
                0,
                now,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
        let first_seen = match self.next_committee_first_seen_ms.load(Ordering::Acquire) {
            0 => None,
            first_seen_ms => Some(first_seen_ms),
        };
        // Backstop anchor: the epoch's first processed consensus
        // commit. A read error degrades to "no anchor" (deadline
        // disabled this tick) — emit-timing only, so unlike freeze-
        // commit reads it must not fail the caller.
        let first_commit_ts = match epoch_store.epoch_first_commit_timestamp_ms() {
            Ok(first_commit_ts) => first_commit_ts,
            Err(err) => {
                debug!(
                    error = ?err,
                    "failed to read the epoch's first-commit timestamp for the \
                     ready-signal emit gate; deadline disabled this tick"
                );
                None
            }
        };
        let deadline =
            ready_signal_deadline_ms(first_commit_ts, epoch_start.epoch_duration_ms(), first_seen);
        // Members covered by the prior epoch's handoff cert cannot be
        // dropped by the freeze (carry-forward re-freezes them at the
        // prior-cert digest), so they must not hold the gate. A read
        // error degrades to "no coverage" — strictly the pre-carry-
        // forward wait, never an early emit — and this read is
        // emit-timing only, so unlike the freeze-time read in
        // `freeze_mpc_data_if_first` it must NOT fail the caller.
        let prior_cert_members: HashSet<AuthorityName> =
            match epoch_store.prior_epoch_mpc_data_digests() {
                Ok(digests) => digests.into_keys().collect(),
                Err(err) => {
                    debug!(
                        error = ?err,
                        "failed to read prior-epoch handoff cert for the ready-signal emit \
                         gate; treating all next-epoch members as requiring fresh validation"
                    );
                    HashSet::new()
                }
            };
        // Translate the Options at the pure-function boundary: an
        // unknown consensus clock (0) can never reach a real deadline,
        // and an absent deadline (u64::MAX) is never reached — both
        // collapse to "the deadline terms are inert; only coverage can
        // make us Ready".
        decide_ready_to_finalize(
            consensus_now.unwrap_or(0),
            deadline.unwrap_or(u64::MAX),
            next_committee_epoch,
            epoch_store.epoch() + 1,
            &next_members,
            validated_peers,
            &prior_cert_members,
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
        // Carry the blob hash we validated for each peer, so the
        // freeze tally is a pure function of consensus signals (the
        // `(peer, hash)` pairs) rather than each validator's local
        // announcement table. Our own hash (for the optimistic
        // self-insert before our announcement lands in the table)
        // comes from the announcement the producer built + persisted.
        let self_blob_hash = self.cached_or_build_announcement()?.blob_hash;
        let validated_peers = epoch_store
            .validated_peers_with_hashes(self_blob_hash)
            .map_err(DwalletMPCError::IkaError)?;
        let validated_names: Vec<AuthorityName> =
            validated_peers.iter().map(|(name, _)| *name).collect();
        // Defer the ready signal until the next-epoch committee is
        // known and all its members are covered — locally validated,
        // or carried forward from the prior epoch's handoff cert (or
        // the announcement deadline elapses). The freeze fires on the
        // first quorum of ready signals, so withholding here is what
        // lets joiners — who announce only after `V_{e+1}` is
        // published, mid-epoch — make it into the frozen set, the
        // next committee's class-groups map, and the handoff cert.
        // The deadline (consensus-clock) only affects WHEN each
        // validator emits; the freeze snapshot itself is still computed
        // deterministically at the consensus-ordered quorum point.
        let deadline_missing = match self.ready_to_finalize(&epoch_store, &validated_names) {
            ReadyToFinalize::NotYet => {
                debug!(
                    epoch = self.epoch_id,
                    "deferring EpochMpcDataReadySignal: \
                     next-epoch committee not yet fully validated"
                );
                return Ok(());
            }
            ReadyToFinalize::Ready => Vec::new(),
            // Liveness backstop fired: we're emitting without having
            // validated every next-epoch member. The operator warn is
            // emitted AFTER the re-emit gate below, so it fires only on
            // ticks that actually emit a signal with missing members —
            // not on every post-deadline poll tick.
            ReadyToFinalize::ReadyViaDeadlineMissing(missing) => missing,
        };
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
        if !deadline_missing.is_empty() {
            // The signal just emitted omits next-epoch members that are
            // neither validated nor prior-cert-covered; the freeze
            // cannot carry them forward, so they risk exclusion from
            // the frozen set / next committee's class-groups map — a
            // first-time joiner whose blob never propagated, or a
            // member that has never announced in any epoch. Surface
            // loudly, naming them, so operators can chase or unstake
            // them. (Members the prior cert covers are deliberately NOT
            // listed here — carry-forward keeps them in the frozen set,
            // so naming them would be a false exclusion alarm.)
            // Bounded: fires only on actual emissions (the validated set
            // strictly grows, so at most committee-size lines per epoch).
            warn!(
                epoch = self.epoch_id,
                missing_count = deadline_missing.len(),
                missing = ?deadline_missing,
                "emitted EpochMpcDataReadySignal at the announcement deadline with \
                 next-epoch members that never announced and have no prior-epoch \
                 handoff-cert coverage — they will be excluded from the next \
                 committee's working set"
            );
        }
        info!(
            epoch = self.epoch_id,
            sequence_number,
            validated_peers_count = new_count,
            prev_count,
            "submitted EpochMpcDataReadySignal"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
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
        // Minimal next-epoch committee membership; the idempotency test
        // never reads it (it exercises `cached_or_build_announcement`).
        let member = name(1);
        let next_committee = CommitteeMembership {
            epoch: 6,
            voting_rights: vec![(member, 1u64)],
            quorum_threshold: 1,
            validity_threshold: 1,
        };
        let (_ntx, next_rx) = tokio::sync::watch::channel(next_committee);
        MpcDataAnnouncementSender::new(
            Weak::new(),
            5,
            AuthorityName::new([9; 48]),
            Arc::new(NoopAdapter),
            blob_cache,
            RootSeed::new([4; 32]),
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
        let no_prior_cert = HashSet::new();
        // Before V_{e+1} is published (next epoch shows current=5,
        // not 6): not ready, even with everything validated.
        assert_eq!(
            decide_ready_to_finalize(100, 1000, 5, 6, &[a, b], &[a, b], &no_prior_cert),
            ReadyToFinalize::NotYet
        );
        // V_{e+1} published (epoch 6) but the joiner isn't validated
        // yet: not ready.
        assert_eq!(
            decide_ready_to_finalize(100, 1000, 6, 6, &[a, b, joiner], &[a, b], &no_prior_cert),
            ReadyToFinalize::NotYet
        );
        // V_{e+1} published AND all its members validated: ready.
        assert_eq!(
            decide_ready_to_finalize(
                100,
                1000,
                6,
                6,
                &[a, b, joiner],
                &[a, b, joiner],
                &no_prior_cert
            ),
            ReadyToFinalize::Ready
        );
    }

    #[test]
    fn ready_to_finalize_deadline_forces_emit_and_reports_missing() {
        let a = name(1);
        let joiner = name(3);
        let no_prior_cert = HashSet::new();
        // Past the deadline, V_{e+1} not yet published: emit via the
        // backstop (no members known to report missing).
        assert_eq!(
            decide_ready_to_finalize(1000, 1000, 5, 6, &[a, joiner], &[a], &no_prior_cert),
            ReadyToFinalize::ReadyViaDeadlineMissing(vec![])
        );
        // Past the deadline, V_{e+1} published but the joiner never
        // got validated: emit via the backstop AND report the joiner
        // as missing so the producer warns.
        assert_eq!(
            decide_ready_to_finalize(2000, 1000, 6, 6, &[a, joiner], &[a], &no_prior_cert),
            ReadyToFinalize::ReadyViaDeadlineMissing(vec![joiner])
        );
    }

    /// A member with a prior-epoch handoff-cert digest can never be
    /// dropped by the freeze (carry-forward re-freezes it), so it must
    /// not hold the emit gate: with the down member cert-covered, the
    /// gate is `Ready` as soon as everyone else validates — no waiting
    /// for the announcement deadline. This is the every-epoch-latency
    /// fix from issue #1866: a dark-but-previously-frozen member no
    /// longer forces the whole network onto the deadline path.
    #[test]
    fn prior_cert_covered_member_does_not_hold_the_gate() {
        let a = name(1);
        let b = name(2);
        let down = name(3);
        let prior_cert: HashSet<AuthorityName> = [down].into_iter().collect();
        // Well before the deadline (100 < 1000), `down` unvalidated but
        // cert-covered: Ready.
        assert_eq!(
            decide_ready_to_finalize(100, 1000, 6, 6, &[a, b, down], &[a, b], &prior_cert),
            ReadyToFinalize::Ready
        );
        // Coverage requires publication regardless: same set, V_{e+1}
        // not yet published -> NotYet.
        assert_eq!(
            decide_ready_to_finalize(100, 1000, 5, 6, &[a, b, down], &[a, b], &prior_cert),
            ReadyToFinalize::NotYet
        );
    }

    /// At the deadline, only members that are neither validated nor
    /// cert-covered are reported missing: naming a carry-forward-
    /// covered member would be a false exclusion alarm (this is the
    /// misleading warn observed in issue #1866's fact 4).
    #[test]
    fn deadline_reports_only_uncovered_members() {
        let a = name(1);
        let down = name(2);
        let never_alive = name(3);
        let prior_cert: HashSet<AuthorityName> = [down].into_iter().collect();
        // Before the deadline the uncovered member still holds the gate.
        assert_eq!(
            decide_ready_to_finalize(100, 1000, 6, 6, &[a, down, never_alive], &[a], &prior_cert),
            ReadyToFinalize::NotYet
        );
        // At the deadline, only the uncovered member is reported.
        assert_eq!(
            decide_ready_to_finalize(1000, 1000, 6, 6, &[a, down, never_alive], &[a], &prior_cert),
            ReadyToFinalize::ReadyViaDeadlineMissing(vec![never_alive])
        );
    }

    /// The deadline formula, all terms on the consensus clock: no
    /// deadline before the epoch's first commit; then the 3/4-epoch
    /// backstop anchored at that commit until V_{e+1} is observed
    /// published; then min(backstop, first-observed + grace) with
    /// grace = epoch/24 clamped to [30s, 1h]. The min means the
    /// publication term can only fire the gate EARLIER than the
    /// backstop, and short test epochs keep the 3/4 behavior exactly.
    #[test]
    fn ready_signal_deadline_tracks_publication_with_clamped_grace() {
        const HOUR_MS: u64 = 3_600_000;
        // No consensus commit processed yet: no deadline at all —
        // nothing can be sequenced, so a deadline could do nothing.
        assert_eq!(ready_signal_deadline_ms(None, 24 * HOUR_MS, None), None);
        assert_eq!(
            ready_signal_deadline_ms(None, 24 * HOUR_MS, Some(12 * HOUR_MS)),
            None
        );
        // Publication not yet observed: the 3/4 backstop.
        assert_eq!(
            ready_signal_deadline_ms(Some(0), 24 * HOUR_MS, None),
            Some(18 * HOUR_MS)
        );
        // 24h epoch, published at mid-epoch: grace = 24h/24 = 1h, so
        // the deadline is 13h — well before the 18h backstop.
        assert_eq!(
            ready_signal_deadline_ms(Some(0), 24 * HOUR_MS, Some(12 * HOUR_MS)),
            Some(13 * HOUR_MS)
        );
        // Publication observed very late: the backstop still caps it.
        assert_eq!(
            ready_signal_deadline_ms(Some(0), 24 * HOUR_MS, Some(HOUR_MS + 18 * HOUR_MS)),
            Some(18 * HOUR_MS)
        );
        // 10s test epoch, published at mid-epoch: grace clamps up to
        // 30s which overshoots the epoch, so the 7.5s backstop wins —
        // identical to the pre-change behavior for short epochs.
        assert_eq!(
            ready_signal_deadline_ms(Some(0), 10_000, Some(5_000)),
            Some(7_500)
        );
        // 5min epoch, published at mid-epoch: grace clamps up to 30s;
        // 150s + 30s = 180s beats the 225s backstop.
        assert_eq!(
            ready_signal_deadline_ms(Some(0), 300_000, Some(150_000)),
            Some(180_000)
        );
        // 7-day epoch: grace caps at 1h rather than 7h.
        let week = 7 * 24 * HOUR_MS;
        assert_eq!(
            ready_signal_deadline_ms(Some(0), week, Some(84 * HOUR_MS)),
            Some(85 * HOUR_MS)
        );
        // A non-zero first-commit anchor shifts the backstop.
        assert_eq!(
            ready_signal_deadline_ms(Some(1_000_000), 24 * HOUR_MS, None),
            Some(1_000_000 + 18 * HOUR_MS)
        );
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
        // The blob does not participate in the consensus key (the key
        // authenticates `sender == announcement.validator`), so an empty blob
        // suffices to exercise the idempotence the test asserts.
        let key_first =
            ConsensusTransaction::new_validator_mpc_data_announcement(first, vec![]).key();
        let key_second =
            ConsensusTransaction::new_validator_mpc_data_announcement(second, vec![]).key();
        assert_eq!(key_first, key_second);
    }
}
