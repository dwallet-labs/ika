// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! A `sui-state-direct` node's fallback for an object it cannot prove itself:
//! read it the way a `sui-state-mirrored` node reads everything — over the
//! existing `SuiStateMirror` relay surface, from the direct peers it is
//! connected to — and keep it only after every check a mirrored node applies
//! to a relayed object, plus a currency check against this node's own
//! fullnode.
//!
//! # When
//!
//! A direct node proves an object from its own fullnode: the checkpoint that
//! wrote the object's current version, or its verified cache's snapshot at
//! exactly that reference (`recover_pruned_proof`). When the fullnode has
//! pruned that checkpoint and the cache has no such snapshot, the node's own
//! proof provider answers `NotFound`. In the mainnet epoch-463 incident a
//! direct node that never folded the `System` anchor's checkpoint hung at the
//! `verified_system_inner` boot barrier on exactly that `NotFound`. A direct
//! peer whose cache still holds a snapshot at that reference can prove the
//! object, and its proof provider serves it from that snapshot. A peer on a
//! binary that pins the anchors' snapshots keeps them; a peer on an older
//! binary (v1.4.x does not pin them) only while its cache still holds the
//! snapshot.
//!
//! There is one trigger: the direct reader's `NotFound` arm on a
//! single-object read (`OcsVerifiedReader::verified_object`, which the bag
//! walk also uses for the children it could not prove, and the anchor reads).
//! Batch reads and the relay requests this node serves never fall back.
//!
//! Not every `NotFound` means a pruned checkpoint: an object written moments
//! ago whose transaction the fullnode has not indexed yet answers the same for
//! a few seconds. So the fallback asks peers only for an object that is
//! stuck: this node's own provider has answered `NotFound` for it for at least
//! `stuck_after`, with no read proving it in between (a single read, or a bag
//! page proving it as a child). A gap of `stuck_reset` without a `NotFound`
//! for it starts that clock over.
//!
//! The fallback never delays a read that has something to serve, and never a
//! read other than an anchor's:
//!
//! - With a cached snapshot (one older than the fullnode's current reference,
//!   or the provider would have proved it), the reader serves the snapshot at
//!   once, as it did without the fallback, and the fallback fetches the
//!   current version in the background.
//! - With nothing cached, a non-anchor read (a bag walk's child included)
//!   fails at once as before, and the fallback fills the cache in the
//!   background: a later read is a cache hit.
//! - Only an anchor read with nothing cached — the boot barrier, which retries
//!   until it succeeds — waits for the attempt, at most `attempt_timeout`: the
//!   deadline covers the whole attempt, this node's own fullnode lookup
//!   included.
//!
//! On a fresh node that needs the fallback for an anchor, the barrier's read
//! is answered at the executor's first retry at least `stuck_after` after the
//! anchor's first `NotFound`: about 31 s with its backoff (1, 2, 4, 8, 16, then
//! 30 s). The anchors are read one after another, and the `System` inner only
//! once the outer is served, so it comes at about 61 s, and the
//! `DWalletCoordinator` pair, if it needs the fallback too, about a minute
//! later. Asking also waits for the pusher's first observed advance of this
//! node's fullnode (below).
//!
//! # Verification parity
//!
//! Each peer's answer goes through an [`OcsVerifiedReader`] configured as a
//! mirrored node configures its own (relay provider, `cache_first` off), over
//! that one peer, so it passes the code a mirrored node runs on a relayed
//! object (`verify_response`):
//!
//! - the response carries the requested id;
//! - the summary is BLS-verified against the committee of its epoch from this
//!   node's `CommitteeStore`;
//! - the inclusion proof's tree root reproduces the summary's committed
//!   artifacts digest, and the object's full reference is a leaf under it.
//!
//! The rest of `verify_response` does nothing in that reader: it has no
//! freshness bound (direct reads have none either), its high-water starts
//! empty, and `check_currency` has no changeset index to consult, as on every
//! direct read. Currency comes from this node's fullnode instead (below), and
//! the direct reader applies its own high-water when it serves the object.
//!
//! # Currency
//!
//! A mirrored node proves currency from its committee-signed changeset index,
//! and gets no verdict (`Unknown`, accepted) for an anchor below that index's
//! window. A direct node's currency source is its own fullnode, as it is for
//! every read it serves: the cache folds that fullnode's checkpoints, the proof
//! provider proves the object that fullnode reports, and `recover_pruned_proof`
//! and the archive backfill reuse a snapshot only at that fullnode's exact
//! current reference. The fallback applies the same rule: a peer's object is
//! accepted only if its reference equals the one this node's fullnode reports
//! now, else `NotCurrent`. A rolled-back version (older), a deleted object (the
//! fullnode reports none, so no peer is asked) and a version this node's
//! fullnode has not reached yet (newer) are all refused, whatever the peer's
//! proof says. Unlike the index, the check has no window: it also refuses a
//! rollback of an anchor older than any changeset retention, which is exactly
//! the population this fallback serves. It trusts the fullnode for nothing a
//! direct node does not already trust it for.
//!
//! # Afterwards
//!
//! An accepted answer is written into this node's verified cache like any
//! network-verified read (`absorb_shadow_entries`: in memory, not persisted;
//! the pusher's folds supersede it). The direct reader serves it from there,
//! under its own high-water, so it never serves below a version it already
//! served. This node's proof provider serves relay requests from the same
//! cache, so the node now also serves a peer-originated snapshot — verified,
//! at its own fullnode's exact current reference — onward to its peers through
//! `recover_pruned_proof`.
//!
//! # A live fullnode first
//!
//! The currency check is only as current as the fullnode. The fallback asks
//! peers only once the checkpoint pusher has seen this node's fullnode advance
//! at least once since the process started
//! (`IkaCheckpointPusher::upstream_advanced`), and not while the pusher reports
//! it frozen (`IkaCheckpointPusher::upstream_frozen`: no advance for
//! `UPSTREAM_FROZEN_AFTER`). The frozen report needs that long to speak, so on
//! its own it would let a fullnode that was already stuck at start through for
//! the first minutes; requiring an advance closes that window. Until the
//! pusher's state is attached ([`PeerFallback::attach_upstream`]), nobody is
//! asked. If the pusher task stops, both watches keep their last values.
//!
//! # Bounds
//!
//! A few attempts at once, counted separately for the reads that wait and the
//! background ones, so background fills never starve the boot barrier; one
//! attempt per object at a time; a deadline per peer and one for the whole
//! attempt; at most `max_peers` peers per attempt; no new attempt for an object
//! within `retry_after` of one that failed; and at most `max_tracked` objects
//! tracked at once — while that many are, a new object a read does not wait
//! for is not tried. A read that waits is exempt: only the singleton anchors
//! read that way, so a table full of bag children never keeps the boot
//! barrier from its fallback, and the exemption adds at most those few
//! entries.
//!
//! # Signals
//!
//! `ika_ocs_direct_peer_fallback_total{outcome}` counts each attempt by how it
//! ended, and, as `skipped_*`, each read that was due an attempt but did not
//! get one — reads, not attempts: a bag walk re-reads a child every few
//! milliseconds, so alert on the attempt outcomes. The readers and relay clients an attempt uses report into metrics
//! of their own that nothing exports, so a peer's answer moves none of the
//! node's relay or verification metrics. One log line per attempt; per-peer
//! detail is at debug.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures::future::BoxFuture;
use ika_network::proof_provider::{ProofProviderMetrics, VerifiedObjectEntry};
use ika_network::sui_state_mirror::{SuiMirrorPeers, SuiMirrorProofProvider};
use ika_sui_client::transport::{SuiTransport, TransportError};
use parking_lot::Mutex;
use prometheus::Registry;
use rand::seq::SliceRandom;
use sui_types::base_types::ObjectID;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::sui_connector::committee_store::CommitteeStore;
use crate::sui_connector::ocs_metrics::OcsMetrics;
use crate::sui_connector::push_worker::IkaCheckpointPusher;
use crate::sui_connector::verified_reader::{OcsVerifiedReader, ReaderError};
use crate::sui_connector::verified_state_cache::{
    SharedVerifiedStateCache, VerifiedSnapshot, VerifiedStateCache,
};

/// The limits on the fallback. `Default` is production; tests shrink them.
#[derive(Clone, Debug)]
pub struct FallbackBounds {
    /// Attempts running at once, per lane: the reads that wait for one, and
    /// the background ones. A due attempt past it is skipped (`skipped_busy`).
    pub max_concurrent: usize,
    /// Peers asked per attempt, in random order, one at a time.
    pub max_peers: usize,
    /// Deadline of one peer's answer. A relay read is one proof build on the
    /// serving side, so this only has to outlast a round trip and that build.
    pub peer_timeout: Duration,
    /// Deadline of a whole attempt, across every peer it asks: an anchor read
    /// waits for its attempt, so peers that accept a request and never answer
    /// must not hold it for `max_peers * peer_timeout`.
    pub attempt_timeout: Duration,
    /// How long this node's own provider must have answered `NotFound` for an
    /// object before peers are asked for it: well past the seconds a fullnode
    /// takes to index a just-written object's transaction.
    pub stuck_after: Duration,
    /// A gap this long without a `NotFound` for an object starts its
    /// `stuck_after` clock over. Longer than the slowest retry of a read that
    /// keeps failing (the executor's anchor reads back off to 30 s).
    pub stuck_reset: Duration,
    /// An object whose attempt failed is not tried again before this has
    /// passed.
    pub retry_after: Duration,
    /// Objects tracked at once. While that many are, after forgetting the ones
    /// that are idle, a new object is not tried (`skipped_tracked_full`).
    pub max_tracked: usize,
}

impl Default for FallbackBounds {
    fn default() -> Self {
        Self {
            max_concurrent: 2,
            max_peers: 16,
            peer_timeout: Duration::from_secs(5),
            attempt_timeout: Duration::from_secs(15),
            stuck_after: Duration::from_secs(20),
            stuck_reset: Duration::from_secs(60),
            retry_after: Duration::from_secs(30),
            max_tracked: 1_024,
        }
    }
}

/// What the checkpoint pusher reports about this node's own fullnode. Taken
/// from the pusher before `run` consumes it ([`Self::of`]).
pub struct PusherUpstream {
    /// `IkaCheckpointPusher::upstream_advanced`.
    advanced: watch::Receiver<bool>,
    /// `IkaCheckpointPusher::upstream_frozen`.
    frozen: watch::Receiver<bool>,
}

impl PusherUpstream {
    pub fn of(pusher: &IkaCheckpointPusher) -> Self {
        Self {
            advanced: pusher.upstream_advanced(),
            frozen: pusher.upstream_frozen(),
        }
    }

    #[cfg(test)]
    fn from_watches(advanced: watch::Receiver<bool>, frozen: watch::Receiver<bool>) -> Self {
        Self { advanced, frozen }
    }

    /// Why the fullnode's current reference cannot be trusted now, if so.
    fn distrust(&self) -> Option<Skip> {
        if *self.frozen.borrow() {
            Some(Skip::Frozen)
        } else if !*self.advanced.borrow() {
            Some(Skip::Unconfirmed)
        } else {
            None
        }
    }
}

/// How an attempt ended; its `outcome` label of
/// `ika_ocs_direct_peer_fallback_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// A peer's answer passed every check and is in the cache.
    Served,
    /// Some peer's answer was authentic but not this node's fullnode's current
    /// reference, and none was acceptable.
    NotCurrent,
    /// Some peer's answer failed verification, and none was acceptable.
    Unverified,
    /// No peer served the object (none serves the relay, none could prove it,
    /// or none answered in time).
    Unavailable,
    /// The fullnode no longer reports the object: nothing to ask for.
    NotLive,
    /// The fullnode could not say what the object's current reference is.
    FullnodeError,
    /// The attempt reached `attempt_timeout` before it could end otherwise:
    /// this node's own fullnode did not answer in time.
    TimedOut,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::NotCurrent => "not_current",
            Self::Unverified => "unverified",
            Self::Unavailable => "unavailable",
            Self::NotLive => "not_live",
            Self::FullnodeError => "fullnode_error",
            Self::TimedOut => "timed_out",
        }
    }
}

/// Why a read's `NotFound` started no attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Skip {
    /// Not stuck (yet): its own provider has not answered `NotFound` for it
    /// for `stuck_after`.
    NotStuck,
    /// An attempt for it is running.
    InFlight,
    /// Its last attempt failed less than `retry_after` ago.
    RetryWait,
    /// `max_tracked` other objects are tracked.
    TrackedFull,
    /// The p2p network is not attached yet.
    NoNetwork,
    /// The pusher has not seen this node's fullnode advance since start, or
    /// its state is not attached yet.
    Unconfirmed,
    /// The pusher reports this node's fullnode frozen.
    Frozen,
    /// The lane's concurrency cap is reached.
    Busy,
}

impl Skip {
    /// The `outcome` label it is counted under; `None` when the object is not
    /// due an attempt at all.
    fn label(self) -> Option<&'static str> {
        match self {
            Self::NotStuck | Self::InFlight => None,
            Self::RetryWait => Some("skipped_retry_wait"),
            Self::TrackedFull => Some("skipped_tracked_full"),
            Self::NoNetwork => Some("skipped_no_network"),
            Self::Unconfirmed => Some("skipped_unconfirmed"),
            Self::Frozen => Some("skipped_frozen"),
            Self::Busy => Some("skipped_busy"),
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::NotStuck => "this node's own provider has not failed to prove it for long enough",
            Self::InFlight => "an attempt for it is running",
            Self::RetryWait => "its last attempt failed recently",
            Self::TrackedFull => "too many objects are tracked",
            Self::NoNetwork => "the p2p network is not attached yet",
            Self::Unconfirmed => {
                "this node's own Sui fullnode has not been seen advancing since start"
            }
            Self::Frozen => "this node's own Sui fullnode is frozen",
            Self::Busy => "the concurrency cap is reached",
        }
    }
}

/// One object whose own provider answered `NotFound`.
struct Tracked {
    /// The first `NotFound` of the current stretch.
    stuck_since: Instant,
    /// The latest `NotFound`.
    last_not_found: Instant,
    /// An attempt for it is running.
    in_flight: bool,
    /// After a failed attempt: no new one before this.
    retry_at: Option<Instant>,
}

impl Tracked {
    /// Nothing about it needs remembering: no attempt running or waiting to be
    /// retried, and its stuck clock would start over anyway.
    fn idle(&self, now: Instant, bounds: &FallbackBounds) -> bool {
        !self.in_flight
            && self.retry_at.is_none_or(|at| now >= at)
            && now.saturating_duration_since(self.last_not_found) > bounds.stuck_reset
    }
}

/// Which attempts a read starts, and which concurrency cap they count against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
    /// A read that waits for its attempt: an anchor read with nothing cached.
    /// Exempt from `max_tracked`, so a table full of other objects (bag
    /// children re-walked every few milliseconds are never idle) can never
    /// keep the boot barrier from its fallback. Only the singleton anchors
    /// read this way, so this adds at most those few entries.
    Waiting,
    /// A read that does not wait.
    Background,
}

/// An attempt allowed to start: the network to ask over and its lane's permit,
/// held until it ends.
struct Admitted {
    network: anemo::Network,
    _permit: OwnedSemaphorePermit,
}

/// Settles an attempt's tracking however its task ends — a panic included, so
/// an object can never stay "in flight" forever.
struct Settle<'a> {
    fallback: &'a PeerFallback,
    id: ObjectID,
    served: bool,
}

impl Drop for Settle<'_> {
    fn drop(&mut self) {
        let mut tracked = self.fallback.tracked.lock();
        if self.served {
            tracked.remove(&self.id);
        } else if let Some(entry) = tracked.get_mut(&self.id) {
            entry.in_flight = false;
            entry.retry_at = Some(Instant::now() + self.fallback.bounds.retry_after);
        }
    }
}

/// See the module docs. Built with the connector stack on a direct node; the
/// p2p network ([`Self::attach_network`]) and the pusher's state
/// ([`Self::attach_upstream`]) are attached once they exist.
pub struct PeerFallback {
    /// This node's own fullnode: the object's current reference.
    fullnode: Arc<dyn SuiTransport>,
    committees: Arc<CommitteeStore>,
    /// This node's verified cache, which an accepted answer is written into.
    cache: SharedVerifiedStateCache,
    network: OnceLock<anemo::Network>,
    upstream: OnceLock<PusherUpstream>,
    bounds: FallbackBounds,
    /// Permits of the attempts a read waits for.
    waiting: Arc<Semaphore>,
    /// Permits of the background attempts.
    background: Arc<Semaphore>,
    tracked: Mutex<HashMap<ObjectID, Tracked>>,
    metrics: Arc<OcsMetrics>,
    /// The per-peer readers' and relay clients' own metrics, on a registry
    /// nothing exports.
    scratch_metrics: Arc<OcsMetrics>,
    scratch_provider_metrics: Arc<ProofProviderMetrics>,
}

impl PeerFallback {
    pub fn new(
        fullnode: Arc<dyn SuiTransport>,
        committees: Arc<CommitteeStore>,
        cache: SharedVerifiedStateCache,
        bounds: FallbackBounds,
        metrics: Arc<OcsMetrics>,
    ) -> Self {
        let scratch = Registry::new();
        Self {
            fullnode,
            committees,
            cache,
            network: OnceLock::new(),
            upstream: OnceLock::new(),
            waiting: Arc::new(Semaphore::new(bounds.max_concurrent)),
            background: Arc::new(Semaphore::new(bounds.max_concurrent)),
            bounds,
            tracked: Mutex::new(HashMap::new()),
            metrics,
            scratch_metrics: OcsMetrics::new(&scratch),
            scratch_provider_metrics: ProofProviderMetrics::new(&scratch),
        }
    }

    /// Attach the p2p network the peers are asked over, once it is up.
    pub fn attach_network(&self, network: anemo::Network) {
        if self.network.set(network).is_err() {
            debug!("peer fallback: network already attached");
        }
    }

    /// Attach the checkpoint pusher's report on this node's own fullnode, once
    /// the pusher is built.
    pub fn attach_upstream(&self, upstream: PusherUpstream) {
        if self.upstream.set(upstream).is_err() {
            debug!("peer fallback: upstream state already attached");
        }
    }

    /// The direct reader's own provider answered `NotFound` for `id` and it
    /// has nothing cached to serve, on a read that waits (an anchor's): run
    /// an attempt if one is due and wait for it. `Ok` means the current
    /// version is now in the cache.
    pub async fn fill(self: &Arc<Self>, id: ObjectID) -> Result<(), ReaderError> {
        let admitted = self
            .admit(id, Lane::Waiting)
            .map_err(|skip| self.refuse(id, skip))?;
        // Its own task, so a caller that stops waiting leaves the attempt to
        // finish and settle. The attempt ends by `attempt_timeout`, so this
        // wait does too.
        tokio::spawn(self.clone().run(id, admitted))
            .await
            .unwrap_or_else(|e| {
                Err(ReaderError::Transport(TransportError::NotFound(format!(
                    "peer fallback for {id} ended without an answer: {e}"
                ))))
            })
    }

    /// The same `NotFound`, on a read that does not wait: start an attempt in
    /// the background if one is due.
    pub fn refresh_in_background(self: &Arc<Self>, id: ObjectID) {
        match self.admit(id, Lane::Background) {
            Ok(admitted) => {
                tokio::spawn(self.clone().run(id, admitted));
            }
            Err(skip) => {
                self.refuse(id, skip);
            }
        }
    }

    /// This node's own provider proved `ids`: none of them is stuck. One lock
    /// for all, so a bag page's children cost one call.
    pub fn note_proved(&self, ids: impl IntoIterator<Item = ObjectID>) {
        let mut tracked = self.tracked.lock();
        if tracked.is_empty() {
            return;
        }
        for id in ids {
            if tracked.get(&id).is_some_and(|entry| !entry.in_flight) {
                tracked.remove(&id);
            }
        }
    }

    /// Note a `NotFound` for `id` and decide whether it starts an attempt.
    fn admit(&self, id: ObjectID, lane: Lane) -> Result<Admitted, Skip> {
        let now = Instant::now();
        let mut tracked = self.tracked.lock();
        if lane == Lane::Background
            && !tracked.contains_key(&id)
            && tracked.len() >= self.bounds.max_tracked
        {
            tracked.retain(|_, entry| !entry.idle(now, &self.bounds));
            if tracked.len() >= self.bounds.max_tracked {
                return Err(Skip::TrackedFull);
            }
        }
        let entry = tracked.entry(id).or_insert(Tracked {
            stuck_since: now,
            last_not_found: now,
            in_flight: false,
            retry_at: None,
        });
        if now.saturating_duration_since(entry.last_not_found) > self.bounds.stuck_reset {
            entry.stuck_since = now;
        }
        entry.last_not_found = now;
        if entry.in_flight {
            return Err(Skip::InFlight);
        }
        if entry.retry_at.is_some_and(|at| now < at) {
            return Err(Skip::RetryWait);
        }
        if now.saturating_duration_since(entry.stuck_since) < self.bounds.stuck_after {
            return Err(Skip::NotStuck);
        }
        let Some(network) = self.network.get() else {
            return Err(Skip::NoNetwork);
        };
        // The currency check compares a peer's answer with what this node's
        // fullnode reports now, so that fullnode must be live: a stuck one
        // reports a past state, and a genuine old version would match it.
        if let Some(skip) = self
            .upstream
            .get()
            .map_or(Some(Skip::Unconfirmed), PusherUpstream::distrust)
        {
            return Err(skip);
        }
        let permits = match lane {
            Lane::Waiting => &self.waiting,
            Lane::Background => &self.background,
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            return Err(Skip::Busy);
        };
        entry.in_flight = true;
        Ok(Admitted {
            network: network.clone(),
            _permit: permit,
        })
    }

    /// Count a refused read and turn it into the read's error.
    fn refuse(&self, id: ObjectID, skip: Skip) -> ReaderError {
        if let Some(label) = skip.label() {
            self.metrics
                .direct_peer_fallback_total
                .with_label_values(&[label])
                .inc();
        }
        ReaderError::Transport(TransportError::NotFound(format!(
            "peer fallback for {id} not tried: {}",
            skip.reason()
        )))
    }

    /// One attempt, settled. Boxed as `Send` by its signature: the attempt
    /// reads through an `OcsVerifiedReader`, whose own `NotFound` arm can spawn
    /// this, and the compiler cannot see through that cycle on its own.
    fn run(
        self: Arc<Self>,
        id: ObjectID,
        admitted: Admitted,
    ) -> BoxFuture<'static, Result<(), ReaderError>> {
        Box::pin(async move {
            // Bound as a whole, so the lane's permit lives until the attempt
            // has settled (an async block captures only the fields it uses).
            let Admitted { network, _permit } = admitted;
            let mut settle = Settle {
                fallback: &self,
                id,
                served: false,
            };
            // One deadline for the whole attempt, this node's own fullnode
            // lookup included: a read that waits for it waits at most
            // `attempt_timeout`, and the lane's permit and the object's
            // in-flight mark are released by then.
            let deadline = Instant::now() + self.bounds.attempt_timeout;
            let (outcome, result) =
                match tokio::time::timeout_at(deadline, self.attempt(id, &network, deadline)).await
                {
                    Ok(ended) => ended,
                    Err(_elapsed) => {
                        debug!(?id, "peer fallback: the attempt reached its deadline");
                        (
                            Outcome::TimedOut,
                            Err(ReaderError::Transport(TransportError::Network(format!(
                                "peer fallback for {id}: no answer within the attempt deadline"
                            )))),
                        )
                    }
                };
            settle.served = outcome == Outcome::Served;
            drop(settle);
            self.metrics
                .direct_peer_fallback_total
                .with_label_values(&[outcome.label()])
                .inc();
            result
        })
    }

    /// Ask the peers, one at a time, until `deadline`. Each peer's read is cut
    /// at the deadline; the caller cuts the whole attempt there too, this
    /// node's own fullnode lookup included.
    async fn attempt(
        &self,
        id: ObjectID,
        network: &anemo::Network,
        deadline: Instant,
    ) -> (Outcome, Result<(), ReaderError>) {
        let current = match self.fullnode.get_object(id).await {
            Ok(object) => object.compute_object_reference(),
            Err(e @ TransportError::NotFound(_)) => {
                debug!(?id, error = %e, "peer fallback: this node's fullnode no longer reports the object");
                return (Outcome::NotLive, Err(ReaderError::Transport(e)));
            }
            Err(e) => {
                debug!(?id, error = %e, "peer fallback: this node's fullnode did not say what is current");
                return (Outcome::FullnodeError, Err(ReaderError::Transport(e)));
            }
        };

        let mut peers = network.peers();
        peers.shuffle(&mut rand::rng());
        peers.truncate(self.bounds.max_peers);
        let mut outcome = Outcome::Unavailable;
        let mut last_error = ReaderError::Transport(TransportError::NotFound(format!(
            "peer fallback for {id}: no connected peer served it"
        )));
        let mut asked = 0usize;
        for peer in peers {
            let now = Instant::now();
            if now >= deadline {
                debug!(?id, "peer fallback: the attempt deadline passed");
                break;
            }
            asked += 1;
            // A reader configured as a mirrored node's, over this one peer: the
            // answer passes the mirrored verification before anything else
            // looks at it. Its cache is its own, so nothing reaches this node's
            // cache before the currency check below.
            let scratch = Arc::new(VerifiedStateCache::new());
            let reader = OcsVerifiedReader::new(
                Arc::new(SuiMirrorProofProvider::new(
                    SuiMirrorPeers::scoped(
                        network.clone(),
                        vec![peer],
                        self.scratch_provider_metrics.clone(),
                    ),
                    self.scratch_provider_metrics.clone(),
                )),
                self.committees.clone(),
                self.scratch_metrics.clone(),
                None,
                scratch.clone(),
                false,
                None,
            );
            // Capped at the attempt deadline, the very instant the caller cuts
            // the attempt at: a peer still holding the read then ends the
            // loop here first (the caller polls this before its own timer),
            // so the attempt reports `unavailable`, not `timed_out`.
            let verified = match tokio::time::timeout_at(
                (now + self.bounds.peer_timeout).min(deadline),
                Box::pin(reader.verified_object(id)),
            )
            .await
            {
                Ok(Ok(verified)) => verified,
                Ok(Err(ReaderError::Transport(e))) => {
                    // The peer does not serve the relay (an older or mirrored
                    // node answers a route miss), could not prove the object,
                    // or failed: a "don't know", never an error that stops the
                    // fallback.
                    debug!(%peer, ?id, error = %e, "peer fallback: the peer did not serve the object");
                    continue;
                }
                Ok(Err(e)) => {
                    debug!(%peer, ?id, error = %e, "peer fallback: the peer's answer failed verification");
                    if outcome != Outcome::NotCurrent {
                        outcome = Outcome::Unverified;
                    }
                    last_error = e;
                    continue;
                }
                Err(_elapsed) => {
                    debug!(%peer, ?id, "peer fallback: the peer did not answer in time");
                    continue;
                }
            };
            let served = verified.object.compute_object_reference();
            if served != current {
                debug!(
                    %peer,
                    ?id,
                    ?served,
                    ?current,
                    "peer fallback: the peer proved another version than this node's fullnode \
                     reports as current"
                );
                outcome = Outcome::NotCurrent;
                last_error = ReaderError::NotCurrent {
                    id,
                    anchored_seq: verified.source_checkpoint_seq,
                    verdict: "not the reference this node's fullnode reports as current",
                };
                continue;
            }
            let Some(snapshot) = scratch.get(id) else {
                last_error = ReaderError::Decode(format!(
                    "peer fallback for {id}: the verified snapshot is missing from the reader's cache"
                ));
                continue;
            };
            let summary = snapshot.summary.clone();
            self.cache
                .absorb_shadow_entries(&summary, &[cache_entry(snapshot)]);
            info!(
                %peer,
                ?id,
                version = served.1.value(),
                checkpoint = verified.source_checkpoint_seq,
                asked,
                "peer fallback: proved an object this node could not prove itself, from a direct \
                 peer, verified as a mirrored node verifies a relayed object and current per this \
                 node's fullnode"
            );
            return (Outcome::Served, Ok(()));
        }
        match outcome {
            Outcome::NotCurrent | Outcome::Unverified => warn!(
                ?id,
                asked,
                outcome = outcome.label(),
                error = %last_error,
                "peer fallback: refused every answer peers gave for an object this node cannot \
                 prove itself (see `ika_ocs_direct_peer_fallback_total`)"
            ),
            _ => debug!(?id, asked, "peer fallback: no peer served the object"),
        }
        (outcome, Err(last_error))
    }
}

/// `snapshot` as a cache entry.
fn cache_entry(snapshot: VerifiedSnapshot) -> VerifiedObjectEntry {
    VerifiedObjectEntry {
        object: snapshot.object,
        checkpoint_seq: snapshot.source_checkpoint_seq,
        proof: snapshot.proof,
        dynamic_field_name_type: String::new(),
        dynamic_field_name_bcs: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use fastcrypto::traits::KeyPair;
    use ika_network::proof_provider::{
        BatchVerifiedObjectsResponse, ProofProvider, VerifiedDynamicFieldsPageRequest,
        VerifiedDynamicFieldsPageResponse, VerifiedObjectResponse,
    };
    use ika_network::sui_state_mirror::{SuiMirrorTransport, make_server};
    use ika_sui_client::transport::{DynamicFieldPage, ExecutedTransaction};
    use ika_types::sui::system_inner_v1::{
        BlsCommittee, ProtocolTreasuryV1, SystemInnerV1, SystemObjectCap, ValidatorSetV1,
    };
    use ika_types::sui::{ExtendedField, System, SystemInner, SystemInnerTrait};
    use sui_light_client::proof::ocs::ModifiedObjectTree;
    use sui_types::TypeTag;
    use sui_types::balance::{Balance, Supply};
    use sui_types::base_types::{
        AuthorityName, MoveObjectType, ObjectDigest, SequenceNumber, TransactionDigest,
    };
    use sui_types::coin::TreasuryCap;
    use sui_types::collection_types::{Bag, Table, VecMap};
    use sui_types::committee::Committee;
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::digests::CheckpointDigest;
    use sui_types::dynamic_field::Field;
    use sui_types::full_checkpoint_content::CheckpointData;
    use sui_types::gas::GasCostSummary;
    use sui_types::id::UID;
    use sui_types::messages_checkpoint::{
        CertifiedCheckpointSummary, CheckpointArtifacts, CheckpointCommitment, CheckpointContents,
        CheckpointSequenceNumber, CheckpointSummary,
    };
    use sui_types::object::{MoveObject, Object, Owner};
    use sui_types::parse_sui_type_tag;

    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use crate::sui_connector::committee_store::CommitteeBootstrap;

    /// This node's fullnode head, claimed in every peer answer.
    const HEAD: CheckpointSequenceNumber = 1_000;

    /// Every `skipped_*` label.
    const SKIPPED: [&str; 6] = [
        "skipped_retry_wait",
        "skipped_tracked_full",
        "skipped_no_network",
        "skipped_unconfirmed",
        "skipped_frozen",
        "skipped_busy",
    ];

    // -- fixtures ---------------------------------------------------------------------------

    /// This node's own fullnode: reports `live` as the current objects and
    /// counts the lookups.
    struct Fullnode {
        live: HashMap<ObjectID, Object>,
        lookups: AtomicUsize,
        /// The next lookup panics, as a bug in a client would.
        panic_next: AtomicBool,
        /// The next lookup hangs for five seconds, as a stuck connection would.
        hang_next: AtomicBool,
    }

    impl Fullnode {
        fn reporting(live: &[&Object]) -> Arc<Self> {
            Arc::new(Self {
                live: live.iter().map(|o| (o.id(), (*o).clone())).collect(),
                lookups: AtomicUsize::new(0),
                panic_next: AtomicBool::new(false),
                hang_next: AtomicBool::new(false),
            })
        }

        fn lookups(&self) -> usize {
            self.lookups.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl SuiTransport for Fullnode {
        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            unimplemented!()
        }
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            unimplemented!()
        }
        async fn get_committee(&self, _: Option<u64>) -> Result<Committee, TransportError> {
            unimplemented!()
        }
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn get_full_checkpoint(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            Err(TransportError::NotFound(format!("checkpoint {seq} pruned")))
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            _: CheckpointDigest,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn last_checkpoint_of_epoch(
            &self,
            _: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            unimplemented!()
        }
        async fn get_object(&self, id: ObjectID) -> Result<Object, TransportError> {
            self.lookups.fetch_add(1, Ordering::Relaxed);
            if self.panic_next.swap(false, Ordering::Relaxed) {
                panic!("the fullnode client panicked");
            }
            if self.hang_next.swap(false, Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            self.live
                .get(&id)
                .cloned()
                .ok_or_else(|| TransportError::NotFound(format!("object {id} not found")))
        }
        async fn get_object_with_version(
            &self,
            _: ObjectID,
            _: SequenceNumber,
        ) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn batch_get_objects(&self, _: &[ObjectID]) -> Result<Vec<Object>, TransportError> {
            unimplemented!()
        }
        async fn list_dynamic_fields(
            &self,
            _: ObjectID,
            _: Option<u32>,
            _: Option<Vec<u8>>,
        ) -> Result<DynamicFieldPage, TransportError> {
            unimplemented!()
        }
        async fn get_transaction(
            &self,
            _: TransactionDigest,
        ) -> Result<ExecutedTransaction, TransportError> {
            unimplemented!()
        }
    }

    /// What a peer's relay answers `verified_object` with, built fresh per
    /// request (the proof is not `Clone`).
    type Answer =
        Arc<dyn Fn(ObjectID) -> Result<VerifiedObjectResponse, TransportError> + Send + Sync>;

    /// A peer's proof provider, behind the real `SuiStateMirror` server.
    struct PeerProvider {
        answer: Answer,
        requests: Arc<AtomicUsize>,
        /// How long the peer sits on a request before answering.
        delay: Duration,
    }

    #[async_trait]
    impl ProofProvider for PeerProvider {
        async fn verified_object(
            &self,
            id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            self.requests.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(self.delay).await;
            (self.answer)(id)
        }
        async fn batch_verified_objects(
            &self,
            _: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            unimplemented!()
        }
        async fn verified_dynamic_fields_page(
            &self,
            _: VerifiedDynamicFieldsPageRequest,
        ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
            unimplemented!()
        }
    }

    fn network(router: anemo::Router) -> anemo::Network {
        anemo::Network::bind("localhost:0")
            .private_key(rand::random::<[u8; 32]>())
            .server_name("test")
            .start(router)
            .unwrap()
    }

    /// A direct peer serving the real `SuiStateMirror` server (as `make_server`
    /// builds it on every direct node), whose provider answers `answer`.
    fn direct_peer(answer: Answer) -> (anemo::Network, Arc<AtomicUsize>) {
        slow_direct_peer(answer, Duration::ZERO)
    }

    /// [`direct_peer`] that sits on every request for `delay` first.
    fn slow_direct_peer(answer: Answer, delay: Duration) -> (anemo::Network, Arc<AtomicUsize>) {
        let requests = Arc::new(AtomicUsize::new(0));
        let metrics = ProofProviderMetrics::new_for_testing();
        let unused = SuiMirrorPeers::new(network(anemo::Router::new()), vec![], metrics.clone());
        let server = make_server(
            Arc::new(SuiMirrorTransport::new(unused)),
            Arc::new(PeerProvider {
                answer,
                requests: requests.clone(),
                delay,
            }),
            metrics,
        );
        (
            network(anemo::Router::new().add_rpc_service(server)),
            requests,
        )
    }

    /// A node that does not serve `SuiStateMirror` — a mirrored or peer-only
    /// node; an older binary's unknown route answers the same bare NotFound.
    fn non_serving_peer() -> anemo::Network {
        network(anemo::Router::new())
    }

    async fn connected(peers: &[&anemo::Network]) -> anemo::Network {
        let node = network(anemo::Router::new());
        for peer in peers {
            node.connect(peer.local_addr()).await.unwrap();
        }
        node
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        committee: Committee,
        keys: Arc<Vec<AuthorityKeyPair>>,
        committees: Arc<CommitteeStore>,
        metrics: Arc<OcsMetrics>,
        /// This node's verified cache.
        cache: SharedVerifiedStateCache,
    }

    fn fixture() -> Fixture {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual,
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );
        Fixture {
            _dir: dir,
            committee,
            keys: Arc::new(keys),
            committees,
            metrics: OcsMetrics::new_for_testing(),
            cache: Arc::new(VerifiedStateCache::new()),
        }
    }

    /// Production bounds, except that an object is stuck at its first
    /// `NotFound`.
    fn bounds() -> FallbackBounds {
        FallbackBounds {
            stuck_after: Duration::ZERO,
            ..FallbackBounds::default()
        }
    }

    /// The pusher's report on a fullnode that has advanced and is not frozen.
    fn live_upstream() -> PusherUpstream {
        PusherUpstream::from_watches(watch::channel(true).1, watch::channel(false).1)
    }

    fn unattached(
        fx: &Fixture,
        fullnode: Arc<Fullnode>,
        bounds: FallbackBounds,
    ) -> Arc<PeerFallback> {
        Arc::new(PeerFallback::new(
            fullnode,
            fx.committees.clone(),
            fx.cache.clone(),
            bounds,
            fx.metrics.clone(),
        ))
    }

    fn fallback(
        fx: &Fixture,
        fullnode: Arc<Fullnode>,
        node: &anemo::Network,
        bounds: FallbackBounds,
    ) -> Arc<PeerFallback> {
        let fallback = unattached(fx, fullnode, bounds);
        fallback.attach_network(node.clone());
        fallback.attach_upstream(live_upstream());
        fallback
    }

    fn outcome(fx: &Fixture, label: &str) -> u64 {
        fx.metrics
            .direct_peer_fallback_total
            .with_label_values(&[label])
            .get()
    }

    fn skipped(fx: &Fixture) -> u64 {
        SKIPPED.iter().map(|label| outcome(fx, label)).sum()
    }

    fn asked(peers: &[(anemo::Network, Arc<AtomicUsize>)]) -> usize {
        peers.iter().map(|(_, r)| r.load(Ordering::Relaxed)).sum()
    }

    fn object(byte: u8, version: u64) -> Object {
        let ika =
            parse_sui_type_tag(&format!("{}::ika::IKA", ObjectID::from_single_byte(0x1A))).unwrap();
        Object::new_move(
            MoveObject::new_coin(
                ika,
                SequenceNumber::from(version),
                ObjectID::from_single_byte(byte),
                1,
            ),
            Owner::AddressOwner(ObjectID::from_single_byte(0x01).into()),
            TransactionDigest::ZERO,
        )
    }

    fn summary_committing_to(
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

    fn tree_over(objects: &[&Object]) -> ModifiedObjectTree {
        let states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)> = objects
            .iter()
            .map(|o| {
                let (id, version, digest) = o.compute_object_reference();
                (id, (version, digest))
            })
            .collect();
        ModifiedObjectTree::new(&CheckpointArtifacts::from_object_states(states)).unwrap()
    }

    fn artifacts_digest_over(objects: &[&Object]) -> CheckpointCommitment {
        let states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)> = objects
            .iter()
            .map(|o| {
                let (id, version, digest) = o.compute_object_reference();
                (id, (version, digest))
            })
            .collect();
        CheckpointCommitment::from(
            CheckpointArtifacts::from_object_states(states)
                .digest()
                .unwrap(),
        )
    }

    /// A genuine answer: `object` proven at checkpoint `seq`, whose
    /// committee-signed summary commits to the artifacts of `written`.
    fn genuine(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        object: &Object,
        written: &[&Object],
    ) -> VerifiedObjectResponse {
        VerifiedObjectResponse {
            object: object.clone(),
            summary: summary_committing_to(committee, keys, seq, artifacts_digest_over(written)),
            proof: tree_over(written)
                .get_inclusion_proof(object.compute_object_reference())
                .unwrap(),
            claimed_latest_checkpoint_seq: HEAD,
        }
    }

    fn answering(build: impl Fn() -> VerifiedObjectResponse + Send + Sync + 'static) -> Answer {
        Arc::new(move |_| Ok(build()))
    }

    /// Genuine answers for each of `objects`, by id, all written at `seq`.
    fn proving(fx: &Fixture, seq: CheckpointSequenceNumber, objects: &[&Object]) -> Answer {
        let (c, k) = (fx.committee.clone(), fx.keys.clone());
        let objects: Vec<Object> = objects.iter().map(|o| (*o).clone()).collect();
        Arc::new(move |id| {
            let written: Vec<&Object> = objects.iter().collect();
            let wanted = objects
                .iter()
                .find(|o| o.id() == id)
                .ok_or_else(|| TransportError::NotFound(format!("{id} unknown")))?;
            Ok(genuine(&c, &k, seq, wanted, &written))
        })
    }

    fn not_proving() -> Answer {
        Arc::new(|id| {
            Err(TransportError::NotFound(format!(
                "the defining checkpoint of {id} is pruned and no snapshot matches"
            )))
        })
    }

    /// The fallback with one peer giving `answer`, and this node's fullnode
    /// reporting `current`.
    async fn ask_one_peer(
        fx: &Fixture,
        current: &Object,
        answer: Answer,
    ) -> Result<(), ReaderError> {
        let (peer, _) = direct_peer(answer);
        let node = connected(&[&peer]).await;
        fallback(fx, Fullnode::reporting(&[current]), &node, bounds())
            .fill(current.id())
            .await
    }

    // -- verification parity: each step rejects an answer that fails it --------------------

    /// A genuine answer — the object at the fullnode's current reference,
    /// proven against a summary Sui's committee signed — lands in this node's
    /// cache with its proof.
    #[tokio::test]
    async fn a_genuine_current_answer_is_served() {
        let fx = fixture();
        let x = object(0xA1, 7);
        ask_one_peer(&fx, &x, proving(&fx, 400, &[&x]))
            .await
            .unwrap();
        let cached = fx.cache.get(x.id()).unwrap();
        assert_eq!(
            cached.object.compute_object_reference(),
            x.compute_object_reference()
        );
        assert_eq!(cached.source_checkpoint_seq, 400);
        assert_eq!(*cached.summary.sequence_number(), 400);
        assert_eq!(outcome(&fx, "served"), 1);
    }

    /// Bad signature: a genuine signature carried over to a summary whose
    /// contents were altered after signing.
    #[tokio::test]
    async fn an_answer_with_a_bad_signature_is_rejected() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let (c, k) = (fx.committee.clone(), fx.keys.clone());
        let x2 = x.clone();
        let result = ask_one_peer(
            &fx,
            &x,
            answering(move || {
                let mut answer = genuine(&c, &k, 400, &x2, &[&x2]);
                let signature = answer.summary.auth_sig().clone();
                let mut altered = answer.summary.data().clone();
                altered.timestamp_ms += 1;
                answer.summary =
                    CertifiedCheckpointSummary::new_from_data_and_sig(altered, signature);
                answer
            }),
        )
        .await;
        assert!(
            matches!(result, Err(ReaderError::InvalidProof(_))),
            "{:?}",
            result.err()
        );
        assert_eq!(outcome(&fx, "unverified"), 1);
        assert!(
            fx.cache.get(x.id()).is_none(),
            "a refused answer is never cached"
        );
    }

    /// Wrong committee: a well-formed summary for the same epoch, signed by a
    /// committee that is not Sui's.
    #[tokio::test]
    async fn an_answer_signed_by_another_committee_is_rejected() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let (foreign, foreign_keys) = Committee::new_simple_test_committee_of_size(7);
        let foreign_keys = Arc::new(foreign_keys);
        let x2 = x.clone();
        let result = ask_one_peer(
            &fx,
            &x,
            answering(move || genuine(&foreign, &foreign_keys, 400, &x2, &[&x2])),
        )
        .await;
        assert!(
            matches!(result, Err(ReaderError::InvalidProof(_))),
            "{:?}",
            result.err()
        );
    }

    /// A summary of an epoch this node holds no committee for cannot be
    /// verified at all.
    #[tokio::test]
    async fn an_answer_from_an_unknown_epoch_is_rejected() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let keys = fx.keys.clone();
        let later = Committee::new_for_testing_with_normalized_voting_power(
            5,
            keys.iter()
                .map(|key| (AuthorityName::from(key.public()), 1))
                .collect(),
        );
        let x2 = x.clone();
        let result = ask_one_peer(
            &fx,
            &x,
            answering(move || genuine(&later, &keys, 400, &x2, &[&x2])),
        )
        .await;
        assert!(
            matches!(result, Err(ReaderError::MissingCommittee(5))),
            "{:?}",
            result.err()
        );
    }

    /// Proof for the wrong id: a genuine, verifiable answer for another object
    /// than the one asked for.
    #[tokio::test]
    async fn an_answer_for_another_object_is_rejected() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let y = object(0xB2, 7);
        let (c, k) = (fx.committee.clone(), fx.keys.clone());
        let result =
            ask_one_peer(&fx, &x, answering(move || genuine(&c, &k, 400, &y, &[&y]))).await;
        match result {
            Err(ReaderError::InvalidProof(reason)) => {
                assert!(reason.contains("carries object"), "{reason}")
            }
            other => panic!(
                "expected the id binding to refuse it, got {:?}",
                other.err()
            ),
        }
    }

    /// Artifacts-digest mismatch: the proof is a genuine path in a tree whose
    /// root is not the artifacts digest the committee signed.
    #[tokio::test]
    async fn an_answer_whose_tree_is_not_the_signed_one_is_rejected() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let other = object(0xC3, 2);
        let (c, k) = (fx.committee.clone(), fx.keys.clone());
        let x2 = x.clone();
        let result = ask_one_peer(
            &fx,
            &x,
            answering(move || VerifiedObjectResponse {
                object: x2.clone(),
                // Signed: the artifacts of a checkpoint that wrote X and another object.
                summary: summary_committing_to(&c, &k, 400, artifacts_digest_over(&[&x2, &other])),
                // Shipped: a path in a tree over X alone.
                proof: tree_over(&[&x2])
                    .get_inclusion_proof(x2.compute_object_reference())
                    .unwrap(),
                claimed_latest_checkpoint_seq: HEAD,
            }),
        )
        .await;
        assert!(
            matches!(result, Err(ReaderError::InvalidProof(_))),
            "{:?}",
            result.err()
        );
    }

    /// Stale-but-authentic: a genuine proof of an older version of the object
    /// is refused `NotCurrent`, and so is a newer one this node's fullnode has
    /// not reached. Nothing a peer proves is kept unless it is exactly what
    /// the fullnode reports now.
    #[tokio::test]
    async fn an_authentic_answer_that_is_not_current_is_rejected() {
        let fx = fixture();
        let current = object(0xA1, 7);
        for (version, seq) in [(6, 350), (8, 450)] {
            let other_version = object(0xA1, version);
            let result = ask_one_peer(&fx, &current, proving(&fx, seq, &[&other_version])).await;
            assert!(
                matches!(result, Err(ReaderError::NotCurrent { anchored_seq, .. }) if anchored_seq == seq),
                "version {version}: {:?}",
                result.err()
            );
        }
        assert_eq!(outcome(&fx, "not_current"), 2);
        assert_eq!(outcome(&fx, "served"), 0);
        assert!(fx.cache.get(current.id()).is_none());
    }

    // -- peers ----------------------------------------------------------------------------------

    /// Each peer is asked on its own, so a peer whose answer fails a check
    /// never hides one whose answer passes, whichever is asked first.
    #[tokio::test]
    async fn a_failing_answer_does_not_hide_a_good_one() {
        for _ in 0..6 {
            let fx = fixture();
            let current = object(0xA1, 7);
            let stale = object(0xA1, 6);
            let (stale_peer, _) = direct_peer(proving(&fx, 350, &[&stale]));
            let (good_peer, _) = direct_peer(proving(&fx, 400, &[&current]));
            let node = connected(&[&stale_peer, &good_peer]).await;
            fallback(&fx, Fullnode::reporting(&[&current]), &node, bounds())
                .fill(current.id())
                .await
                .unwrap();
            assert_eq!(
                fx.cache.get(current.id()).unwrap().source_checkpoint_seq,
                400
            );
        }
    }

    /// A peer that does not serve the relay (a mirrored node, or an older
    /// binary's unknown route) and a peer that cannot prove the object are
    /// "don't know": the fallback moves on, and with only such peers it ends
    /// without an answer, never with an error that stops anything.
    #[tokio::test]
    async fn a_non_serving_or_unknowing_peer_is_a_dont_know() {
        for _ in 0..6 {
            let fx = fixture();
            let current = object(0xA1, 7);
            let non_serving = non_serving_peer();
            let (unknowing, _) = direct_peer(not_proving());
            let (good_peer, _) = direct_peer(proving(&fx, 400, &[&current]));
            let node = connected(&[&non_serving, &unknowing, &good_peer]).await;
            fallback(&fx, Fullnode::reporting(&[&current]), &node, bounds())
                .fill(current.id())
                .await
                .unwrap();
        }
        let fx = fixture();
        let current = object(0xA1, 7);
        let non_serving = non_serving_peer();
        let (unknowing, _) = direct_peer(not_proving());
        let node = connected(&[&non_serving, &unknowing]).await;
        let result = fallback(&fx, Fullnode::reporting(&[&current]), &node, bounds())
            .fill(current.id())
            .await;
        assert!(matches!(result, Err(ReaderError::Transport(_))));
        assert_eq!(outcome(&fx, "unavailable"), 1);
    }

    /// At most `max_peers` peers are asked per attempt.
    #[tokio::test]
    async fn at_most_max_peers_are_asked() {
        let fx = fixture();
        let current = object(0xA1, 7);
        let peers: Vec<_> = (0..3).map(|_| direct_peer(not_proving())).collect();
        let node = connected(&peers.iter().map(|(n, _)| n).collect::<Vec<_>>()).await;
        let bounded = fallback(
            &fx,
            Fullnode::reporting(&[&current]),
            &node,
            FallbackBounds {
                max_peers: 2,
                ..bounds()
            },
        );
        assert!(bounded.fill(current.id()).await.is_err());
        assert_eq!(asked(&peers), 2);
    }

    /// A whole attempt ends at `attempt_timeout`, however many peers are left
    /// and however long each may take: peers that accept a request and never
    /// answer cannot hold the read for `max_peers * peer_timeout`.
    #[tokio::test]
    async fn an_attempt_ends_at_its_deadline() {
        let fx = fixture();
        let current = object(0xA1, 7);
        // Peers that accept the request and sit on it far past every deadline.
        let peers: Vec<_> = (0..4)
            .map(|_| slow_direct_peer(not_proving(), Duration::from_secs(60)))
            .collect();
        let node = connected(&peers.iter().map(|(n, _)| n).collect::<Vec<_>>()).await;
        let bounded = fallback(
            &fx,
            Fullnode::reporting(&[&current]),
            &node,
            FallbackBounds {
                peer_timeout: Duration::from_secs(2),
                attempt_timeout: Duration::from_millis(2_500),
                ..bounds()
            },
        );
        let started = std::time::Instant::now();
        assert!(bounded.fill(current.id()).await.is_err());
        let took = started.elapsed();
        // The first peer gets its full 2 s, the second only the half second
        // left, and no peer is asked once the deadline has passed. Without the
        // attempt deadline it would take 8 s; with each peer given its full
        // timeout, 4 s.
        assert!(
            took < Duration::from_millis(3_500),
            "bounded at 2.5 s: took {took:?}"
        );
        assert_eq!(asked(&peers), 2, "no peer is asked after the deadline");
        assert_eq!(
            bounded
                .scratch_provider_metrics
                .relay_request_total
                .with_label_values(&["verified_object"])
                .get(),
            2,
            "no read is even started after the deadline"
        );
        // The peers ran out the clock, not this node's fullnode.
        assert_eq!(outcome(&fx, "unavailable"), 1);
        assert_eq!(outcome(&fx, "timed_out"), 0);
    }

    /// The deadline covers the whole attempt, this node's own fullnode lookup
    /// included: a read that waits for an attempt whose lookup hangs gets its
    /// answer by `attempt_timeout`, and the lane's permit and the object's
    /// in-flight mark are released then.
    #[tokio::test]
    async fn an_attempt_ends_at_its_deadline_even_when_this_nodes_fullnode_hangs() {
        let fx = fixture();
        let (x, y) = (object(0xA1, 7), object(0xB2, 3));
        let (peer, requests) = direct_peer(proving(&fx, 400, &[&x, &y]));
        let node = connected(&[&peer]).await;
        let fullnode = Fullnode::reporting(&[&x, &y]);
        let gated = fallback(
            &fx,
            fullnode.clone(),
            &node,
            FallbackBounds {
                max_concurrent: 1,
                attempt_timeout: Duration::from_millis(500),
                ..bounds()
            },
        );
        fullnode.hang_next.store(true, Ordering::Relaxed);
        let started = std::time::Instant::now();
        assert!(gated.fill(x.id()).await.is_err());
        let took = started.elapsed();
        assert!(
            took < Duration::from_millis(1_500),
            "bounded at 0.5 s, the lookup hangs 5 s: took {took:?}"
        );
        assert_eq!(outcome(&fx, "timed_out"), 1);

        gated.fill(y.id()).await.unwrap();
        assert_eq!(
            outcome(&fx, "skipped_busy"),
            0,
            "the lane's only permit was released"
        );
        assert!(gated.fill(x.id()).await.is_err());
        assert_eq!(
            outcome(&fx, "skipped_retry_wait"),
            1,
            "settled as a failure, not left in flight"
        );
        assert_eq!(requests.load(Ordering::Relaxed), 1);
    }

    // -- when an attempt is due -----------------------------------------------------------------

    /// An object is asked for only once this node's own provider has answered
    /// `NotFound` for it for `stuck_after`, as a just-written object whose
    /// transaction the fullnode has not indexed yet answers for a few seconds.
    /// A quiet gap of `stuck_reset` starts the clock over, and so does a read
    /// that proves it. None of this counts as a skipped attempt.
    #[tokio::test]
    async fn only_a_stuck_object_is_asked_for() {
        let fx = fixture();
        let (x, y, z) = (object(0xA1, 7), object(0xB2, 3), object(0xC3, 5));
        let (peer, requests) = direct_peer(proving(&fx, 400, &[&x, &y, &z]));
        let node = connected(&[&peer]).await;
        let fullnode = Fullnode::reporting(&[&x, &y, &z]);
        let stuck_after = Duration::from_millis(400);
        let gated = fallback(
            &fx,
            fullnode.clone(),
            &node,
            FallbackBounds {
                stuck_after,
                stuck_reset: Duration::from_secs(1),
                ..bounds()
            },
        );
        let pause = |d: u64| tokio::time::sleep(Duration::from_millis(d));

        assert!(gated.fill(x.id()).await.is_err());
        pause(200).await;
        assert!(
            gated.fill(x.id()).await.is_err(),
            "not stuck for long enough"
        );
        assert_eq!(requests.load(Ordering::Relaxed), 0);
        assert_eq!(fullnode.lookups(), 0, "not even the fullnode is asked");
        pause(250).await;
        gated.fill(x.id()).await.unwrap();
        assert_eq!(requests.load(Ordering::Relaxed), 1);

        assert!(gated.fill(y.id()).await.is_err());
        pause(1_100).await;
        assert!(
            gated.fill(y.id()).await.is_err(),
            "a quiet gap past stuck_reset starts the clock over"
        );
        pause(450).await;
        gated.fill(y.id()).await.unwrap();
        assert_eq!(requests.load(Ordering::Relaxed), 2);

        assert!(gated.fill(z.id()).await.is_err());
        pause(450).await;
        gated.note_proved([z.id()]);
        assert!(
            gated.fill(z.id()).await.is_err(),
            "a read that proved it starts the clock over"
        );
        assert_eq!(requests.load(Ordering::Relaxed), 2);
        assert_eq!(skipped(&fx), 0);
    }

    /// Nobody is asked before the network is attached, before the pusher's
    /// report on this node's fullnode is attached, before that fullnode has
    /// advanced since start, or while it is reported frozen: in each case the
    /// fullnode's "current" reference cannot be trusted or there is nobody to
    /// ask. Each counts under its own label.
    #[tokio::test]
    async fn an_attempt_needs_the_network_and_a_live_fullnode() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let (peer, requests) = direct_peer(proving(&fx, 400, &[&x]));
        let node = connected(&[&peer]).await;
        let fullnode = Fullnode::reporting(&[&x]);
        let gated = unattached(&fx, fullnode.clone(), bounds());

        assert!(gated.fill(x.id()).await.is_err());
        assert_eq!(outcome(&fx, "skipped_no_network"), 1);
        gated.attach_network(node.clone());
        assert!(gated.fill(x.id()).await.is_err());
        assert_eq!(
            outcome(&fx, "skipped_unconfirmed"),
            1,
            "no pusher state yet"
        );

        let (advanced_tx, advanced) = watch::channel(false);
        let (frozen_tx, frozen) = watch::channel(false);
        gated.attach_upstream(PusherUpstream::from_watches(advanced, frozen));
        assert!(gated.fill(x.id()).await.is_err());
        assert_eq!(
            outcome(&fx, "skipped_unconfirmed"),
            2,
            "not seen advancing since start"
        );
        advanced_tx.send_replace(true);
        frozen_tx.send_replace(true);
        assert!(gated.fill(x.id()).await.is_err());
        assert_eq!(outcome(&fx, "skipped_frozen"), 1);
        assert_eq!(requests.load(Ordering::Relaxed), 0);
        assert_eq!(fullnode.lookups(), 0);

        frozen_tx.send_replace(false);
        gated.fill(x.id()).await.unwrap();
        assert_eq!(requests.load(Ordering::Relaxed), 1);
    }

    /// A deleted object: the fullnode reports none, so no peer is asked.
    #[tokio::test]
    async fn a_deleted_object_asks_no_peer() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let (peer, requests) = direct_peer(proving(&fx, 400, &[&x]));
        let node = connected(&[&peer]).await;
        let gated = fallback(&fx, Fullnode::reporting(&[]), &node, bounds());
        assert!(gated.fill(x.id()).await.is_err());
        assert_eq!(outcome(&fx, "not_live"), 1);
        assert_eq!(requests.load(Ordering::Relaxed), 0);
    }

    /// Each lane has its own cap: busy background attempts never keep a read
    /// that waits (the boot barrier) from its own, and a full lane skips.
    #[tokio::test]
    async fn each_lane_has_its_own_cap() {
        let fx = fixture();
        let (x, y) = (object(0xA1, 7), object(0xB2, 3));
        let (peer, requests) =
            slow_direct_peer(proving(&fx, 400, &[&x, &y]), Duration::from_millis(300));
        let node = connected(&[&peer]).await;
        let capped = fallback(
            &fx,
            Fullnode::reporting(&[&x, &y]),
            &node,
            FallbackBounds {
                max_concurrent: 1,
                ..bounds()
            },
        );
        capped.refresh_in_background(x.id());
        capped.refresh_in_background(y.id());
        assert_eq!(
            outcome(&fx, "skipped_busy"),
            1,
            "the background lane is full"
        );
        capped.fill(y.id()).await.unwrap();

        let held = capped.waiting.clone().try_acquire_owned().unwrap();
        assert!(capped.fill(x.id()).await.is_err());
        assert_eq!(outcome(&fx, "skipped_busy"), 2, "the waiting lane is full");
        drop(held);
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(requests.load(Ordering::Relaxed), 2);
        assert!(
            fx.cache.get(x.id()).is_some(),
            "the background attempt landed"
        );
    }

    /// One attempt per object at a time: reads of an object whose attempt is
    /// running start no other, and are not counted as skipped.
    #[tokio::test]
    async fn one_attempt_per_object_at_a_time() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let (peer, requests) =
            slow_direct_peer(proving(&fx, 400, &[&x]), Duration::from_millis(300));
        let node = connected(&[&peer]).await;
        let gated = fallback(&fx, Fullnode::reporting(&[&x]), &node, bounds());
        gated.refresh_in_background(x.id());
        gated.refresh_in_background(x.id());
        let started = std::time::Instant::now();
        assert!(gated.fill(x.id()).await.is_err());
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "a read does not wait for another read's attempt"
        );
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        assert_eq!(outcome(&fx, "served"), 1);
        assert_eq!(skipped(&fx), 0);
        assert!(fx.cache.get(x.id()).is_some());
    }

    /// An object whose attempt failed is not tried again before
    /// `retry_after`; after it, it is.
    #[tokio::test]
    async fn a_failed_object_is_not_retried_before_retry_after() {
        let fx = fixture();
        let current = object(0xA1, 7);
        let (peer, requests) = direct_peer(not_proving());
        let node = connected(&[&peer]).await;
        let retry_after = Duration::from_millis(300);
        let gated = fallback(
            &fx,
            Fullnode::reporting(&[&current]),
            &node,
            FallbackBounds {
                retry_after,
                ..bounds()
            },
        );
        assert!(gated.fill(current.id()).await.is_err());
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        assert!(gated.fill(current.id()).await.is_err());
        assert_eq!(requests.load(Ordering::Relaxed), 1, "within retry_after");
        assert_eq!(outcome(&fx, "skipped_retry_wait"), 1);
        tokio::time::sleep(retry_after).await;
        assert!(gated.fill(current.id()).await.is_err());
        assert_eq!(requests.load(Ordering::Relaxed), 2);
    }

    /// The tracking table is bounded: while `max_tracked` objects are tracked
    /// and none is idle, a new object a read does not wait for is not tried,
    /// and the ones waiting out a failure keep waiting, however long since
    /// their last read. Once they are idle, they are forgotten.
    #[tokio::test]
    async fn a_full_tracking_table_refuses_new_objects() {
        let fx = fixture();
        let (a, b, c) = (
            ObjectID::from_single_byte(0xA1),
            ObjectID::from_single_byte(0xB2),
            ObjectID::from_single_byte(0xC3),
        );
        let node = connected(&[]).await;
        // The fullnode reports none of them: each attempt fails `not_live`.
        let fullnode = Fullnode::reporting(&[]);
        let gated = fallback(
            &fx,
            fullnode.clone(),
            &node,
            FallbackBounds {
                max_tracked: 2,
                retry_after: Duration::from_millis(600),
                stuck_reset: Duration::from_millis(100),
                ..bounds()
            },
        );
        assert!(gated.fill(a).await.is_err());
        assert!(gated.fill(b).await.is_err());
        assert_eq!(fullnode.lookups(), 2);

        // Past `stuck_reset` since their last read, still in their retry wait.
        tokio::time::sleep(Duration::from_millis(200)).await;
        gated.refresh_in_background(c);
        assert_eq!(outcome(&fx, "skipped_tracked_full"), 1);
        assert!(gated.fill(a).await.is_err());
        assert_eq!(
            outcome(&fx, "skipped_retry_wait"),
            1,
            "a full table keeps a failed object waiting"
        );
        assert_eq!(fullnode.lookups(), 2);

        tokio::time::sleep(Duration::from_millis(600)).await;
        gated.refresh_in_background(c);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(fullnode.lookups(), 3, "idle entries were forgotten");
    }

    /// A read that waits — an anchor read with nothing cached, the boot
    /// barrier — is never refused for a full table, however many other
    /// objects (bag children re-walked every few milliseconds) fill it.
    #[tokio::test]
    async fn a_read_that_waits_is_never_refused_for_a_full_table() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let (peer, requests) = direct_peer(proving(&fx, 400, &[&x]));
        let node = connected(&[&peer]).await;
        // The fullnode reports none of the children: each of their attempts
        // fails `not_live` and waits out `retry_after`, so none is idle.
        let gated = fallback(
            &fx,
            Fullnode::reporting(&[&x]),
            &node,
            FallbackBounds {
                max_tracked: 2,
                ..bounds()
            },
        );
        for byte in [0xC1, 0xC2] {
            gated.refresh_in_background(ObjectID::from_single_byte(byte));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        gated.refresh_in_background(ObjectID::from_single_byte(0xC3));
        assert_eq!(outcome(&fx, "skipped_tracked_full"), 1, "the table is full");

        gated.fill(x.id()).await.unwrap();
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        assert_eq!(outcome(&fx, "skipped_tracked_full"), 1);
    }

    /// An object whose attempt is running is never forgotten to make room,
    /// however long since its last read: it would be tried twice at once.
    #[tokio::test]
    async fn an_object_in_flight_is_never_forgotten() {
        let fx = fixture();
        let (x, y) = (object(0xA1, 7), object(0xB2, 3));
        let (peer, requests) =
            slow_direct_peer(proving(&fx, 400, &[&x, &y]), Duration::from_millis(600));
        let node = connected(&[&peer]).await;
        let fullnode = Fullnode::reporting(&[&x, &y]);
        let gated = fallback(
            &fx,
            fullnode.clone(),
            &node,
            FallbackBounds {
                max_tracked: 1,
                stuck_reset: Duration::from_millis(100),
                ..bounds()
            },
        );
        gated.refresh_in_background(x.id());
        tokio::time::sleep(Duration::from_millis(250)).await;
        gated.refresh_in_background(y.id());
        assert_eq!(outcome(&fx, "skipped_tracked_full"), 1);
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        assert_eq!(fullnode.lookups(), 1);
    }

    /// An attempt whose task panics still settles: the object is not left
    /// "in flight" forever, it waits out `retry_after` like any failure.
    #[tokio::test]
    async fn an_attempt_that_panics_still_settles() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let (peer, _) = direct_peer(proving(&fx, 400, &[&x]));
        let node = connected(&[&peer]).await;
        let fullnode = Fullnode::reporting(&[&x]);
        let retry_after = Duration::from_millis(200);
        let gated = fallback(
            &fx,
            fullnode.clone(),
            &node,
            FallbackBounds {
                retry_after,
                ..bounds()
            },
        );
        fullnode.panic_next.store(true, Ordering::Relaxed);
        assert!(gated.fill(x.id()).await.is_err());
        assert!(gated.fill(x.id()).await.is_err());
        assert_eq!(
            outcome(&fx, "skipped_retry_wait"),
            1,
            "settled as a failure"
        );
        tokio::time::sleep(retry_after).await;
        gated.fill(x.id()).await.unwrap();
    }

    /// A fullnode whose latest checkpoint the test sets, and which serves no
    /// checkpoint contents.
    struct WatermarkFullnode {
        height: std::sync::atomic::AtomicU64,
    }

    #[async_trait]
    impl SuiTransport for WatermarkFullnode {
        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            unimplemented!()
        }
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            unimplemented!()
        }
        async fn get_committee(&self, _: Option<u64>) -> Result<Committee, TransportError> {
            unimplemented!()
        }
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!("the pusher probes the watermark")
        }
        async fn get_latest_checkpoint_sequence(
            &self,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            Ok(self.height.load(Ordering::Relaxed))
        }
        async fn get_full_checkpoint(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            Err(TransportError::NotFound(format!(
                "checkpoint {seq} not served"
            )))
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            _: CheckpointDigest,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn last_checkpoint_of_epoch(
            &self,
            _: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            unimplemented!()
        }
        async fn get_object(&self, _: ObjectID) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn get_object_with_version(
            &self,
            _: ObjectID,
            _: SequenceNumber,
        ) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn batch_get_objects(&self, _: &[ObjectID]) -> Result<Vec<Object>, TransportError> {
            unimplemented!()
        }
        async fn list_dynamic_fields(
            &self,
            _: ObjectID,
            _: Option<u32>,
            _: Option<Vec<u8>>,
        ) -> Result<DynamicFieldPage, TransportError> {
            unimplemented!()
        }
        async fn get_transaction(
            &self,
            _: TransactionDigest,
        ) -> Result<ExecutedTransaction, TransportError> {
            unimplemented!()
        }
    }

    /// Through the real checkpoint pusher, read as the node attaches it
    /// (`PusherUpstream::of`): its fullnode is not trusted until the pusher has
    /// seen it advance since start — however long the frozen report takes to
    /// speak — nor while it reports it frozen; an advance is never forgotten.
    #[tokio::test(start_paused = true)]
    async fn the_pusher_gates_the_fallback() {
        use crate::sui_connector::push_worker::IkaCheckpointPusher;
        use ika_types::messages_dwallet_mpc::IkaPackageConfig;

        let dir = tempfile::tempdir().unwrap();
        let (committee, _) = Committee::new_simple_test_committee();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee)),
            )
            .unwrap(),
        );
        perpetual.put_sui_pusher_last_seq(100).unwrap();
        let fullnode = Arc::new(WatermarkFullnode {
            height: std::sync::atomic::AtomicU64::new(100),
        });
        let packages = IkaPackageConfig {
            ika_package_id: ObjectID::from_single_byte(0x1A),
            ika_common_package_id: ObjectID::from_single_byte(0x1B),
            ika_dwallet_2pc_mpc_package_id: ObjectID::from_single_byte(0x1C),
            ika_dwallet_2pc_mpc_package_id_v2: None,
            ika_system_package_id: ObjectID::from_single_byte(0x1D),
        };
        let pusher = IkaCheckpointPusher::new(
            fullnode.clone(),
            perpetual,
            OcsMetrics::new_for_testing(),
            &packages,
            Duration::from_secs(1),
            Arc::new(VerifiedStateCache::new()),
            committees,
            None,
        )
        .await
        .unwrap();
        let upstream = PusherUpstream::of(&pusher);
        let advanced = pusher.upstream_advanced();
        tokio::spawn(pusher.run());

        // The pusher polls every second and checks for a freeze every ten, so
        // allow it one check past each transition.
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(
            upstream.distrust(),
            Some(Skip::Unconfirmed),
            "not seen advancing since start, and not yet reported frozen"
        );
        fullnode.height.store(101, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(upstream.distrust(), None, "advanced");

        tokio::time::sleep(Duration::from_secs(285)).await;
        assert_eq!(upstream.distrust(), None, "under five minutes since");
        tokio::time::sleep(Duration::from_secs(35)).await;
        assert_eq!(
            upstream.distrust(),
            Some(Skip::Frozen),
            "no advance for five minutes"
        );
        assert!(*advanced.borrow(), "an advance is never forgotten");

        fullnode.height.store(102, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(15)).await;
        assert_eq!(upstream.distrust(), None, "advancing again");
    }

    // -- signals --------------------------------------------------------------------------------

    /// Records where each WARN and ERROR event Ika's own crates emit comes
    /// from.
    struct CountWarnings(Arc<Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CountWarnings {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let metadata = event.metadata();
            if *metadata.level() <= tracing::Level::WARN && metadata.target().starts_with("ika_") {
                self.0.lock().push(metadata.name().to_owned());
            }
        }
    }

    /// A peer's answer moves none of this node's relay or verification
    /// metrics — the per-peer readers count into their own — and an attempt
    /// logs one line, however many peers it asks: a failed one at WARN, the
    /// per-peer detail at debug.
    #[tokio::test]
    async fn an_attempt_reports_only_through_its_own_metric_and_one_line() {
        use tracing_subscriber::layer::SubscriberExt;

        let warnings = Arc::new(Mutex::new(Vec::new()));
        // With a single registered dispatcher, tracing decides whether a
        // callsite is interesting by the default of whichever thread reaches
        // it first, and other tests' threads have none. A second registered
        // one makes it ask every registered dispatcher, this test's included.
        let _second = tracing::Dispatch::new(tracing_subscriber::registry());
        let _logs = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(CountWarnings(warnings.clone())),
        );
        let fx = fixture();
        let (x, y) = (object(0xA1, 7), object(0xB2, 3));
        let honest = proving(&fx, 400, &[&y]);
        let (c, k) = (fx.committee.clone(), fx.keys.clone());
        let x2 = x.clone();
        // Proves Y, and answers X with a summary altered after signing.
        let (mixed, _) = direct_peer(Arc::new(move |id| {
            if id != x2.id() {
                return honest(id);
            }
            let mut answer = genuine(&c, &k, 400, &x2, &[&x2]);
            let signature = answer.summary.auth_sig().clone();
            let mut altered = answer.summary.data().clone();
            altered.timestamp_ms += 1;
            answer.summary = CertifiedCheckpointSummary::new_from_data_and_sig(altered, signature);
            Ok(answer)
        }));
        let (unknowing, _) = direct_peer(not_proving());
        let non_serving = non_serving_peer();
        let node = connected(&[&mixed, &unknowing, &non_serving]).await;
        let gated = fallback(&fx, Fullnode::reporting(&[&x, &y]), &node, bounds());

        assert!(gated.fill(x.id()).await.is_err());
        gated.fill(y.id()).await.unwrap();
        assert_eq!(outcome(&fx, "unverified"), 1);
        assert_eq!(outcome(&fx, "served"), 1);
        let warnings = warnings.lock().clone();
        assert_eq!(
            warnings.len(),
            1,
            "one WARN for the failed attempt, none per peer: {warnings:?}"
        );

        let invalid = |metrics: &OcsMetrics| {
            metrics
                .proof_verify_failures_total
                .with_label_values(&["object", "invalid_proof"])
                .get()
        };
        let verified = |metrics: &OcsMetrics| {
            metrics
                .proof_verify_total
                .with_label_values(&["object"])
                .get()
        };
        assert_eq!(invalid(&fx.metrics), 0);
        assert_eq!(verified(&fx.metrics), 0);
        assert_eq!(fx.metrics.last_successful_relay_timestamp_seconds.get(), 0);
        // They were counted, only not as this node's relay reads.
        assert_eq!(invalid(&gated.scratch_metrics), 1);
        assert_eq!(verified(&gated.scratch_metrics), 1);
        assert!(
            gated
                .scratch_metrics
                .last_successful_relay_timestamp_seconds
                .get()
                > 0
        );
    }

    // -- the direct reader ----------------------------------------------------------------------

    /// The direct node's own provider: it cannot prove anything (its fullnode
    /// pruned every defining checkpoint). Its batch answers carry an empty slot
    /// for such an object, and its bag page lists `children` as skipped.
    struct PrunedLocalProvider {
        children: Vec<ObjectID>,
    }

    #[async_trait]
    impl ProofProvider for PrunedLocalProvider {
        async fn verified_object(
            &self,
            id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            Err(TransportError::NotFound(format!(
                "the defining checkpoint of {id} is pruned and no snapshot matches"
            )))
        }
        async fn batch_verified_objects(
            &self,
            ids: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            Ok(BatchVerifiedObjectsResponse {
                summaries: BTreeMap::new(),
                results: ids.iter().map(|_| None).collect(),
                claimed_latest_checkpoint_seq: HEAD,
            })
        }
        async fn verified_dynamic_fields_page(
            &self,
            _: VerifiedDynamicFieldsPageRequest,
        ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
            Ok(VerifiedDynamicFieldsPageResponse {
                summaries: BTreeMap::new(),
                entries: vec![],
                next_page_token: None,
                claimed_latest_checkpoint_seq: HEAD,
                skipped_entry_ids: self.children.clone(),
            })
        }
    }

    fn reader(
        fx: &Fixture,
        cache_first: bool,
        children: Vec<ObjectID>,
        fallback: Arc<PeerFallback>,
    ) -> OcsVerifiedReader {
        OcsVerifiedReader::new(
            Arc::new(PrunedLocalProvider { children }),
            fx.committees.clone(),
            fx.metrics.clone(),
            None,
            fx.cache.clone(),
            cache_first,
            None,
        )
        .with_peer_fallback(Some(fallback))
    }

    /// A direct read with nothing cached fails at once, as before, while the
    /// fallback fills the cache in the background: a later read is a cache hit
    /// that asks no peer. A batch read never falls back, and a mirrored
    /// reader never does.
    #[tokio::test]
    async fn a_read_with_nothing_cached_does_not_wait_and_a_later_read_is_a_hit() {
        let fx = fixture();
        let (x, y) = (object(0xA1, 7), object(0xB2, 3));
        let (peer, requests) =
            slow_direct_peer(proving(&fx, 400, &[&x, &y]), Duration::from_millis(500));
        let node = connected(&[&peer]).await;
        let fullnode = Fullnode::reporting(&[&x, &y]);

        let mirrored = reader(
            &fx,
            false,
            vec![],
            fallback(&fx, fullnode.clone(), &node, bounds()),
        );
        assert!(mirrored.verified_object(x.id()).await.is_err());

        let direct = reader(&fx, true, vec![], fallback(&fx, fullnode, &node, bounds()));
        assert!(direct.verified_objects(&[y.id()]).await.is_err());
        let started = std::time::Instant::now();
        assert!(direct.verified_object(x.id()).await.is_err());
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "the read does not wait for the peer"
        );
        tokio::time::sleep(Duration::from_millis(800)).await;
        let read = direct.verified_object(x.id()).await.unwrap();
        assert_eq!(
            read.object.compute_object_reference(),
            x.compute_object_reference()
        );
        direct.verified_object(x.id()).await.unwrap();
        assert_eq!(
            requests.load(Ordering::Relaxed),
            1,
            "only the direct single read asked, once"
        );
        assert!(fx.cache.get(y.id()).is_none());
    }

    /// The bag walk never waits for a peer: a listed child it could not prove
    /// is left out of this walk while the fallback fills it, and a later walk
    /// serves it from the cache. A child that only just became unprovable — a
    /// just-written object the fullnode has not indexed yet — is not asked for
    /// at all.
    #[tokio::test]
    async fn the_bag_walk_never_waits_for_a_peer() {
        let fx = fixture();
        let child = object(0xC1, 4);
        let parent = ObjectID::from_single_byte(0xBA);
        let (peer, requests) =
            slow_direct_peer(proving(&fx, 400, &[&child]), Duration::from_secs(1));
        let node = connected(&[&peer]).await;
        let fullnode = Fullnode::reporting(&[&child]);

        let just_written = reader(
            &fx,
            true,
            vec![child.id()],
            fallback(&fx, fullnode.clone(), &node, FallbackBounds::default()),
        );
        for _ in 0..3 {
            let page = just_written
                .verified_dynamic_fields_page(parent, None, None)
                .await
                .unwrap();
            assert!(page.entries.is_empty());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            requests.load(Ordering::Relaxed),
            0,
            "not stuck: nobody asked"
        );
        assert_eq!(fullnode.lookups(), 0);

        let direct = reader(
            &fx,
            true,
            vec![child.id()],
            fallback(&fx, fullnode, &node, bounds()),
        );
        let started = std::time::Instant::now();
        let page = direct
            .verified_dynamic_fields_page(parent, None, None)
            .await
            .unwrap();
        assert!(page.entries.is_empty());
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "the walk does not wait for the peer"
        );
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        let started = std::time::Instant::now();
        let page = direct
            .verified_dynamic_fields_page(parent, None, None)
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(page.entries.len(), 1);
        assert_eq!(
            page.entries[0].object.compute_object_reference(),
            child.compute_object_reference()
        );
        assert_eq!(requests.load(Ordering::Relaxed), 1);
    }

    /// The direct reader's own high-water still applies: a peer-verified
    /// object below a version this reader has already served is not served.
    #[tokio::test]
    async fn the_direct_readers_high_water_applies_to_a_fallback_answer() {
        let fx = fixture();
        let x7 = object(0xA1, 7);
        let x8 = object(0xA1, 8);
        let (peer, _) = direct_peer(proving(&fx, 400, &[&x7]));
        let node = connected(&[&peer]).await;
        // The fullnode lags: it reports version 7 after version 8 was served.
        let direct = reader(
            &fx,
            true,
            vec![],
            fallback(&fx, Fullnode::reporting(&[&x7]), &node, bounds()),
        );
        direct.record_high_water(x8.id(), x8.version()).unwrap();
        assert!(direct.verified_object(x7.id()).await.is_err());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(outcome(&fx, "served"), 1, "the fallback itself verified it");
        assert!(direct.verified_object(x7.id()).await.is_err());
    }

    /// The same on the anchor read that waits for the fallback: a fresh
    /// `System` anchor below a version already served is not served.
    #[tokio::test]
    async fn the_direct_readers_high_water_applies_to_a_waited_for_anchor() {
        let fx = fixture();
        let system_id = ObjectID::from_single_byte(0x5A);
        let (outer, inner) = system_anchor(system_id, 11, 463);
        let peer_cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        folded(&fx, &peer_cache, 700, &[&outer, &inner]);
        let (peer, _) = direct_peer(served_from_cache(peer_cache));
        let node = connected(&[&peer]).await;
        let direct = reader(
            &fx,
            true,
            vec![],
            fallback(&fx, Fullnode::reporting(&[&outer, &inner]), &node, bounds()),
        );
        direct
            .record_high_water(system_id, SequenceNumber::from(12u64))
            .unwrap();
        assert!(direct.verified_system_inner(system_id).await.is_err());
        assert_eq!(outcome(&fx, "served"), 1, "the fallback itself verified it");
    }

    /// The direct node's own provider for one bag: its page lists `child` as
    /// skipped (not provable yet) until `proves` is set, then proves it.
    struct BagLocalProvider {
        proves: AtomicBool,
        child: Object,
        committee: Committee,
        keys: Arc<Vec<AuthorityKeyPair>>,
    }

    #[async_trait]
    impl ProofProvider for BagLocalProvider {
        async fn verified_object(
            &self,
            id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            Err(TransportError::NotFound(format!("{id} not provable now")))
        }
        async fn batch_verified_objects(
            &self,
            _: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            unimplemented!()
        }
        async fn verified_dynamic_fields_page(
            &self,
            _: VerifiedDynamicFieldsPageRequest,
        ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
            if !self.proves.load(Ordering::Relaxed) {
                return Ok(VerifiedDynamicFieldsPageResponse {
                    summaries: BTreeMap::new(),
                    entries: vec![],
                    next_page_token: None,
                    claimed_latest_checkpoint_seq: HEAD,
                    skipped_entry_ids: vec![self.child.id()],
                });
            }
            let child = &self.child;
            Ok(VerifiedDynamicFieldsPageResponse {
                summaries: BTreeMap::from([(
                    400,
                    summary_committing_to(
                        &self.committee,
                        &self.keys,
                        400,
                        artifacts_digest_over(&[child]),
                    ),
                )]),
                entries: vec![VerifiedObjectEntry {
                    object: child.clone(),
                    checkpoint_seq: 400,
                    proof: tree_over(&[child])
                        .get_inclusion_proof(child.compute_object_reference())
                        .unwrap(),
                    dynamic_field_name_type: String::new(),
                    dynamic_field_name_bcs: Vec::new(),
                }],
                next_page_token: None,
                claimed_latest_checkpoint_seq: HEAD,
                skipped_entry_ids: vec![],
            })
        }
    }

    /// A bag child the fallback started tracking while it was not provable yet
    /// is forgotten once a page proves it, so bag children that resolve on
    /// their own do not linger in the tracking table.
    #[tokio::test]
    async fn a_bag_page_that_proves_a_child_forgets_it() {
        let fx = fixture();
        let parent = ObjectID::from_single_byte(0xBA);
        let child = Object::new_move(
            MoveObject::new_coin(
                parse_sui_type_tag(&format!("{}::ika::IKA", ObjectID::from_single_byte(0x1A)))
                    .unwrap(),
                SequenceNumber::from(4u64),
                ObjectID::from_single_byte(0xC1),
                1,
            ),
            Owner::ObjectOwner(parent.into()),
            TransactionDigest::ZERO,
        );
        let local = Arc::new(BagLocalProvider {
            proves: AtomicBool::new(false),
            child: child.clone(),
            committee: fx.committee.clone(),
            keys: fx.keys.clone(),
        });
        let node = connected(&[]).await;
        let tracking = fallback(
            &fx,
            Fullnode::reporting(&[&child]),
            &node,
            FallbackBounds::default(),
        );
        let direct = OcsVerifiedReader::new(
            local.clone(),
            fx.committees.clone(),
            fx.metrics.clone(),
            None,
            fx.cache.clone(),
            true,
            None,
        )
        .with_peer_fallback(Some(tracking.clone()));

        let page = direct
            .verified_dynamic_fields_page(parent, None, None)
            .await
            .unwrap();
        assert!(page.entries.is_empty());
        assert!(tracking.tracked.lock().contains_key(&child.id()));

        local.proves.store(true, Ordering::Relaxed);
        let page = direct
            .verified_dynamic_fields_page(parent, None, None)
            .await
            .unwrap();
        assert_eq!(page.entries.len(), 1);
        assert!(
            !tracking.tracked.lock().contains_key(&child.id()),
            "proved in a page: forgotten"
        );
    }

    /// The direct node's own provider, proving `object` while `proves` is set
    /// and answering `NotFound` otherwise.
    struct TogglingLocalProvider {
        proves: AtomicBool,
        answer: Answer,
        object: ObjectID,
    }

    #[async_trait]
    impl ProofProvider for TogglingLocalProvider {
        async fn verified_object(
            &self,
            id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            if self.proves.load(Ordering::Relaxed) && id == self.object {
                (self.answer)(id)
            } else {
                Err(TransportError::NotFound(format!("{id} not provable now")))
            }
        }
        async fn batch_verified_objects(
            &self,
            _: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            unimplemented!()
        }
        async fn verified_dynamic_fields_page(
            &self,
            _: VerifiedDynamicFieldsPageRequest,
        ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
            unimplemented!()
        }
    }

    /// A read the node's own provider proves starts the object's stuck clock
    /// over: a `NotFound` just after it does not count the time before.
    #[tokio::test]
    async fn a_read_that_proves_the_object_restarts_its_clock() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let (peer, requests) = direct_peer(proving(&fx, 400, &[&x]));
        let node = connected(&[&peer]).await;
        let local = Arc::new(TogglingLocalProvider {
            proves: AtomicBool::new(false),
            answer: proving(&fx, 400, &[&x]),
            object: x.id(),
        });
        // A zero staleness bound sends every read past the cache to the
        // provider once a response has shown a head.
        let direct = OcsVerifiedReader::new(
            local.clone(),
            fx.committees.clone(),
            fx.metrics.clone(),
            None,
            fx.cache.clone(),
            true,
            Some(0),
        )
        .with_peer_fallback(Some(fallback(
            &fx,
            Fullnode::reporting(&[&x]),
            &node,
            FallbackBounds {
                stuck_after: Duration::from_millis(400),
                stuck_reset: Duration::from_secs(5),
                ..bounds()
            },
        )));

        assert!(direct.verified_object(x.id()).await.is_err());
        tokio::time::sleep(Duration::from_millis(450)).await;
        local.proves.store(true, Ordering::Relaxed);
        direct.verified_object(x.id()).await.unwrap();
        local.proves.store(false, Ordering::Relaxed);
        // Served from the cache, and not stuck: its clock started again.
        direct.verified_object(x.id()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(requests.load(Ordering::Relaxed), 0);
    }
    // -- the incident, end to end ---------------------------------------------------------------

    /// A direct peer's proof provider as it serves a pruned anchor: from its
    /// verified cache's snapshot (`recover_pruned_proof`).
    fn served_from_cache(cache: SharedVerifiedStateCache) -> Answer {
        Arc::new(move |id| {
            let snapshot = cache
                .get(id)
                .ok_or_else(|| TransportError::NotFound(format!("{id} pruned and not cached")))?;
            Ok(VerifiedObjectResponse {
                object: snapshot.object,
                summary: snapshot.summary,
                proof: snapshot.proof,
                claimed_latest_checkpoint_seq: HEAD,
            })
        })
    }

    fn move_object(type_tag: &str, version: u64, contents: Vec<u8>, owner: Owner) -> Object {
        let TypeTag::Struct(tag) = parse_sui_type_tag(type_tag).unwrap() else {
            panic!("{type_tag} is a struct type");
        };
        // `MoveObject`'s fields are private and its constructor for an
        // arbitrary type is `unsafe`; its serialized layout is public. Neither
        // anchor type has `store`, so `has_public_transfer` is false.
        let layout = (
            MoveObjectType::from(*tag),
            false,
            SequenceNumber::from(version),
            contents,
        );
        let object: MoveObject = bcs::from_bytes(&bcs::to_bytes(&layout).unwrap()).unwrap();
        Object::new_move(object, owner, TransactionDigest::ZERO)
    }

    fn empty_bls_committee() -> BlsCommittee {
        BlsCommittee {
            members: vec![],
            aggregated_protocol_pubkey: bcs::from_bytes(&bcs::to_bytes(&Vec::<u8>::new()).unwrap())
                .unwrap(),
            quorum_threshold: 0,
            validity_threshold: 0,
        }
    }

    fn system_inner(epoch: u64) -> SystemInnerV1 {
        let oid = ObjectID::from_single_byte;
        SystemInnerV1 {
            epoch,
            epoch_start_tx_digest: vec![7; 32],
            system_object_cap: SystemObjectCap { id: oid(0x31) },
            protocol_version: 1,
            next_protocol_version: None,
            upgrade_caps: vec![],
            approved_upgrades: VecMap { contents: vec![] },
            validator_set: ValidatorSetV1 {
                total_stake: 0,
                reward_slashing_rate: 0,
                validators: Table::default(),
                active_committee: empty_bls_committee(),
                next_epoch_committee: None,
                previous_committee: empty_bls_committee(),
                pending_active_set: ExtendedField { id: oid(0x32) },
                validator_report_records: VecMap { contents: vec![] },
                extra_fields: Bag::default(),
            },
            epoch_duration_ms: 86_400_000,
            stake_subsidy_start_epoch: 1,
            protocol_treasury: ProtocolTreasuryV1 {
                treasury_cap: TreasuryCap {
                    id: UID::new(oid(0x33)),
                    total_supply: Supply { value: 0 },
                },
                stake_subsidy_distribution_counter: 0,
                stake_subsidy_rate: 0,
                stake_subsidy_amount_per_distribution: 0,
                stake_subsidy_period_length: 0,
                total_supply_at_period_start: 0,
                extra_fields: Bag::default(),
            },
            epoch_start_timestamp_ms: 0,
            last_processed_checkpoint_sequence_number: 0,
            previous_epoch_last_checkpoint_sequence_number: 0,
            total_messages_processed: 0,
            remaining_rewards: Balance::new(0),
            authorized_protocol_cap_ids: vec![],
            witness_approving_advance_epoch: vec![],
            received_end_of_publish: false,
            extra_fields: Bag::default(),
        }
    }

    /// The `System` anchor and its versioned inner, both written at object
    /// version `version` and holding Ika epoch `epoch`.
    fn system_anchor(system_id: ObjectID, version: u64, epoch: u64) -> (Object, Object) {
        let package = ObjectID::from_single_byte(0x1D);
        let outer = System {
            id: system_id,
            version: 1,
            package_id: package,
            new_package_id: None,
            migration_epoch: None,
        };
        let inner_id = ika_sui_client::transport::derive_versioned_child_id(system_id, 1).unwrap();
        let inner = Field {
            id: UID::new(inner_id),
            name: 1u64,
            value: system_inner(epoch),
        };
        (
            move_object(
                &format!("{package}::system::System"),
                version,
                bcs::to_bytes(&outer).unwrap(),
                Owner::Shared {
                    initial_shared_version: SequenceNumber::from(1u64),
                },
            ),
            move_object(
                &format!("0x2::dynamic_field::Field<u64, {package}::system_inner::SystemInner>"),
                version,
                bcs::to_bytes(&inner).unwrap(),
                Owner::ObjectOwner(system_id.into()),
            ),
        )
    }

    /// Fold `objects`, written together at `seq`, into `cache` as a direct
    /// node's pusher would have while the checkpoint was live.
    fn folded(
        fx: &Fixture,
        cache: &SharedVerifiedStateCache,
        seq: CheckpointSequenceNumber,
        objects: &[&Object],
    ) {
        let tree = tree_over(objects);
        let summary =
            summary_committing_to(&fx.committee, &fx.keys, seq, artifacts_digest_over(objects));
        let entries: Vec<VerifiedObjectEntry> = objects
            .iter()
            .map(|o| VerifiedObjectEntry {
                object: (*o).clone(),
                checkpoint_seq: seq,
                proof: tree
                    .get_inclusion_proof(o.compute_object_reference())
                    .unwrap(),
                dynamic_field_name_type: String::new(),
                dynamic_field_name_bcs: Vec::new(),
            })
            .collect();
        cache.absorb_entries(&summary, &entries);
    }

    /// The incident shape, end to end over real anemo networks. A fresh direct
    /// node — empty cache — whose fullnode reports the `System` anchor but has
    /// pruned the checkpoint that wrote it is stuck at the
    /// `verified_system_inner` boot barrier. Its peers: an up-to-date direct
    /// node serving the anchor from its own verified cache, a malicious one
    /// serving the previous, genuinely signed version of the anchor, and a node
    /// that does not serve the relay. The anchor read, with nothing cached,
    /// waits for the fallback: it reads the anchor from the honest peer,
    /// verified as a mirrored node would, and gets past the barrier; the
    /// malicious answer is refused whichever peer is asked first.
    #[tokio::test]
    async fn a_fresh_direct_node_gets_past_the_system_barrier_through_a_direct_peer() {
        for _ in 0..4 {
            let fx = fixture();
            let system_id = ObjectID::from_single_byte(0x5A);
            let (outer, inner) = system_anchor(system_id, 11, 463);
            let (old_outer, old_inner) = system_anchor(system_id, 10, 462);

            let honest_cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
            folded(&fx, &honest_cache, 700, &[&outer, &inner]);
            let (honest, _) = direct_peer(served_from_cache(honest_cache));
            let stale_cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
            folded(&fx, &stale_cache, 650, &[&old_outer, &old_inner]);
            let (malicious, _) = direct_peer(served_from_cache(stale_cache));
            let non_serving = non_serving_peer();
            let node = connected(&[&honest, &malicious, &non_serving]).await;

            let direct = reader(
                &fx,
                true,
                vec![],
                fallback(&fx, Fullnode::reporting(&[&outer, &inner]), &node, bounds()),
            );
            let (system, inner_state) = direct.verified_system_inner(system_id).await.unwrap();
            assert_eq!(system.id, system_id);
            assert_eq!(inner_state.epoch(), 463);
            assert_eq!(fx.cache.get(outer.id()).unwrap().source_checkpoint_seq, 700);
            assert_eq!(fx.cache.get(inner.id()).unwrap().source_checkpoint_seq, 700);
        }
    }

    /// An anchor with an older snapshot cached — its newer write never folded
    /// (#1736) — is served from the cache at once when its refresh finds the
    /// checkpoint pruned, whether the fallback is still running or fails; the
    /// fallback fetches the current version off the read's path, and a later
    /// read serves it.
    #[tokio::test]
    async fn a_cached_anchor_is_served_at_once_and_refreshed_in_the_background() {
        for honest in [true, false] {
            let fx = fixture();
            let system_id = ObjectID::from_single_byte(0x5A);
            let (outer, inner) = system_anchor(system_id, 11, 463);
            let (old_outer, old_inner) = system_anchor(system_id, 10, 462);
            folded(&fx, &fx.cache, 650, &[&old_outer, &old_inner]);

            let answer = if honest {
                let peer_cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
                folded(&fx, &peer_cache, 700, &[&outer, &inner]);
                served_from_cache(peer_cache)
            } else {
                not_proving()
            };
            let (peer, _) = slow_direct_peer(answer, Duration::from_secs(1));
            let node = connected(&[&peer]).await;
            let direct = reader(
                &fx,
                true,
                vec![],
                fallback(&fx, Fullnode::reporting(&[&outer, &inner]), &node, bounds()),
            );
            let epoch = |read: Result<(System, SystemInner), ReaderError>| read.unwrap().1.epoch();

            assert_eq!(epoch(direct.verified_system_inner(system_id).await), 462);
            // Past the anchor refresh interval: the next read goes to this
            // node's own provider, which cannot prove the anchor.
            tokio::time::sleep(Duration::from_millis(2_100)).await;
            let started = std::time::Instant::now();
            assert_eq!(epoch(direct.verified_system_inner(system_id).await), 462);
            assert!(
                started.elapsed() < Duration::from_millis(500),
                "served from the cache without waiting for the peer: {:?}",
                started.elapsed()
            );

            tokio::time::sleep(Duration::from_millis(1_500)).await;
            let later = epoch(direct.verified_system_inner(system_id).await);
            assert_eq!(later, if honest { 463 } else { 462 });
        }
    }
}
