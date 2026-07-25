// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! sui-state-mirrored side of the [`SuiStateMirror`] service. Two adapters live here:
//!
//! - [`SuiMirrorProofProvider`] implements
//!   [`crate::proof_provider::ProofProvider`] — the verified-read surface
//!   the consumer uses (see `OcsVerifiedReader`).
//! - [`SuiMirrorTransport`] implements [`SuiTransport`] for the
//!   committee-ratchet primitives (full-checkpoint fetch, end-of-epoch
//!   resolution). Every other `SuiTransport` method errors out: object reads
//!   use the proof-bearing surface instead, and `get_committee` /
//!   `get_transaction` fall through to the direct fallback. It implements no
//!   writer surface (`SuiWriter`) at all — a relay can neither submit nor price
//!   transactions (writes are notifier-gated to a direct uplink).
//!
//! Both adapters share an identical multi-peer health strategy: try
//! peers in order, demote on failure. The peer set comes in two modes
//! (selected by whether `sui-state-mirror-peers` is configured):
//! a pinned operator override, or automatic discovery — every operation
//! snapshots the peers currently connected through Ika's discovery
//! system, and a connected peer that doesn't serve `SuiStateMirror`
//! fails fast (anemo route miss) and is skipped.
//!
//! Trust-wise, the relayer is untrusted; every byte returned through the
//! verified-read surface is checked by the consumer-side
//! `OcsVerifiedReader` against `CommitteeStore`.

use std::sync::Arc;

use anemo::{Network, PeerId, Request};
use async_trait::async_trait;
use futures::future::join_all;
use parking_lot::RwLock;
use sui_types::base_types::{ObjectID, SequenceNumber, TransactionDigest};
use sui_types::digests::CheckpointDigest;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::object::Object;
use tracing::{debug, warn};

use ika_sui_client::transport::{
    DynamicFieldPage, ExecutedTransaction, SuiTransport, TransportError,
};

use crate::proof_provider::{
    BatchVerifiedObjectsResponse, ProofProvider, ProofProviderMetrics,
    VerifiedDynamicFieldsPageRequest, VerifiedDynamicFieldsPageResponse, VerifiedObjectResponse,
};

use super::{
    BatchVerifiedObjectsRequest, ChangesetPageRequest, ChangesetPageResponse,
    GetCheckpointSummaryByDigestRequest, GetFullCheckpointRequest, LastCheckpointOfEpochRequest,
    SuiStateMirrorClient, VerifiedObjectRequest,
};

/// Per-peer, per-request deadline for relay reads. anemo configures no
/// default outbound timeout and QUIC keep-alives keep an idle-but-connected
/// peer's connection alive, so without this a peer that accepts the stream and
/// never responds would hang the read forever and starve `try_peers` of any
/// failover. Matches the 30s the push path already uses.
const RELAY_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone)]
pub struct SuiMirrorPeers {
    network: Network,
    /// The peer-selection working set. Pinned mode: the operator-configured
    /// list, reordered by demotion. Automatic mode: a preference-order cache
    /// over the currently-connected peers, reconciled against the live
    /// connection set on every [`Self::snapshot`] (so demotion ordering
    /// persists across passes for as long as a peer stays connected).
    peers: Arc<RwLock<Vec<PeerId>>>,
    /// True when the operator configured an explicit non-empty
    /// `sui-state-mirror-peers` list. False selects automatic mode: every
    /// operation works over the peers connected through Ika's discovery
    /// system at that moment.
    pinned: bool,
    /// Pinned mode only: round-robin start offset so the fleet spreads reads
    /// across serving peers instead of every node hammering `peers[0]` of the
    /// shared operator-written list. Each `try_peers` pass still visits all
    /// peers (preserving the NotFound-only-if-all semantics); only the *order*
    /// rotates. Automatic mode never rotates (see `try_peers`): demotion is
    /// its shield against non-serving/stalling peers, and rotation would cycle
    /// the pass start right back into the demoted tail.
    next_start: Arc<std::sync::atomic::AtomicUsize>,
    metrics: Arc<ProofProviderMetrics>,
}

impl SuiMirrorPeers {
    /// `peers` is the operator's pinned override; an EMPTY list selects
    /// automatic mode, where each operation snapshots the peers currently
    /// connected on the anemo network instead of a static list.
    pub fn new(network: Network, peers: Vec<PeerId>, metrics: Arc<ProofProviderMetrics>) -> Self {
        let pinned = !peers.is_empty();
        Self {
            network,
            peers: Arc::new(RwLock::new(peers)),
            pinned,
            next_start: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            metrics,
        }
    }

    fn snapshot(&self) -> Vec<PeerId> {
        if self.pinned {
            return self.peers.read().clone();
        }
        // Automatic mode: work over the peers connected RIGHT NOW — peers
        // connect, disconnect, and change across epoch transitions, so the
        // set must track the live discovery/network state, not a boot-time
        // capture. The stored list is only an ordering memory layered on top.
        let connected = self.network.peers();
        let mut order = self.peers.write();
        reconcile_preference_order(&mut order, connected);
        order.clone()
    }

    fn demote(&self, bad: PeerId) {
        let mut peers = self.peers.write();
        if let Some(pos) = peers.iter().position(|p| p == &bad) {
            let id = peers.remove(pos);
            peers.push(id);
        }
    }

    /// Iterate peers, calling `op` against a fresh `SuiStateMirrorClient` for
    /// each. Returns the first `Ok`. Demotes peers that fail.
    async fn try_peers<T, F>(&self, op_label: &'static str, mut op: F) -> Result<T, TransportError>
    where
        F: for<'a> FnMut(
            &'a mut SuiStateMirrorClient<anemo::Peer>,
        ) -> futures::future::BoxFuture<
            'a,
            Result<anemo::Response<T>, anemo::rpc::Status>,
        >,
    {
        let mut peers = self.snapshot();
        if peers.is_empty() {
            // Pinned mode always has a non-empty list (the mode is selected by
            // non-emptiness at construction), so an empty snapshot means
            // automatic mode found no connected peers to try.
            return Err(TransportError::Network(format!(
                "{op_label}: no connected p2p peers to relay through (automatic \
                 SuiStateMirror peer discovery; is the p2p network up?)"
            )));
        }
        // Pinned mode: spread load by rotating the start of the pass
        // round-robin — the fleet shares one operator-written list, so without
        // rotation every node would hammer `peers[0]`. Still a full pass over
        // every peer, so the all-peers-NotFound semantics below hold.
        //
        // Automatic mode deliberately does NOT rotate: rotation would cycle
        // the start through the demoted tail (non-serving committee peers, or
        // a stalling one that costs the full per-request timeout), taxing a
        // 1/n share of every read and neutralizing demotion. Each pass starts
        // at the preference-order head instead — demoted peers are only
        // revisited when everything ahead of them fails. Fleet load still
        // spreads because each node's preference order is emergent (its own
        // connection order + demotion history), not a shared list.
        if self.pinned && peers.len() > 1 {
            let start = self
                .next_start
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                % peers.len();
            peers.rotate_left(start);
        }

        let mut last_err: Option<String> = None;
        // One entry per peer we actually reached and that failed (a success
        // short-circuits the pass). The relay verdict is computed from these.
        let mut reached: Vec<PeerFailure> = Vec::new();
        for peer_id in peers {
            let Some(peer) = self.network.peer(peer_id) else {
                debug!(?peer_id, "{op_label}: peer not connected, skipping");
                continue;
            };
            let mut client = SuiStateMirrorClient::new(peer);
            match tokio::time::timeout(RELAY_REQUEST_TIMEOUT, op(&mut client)).await {
                Ok(Ok(resp)) => return Ok(resp.into_inner()),
                Ok(Err(status)) if is_service_unimplemented(&status) => {
                    // The peer is connected but doesn't serve `SuiStateMirror`
                    // at all (anemo's router fallback for an unregistered
                    // route). Expected in automatic mode, where discovery
                    // connects every committee peer, mirrored/peer-only ones
                    // included — but a misconfigured entry in pinned mode, so
                    // that mode keeps the warn + failover metric the error arm
                    // would have produced. Either way the peer is treated like
                    // a not-connected one: demoted and skipped WITHOUT
                    // counting as "reached", so a set of non-serving peers can
                    // neither manufacture an all-peers-NotFound data-absence
                    // verdict nor destroy one produced by genuinely-serving
                    // peers.
                    if self.pinned {
                        warn!(
                            ?peer_id,
                            "{op_label}: configured sui-state-mirror peer does not serve \
                             SuiStateMirror (misconfigured pin?), trying next"
                        );
                        self.metrics
                            .relay_peer_failover_total
                            .with_label_values(&[op_label, &peer_id.to_string()])
                            .inc();
                    } else {
                        debug!(
                            ?peer_id,
                            "{op_label}: peer does not serve SuiStateMirror, trying next"
                        );
                    }
                    self.demote(peer_id);
                    last_err = Some(format!("peer {peer_id} does not serve SuiStateMirror"));
                }
                Ok(Err(status)) => {
                    // Only a genuine NotFound keeps the all-peers-NotFound verdict
                    // alive; any other error is a peer/network failure.
                    reached.push(
                        if status.status() == anemo::types::response::StatusCode::NotFound {
                            PeerFailure::NotFound
                        } else {
                            PeerFailure::Unreachable
                        },
                    );
                    warn!(
                        ?peer_id,
                        ?status,
                        "{op_label}: peer returned error, trying next"
                    );
                    self.metrics
                        .relay_peer_failover_total
                        .with_label_values(&[op_label, &peer_id.to_string()])
                        .inc();
                    self.demote(peer_id);
                    last_err = Some(format!("{status:?}"));
                }
                Err(_elapsed) => {
                    // A timeout is a peer/network failure, not a NotFound, so it
                    // must not be folded into the all-peers-NotFound result that
                    // the committee ratchet keys its fallback decision on.
                    reached.push(PeerFailure::Unreachable);
                    warn!(
                        ?peer_id,
                        timeout = ?RELAY_REQUEST_TIMEOUT,
                        "{op_label}: peer timed out, trying next"
                    );
                    self.metrics
                        .relay_peer_failover_total
                        .with_label_values(&[op_label, &peer_id.to_string()])
                        .inc();
                    self.demote(peer_id);
                    last_err = Some(format!("{op_label}: peer {peer_id} timed out"));
                }
            }
        }
        // Verdict for a pass in which no peer returned a successful response.
        Err(classify_failed_pass(op_label, &reached, last_err))
    }
}

/// One reached-but-failed peer's outcome within a `try_peers` pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerFailure {
    /// The peer answered `NotFound` — the data may genuinely be absent.
    NotFound,
    /// The peer returned a non-`NotFound` error, or timed out: a peer/network
    /// failure that must NOT be folded into the all-peers-NotFound verdict.
    Unreachable,
}

/// The relay verdict for a pass in which no peer returned a successful response.
///
/// `NotFound` is preserved across the untrusted relay ONLY when at least one
/// peer was reached AND every reached peer answered `NotFound` — the committee
/// ratchet keys its "fall back to a direct committee fetch" decision on exactly
/// this distinction, so a timeout or any non-`NotFound` error (and the
/// no-peer-reached case) must downgrade the verdict to a retriable `Network`
/// error. (Spec invariant 6.)
fn classify_failed_pass(
    op_label: &str,
    reached: &[PeerFailure],
    last_err: Option<String>,
) -> TransportError {
    let all_not_found = !reached.is_empty() && reached.iter().all(|f| *f == PeerFailure::NotFound);
    if all_not_found {
        TransportError::NotFound(last_err.unwrap_or_else(|| format!("{op_label}: not found")))
    } else {
        TransportError::Network(format!(
            "{op_label}: all peers failed (last: {})",
            last_err.unwrap_or_else(|| "no peers reachable".into())
        ))
    }
}

/// Reconcile the automatic-mode preference order with the currently-connected
/// set: drop peers no longer connected, append newly-connected peers at the
/// back. Peers already in the order keep their positions, so proven peers stay
/// preferred and demoted ones stay at the back until they disconnect.
fn reconcile_preference_order(order: &mut Vec<PeerId>, connected: Vec<PeerId>) {
    order.retain(|peer_id| connected.contains(peer_id));
    for peer_id in connected {
        if !order.contains(&peer_id) {
            order.push(peer_id);
        }
    }
}

/// True when `status` is anemo's router fallback for an unregistered route — a
/// bare `NotFound` with no `status-message` header — meaning the peer does not
/// serve the `SuiStateMirror` service at all. Every data-absence `NotFound`
/// the service itself returns goes through the server's `map_err`, which
/// always attaches a message (carried on the wire in the `status-message`
/// header), so header presence is what separates "the peer answered: the data
/// does not exist" from "the peer has no such service".
fn is_service_unimplemented(status: &anemo::rpc::Status) -> bool {
    status.status() == anemo::types::response::StatusCode::NotFound
        && !status
            .headers()
            .contains_key(anemo::types::header::STATUS_MESSAGE)
}

/// Per-peer timeout for [`find_serving_mirror_peer`] probes: generous for a
/// healthy peer's trivial `get_chain_identifier` round-trip, short enough that
/// a hung peer doesn't stall the startup wait loop it is called from.
const SERVING_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Probe the currently-connected peers for one that actually serves the
/// `SuiStateMirror` service (a cheap `get_chain_identifier` round-trip; a peer
/// without the service fails fast on anemo's route miss). Used by the
/// sui-state-mirrored startup wait in automatic discovery mode, where mere
/// connectivity is not enough: discovery connects every committee peer and
/// most may be mirrored nodes that don't serve the relay.
pub async fn find_serving_mirror_peer(network: &Network) -> Option<PeerId> {
    let probes = network.peers().into_iter().filter_map(|peer_id| {
        let peer = network.peer(peer_id)?;
        Some(async move {
            let mut client = SuiStateMirrorClient::new(peer);
            let probe = client.get_chain_identifier(Request::new(()));
            match tokio::time::timeout(SERVING_PROBE_TIMEOUT, probe).await {
                Ok(Ok(_)) => Some(peer_id),
                _ => None,
            }
        })
    });
    join_all(probes).await.into_iter().flatten().next()
}

// -- Verified-read surface --------------------------------------------------------------------

pub struct SuiMirrorProofProvider {
    peers: SuiMirrorPeers,
    metrics: Arc<ProofProviderMetrics>,
}

impl SuiMirrorProofProvider {
    pub fn new(peers: SuiMirrorPeers, metrics: Arc<ProofProviderMetrics>) -> Self {
        Self { peers, metrics }
    }

    fn record_relay_request(&self, op: &'static str) {
        self.metrics
            .relay_request_total
            .with_label_values(&[op])
            .inc();
    }

    fn record_relay_latency(&self, op: &'static str, started: std::time::Instant) {
        self.metrics
            .relay_request_latency_seconds
            .with_label_values(&[op])
            .observe(started.elapsed().as_secs_f64());
    }

    fn record_relay_failure(&self, op: &'static str, err: &TransportError) {
        let reason = match err {
            TransportError::NotFound(_) => "not_found",
            TransportError::Encoding(_) => "encoding",
            TransportError::Network(_) => "network",
        };
        self.metrics
            .relay_failures_total
            .with_label_values(&[op, reason])
            .inc();
    }
}

#[async_trait]
impl ProofProvider for SuiMirrorProofProvider {
    async fn verified_object(
        &self,
        id: ObjectID,
    ) -> Result<VerifiedObjectResponse, TransportError> {
        let started = std::time::Instant::now();
        self.record_relay_request("verified_object");
        let result = self
            .peers
            .try_peers("verified_object", move |c| {
                let req = Request::new(VerifiedObjectRequest { id });
                Box::pin(async move { c.verified_object(req).await })
            })
            .await
            .inspect_err(|e| self.record_relay_failure("verified_object", e));
        self.record_relay_latency("verified_object", started);
        result
    }

    async fn batch_verified_objects(
        &self,
        ids: &[ObjectID],
    ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
        let started = std::time::Instant::now();
        self.record_relay_request("batch_verified_objects");
        let ids = ids.to_vec();
        let result = self
            .peers
            .try_peers("batch_verified_objects", move |c| {
                let req = Request::new(BatchVerifiedObjectsRequest { ids: ids.clone() });
                Box::pin(async move { c.batch_verified_objects(req).await })
            })
            .await
            .inspect_err(|e| self.record_relay_failure("batch_verified_objects", e));
        self.record_relay_latency("batch_verified_objects", started);
        result
    }

    async fn verified_dynamic_fields_page(
        &self,
        request: VerifiedDynamicFieldsPageRequest,
    ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
        let started = std::time::Instant::now();
        self.record_relay_request("verified_dynamic_fields_page");
        let result = self
            .peers
            .try_peers("verified_dynamic_fields_page", move |c| {
                let req = Request::new(request.clone());
                Box::pin(async move { c.verified_dynamic_fields_page(req).await })
            })
            .await
            .inspect_err(|e| self.record_relay_failure("verified_dynamic_fields_page", e));
        self.record_relay_latency("verified_dynamic_fields_page", started);
        result
    }
}

// -- Ratchet-primitive surface (a small SuiTransport) -----------------------------------------

pub struct SuiMirrorTransport {
    peers: SuiMirrorPeers,
}

impl SuiMirrorTransport {
    pub fn new(peers: SuiMirrorPeers) -> Self {
        Self { peers }
    }

    /// Pull a page of changesets (committee-signed summary + modified
    /// object-set per checkpoint) starting at `from_seq`, for a mirrored node
    /// to fold for currency. Not part of [`SuiTransport`] — a separate
    /// capability the changeset-stream receiver calls; each entry is still
    /// committee-bound (the receiver checks it against the summary).
    pub async fn changeset_page(
        &self,
        from_seq: CheckpointSequenceNumber,
        limit: u32,
    ) -> Result<ChangesetPageResponse, TransportError> {
        self.peers
            .try_peers("changeset_page", move |c| {
                let req = Request::new(ChangesetPageRequest { from_seq, limit });
                Box::pin(async move { c.changeset_page(req).await })
            })
            .await
    }
}

#[async_trait]
impl SuiTransport for SuiMirrorTransport {
    async fn get_chain_identifier(&self) -> Result<String, TransportError> {
        self.peers
            .try_peers("get_chain_identifier", |c| {
                Box::pin(async move { c.get_chain_identifier(Request::new(())).await })
            })
            .await
    }

    async fn get_current_epoch(&self) -> Result<u64, TransportError> {
        self.peers
            .try_peers("get_current_epoch", |c| {
                Box::pin(async move { c.get_current_epoch(Request::new(())).await })
            })
            .await
    }

    async fn get_latest_checkpoint(&self) -> Result<CertifiedCheckpointSummary, TransportError> {
        self.peers
            .try_peers("get_latest_checkpoint", |c| {
                Box::pin(async move { c.get_latest_checkpoint(Request::new(())).await })
            })
            .await
    }

    async fn get_full_checkpoint(
        &self,
        seq: CheckpointSequenceNumber,
    ) -> Result<CheckpointData, TransportError> {
        self.peers
            .try_peers("get_full_checkpoint", move |c| {
                let req = Request::new(GetFullCheckpointRequest { seq });
                Box::pin(async move { c.get_full_checkpoint(req).await })
            })
            .await
    }

    async fn get_checkpoint_summary_by_digest(
        &self,
        digest: CheckpointDigest,
    ) -> Result<CertifiedCheckpointSummary, TransportError> {
        self.peers
            .try_peers("get_checkpoint_summary_by_digest", move |c| {
                let req = Request::new(GetCheckpointSummaryByDigestRequest { digest });
                Box::pin(async move { c.get_checkpoint_summary_by_digest(req).await })
            })
            .await
    }

    async fn last_checkpoint_of_epoch(
        &self,
        epoch: u64,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        self.peers
            .try_peers("last_checkpoint_of_epoch", move |c| {
                let req = Request::new(LastCheckpointOfEpochRequest { epoch });
                Box::pin(async move { c.last_checkpoint_of_epoch(req).await })
            })
            .await
    }

    async fn get_committee(
        &self,
        _epoch: Option<u64>,
    ) -> Result<sui_types::committee::Committee, TransportError> {
        Err(TransportError::Network(
            "get_committee is not relayed over SuiStateMirror; \
             sui-state-mirrored should re-anchor or use the FallbackTransport"
                .into(),
        ))
    }

    async fn get_object(&self, _id: ObjectID) -> Result<Object, TransportError> {
        Err(TransportError::Network(
            "get_object is not exposed by the verified mirror surface; use \
             ProofProvider::verified_object instead"
                .into(),
        ))
    }

    async fn get_object_with_version(
        &self,
        _id: ObjectID,
        _version: SequenceNumber,
    ) -> Result<Object, TransportError> {
        Err(TransportError::Network(
            "get_object_with_version is not exposed by the verified mirror \
             surface"
                .into(),
        ))
    }

    async fn batch_get_objects(&self, _ids: &[ObjectID]) -> Result<Vec<Object>, TransportError> {
        Err(TransportError::Network(
            "batch_get_objects is not exposed by the verified mirror surface; \
             use ProofProvider::batch_verified_objects instead"
                .into(),
        ))
    }

    async fn list_dynamic_fields(
        &self,
        _parent: ObjectID,
        _page_size: Option<u32>,
        _page_token: Option<Vec<u8>>,
    ) -> Result<DynamicFieldPage, TransportError> {
        Err(TransportError::Network(
            "list_dynamic_fields is not exposed by the verified mirror \
             surface; use ProofProvider::verified_dynamic_fields_page instead"
                .into(),
        ))
    }

    async fn get_transaction(
        &self,
        _tx: TransactionDigest,
    ) -> Result<ExecutedTransaction, TransportError> {
        Err(TransportError::Network(
            "get_transaction is not relayable over SuiStateMirror; use a \
             fallback gRPC client"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The relay verdict for a pass in which no peer succeeded: `NotFound` is
    /// preserved across the untrusted relay ONLY when at least one peer was
    /// reached and EVERY reached peer answered `NotFound`; a timeout, any
    /// non-`NotFound` error, or no peer reached at all downgrades to a retriable
    /// `Network` error. The committee ratchet's fall-back-to-direct decision keys
    /// on exactly this distinction (spec invariant 6), so this is a trust gate.
    /// (The anemo round-trip / demotion plumbing is covered by the cluster
    /// failover tests; this pins the classification logic deterministically.)
    #[test]
    fn try_peers_verdict_preserves_notfound_only_when_all_reached_agree() {
        use PeerFailure::{NotFound, Unreachable};

        // (a) every reached peer NotFound -> NotFound (carries the last message).
        match classify_failed_pass("op", &[NotFound, NotFound, NotFound], Some("gone".into())) {
            TransportError::NotFound(msg) => assert_eq!(msg, "gone"),
            other => panic!("all-NotFound must be NotFound, got {other:?}"),
        }
        // A single reached peer that said NotFound is still NotFound.
        match classify_failed_pass("op", &[NotFound], None) {
            TransportError::NotFound(_) => {}
            other => panic!("single NotFound must be NotFound, got {other:?}"),
        }
        // (b) mixed NotFound + a non-NotFound error -> Network (never NotFound).
        match classify_failed_pass("op", &[NotFound, Unreachable], Some("boom".into())) {
            TransportError::Network(_) => {}
            other => panic!("a non-NotFound error must downgrade to Network, got {other:?}"),
        }
        // (c) a single timeout / network error -> Network, never NotFound.
        match classify_failed_pass("op", &[Unreachable], Some("timed out".into())) {
            TransportError::Network(_) => {}
            other => panic!("a timeout must be Network, got {other:?}"),
        }
        // (d) no peer reached (tried_any == false) -> Network, never NotFound.
        match classify_failed_pass("op", &[], None) {
            TransportError::Network(msg) => assert!(msg.contains("no peers reachable")),
            other => panic!("no peer reached must be Network, got {other:?}"),
        }
    }

    /// `reconcile_preference_order` (the automatic-mode snapshot core): peers
    /// already in the order keep their positions (so demotion survives across
    /// passes), disconnected peers drop out, newly-connected peers append at
    /// the back behind the proven ones.
    #[test]
    fn reconcile_preference_order_keeps_order_drops_gone_appends_new() {
        let first = PeerId([1; 32]);
        let second = PeerId([2; 32]);
        let third = PeerId([3; 32]);
        let fourth = PeerId([4; 32]);

        // `second` was demoted behind `third`; `third` disconnects; `fourth`
        // is newly connected. Connected-set order must not matter.
        let mut order = vec![first, third, second];
        reconcile_preference_order(&mut order, vec![fourth, second, first]);
        assert_eq!(order, vec![first, second, fourth]);

        // Steady state is idempotent.
        reconcile_preference_order(&mut order, vec![fourth, second, first]);
        assert_eq!(order, vec![first, second, fourth]);

        // Everything disconnected -> empty.
        reconcile_preference_order(&mut order, vec![]);
        assert!(order.is_empty());
    }

    /// Classification of anemo's route-miss `NotFound` (the peer has no
    /// `SuiStateMirror` service) vs the service's own data-absence `NotFound`:
    /// the service always attaches a message (`map_err` puts it on the wire in
    /// the `status-message` header), the router fallback never does.
    /// Misclassifying a route miss as data absence would let a set of
    /// non-serving peers manufacture the all-peers-NotFound verdict the
    /// committee ratchet keys its fallback decision on (spec invariant 6).
    #[test]
    fn route_miss_not_found_is_service_absent_not_data_absence() {
        use anemo::rpc::Status;
        use anemo::types::header::STATUS_MESSAGE;
        use anemo::types::response::{IntoResponse, StatusCode};

        // Wire shapes: data-absence carries the status-message header...
        let genuine = Status::new_with_message(StatusCode::NotFound, "gone").into_response();
        assert!(genuine.headers().contains_key(STATUS_MESSAGE));
        // ...anemo's route-miss fallback is a bare NotFound without it.
        let route_miss = StatusCode::NotFound.into_response();
        assert!(!route_miss.headers().contains_key(STATUS_MESSAGE));

        // Classification over client-side `Status` values of the same shapes.
        assert!(is_service_unimplemented(&Status::new(StatusCode::NotFound)));
        assert!(!is_service_unimplemented(
            &Status::new(StatusCode::NotFound).with_header(STATUS_MESSAGE, "gone")
        ));
        assert!(!is_service_unimplemented(&Status::internal("boom")));
    }

    /// Minimal `SuiStateMirror` impl for the automatic-discovery test below:
    /// `get_chain_identifier` answers, `last_checkpoint_of_epoch` returns the
    /// service's genuine (message-bearing) data-absence `NotFound`, everything
    /// else errors as unused.
    struct StubMirror;

    #[anemo::async_trait]
    impl crate::sui_state_mirror::SuiStateMirror for StubMirror {
        async fn get_chain_identifier(
            &self,
            _: Request<()>,
        ) -> Result<anemo::Response<String>, anemo::rpc::Status> {
            Ok(anemo::Response::new("test-chain".to_string()))
        }
        async fn get_current_epoch(
            &self,
            _: Request<()>,
        ) -> Result<anemo::Response<u64>, anemo::rpc::Status> {
            Err(anemo::rpc::Status::internal("unused"))
        }
        async fn get_latest_checkpoint(
            &self,
            _: Request<()>,
        ) -> Result<anemo::Response<CertifiedCheckpointSummary>, anemo::rpc::Status> {
            Err(anemo::rpc::Status::internal("unused"))
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            _: Request<GetCheckpointSummaryByDigestRequest>,
        ) -> Result<anemo::Response<CertifiedCheckpointSummary>, anemo::rpc::Status> {
            Err(anemo::rpc::Status::internal("unused"))
        }
        async fn get_full_checkpoint(
            &self,
            _: Request<GetFullCheckpointRequest>,
        ) -> Result<anemo::Response<CheckpointData>, anemo::rpc::Status> {
            Err(anemo::rpc::Status::internal("unused"))
        }
        async fn changeset_page(
            &self,
            _: Request<ChangesetPageRequest>,
        ) -> Result<anemo::Response<ChangesetPageResponse>, anemo::rpc::Status> {
            Err(anemo::rpc::Status::internal("unused"))
        }
        async fn last_checkpoint_of_epoch(
            &self,
            _: Request<LastCheckpointOfEpochRequest>,
        ) -> Result<anemo::Response<CheckpointSequenceNumber>, anemo::rpc::Status> {
            Err(anemo::rpc::Status::new_with_message(
                anemo::types::response::StatusCode::NotFound,
                "epoch not on chain yet",
            ))
        }
        async fn verified_object(
            &self,
            _: Request<VerifiedObjectRequest>,
        ) -> Result<anemo::Response<VerifiedObjectResponse>, anemo::rpc::Status> {
            Err(anemo::rpc::Status::internal("unused"))
        }
        async fn batch_verified_objects(
            &self,
            _: Request<BatchVerifiedObjectsRequest>,
        ) -> Result<anemo::Response<BatchVerifiedObjectsResponse>, anemo::rpc::Status> {
            Err(anemo::rpc::Status::internal("unused"))
        }
        async fn verified_dynamic_fields_page(
            &self,
            _: Request<VerifiedDynamicFieldsPageRequest>,
        ) -> Result<anemo::Response<VerifiedDynamicFieldsPageResponse>, anemo::rpc::Status>
        {
            Err(anemo::rpc::Status::internal("unused"))
        }
    }

    /// End-to-end automatic discovery over real anemo networks: a consumer
    /// connected to one serving and one non-serving peer must (a) probe out
    /// the serving peer, (b) serve reads through it on every round-robin
    /// offset (the pass that starts at the non-serving peer proves the route
    /// miss is skipped, not fatal), (c) preserve a genuine data-absence
    /// NotFound from the serving peer (the non-serving peer must not downgrade
    /// the verdict), and (d) degrade to a Network error — never NotFound —
    /// once the serving peer disconnects and only the non-serving one remains.
    #[tokio::test]
    async fn automatic_mode_skips_non_serving_peers_and_tracks_connections() {
        use crate::sui_state_mirror::SuiStateMirrorServer;
        use crate::utils::build_network;

        let serving =
            build_network(|router| router.add_rpc_service(SuiStateMirrorServer::new(StubMirror)));
        let non_serving = build_network(|router| router);
        let consumer = build_network(|router| router);

        let serving_id = consumer.connect(serving.local_addr()).await.unwrap();
        let non_serving_id = consumer.connect(non_serving.local_addr()).await.unwrap();
        assert_eq!(serving_id, serving.peer_id());
        assert_eq!(non_serving_id, non_serving.peer_id());

        // (a) the startup probe finds exactly the serving peer.
        assert_eq!(find_serving_mirror_peer(&consumer).await, Some(serving_id));

        // (b) automatic mode (empty configured list): reads succeed repeatedly.
        // Automatic passes start at the preference-order head (no rotation),
        // so if the non-serving peer happens to sit first it is skipped on its
        // route miss and demoted; (c) below then visits BOTH peers
        // deterministically (the serving peer's NotFound is not a success, so
        // the pass continues into the non-serving one).
        let metrics = ProofProviderMetrics::new(&prometheus::Registry::new());
        let peers = SuiMirrorPeers::new(consumer.clone(), vec![], metrics);
        let transport = SuiMirrorTransport::new(peers);
        for _ in 0..2 {
            assert_eq!(
                transport.get_chain_identifier().await.unwrap(),
                "test-chain"
            );
        }

        // (c) the serving peer's genuine NotFound survives the non-serving
        // peer's presence in the pass (route misses don't count as "reached").
        match transport.last_checkpoint_of_epoch(7).await {
            Err(TransportError::NotFound(_)) => {}
            other => panic!("expected data-absence NotFound, got {other:?}"),
        }

        // (d) disconnect the serving peer and wait until the connection set
        // reflects it; the next pass sees only the non-serving peer.
        consumer.disconnect(serving_id).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while consumer.peers().contains(&serving_id) {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("serving peer should leave the connected set");
        match transport.get_chain_identifier().await {
            Err(TransportError::Network(_)) => {}
            other => panic!("expected Network error with no serving peer, got {other:?}"),
        }
    }
}
