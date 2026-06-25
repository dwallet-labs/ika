// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! sui-state-mirrored side of the [`SuiStateMirror`] service. Two adapters live here:
//!
//! - [`SuiMirrorProofProvider`] implements
//!   [`crate::proof_provider::ProofProvider`] — the verified-read surface
//!   the consumer uses (see `OcsVerifiedReader`).
//! - [`SuiMirrorTransport`] implements [`SuiTransport`] for the
//!   committee-ratchet primitives (full-checkpoint fetch, end-of-epoch
//!   resolution, tx→checkpoint lookup) and peer-only tx submission
//!   (`execute_transaction` — forward our own signed tx to a direct peer;
//!   its `SubmittedTransaction` return is `Deserialize`, so it relays).
//!   The non-ratchet reads error out: `get_object` (use the proof-bearing
//!   surface instead), and `get_committee` / `get_transaction` /
//!   `list_owned_gas_coins` (served by the direct fallback — only
//!   `get_transaction`'s `ExecutedTransaction` return is genuinely
//!   non-`Deserialize`).
//!
//! Both adapters share an identical multi-peer health strategy: try
//! peers in order, demote on failure.
//!
//! Trust-wise, the relayer is untrusted; every byte returned through the
//! verified-read surface is checked by the consumer-side
//! `OcsVerifiedReader` against `CommitteeStore`.

use std::sync::Arc;

use anemo::{Network, PeerId, Request};
use async_trait::async_trait;
use parking_lot::RwLock;
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, SuiAddress, TransactionDigest};
use sui_types::digests::CheckpointDigest;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::object::Object;
use sui_types::transaction::Transaction;
use tracing::{debug, warn};

use ika_sui_client::transport::{
    DynamicFieldPage, ExecutedTransaction, SubmittedTransaction, SuiTransport, TransportError,
};

use crate::proof_provider::{
    BatchVerifiedObjectsResponse, ProofProvider, ProofProviderMetrics, VerifiedBagPageRequest,
    VerifiedBagPageResponse, VerifiedObjectResponse,
};

use super::{
    BatchVerifiedObjectsRequest, ChangesetPageRequest, ChangesetPageResponse,
    GetCheckpointSummaryByDigestRequest, GetFullCheckpointRequest, GetTransactionCheckpointRequest,
    LastCheckpointOfEpochRequest, SuiStateMirrorClient, VerifiedObjectRequest,
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
    peers: Arc<RwLock<Vec<PeerId>>>,
    /// Round-robin start offset so the fleet spreads reads across serving
    /// peers instead of every node hammering `peers[0]`. Each `try_peers`
    /// pass still visits all peers (preserving the NotFound-only-if-all
    /// semantics); only the *order* rotates.
    next_start: Arc<std::sync::atomic::AtomicUsize>,
    metrics: Arc<ProofProviderMetrics>,
}

impl SuiMirrorPeers {
    pub fn new(network: Network, peers: Vec<PeerId>, metrics: Arc<ProofProviderMetrics>) -> Self {
        Self {
            network,
            peers: Arc::new(RwLock::new(peers)),
            next_start: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            metrics,
        }
    }

    pub fn replace_peers(&self, peers: Vec<PeerId>) {
        *self.peers.write() = peers;
    }

    fn snapshot(&self) -> Vec<PeerId> {
        self.peers.read().clone()
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
            return Err(TransportError::Network(format!(
                "{op_label}: no SuiStateMirror peers configured"
            )));
        }
        // Spread load: rotate the start of the pass round-robin. Still a full
        // pass over every peer, so the all-peers-NotFound semantics below hold.
        if peers.len() > 1 {
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

    async fn verified_bag_page(
        &self,
        request: VerifiedBagPageRequest,
    ) -> Result<VerifiedBagPageResponse, TransportError> {
        let started = std::time::Instant::now();
        self.record_relay_request("verified_bag_page");
        let result = self
            .peers
            .try_peers("verified_bag_page", move |c| {
                let req = Request::new(request.clone());
                Box::pin(async move { c.verified_bag_page(req).await })
            })
            .await
            .inspect_err(|e| self.record_relay_failure("verified_bag_page", e));
        self.record_relay_latency("verified_bag_page", started);
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

    async fn get_reference_gas_price(&self) -> Result<u64, TransportError> {
        self.peers
            .try_peers("get_reference_gas_price", |c| {
                Box::pin(async move { c.get_reference_gas_price(Request::new(())).await })
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

    async fn get_transaction_checkpoint(
        &self,
        tx: TransactionDigest,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        self.peers
            .try_peers("get_transaction_checkpoint", move |c| {
                let req = Request::new(GetTransactionCheckpointRequest { tx });
                Box::pin(async move { c.get_transaction_checkpoint(req).await })
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
             surface; use ProofProvider::verified_bag_page instead"
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

    async fn execute_transaction(
        &self,
        _tx: &Transaction,
    ) -> Result<SubmittedTransaction, TransportError> {
        // FAIL-CLOSED. A relay cannot return committee-verified transaction
        // EFFECTS: only the echoed digest and a relay-served commit confirmation
        // are checkable; the effects bytes would be the relay's unverified word
        // (a malicious relay could claim success for an aborted-but-committed
        // digest). Rather than forward and return those unverified effects, refuse.
        //
        // This path is unreachable today — writes are notifier-gated and notifiers
        // run direct gRPC; `FallbackTransport` routes `execute_transaction` to the
        // direct uplink and `VerifiedSuiTransport::execute_transaction` is itself
        // unreachable — so a future change that wires a bare `SuiMirrorTransport`
        // as a submitter (or drops those guards) now fails LOUDLY here instead of
        // trusting forged effects. To support peer-only submit, first verify the
        // effects against the committed checkpoint's artifacts before returning.
        Err(TransportError::Network(
            "SuiMirrorTransport::execute_transaction is unsupported: a relay cannot \
             return committee-verified effects. Submit over a direct uplink."
                .to_string(),
        ))
    }

    async fn list_owned_gas_coins(
        &self,
        _address: SuiAddress,
    ) -> Result<Vec<ObjectRef>, TransportError> {
        Err(TransportError::Network(
            "list_owned_gas_coins is not relayable over SuiStateMirror; use a \
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
}
