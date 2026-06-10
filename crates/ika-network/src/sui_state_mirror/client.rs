// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! sui-state-mirrored side of the [`SuiStateMirror`] service. Two adapters live here:
//!
//! - [`SuiMirrorProofProvider`] implements
//!   [`crate::proof_provider::ProofProvider`] — the verified-read surface
//!   the consumer uses (see `OcsVerifiedReader`).
//! - [`SuiMirrorTransport`] implements [`SuiTransport`] for the
//!   committee-ratchet primitives only (full-checkpoint fetch,
//!   end-of-epoch resolution, tx→checkpoint lookup). Methods that
//!   can't be relayed (`get_object`, `get_committee`, `get_transaction`,
//!   `execute_transaction`, ...) error out — the OCS verifier should be
//!   reaching for the proof-bearing surface instead.
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
use sui_types::effects::TransactionEffects;
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
    BatchVerifiedObjectsRequest, GetCheckpointSummaryByDigestRequest, GetFullCheckpointRequest,
    GetTransactionCheckpointRequest, LastCheckpointOfEpochRequest, SubmitTransactionRequest,
    SuiStateMirrorClient, VerifiedObjectRequest,
};

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
        let mut all_not_found = true;
        let mut tried_any = false;
        for peer_id in peers {
            let Some(peer) = self.network.peer(peer_id) else {
                debug!(?peer_id, "{op_label}: peer not connected, skipping");
                continue;
            };
            tried_any = true;
            let mut client = SuiStateMirrorClient::new(peer);
            match op(&mut client).await {
                Ok(resp) => return Ok(resp.into_inner()),
                Err(status) => {
                    if status.status() != anemo::types::response::StatusCode::NotFound {
                        all_not_found = false;
                    }
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
            }
        }
        // Preserve `NotFound` semantics across the relay: if every peer
        // we successfully reached said NotFound, the underlying data
        // really doesn't exist (committee ratchet uses this distinction
        // to decide whether to fall back to direct committee fetch).
        if tried_any && all_not_found {
            return Err(TransportError::NotFound(
                last_err.unwrap_or_else(|| format!("{op_label}: not found")),
            ));
        }
        Err(TransportError::Network(format!(
            "{op_label}: all peers failed (last: {})",
            last_err.unwrap_or_else(|| "no peers reachable".into())
        )))
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
        tx: &Transaction,
    ) -> Result<SubmittedTransaction, TransportError> {
        // Peer-only submission: forward our own signed tx to a direct peer,
        // which submits it and returns the committed effects.
        //
        // What IS verified: that the relay echoed our digest, and that the tx
        // is committed under a checkpoint (`get_transaction_checkpoint`,
        // itself relay-served and committee-anchored via the ratchet). A
        // relay can't forge a *committed* tx — Sui rejects any tampered tx
        // and the digest is deterministic — and a censoring/withholding peer
        // surfaces as a retry, not a falsely-committed result.
        //
        // What is NOT verified: the effects BYTES. They come from the relay's
        // word; a malicious relay could return fabricated effects (e.g. claim
        // success for an aborted tx) for a genuinely-committed digest. This
        // is acceptable today only because no caller reaches this path: the
        // writer is notifier-gated and notifiers run direct gRPC, so a
        // peer-only node never submits. Before any real submitter uses this,
        // the effects must be verified against the committed checkpoint
        // (effects digest is bound by the checkpoint contents/artifacts).
        let digest = *tx.digest();
        let tx = tx.clone();
        let resp = self
            .peers
            .try_peers("submit_transaction", move |c| {
                let req = Request::new(SubmitTransactionRequest { tx: tx.clone() });
                Box::pin(async move { c.submit_transaction(req).await })
            })
            .await?;
        if resp.digest != digest {
            return Err(TransportError::Network(format!(
                "submit_transaction: peer returned digest {} for tx {digest}",
                resp.digest
            )));
        }
        // Confirm committed under a BLS-signed checkpoint (this call is itself
        // relay-served and committee-anchored on the ratchet side).
        self.get_transaction_checkpoint(digest).await?;
        let effects: TransactionEffects = bcs::from_bytes(&resp.effects_bcs).map_err(|e| {
            TransportError::Encoding(format!("decode relayed effects for {digest}: {e}"))
        })?;
        Ok(SubmittedTransaction { digest, effects })
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
