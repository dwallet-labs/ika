// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Read-only mirror of Ika-relevant Sui state over Ika's p2p network.
//!
//! sui-state-direct validators (those with a direct Sui gRPC connection) install
//! [`SuiStateMirrorServer`] and serve **verified** reads to peers: every
//! response carries an OCS inclusion proof against a BLS-signed
//! checkpoint summary. sui-state-mirrored validators consume the same surface via
//! [`client::SuiMirrorProofProvider`], feed it into
//! [`crate::proof_provider::ProofProvider`], and let
//! `ika-core::sui_connector::verified_reader::OcsVerifiedReader` do the
//! committee verification.
//!
//! Wire layer is committee-scoped: relayer is untrusted, every byte the
//! receiver consumes is checked against the local
//! `CommitteeStore`. We never ship full `CheckpointData` over this
//! service; the few RPCs that still return one
//! (`get_full_checkpoint`, `last_checkpoint_of_epoch`,
//! `get_transaction_checkpoint`) are committee-ratchet plumbing.

mod generated {
    include!(concat!(env!("OUT_DIR"), "/ika.SuiStateMirror.rs"));
}
pub mod client;

use std::sync::Arc;

use anemo::{PeerId, Request, Response, rpc::Status, types::response::StatusCode};
use async_trait::async_trait;
use ika_sui_client::transport::{SuiTransport, TransportError};
use serde::{Deserialize, Serialize};
use sui_types::base_types::{ObjectID, TransactionDigest};
use sui_types::digests::CheckpointDigest;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::transaction::Transaction;

use crate::proof_provider::{
    BatchVerifiedObjectsResponse, ProofProvider, ProofProviderMetrics, VerifiedBagPageRequest,
    VerifiedBagPageResponse, VerifiedObjectEntry, VerifiedObjectResponse,
};

pub use client::{SuiMirrorPeers, SuiMirrorProofProvider, SuiMirrorTransport};
pub use generated::{
    sui_state_mirror_client::SuiStateMirrorClient,
    sui_state_mirror_server::{SuiStateMirror, SuiStateMirrorServer},
};

// -- Ratchet primitives -----------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetFullCheckpointRequest {
    pub seq: CheckpointSequenceNumber,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastCheckpointOfEpochRequest {
    pub epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTransactionCheckpointRequest {
    pub tx: TransactionDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCheckpointSummaryByDigestRequest {
    pub digest: CheckpointDigest,
}

// -- Verified-read primitives -----------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedObjectRequest {
    pub id: ObjectID,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerifiedObjectsRequest {
    pub ids: Vec<ObjectID>,
}

// -- Push primitive ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct PushVerifiedObjectsRequest {
    pub summary: CertifiedCheckpointSummary,
    pub objects_with_proofs: Vec<VerifiedObjectEntry>,
    /// Sequence number of the *previous* push from this sender, or
    /// `None` on the very first push since the sender booted. Receiver
    /// uses it to detect gaps: if `prev_checkpoint_seq > cache.head_seq`,
    /// at least one push was lost in transit and the receiver should
    /// re-snapshot from a direct peer (`GetVerifiedSnapshot`).
    #[serde(default)]
    pub prev_checkpoint_seq: Option<CheckpointSequenceNumber>,
}

// -- Bootstrap / gap-recovery snapshot ---------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetVerifiedSnapshotRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetVerifiedSnapshotResponse {
    /// Map from checkpoint seq to the certified summary at that seq.
    /// Each `VerifiedObjectEntry` references one of these by its
    /// `checkpoint_seq` field.
    pub summaries: std::collections::BTreeMap<CheckpointSequenceNumber, CertifiedCheckpointSummary>,
    /// All Ika-relevant objects we currently have in our cache, each
    /// with the inclusion proof we built when we first observed it.
    pub objects_with_proofs: Vec<VerifiedObjectEntry>,
    /// Highest checkpoint seq the responder's cache had been advanced
    /// to at the moment the snapshot was taken. Receivers seed
    /// `cache.head_seq` from this so subsequent push gap detection
    /// has a baseline.
    pub head_seq: CheckpointSequenceNumber,
}

// -- Peer-only tx submission ------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransactionRequest {
    pub tx: Transaction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransactionResponse {
    pub digest: TransactionDigest,
    /// BCS of `sui_types::effects::TransactionEffects`. Shipped as bytes
    /// because the SDK `ExecutedTransaction` wrapper is `Serialize`-only; the
    /// inner `TransactionEffects` round-trips fine. The submitter re-verifies
    /// the tx is committed (via `get_transaction_checkpoint`) before trusting.
    pub effects_bcs: Vec<u8>,
}

// -- Push handler trait -----------------------------------------------------------------------

/// Receive-side of [`SuiStateMirror::push_verified_objects`]. Implementer
/// is responsible for verifying each `(object, proof)` against its
/// trusted committee history and (on success) persisting the verified
/// objects.
#[async_trait]
pub trait PushVerifiedObjectsHandler: Send + Sync {
    async fn handle_pushed_verified_objects(
        &self,
        from: PeerId,
        push: PushVerifiedObjectsRequest,
    ) -> Result<(), String>;
}

/// Source of [`GetVerifiedSnapshotResponse`] for the bootstrap RPC.
/// Implemented by the verified state cache in `ika-core` (kept behind
/// a trait so the network layer doesn't depend on core).
pub trait VerifiedSnapshotProvider: Send + Sync {
    fn snapshot(&self) -> GetVerifiedSnapshotResponse;
}

// -- Server -----------------------------------------------------------------------------------

/// sui-state-direct validator-side anemo server. Serves verified reads via a
/// [`ProofProvider`] (sui-state-direct: [`crate::proof_provider::LocalProofProvider`]).
/// The ratchet primitives delegate to a [`SuiTransport`] (the same
/// underlying gRPC client the provider wraps).
///
/// `push_handler` is `None` on validators that don't accept pushes
/// (notifiers, fullnodes, sui-state-mirrored). The push RPC errors with `NotFound`
/// in that case so the sender's negative cache can suppress retries.
pub struct Server {
    transport: Arc<dyn SuiTransport>,
    provider: Arc<dyn ProofProvider>,
    push_handler: Option<Arc<dyn PushVerifiedObjectsHandler>>,
    snapshot_provider: Option<Arc<dyn VerifiedSnapshotProvider>>,
    metrics: Arc<ProofProviderMetrics>,
}

impl Server {
    pub fn new(
        transport: Arc<dyn SuiTransport>,
        provider: Arc<dyn ProofProvider>,
        metrics: Arc<ProofProviderMetrics>,
    ) -> Self {
        Self {
            transport,
            provider,
            push_handler: None,
            snapshot_provider: None,
            metrics,
        }
    }

    pub fn with_push_handler(mut self, handler: Arc<dyn PushVerifiedObjectsHandler>) -> Self {
        self.push_handler = Some(handler);
        self
    }

    pub fn with_snapshot_provider(mut self, provider: Arc<dyn VerifiedSnapshotProvider>) -> Self {
        self.snapshot_provider = Some(provider);
        self
    }

    /// Record that a relay request is being served: bump the op counter (and,
    /// when known, the per-peer counter) and return a timer for the latency
    /// histogram. Lets a serving (direct) validator see the load the mirrored
    /// fleet puts on it.
    fn serve_start(&self, op: &'static str, peer: Option<PeerId>) -> std::time::Instant {
        self.metrics
            .serve_request_total
            .with_label_values(&[op])
            .inc();
        if let Some(peer) = peer {
            self.metrics
                .serve_request_by_peer_total
                .with_label_values(&[op, &peer.to_string()])
                .inc();
        }
        std::time::Instant::now()
    }

    fn serve_end(&self, op: &'static str, started: std::time::Instant) {
        self.metrics
            .serve_latency_seconds
            .with_label_values(&[op])
            .observe(started.elapsed().as_secs_f64());
    }
}

fn map_err(e: TransportError) -> Status {
    match e {
        TransportError::NotFound(s) => Status::new_with_message(StatusCode::NotFound, s),
        TransportError::Network(s) => Status::internal(s),
        TransportError::Encoding(s) => Status::internal(s),
    }
}

#[anemo::async_trait]
impl SuiStateMirror for Server {
    async fn get_chain_identifier(&self, _: Request<()>) -> Result<Response<String>, Status> {
        let v = self
            .transport
            .get_chain_identifier()
            .await
            .map_err(map_err)?;
        Ok(Response::new(v))
    }
    async fn get_current_epoch(&self, _: Request<()>) -> Result<Response<u64>, Status> {
        let v = self.transport.get_current_epoch().await.map_err(map_err)?;
        Ok(Response::new(v))
    }
    async fn get_reference_gas_price(&self, _: Request<()>) -> Result<Response<u64>, Status> {
        let v = self
            .transport
            .get_reference_gas_price()
            .await
            .map_err(map_err)?;
        Ok(Response::new(v))
    }
    async fn get_latest_checkpoint(
        &self,
        _: Request<()>,
    ) -> Result<Response<CertifiedCheckpointSummary>, Status> {
        let v = self
            .transport
            .get_latest_checkpoint()
            .await
            .map_err(map_err)?;
        Ok(Response::new(v))
    }
    async fn get_checkpoint_summary_by_digest(
        &self,
        request: Request<GetCheckpointSummaryByDigestRequest>,
    ) -> Result<Response<CertifiedCheckpointSummary>, Status> {
        let v = self
            .transport
            .get_checkpoint_summary_by_digest(request.into_inner().digest)
            .await
            .map_err(map_err)?;
        Ok(Response::new(v))
    }
    async fn get_full_checkpoint(
        &self,
        request: Request<GetFullCheckpointRequest>,
    ) -> Result<Response<CheckpointData>, Status> {
        let v = self
            .transport
            .get_full_checkpoint(request.into_inner().seq)
            .await
            .map_err(map_err)?;
        Ok(Response::new(v))
    }
    async fn last_checkpoint_of_epoch(
        &self,
        request: Request<LastCheckpointOfEpochRequest>,
    ) -> Result<Response<CheckpointSequenceNumber>, Status> {
        let v = self
            .transport
            .last_checkpoint_of_epoch(request.into_inner().epoch)
            .await
            .map_err(map_err)?;
        Ok(Response::new(v))
    }
    async fn get_transaction_checkpoint(
        &self,
        request: Request<GetTransactionCheckpointRequest>,
    ) -> Result<Response<CheckpointSequenceNumber>, Status> {
        let v = self
            .transport
            .get_transaction_checkpoint(request.into_inner().tx)
            .await
            .map_err(map_err)?;
        Ok(Response::new(v))
    }

    async fn verified_object(
        &self,
        request: Request<VerifiedObjectRequest>,
    ) -> Result<Response<VerifiedObjectResponse>, Status> {
        let started = self.serve_start("verified_object", request.peer_id().copied());
        let v = self
            .provider
            .verified_object(request.into_inner().id)
            .await
            .map_err(map_err)?;
        self.serve_end("verified_object", started);
        Ok(Response::new(v))
    }
    async fn batch_verified_objects(
        &self,
        request: Request<BatchVerifiedObjectsRequest>,
    ) -> Result<Response<BatchVerifiedObjectsResponse>, Status> {
        let started = self.serve_start("batch_verified_objects", request.peer_id().copied());
        let v = self
            .provider
            .batch_verified_objects(&request.into_inner().ids)
            .await
            .map_err(map_err)?;
        self.serve_end("batch_verified_objects", started);
        Ok(Response::new(v))
    }
    async fn verified_bag_page(
        &self,
        request: Request<VerifiedBagPageRequest>,
    ) -> Result<Response<VerifiedBagPageResponse>, Status> {
        let started = self.serve_start("verified_bag_page", request.peer_id().copied());
        let v = self
            .provider
            .verified_bag_page(request.into_inner())
            .await
            .map_err(map_err)?;
        self.serve_end("verified_bag_page", started);
        Ok(Response::new(v))
    }

    async fn get_verified_snapshot(
        &self,
        request: Request<GetVerifiedSnapshotRequest>,
    ) -> Result<Response<GetVerifiedSnapshotResponse>, Status> {
        let started = self.serve_start("get_verified_snapshot", request.peer_id().copied());
        let provider = self.snapshot_provider.as_ref().ok_or_else(|| {
            Status::new_with_message(
                StatusCode::NotFound,
                "get_verified_snapshot not enabled on this validator",
            )
        })?;
        let snapshot = provider.snapshot();
        self.serve_end("get_verified_snapshot", started);
        Ok(Response::new(snapshot))
    }

    async fn push_verified_objects(
        &self,
        request: Request<PushVerifiedObjectsRequest>,
    ) -> Result<Response<()>, Status> {
        let handler = self.push_handler.as_ref().ok_or_else(|| {
            Status::new_with_message(
                StatusCode::NotFound,
                "push_verified_objects not enabled on this validator",
            )
        })?;
        let from = request
            .peer_id()
            .copied()
            .ok_or_else(|| Status::internal("missing peer id on push"))?;
        handler
            .handle_pushed_verified_objects(from, request.into_inner())
            .await
            .map_err(Status::internal)?;
        Ok(Response::new(()))
    }

    async fn submit_transaction(
        &self,
        request: Request<SubmitTransactionRequest>,
    ) -> Result<Response<SubmitTransactionResponse>, Status> {
        let started = self.serve_start("submit_transaction", request.peer_id().copied());
        let tx = request.into_inner().tx;
        // We forward the peer's *already-signed* transaction to our full node;
        // a tampered tx is rejected on-chain, so this is safe to serve.
        let submitted = self
            .transport
            .execute_transaction(&tx)
            .await
            .map_err(map_err)?;
        let effects_bcs = bcs::to_bytes(&submitted.effects)
            .map_err(|e| Status::internal(format!("encode effects: {e}")))?;
        self.serve_end("submit_transaction", started);
        Ok(Response::new(SubmitTransactionResponse {
            digest: submitted.digest,
            effects_bcs,
        }))
    }
}

/// Build the anemo router service. Pass `Some(handler)` to accept pushed
/// proofs; pass `Some(snapshot_provider)` to serve `GetVerifiedSnapshot`.
pub fn make_server(
    transport: Arc<dyn SuiTransport>,
    provider: Arc<dyn ProofProvider>,
    push_handler: Option<Arc<dyn PushVerifiedObjectsHandler>>,
    snapshot_provider: Option<Arc<dyn VerifiedSnapshotProvider>>,
    metrics: Arc<ProofProviderMetrics>,
) -> SuiStateMirrorServer<Server> {
    let mut server = Server::new(transport, provider, metrics);
    if let Some(handler) = push_handler {
        server = server.with_push_handler(handler);
    }
    if let Some(snap) = snapshot_provider {
        server = server.with_snapshot_provider(snap);
    }
    SuiStateMirrorServer::new(server)
}
