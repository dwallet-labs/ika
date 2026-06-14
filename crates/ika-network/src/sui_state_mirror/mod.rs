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

use anemo::codegen::InboundRequestLayer;
use anemo::{PeerId, Request, Response, rpc::Status, types::response::StatusCode};
use anemo_tower::inflight_limit;
use ika_sui_client::transport::{SuiTransport, TransportError};
use serde::{Deserialize, Serialize};
use sui_types::base_types::{ObjectID, TransactionDigest};
use sui_types::digests::CheckpointDigest;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::transaction::Transaction;

use crate::proof_provider::{
    BatchVerifiedObjectsResponse, ProofProvider, ProofProviderMetrics, VerifiedBagPageRequest,
    VerifiedBagPageResponse, VerifiedObjectResponse,
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

// -- Server -----------------------------------------------------------------------------------

/// sui-state-direct validator-side anemo server. Serves verified reads via a
/// [`ProofProvider`] (sui-state-direct: [`crate::proof_provider::LocalProofProvider`]).
/// The ratchet primitives delegate to a [`SuiTransport`] (the same
/// underlying gRPC client the provider wraps).
pub struct Server {
    transport: Arc<dyn SuiTransport>,
    provider: Arc<dyn ProofProvider>,
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
            metrics,
        }
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

/// Coarse per-method concurrency ceilings for the heaviest serving RPCs, to
/// bound a peer flooding a sui-state-direct node: each proof-building method
/// costs CPU + DB per request, and `get_full_checkpoint` ships a large
/// payload. Generous (well above normal fleet load); over the limit a peer
/// gets an error and fails over to another direct node (its relay client
/// retries). Per-request size is also capped in `proof_provider.rs`.
const INFLIGHT_VERIFIED_OBJECT: usize = 256;
const INFLIGHT_BATCH_VERIFIED_OBJECTS: usize = 64;
const INFLIGHT_VERIFIED_BAG_PAGE: usize = 64;
const INFLIGHT_GET_FULL_CHECKPOINT: usize = 32;

/// Build the anemo router service serving the verified-read and
/// committee-ratchet RPCs, with per-method inflight caps on the heavy ones.
pub fn make_server(
    transport: Arc<dyn SuiTransport>,
    provider: Arc<dyn ProofProvider>,
    metrics: Arc<ProofProviderMetrics>,
) -> SuiStateMirrorServer<Server> {
    SuiStateMirrorServer::new(Server::new(transport, provider, metrics))
        .add_layer_for_verified_object(InboundRequestLayer::new(
            inflight_limit::InflightLimitLayer::new(
                INFLIGHT_VERIFIED_OBJECT,
                inflight_limit::WaitMode::ReturnError,
            ),
        ))
        .add_layer_for_batch_verified_objects(InboundRequestLayer::new(
            inflight_limit::InflightLimitLayer::new(
                INFLIGHT_BATCH_VERIFIED_OBJECTS,
                inflight_limit::WaitMode::ReturnError,
            ),
        ))
        .add_layer_for_verified_bag_page(InboundRequestLayer::new(
            inflight_limit::InflightLimitLayer::new(
                INFLIGHT_VERIFIED_BAG_PAGE,
                inflight_limit::WaitMode::ReturnError,
            ),
        ))
        .add_layer_for_get_full_checkpoint(InboundRequestLayer::new(
            inflight_limit::InflightLimitLayer::new(
                INFLIGHT_GET_FULL_CHECKPOINT,
                inflight_limit::WaitMode::ReturnError,
            ),
        ))
}
