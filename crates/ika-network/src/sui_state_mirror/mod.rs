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

use std::collections::BTreeMap;
use std::sync::Arc;

use anemo::codegen::InboundRequestLayer;
use anemo::{PeerId, Request, Response, rpc::Status, types::response::StatusCode};
use anemo_tower::inflight_limit;
use ika_sui_client::transport::{SuiTransport, TransportError};
use serde::{Deserialize, Serialize};
use sui_types::base_types::{ObjectDigest, ObjectID, SequenceNumber, TransactionDigest};
use sui_types::digests::CheckpointDigest;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointArtifacts, CheckpointSequenceNumber,
};

use crate::proof_provider::{
    BatchVerifiedObjectsResponse, ProofProvider, ProofProviderMetrics,
    VerifiedDynamicFieldsPageRequest, VerifiedDynamicFieldsPageResponse, VerifiedObjectResponse,
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

// -- Changeset stream (mirrored-node currency) ------------------------------------------------

/// One checkpoint's changeset: the committee-signed summary plus its modified
/// object-set (`id → (version, digest)`). The receiver binds the object-set to
/// the summary's `checkpoint_artifacts_digest` (so a relay can't add/drop ids)
/// and folds it for currency — see `ika_core::sui_connector::ocs_currency`.
/// Only ids + versions + the summary cross the wire, never object bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangesetEntry {
    pub summary: CertifiedCheckpointSummary,
    pub object_states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangesetPageRequest {
    /// First checkpoint sequence to return.
    pub from_seq: CheckpointSequenceNumber,
    /// Maximum checkpoints to return; the server clamps to `MAX_CHANGESET_PAGE`.
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangesetPageResponse {
    /// Changesets for `from_seq, from_seq+1, …`, contiguous from `from_seq`.
    /// Short (possibly empty) when the server's head is reached — exactly what
    /// the receiver's contiguous fold expects.
    pub entries: Vec<ChangesetEntry>,
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
    async fn changeset_page(
        &self,
        request: Request<ChangesetPageRequest>,
    ) -> Result<Response<ChangesetPageResponse>, Status> {
        let ChangesetPageRequest { from_seq, limit } = request.into_inner();
        let limit = (limit as usize).min(MAX_CHANGESET_PAGE);
        let mut entries = Vec::with_capacity(limit);
        for seq in from_seq..from_seq.saturating_add(limit as u64) {
            // Stop at the first unavailable checkpoint (head reached / pruned):
            // a short, contiguous prefix is exactly what the receiver folds.
            let checkpoint = match self.transport.get_full_checkpoint(seq).await {
                Ok(checkpoint) => checkpoint,
                Err(_) => break,
            };
            // Ship only the modified object-set, not the bodies. The receiver
            // re-derives the artifacts digest and checks it against the
            // summary's commitment, so this is committee-bound on arrival.
            let object_states = CheckpointArtifacts::from(&checkpoint)
                .object_states()
                .map_err(|e| Status::internal(e.to_string()))?
                .clone();
            entries.push(ChangesetEntry {
                summary: checkpoint.checkpoint_summary,
                object_states,
            });
        }
        Ok(Response::new(ChangesetPageResponse { entries }))
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
    async fn verified_dynamic_fields_page(
        &self,
        request: Request<VerifiedDynamicFieldsPageRequest>,
    ) -> Result<Response<VerifiedDynamicFieldsPageResponse>, Status> {
        let started = self.serve_start("verified_dynamic_fields_page", request.peer_id().copied());
        let v = self
            .provider
            .verified_dynamic_fields_page(request.into_inner())
            .await
            .map_err(map_err)?;
        self.serve_end("verified_dynamic_fields_page", started);
        Ok(Response::new(v))
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
const INFLIGHT_VERIFIED_DYNAMIC_FIELDS_PAGE: usize = 64;
const INFLIGHT_GET_FULL_CHECKPOINT: usize = 32;
const INFLIGHT_CHANGESET_PAGE: usize = 16;
/// The checkpoint/transaction lookups a peer-only node's committee ratchet makes
/// over the relay (`last_checkpoint_of_epoch`, `get_transaction_checkpoint`,
/// `get_checkpoint_summary_by_digest`, `get_latest_checkpoint`) — each a
/// fullnode/store round-trip, so bound like the other heavy reads.
const INFLIGHT_CHECKPOINT_READ: usize = 64;
/// The cheap single-value metadata reads (`get_current_epoch`,
/// `get_reference_gas_price`, `get_chain_identifier`). Generous, but still
/// bounded so every served read has a ceiling.
const INFLIGHT_METADATA_READ: usize = 256;
/// Max checkpoints served per `changeset_page` call. Each fetches a full
/// checkpoint server-side to extract its object-set, so keep the page modest;
/// the receiver simply requests the next page to continue.
const MAX_CHANGESET_PAGE: usize = 64;

/// Build the anemo router service serving the verified-read and
/// committee-ratchet RPCs, with per-method inflight caps on the heavy ones.
pub fn make_server(
    transport: Arc<dyn SuiTransport>,
    provider: Arc<dyn ProofProvider>,
    metrics: Arc<ProofProviderMetrics>,
) -> SuiStateMirrorServer<Server> {
    // Every served READ RPC gets an inflight ceiling so a byzantine peer can't
    // open unbounded concurrent streams against a sui-state-direct node. (Each
    // `add_layer_for_*` is generic over its own request type, so the layers must
    // be built inline rather than via a shared helper.) There is no
    // `submit_transaction` RPC — the relay serves verified reads only (see
    // `build.rs`), so there is nothing to cap on the write side.
    macro_rules! inflight {
        ($n:expr) => {
            InboundRequestLayer::new(inflight_limit::InflightLimitLayer::new(
                $n,
                inflight_limit::WaitMode::ReturnError,
            ))
        };
    }
    SuiStateMirrorServer::new(Server::new(transport, provider, metrics))
        // verified reads
        .add_layer_for_verified_object(inflight!(INFLIGHT_VERIFIED_OBJECT))
        .add_layer_for_batch_verified_objects(inflight!(INFLIGHT_BATCH_VERIFIED_OBJECTS))
        .add_layer_for_verified_dynamic_fields_page(inflight!(
            INFLIGHT_VERIFIED_DYNAMIC_FIELDS_PAGE
        ))
        .add_layer_for_get_full_checkpoint(inflight!(INFLIGHT_GET_FULL_CHECKPOINT))
        .add_layer_for_changeset_page(inflight!(INFLIGHT_CHANGESET_PAGE))
        // committee-ratchet checkpoint / transaction lookups (were uncapped)
        .add_layer_for_last_checkpoint_of_epoch(inflight!(INFLIGHT_CHECKPOINT_READ))
        .add_layer_for_get_transaction_checkpoint(inflight!(INFLIGHT_CHECKPOINT_READ))
        .add_layer_for_get_checkpoint_summary_by_digest(inflight!(INFLIGHT_CHECKPOINT_READ))
        .add_layer_for_get_latest_checkpoint(inflight!(INFLIGHT_CHECKPOINT_READ))
        // cheap metadata reads (were uncapped)
        .add_layer_for_get_current_epoch(inflight!(INFLIGHT_METADATA_READ))
        .add_layer_for_get_reference_gas_price(inflight!(INFLIGHT_METADATA_READ))
        .add_layer_for_get_chain_identifier(inflight!(INFLIGHT_METADATA_READ))
}
