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
//! (`get_full_checkpoint`, `last_checkpoint_of_epoch`) are committee-ratchet
//! plumbing.

// Anemo fixes the generated RPC error type to Status; boxing it changes the API.
#[allow(clippy::result_large_err)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/ika.SuiStateMirror.rs"));
}
pub mod client;

use std::collections::BTreeMap;
use std::sync::Arc;

use anemo::codegen::InboundRequestLayer;
use anemo::{PeerId, Request, Response, rpc::Status, types::response::StatusCode};
use anemo_tower::inflight_limit;
use ika_sui_client::transport::{
    SuiTransport, TransportError, check_checkpoint_written_versions_increase,
};
use serde::{Deserialize, Serialize};
use sui_types::base_types::{ObjectDigest, ObjectID, SequenceNumber};
use sui_types::digests::CheckpointDigest;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointArtifacts, CheckpointSequenceNumber,
};

use crate::proof_provider::{
    BatchVerifiedObjectsResponse, ProofProvider, ProofProviderMetrics,
    VerifiedDynamicFieldsPageRequest, VerifiedDynamicFieldsPageResponse, VerifiedObjectResponse,
};

pub use client::{
    SuiMirrorPeers, SuiMirrorProofProvider, SuiMirrorTransport, find_serving_mirror_peer,
    register_addressed_mirror_peers,
};
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
    /// When the unservable-changeset warn last fired: every mirrored node
    /// reading through this relay asks for the same checkpoint, so it is
    /// rate limited; the counter carries the volume.
    last_unservable_warn: parking_lot::Mutex<Option<std::time::Instant>>,
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
            last_unservable_warn: parking_lot::Mutex::new(None),
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

    /// The lowest sequence at or above `from_seq` this node can serve, or
    /// `None` when there is none (the caller is caught up to our head, or the
    /// head is unreadable).
    ///
    /// The common case costs exactly the one fetch the caller was going to
    /// make anyway. Only when `from_seq` itself is unavailable do we look for
    /// the floor, and then only if `from_seq` is actually behind the head —
    /// ahead of the head means "nothing yet", which is not a gap to skip.
    async fn first_servable_seq(&self, from_seq: CheckpointSequenceNumber) -> Option<u64> {
        if checkpoint_exists(&self.transport.get_full_checkpoint(from_seq).await) {
            return Some(from_seq);
        }
        let head = *self
            .transport
            .get_latest_checkpoint()
            .await
            .ok()?
            .sequence_number();
        if from_seq >= head {
            return None;
        }
        let floor = lowest_available_seq(from_seq + 1, head, |seq| async move {
            checkpoint_exists(&self.transport.get_full_checkpoint(seq).await)
        })
        .await?;
        tracing::info!(
            requested_seq = from_seq,
            serving_from = floor,
            head,
            "changeset_page: requested sequence is below our retention floor; \
             fast-forwarding so the caller can re-anchor instead of stalling"
        );
        Some(floor)
    }

    /// Checkpoint `seq`'s changeset read in parts, for a checkpoint too large
    /// to read whole. A part read that fails refuses the page with the reason:
    /// skipping the checkpoint would leave the receiver, which folds only a
    /// contiguous chain, at a gap it reports forever without saying why.
    // The handler's own error type: anemo fixes it to `Status`.
    #[allow(clippy::result_large_err)]
    async fn changeset_in_parts(
        &self,
        seq: CheckpointSequenceNumber,
    ) -> Result<ChangesetEntry, Status> {
        match self.provider.checkpoint_changeset_in_parts(seq).await {
            Ok((summary, object_states)) => {
                self.metrics
                    .serve_changeset_part_reads_total
                    .with_label_values(&["served"])
                    .inc();
                Ok(ChangesetEntry {
                    summary,
                    object_states,
                })
            }
            Err(error) => {
                self.metrics
                    .serve_changeset_part_reads_total
                    .with_label_values(&["failed"])
                    .inc();
                let mut last = self.last_unservable_warn.lock();
                if last.is_none_or(|at| at.elapsed() >= UNSERVABLE_CHANGESET_WARN_INTERVAL) {
                    *last = Some(std::time::Instant::now());
                    tracing::warn!(
                        seq,
                        %error,
                        "changeset_page: checkpoint is too large to read whole and its part read \
                         failed; mirrored nodes reading Sui through this relay cannot advance \
                         past it until it is served"
                    );
                }
                Err(Status::internal(format!(
                    "changeset {seq} cannot be served: the checkpoint is too large to read whole \
                     and its part read failed: {error}"
                )))
            }
        }
    }
}

/// Whether a whole-checkpoint read shows the checkpoint is there: it was
/// read, or it is too large to read whole (served from its part read).
fn checkpoint_exists(read: &Result<CheckpointData, TransportError>) -> bool {
    matches!(read, Ok(_) | Err(TransportError::TooLarge(_)))
}

/// Lowest sequence in `[lo, hi]` for which `is_available` holds, by binary
/// search; `None` if none does.
///
/// Sound because retention is a suffix: a fullnode keeps a contiguous
/// `[floor, head]`, so availability is monotone in the sequence number and
/// the search is O(log(hi - lo)) probes rather than a linear walk over a gap
/// that can be millions of checkpoints wide.
async fn lowest_available_seq<P, F>(lo: u64, hi: u64, mut is_available: P) -> Option<u64>
where
    P: FnMut(u64) -> F,
    F: std::future::Future<Output = bool>,
{
    if lo > hi {
        return None;
    }
    let (mut lo, mut hi) = (lo, hi);
    let mut found = None;
    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        if is_available(mid).await {
            found = Some(mid);
            // Everything above `mid` is available too; the floor is at or
            // below it.
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }
    found
}

fn map_err(e: TransportError) -> Status {
    match e {
        TransportError::NotFound(s) => Status::new_with_message(StatusCode::NotFound, s),
        TransportError::Network(s) => Status::internal(s),
        TransportError::Encoding(s) => Status::internal(s),
        TransportError::TooLarge(s) => Status::internal(s),
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
        // `from_seq` below our retention floor must fast-forward, not return
        // empty. The receiver's cursor falls back to its `bootstrap_from`
        // exactly when its index is empty, so an empty page leaves it asking
        // for the same pruned sequence forever — the index never fills, the
        // currency gate never engages, and it does not recover until the
        // process restarts. Serving from our floor instead re-anchors it:
        // `ChangesetIndex::absorb` bootstrap-cases an empty index, so the
        // first entry it folds becomes its base. (A gap below that base is
        // legitimate and already the pull path's model.)
        //
        // Only the FIRST requested sequence is fast-forwarded. A later
        // unavailable sequence inside the page is the head, and stopping
        // there is what keeps the served prefix contiguous.
        let start_seq = match self.first_servable_seq(from_seq).await {
            Some(seq) => seq,
            // Nothing at or above `from_seq` — the receiver is caught up to
            // our head, and an empty page is the correct "no progress" answer.
            None => return Ok(Response::new(ChangesetPageResponse { entries: vec![] })),
        };
        let mut entries = Vec::with_capacity(limit);
        for seq in start_seq..start_seq.saturating_add(limit as u64) {
            // Stop at the first unavailable checkpoint (head reached): a
            // short, contiguous prefix is exactly what the receiver folds.
            let checkpoint = match self.transport.get_full_checkpoint(seq).await {
                Ok(checkpoint) => checkpoint,
                // Too large to read whole: served from its part read, alone.
                // A page ends before it, and the next page is just it, so an
                // entry this large never shares a response.
                Err(TransportError::TooLarge(_)) => {
                    if entries.is_empty() {
                        entries.push(self.changeset_in_parts(seq).await?);
                    }
                    break;
                }
                Err(_) => break,
            };
            // Ship only the modified object-set, not the bodies. The receiver
            // re-derives the artifacts digest and checks it against the
            // summary's commitment, so this is committee-bound on arrival.
            check_checkpoint_written_versions_increase(&checkpoint)
                .map_err(|e| Status::internal(e.to_string()))?;
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
/// The checkpoint lookups a peer-only node's committee ratchet makes
/// over the relay (`last_checkpoint_of_epoch`,
/// `get_checkpoint_summary_by_digest`, `get_latest_checkpoint`) — each a
/// fullnode/store round-trip, so bound like the other heavy reads.
const INFLIGHT_CHECKPOINT_READ: usize = 64;
/// The cheap single-value metadata reads (`get_current_epoch`,
/// `get_chain_identifier`). Generous, but still bounded so every served read
/// has a ceiling.
const INFLIGHT_METADATA_READ: usize = 256;
/// Max checkpoints served per `changeset_page` call. Each fetches a full
/// checkpoint server-side to extract its object-set, so keep the page modest;
/// the receiver simply requests the next page to continue.
const MAX_CHANGESET_PAGE: usize = 64;
/// How often the relay warns that a changeset cannot be served.
const UNSERVABLE_CHANGESET_WARN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

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
        // committee-ratchet checkpoint lookups (were uncapped)
        .add_layer_for_last_checkpoint_of_epoch(inflight!(INFLIGHT_CHECKPOINT_READ))
        .add_layer_for_get_checkpoint_summary_by_digest(inflight!(INFLIGHT_CHECKPOINT_READ))
        .add_layer_for_get_latest_checkpoint(inflight!(INFLIGHT_CHECKPOINT_READ))
        // cheap metadata reads (were uncapped)
        .add_layer_for_get_current_epoch(inflight!(INFLIGHT_METADATA_READ))
        .add_layer_for_get_chain_identifier(inflight!(INFLIGHT_METADATA_READ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Availability is a retained suffix `[floor, head]`, which is what makes
    /// the binary search sound.
    fn retained_from(floor: u64) -> impl Fn(u64) -> std::future::Ready<bool> {
        move |seq| std::future::ready(seq >= floor)
    }

    #[tokio::test]
    async fn finds_the_floor_of_a_pruned_prefix() {
        assert_eq!(
            lowest_available_seq(1, 1_000_000, retained_from(432_101)).await,
            Some(432_101)
        );
    }

    #[tokio::test]
    async fn returns_the_low_bound_when_everything_is_available() {
        assert_eq!(lowest_available_seq(7, 99, retained_from(0)).await, Some(7));
    }

    #[tokio::test]
    async fn returns_none_when_nothing_in_range_is_available() {
        assert_eq!(lowest_available_seq(1, 500, retained_from(900)).await, None);
    }

    #[tokio::test]
    async fn handles_a_single_element_range_both_ways() {
        assert_eq!(lowest_available_seq(5, 5, retained_from(5)).await, Some(5));
        assert_eq!(lowest_available_seq(5, 5, retained_from(6)).await, None);
        // An inverted range is empty, not a panic: `from_seq + 1 > head` is
        // reachable when the head moves between the two reads.
        assert_eq!(lowest_available_seq(9, 8, retained_from(0)).await, None);
    }

    /// The point of the search: a gap of a million checkpoints costs ~20
    /// probes, not a million. A linear walk here would be its own outage.
    #[tokio::test]
    async fn probes_logarithmically_not_linearly() {
        let probes = Cell::new(0usize);
        let found = lowest_available_seq(1, 1_000_000, |seq| {
            probes.set(probes.get() + 1);
            std::future::ready(seq >= 999_999)
        })
        .await;
        assert_eq!(found, Some(999_999));
        assert!(
            probes.get() <= 21,
            "expected ~log2(1e6) probes, made {}",
            probes.get()
        );
    }

    // ---- changeset_page over a checkpoint too large to read whole ----

    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicU32, Ordering};

    use ika_sui_client::transport::{DynamicFieldPage, ExecutedTransaction};
    use sui_types::base_types::TransactionDigest;
    use sui_types::committee::Committee;
    use sui_types::gas::GasCostSummary;
    use sui_types::messages_checkpoint::{
        CheckpointCommitment, CheckpointContents, CheckpointSummary,
    };
    use sui_types::object::Object;

    use crate::proof_provider::CheckpointChangeset;

    /// A committee-signed checkpoint `seq` with no transactions.
    fn checkpoint(seq: CheckpointSequenceNumber) -> CheckpointData {
        let (committee, keys) = Committee::new_simple_test_committee();
        let contents = CheckpointContents::new_with_digests_only_for_tests(vec![]);
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: *contents.digest(),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![CheckpointCommitment::CheckpointArtifactsDigest(
                CheckpointArtifacts::from_object_states(BTreeMap::new())
                    .digest()
                    .unwrap(),
            )],
            end_of_epoch_data: None,
            version_specific_data: Vec::new(),
        };
        CheckpointData {
            checkpoint_summary: CertifiedCheckpointSummary::new_from_keypairs_for_testing(
                summary, &keys, &committee,
            ),
            checkpoint_contents: contents,
            transactions: vec![],
        }
    }

    /// A fullnode holding checkpoints `10..=head`, of which `too_large` are
    /// over the decode limit for a whole read.
    struct Fullnode {
        checkpoints: HashMap<CheckpointSequenceNumber, CheckpointData>,
        too_large: HashSet<CheckpointSequenceNumber>,
        head: CheckpointSequenceNumber,
    }

    impl Fullnode {
        fn new(head: CheckpointSequenceNumber, too_large: &[CheckpointSequenceNumber]) -> Self {
            Self {
                checkpoints: (10..=head).map(|seq| (seq, checkpoint(seq))).collect(),
                too_large: too_large.iter().copied().collect(),
                head,
            }
        }
    }

    #[anemo::async_trait]
    impl SuiTransport for Fullnode {
        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            unimplemented!()
        }
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            unimplemented!()
        }
        async fn get_committee(&self, _epoch: Option<u64>) -> Result<Committee, TransportError> {
            unimplemented!()
        }
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            Ok(self.checkpoints[&self.head].checkpoint_summary.clone())
        }
        async fn get_full_checkpoint(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            if self.too_large.contains(&seq) {
                return Err(TransportError::TooLarge(format!(
                    "checkpoint {seq} is over the decode limit"
                )));
            }
            self.checkpoints
                .get(&seq)
                .cloned()
                .ok_or_else(|| TransportError::NotFound(format!("checkpoint {seq} not found")))
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

    /// A provider whose part read answers `answer`, counting the reads.
    struct PartReader {
        answer: Result<CheckpointChangeset, TransportError>,
        reads: AtomicU32,
    }

    #[anemo::async_trait]
    impl ProofProvider for PartReader {
        async fn verified_object(
            &self,
            _id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            unimplemented!()
        }
        async fn batch_verified_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            unimplemented!()
        }
        async fn verified_dynamic_fields_page(
            &self,
            _request: VerifiedDynamicFieldsPageRequest,
        ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
            unimplemented!()
        }
        async fn checkpoint_changeset_in_parts(
            &self,
            _seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointChangeset, TransportError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.answer.clone()
        }
    }

    fn server(fullnode: Fullnode, answer: Result<CheckpointChangeset, TransportError>) -> Server {
        Server::new(
            Arc::new(fullnode),
            Arc::new(PartReader {
                answer,
                reads: AtomicU32::new(0),
            }),
            ProofProviderMetrics::new_for_testing(),
        )
    }

    #[allow(clippy::result_large_err)]
    async fn page(server: &Server, from_seq: CheckpointSequenceNumber) -> Result<Vec<u64>, Status> {
        server
            .changeset_page(Request::new(ChangesetPageRequest {
                from_seq,
                limit: 64,
            }))
            .await
            .map(|response| {
                response
                    .into_inner()
                    .entries
                    .iter()
                    .map(|entry| *entry.summary.sequence_number())
                    .collect()
            })
    }

    fn part_reads(server: &Server, outcome: &str) -> u64 {
        server
            .metrics
            .serve_changeset_part_reads_total
            .with_label_values(&[outcome])
            .get()
    }

    /// Checkpoint 12 is too large to read whole. A page ends before it, the
    /// next page is it alone, served from its part read, and the page after
    /// carries on: the stream stays contiguous.
    #[tokio::test]
    async fn a_checkpoint_too_large_to_read_whole_is_served_alone_from_its_part_read() {
        let changeset = (checkpoint(12).checkpoint_summary, BTreeMap::new());
        let server = server(Fullnode::new(14, &[12]), Ok(changeset));

        assert_eq!(page(&server, 10).await.unwrap(), vec![10, 11]);
        assert_eq!(page(&server, 12).await.unwrap(), vec![12]);
        assert_eq!(page(&server, 13).await.unwrap(), vec![13, 14]);
        assert_eq!(part_reads(&server, "served"), 1);
        assert_eq!(part_reads(&server, "failed"), 0);
    }

    /// When the part read fails, the page is refused with the checkpoint and
    /// the reason, rather than skipping to 13, which would leave the receiver
    /// at a gap it reports forever without saying why.
    #[tokio::test]
    async fn a_part_read_that_fails_refuses_the_page_with_the_reason() {
        let server = server(
            Fullnode::new(14, &[12]),
            Err(TransportError::Encoding(
                "checkpoint 12 writes more than 2000000 object states".into(),
            )),
        );

        let refused = page(&server, 12).await.expect_err("refused, not skipped");
        let message = format!("{refused:?}");
        assert!(
            message.contains("changeset 12 cannot be served"),
            "{message}"
        );
        assert!(message.contains("2000000 object states"), "{message}");
        assert_eq!(part_reads(&server, "failed"), 1);
        assert_eq!(
            page(&server, 10).await.unwrap(),
            vec![10, 11],
            "the checkpoints before it are still served"
        );
    }
}
