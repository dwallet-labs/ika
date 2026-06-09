// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Producer side of OCS inclusion proofs.
//!
//! [`ProofProvider`] is the abstraction the relay-server-side and the
//! sui-state-direct local consumer share: "give me the current state of an Ika
//! object plus a Merkle inclusion proof against the checkpoint where it
//! was last modified."
//!
//! [`LocalProofProvider`] is the only impl right now. It wraps a raw
//! [`SuiTransport`] (direct gRPC) and a [`ProofCache`] that memoises the
//! `ModifiedObjectTree` per checkpoint so concurrent readers don't each
//! pay an O(checkpoint_size) tree build.
//!
//! The sui-state-mirrored side reaches a remote provider via anemo (see
//! `ika-network::sui_state_mirror::SuiStateMirrorClient`) and adapts the
//! responses into the same [`VerifiedObjectResponse`] shape; consumers see
//! the same trait either way.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;
use prometheus::{
    HistogramVec, IntCounter, IntCounterVec, IntGaugeVec, Registry,
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_counter_with_registry, register_int_gauge_vec_with_registry,
};
use serde::{Deserialize, Serialize};
use sui_light_client::proof::ocs::{ModifiedObjectTree, OCSInclusionProof};
use sui_types::base_types::ObjectID;
use sui_types::digests::TransactionDigest;
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointArtifacts, CheckpointSequenceNumber,
};
use sui_types::object::Object;

use ika_sui_client::transport::{SuiTransport, TransportError};

/// Producer-side metrics for the `ProofProvider` layer. sui-state-direct nodes
/// running [`LocalProofProvider`] populate the local-only counters
/// (`*_built_total`, `tree_cache_*`); sui-state-mirrored nodes running
/// `SuiMirrorProofProvider` populate the relay-call counters
/// (`relay_*`). Both share `bag_walk_*` which counts at the wrapper
/// layer.
#[derive(Clone, Debug)]
pub struct ProofProviderMetrics {
    // -- LocalProofProvider (sui-state-direct) --
    /// Inclusion proofs successfully constructed, by request kind.
    pub proof_built_total: IntCounterVec, // labels: ["kind"="object"|"bag_page_entry"|"batch_entry"]
    /// Proof construction failures, by kind and reason.
    pub proof_build_failures_total: IntCounterVec, // labels: ["kind", "reason"]
    /// Times we found the per-checkpoint `ModifiedObjectTree` in cache
    /// and didn't have to refetch + rebuild.
    pub proof_tree_cache_hits_total: IntCounter,
    /// Cache miss → had to fetch the full checkpoint and build the tree.
    pub proof_tree_cache_misses_total: IntCounter,

    // -- SuiMirrorProofProvider (sui-state-mirrored) --
    /// Relay calls initiated by a sui-state-mirrored provider, by op label.
    pub relay_request_total: IntCounterVec, // labels: ["op"]
    /// Relay calls that failed (after exhausting the peer fallback list).
    pub relay_failures_total: IntCounterVec, // labels: ["op", "reason"="not_found"|"network"]
    /// Per-peer relay failovers: a peer errored and we tried the next one.
    /// Fires *before* the all-peers-exhausted `relay_failures_total`, so a
    /// single flaky serving peer is visible long before total outage. Peer
    /// label is bounded-cardinality (the committee).
    pub relay_peer_failover_total: IntCounterVec, // labels: ["op", "peer"]

    // -- SuiStateMirrorServer (sui-state-direct serving side) --
    /// Relay requests served to peers, by op. Lets a serving (direct)
    /// validator see how much load the mirrored fleet puts on it.
    pub serve_request_total: IntCounterVec, // labels: ["op"]
    /// Relay requests served, attributed to the requesting peer (for the
    /// object/bag/snapshot ops). Bounded-cardinality peer label.
    pub serve_request_by_peer_total: IntCounterVec, // labels: ["op", "peer"]
    /// Serving-side handler latency, by op.
    pub serve_latency_seconds: HistogramVec, // labels: ["op"]

    // -- Bag walk (both roles) --
    /// Children scanned in `verified_bag_page` (across all pages).
    pub bag_walk_entries_seen_total: IntCounter,
    /// Children successfully verified and returned.
    pub bag_walk_entries_returned_total: IntCounter,
    /// Children skipped because their previous_transaction or object
    /// hadn't been indexed yet — picked up on the next tick.
    pub bag_walk_entries_skipped_transient_total: IntCounter,

    // -- Static info gauges (set once at startup; value is always 1) --
    /// `role_info{role}` — set to 1 with the validator's role label.
    /// Lets dashboards filter sui-state-direct vs sui-state-mirrored without pinning to the
    /// `instance` scrape label.
    pub role_info: IntGaugeVec,
    /// `anchor_info{epoch}` — set to 1 to publish the head Sui epoch
    /// this validator booted at (post-bootstrap or post-hydrate). The
    /// digest itself is the operator-pinned constant; what dashboards
    /// want to see is *which committee* we're tracking right now.
    pub anchor_info: IntGaugeVec,

    // -- Latency histograms --
    /// Wall time for proof construction on the producer side, by kind.
    /// Captures the local hot path (cache lookup or tree build + proof
    /// extraction). Zero on sui-state-mirrored.
    pub proof_build_latency_seconds: HistogramVec,
    /// Wall time for a relay request round-trip on the consumer side,
    /// by op. Captures network + remote-side proof construction. Zero
    /// on sui-state-direct (no relay calls).
    pub relay_request_latency_seconds: HistogramVec,
}

impl ProofProviderMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        Arc::new(Self {
            proof_built_total: register_int_counter_vec_with_registry!(
                "ika_ocs_proof_built_total",
                "OCS inclusion proofs successfully constructed (sui-state-direct only)",
                &["kind"],
                registry,
            )
            .unwrap(),
            proof_build_failures_total: register_int_counter_vec_with_registry!(
                "ika_ocs_proof_build_failures_total",
                "OCS proof construction failures (sui-state-direct only)",
                &["kind", "reason"],
                registry,
            )
            .unwrap(),
            proof_tree_cache_hits_total: register_int_counter_with_registry!(
                "ika_ocs_proof_tree_cache_hits_total",
                "Per-checkpoint ModifiedObjectTree found in cache",
                registry,
            )
            .unwrap(),
            proof_tree_cache_misses_total: register_int_counter_with_registry!(
                "ika_ocs_proof_tree_cache_misses_total",
                "Per-checkpoint ModifiedObjectTree not in cache; refetched and rebuilt",
                registry,
            )
            .unwrap(),
            relay_request_total: register_int_counter_vec_with_registry!(
                "ika_ocs_relay_request_total",
                "SuiStateMirror relay calls initiated by a sui-state-mirrored provider",
                &["op"],
                registry,
            )
            .unwrap(),
            relay_failures_total: register_int_counter_vec_with_registry!(
                "ika_ocs_relay_failures_total",
                "Relay calls that failed (after peer fallback exhausted)",
                &["op", "reason"],
                registry,
            )
            .unwrap(),
            relay_peer_failover_total: register_int_counter_vec_with_registry!(
                "ika_ocs_relay_peer_failover_total",
                "Per-peer relay failovers (a serving peer errored and we tried the next); fires before the all-peers-exhausted relay_failures_total",
                &["op", "peer"],
                registry,
            )
            .unwrap(),
            serve_request_total: register_int_counter_vec_with_registry!(
                "ika_ocs_serve_request_total",
                "SuiStateMirror relay requests served to peers (sui-state-direct serving side)",
                &["op"],
                registry,
            )
            .unwrap(),
            serve_request_by_peer_total: register_int_counter_vec_with_registry!(
                "ika_ocs_serve_request_by_peer_total",
                "SuiStateMirror relay requests served, attributed to the requesting peer (bounded-cardinality)",
                &["op", "peer"],
                registry,
            )
            .unwrap(),
            serve_latency_seconds: register_histogram_vec_with_registry!(
                "ika_ocs_serve_latency_seconds",
                "SuiStateMirror serving-side handler latency, by op",
                &["op"],
                vec![
                    0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
                ],
                registry,
            )
            .unwrap(),
            bag_walk_entries_seen_total: register_int_counter_with_registry!(
                "ika_ocs_bag_walk_entries_seen_total",
                "Children scanned during a verified bag walk",
                registry,
            )
            .unwrap(),
            bag_walk_entries_returned_total: register_int_counter_with_registry!(
                "ika_ocs_bag_walk_entries_returned_total",
                "Children successfully verified and returned to the consumer",
                registry,
            )
            .unwrap(),
            bag_walk_entries_skipped_transient_total: register_int_counter_with_registry!(
                "ika_ocs_bag_walk_entries_skipped_transient_total",
                "Children skipped due to a transient indexer race; retried next tick",
                registry,
            )
            .unwrap(),
            role_info: register_int_gauge_vec_with_registry!(
                "ika_ocs_role_info",
                "OCS role for this validator (set to 1; role carried in label)",
                &["role"],
                registry,
            )
            .unwrap(),
            anchor_info: register_int_gauge_vec_with_registry!(
                "ika_ocs_anchor_info",
                "Sui epoch the validator's committee head was at on boot \
                 (set to 1; epoch in label)",
                &["epoch"],
                registry,
            )
            .unwrap(),
            proof_build_latency_seconds: register_histogram_vec_with_registry!(
                "ika_ocs_proof_build_latency_seconds",
                "Wall time for proof construction on the producer side",
                &["kind"],
                // Sub-millisecond resolution — proof construction is
                // either a cache hit (~µs) or a tree build (~ms).
                vec![
                    0.0001, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0,
                    2.5, 5.0,
                ],
                registry,
            )
            .unwrap(),
            relay_request_latency_seconds: register_histogram_vec_with_registry!(
                "ika_ocs_relay_request_latency_seconds",
                "Wall time for a relay round-trip on the consumer side",
                &["op"],
                // Network round-trip dominates; floor ~hundreds of µs.
                vec![
                    0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ],
                registry,
            )
            .unwrap(),
        })
    }

    pub fn new_for_testing() -> Arc<Self> {
        Self::new(&Registry::new())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiedObjectResponse {
    pub object: Object,
    pub summary: CertifiedCheckpointSummary,
    pub proof: OCSInclusionProof,
    /// Provider's view of the current Sui checkpoint head. Receiver uses
    /// this to bound staleness.
    pub claimed_latest_checkpoint_seq: CheckpointSequenceNumber,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiedObjectEntry {
    pub object: Object,
    pub checkpoint_seq: CheckpointSequenceNumber,
    pub proof: OCSInclusionProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchVerifiedObjectsResponse {
    pub summaries: BTreeMap<CheckpointSequenceNumber, CertifiedCheckpointSummary>,
    /// Parallel to request `ids`. `None` = couldn't construct (e.g.,
    /// upstream pruned the touching checkpoint).
    pub results: Vec<Option<VerifiedObjectEntry>>,
    pub claimed_latest_checkpoint_seq: CheckpointSequenceNumber,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedBagPageRequest {
    pub bag_id: ObjectID,
    pub page_size: Option<u32>,
    pub page_token: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiedBagPageResponse {
    /// The bag's parent object verified — lets the caller bound omission
    /// by comparing `bag.size` against the accumulated children.
    pub bag: Option<VerifiedObjectEntry>,
    pub summaries: BTreeMap<CheckpointSequenceNumber, CertifiedCheckpointSummary>,
    pub entries: Vec<VerifiedObjectEntry>,
    pub next_page_token: Option<Vec<u8>>,
    pub claimed_latest_checkpoint_seq: CheckpointSequenceNumber,
}

#[async_trait]
pub trait ProofProvider: Send + Sync {
    async fn verified_object(&self, id: ObjectID)
    -> Result<VerifiedObjectResponse, TransportError>;

    async fn batch_verified_objects(
        &self,
        ids: &[ObjectID],
    ) -> Result<BatchVerifiedObjectsResponse, TransportError>;

    async fn verified_bag_page(
        &self,
        request: VerifiedBagPageRequest,
    ) -> Result<VerifiedBagPageResponse, TransportError>;
}

#[derive(Clone, Debug)]
pub struct ProofCacheConfig {
    pub tree_capacity: u64,
    pub tree_ttl: Duration,
    /// LRU capacity for the `tx_digest → checkpoint_seq` map. This mapping is
    /// immutable once a tx is committed, so entries never go stale; the bound
    /// only caps memory. Serves relayed reads without a `get_transaction_checkpoint`
    /// round-trip to the full node.
    pub tx_checkpoint_capacity: u64,
}

impl Default for ProofCacheConfig {
    fn default() -> Self {
        Self {
            tree_capacity: 32,
            tree_ttl: Duration::from_secs(300),
            tx_checkpoint_capacity: 8_192,
        }
    }
}

/// Per-checkpoint `ModifiedObjectTree` cache. The tree build is the
/// expensive part of proof construction (O(N) hashes for N modified
/// objects) and many proofs against the same checkpoint share it.
struct ProofCache {
    /// Keyed by checkpoint sequence. Holds both the summary and the tree
    /// so we can serve proofs without re-fetching either.
    trees: Cache<CheckpointSequenceNumber, Arc<CachedCheckpoint>>,
    /// `tx_digest → checkpoint_seq`, immutable once committed. Saves a
    /// `get_transaction_checkpoint` full-node round-trip per relayed read.
    tx_checkpoints: Cache<TransactionDigest, CheckpointSequenceNumber>,
}

struct CachedCheckpoint {
    summary: CertifiedCheckpointSummary,
    tree: ModifiedObjectTree,
}

impl ProofCache {
    fn new(cfg: &ProofCacheConfig) -> Self {
        Self {
            trees: Cache::builder()
                .max_capacity(cfg.tree_capacity)
                .time_to_live(cfg.tree_ttl)
                .build(),
            tx_checkpoints: Cache::builder()
                .max_capacity(cfg.tx_checkpoint_capacity)
                .build(),
        }
    }
}

pub struct LocalProofProvider {
    raw: Arc<dyn SuiTransport>,
    cache: ProofCache,
    metrics: Arc<ProofProviderMetrics>,
}

impl LocalProofProvider {
    pub fn new(
        raw: Arc<dyn SuiTransport>,
        cfg: &ProofCacheConfig,
        metrics: Arc<ProofProviderMetrics>,
    ) -> Self {
        Self {
            raw,
            cache: ProofCache::new(cfg),
            metrics,
        }
    }

    async fn cached_checkpoint(
        &self,
        seq: CheckpointSequenceNumber,
    ) -> Result<Arc<CachedCheckpoint>, TransportError> {
        if let Some(c) = self.cache.trees.get(&seq).await {
            self.metrics.proof_tree_cache_hits_total.inc();
            return Ok(c);
        }
        self.metrics.proof_tree_cache_misses_total.inc();
        let data = self.raw.get_full_checkpoint(seq).await?;
        let artifacts = CheckpointArtifacts::from(&data);
        let tree = ModifiedObjectTree::new(&artifacts).map_err(|e| {
            TransportError::Encoding(format!("ModifiedObjectTree::new({seq}): {e}"))
        })?;
        let entry = Arc::new(CachedCheckpoint {
            summary: data.checkpoint_summary,
            tree,
        });
        self.cache.trees.insert(seq, entry.clone()).await;
        Ok(entry)
    }

    async fn build_object_entry(
        &self,
        object: Object,
    ) -> Result<
        (
            CheckpointSequenceNumber,
            VerifiedObjectEntry,
            CertifiedCheckpointSummary,
        ),
        TransportError,
    > {
        let cp_seq = self.tx_checkpoint(object.previous_transaction).await?;
        let cached = self.cached_checkpoint(cp_seq).await?;
        let object_ref = object.compute_object_reference();
        let proof = cached.tree.get_inclusion_proof(object_ref).map_err(|e| {
            TransportError::NotFound(format!("inclusion proof for {object_ref:?}: {e}"))
        })?;
        Ok((
            cp_seq,
            VerifiedObjectEntry {
                object,
                checkpoint_seq: cp_seq,
                proof,
            },
            cached.summary.clone(),
        ))
    }

    /// `tx_digest → checkpoint_seq`, memoized. The mapping is immutable once
    /// committed, so a cache hit is always correct and saves a full-node
    /// round-trip on the serving side (the hot path for relayed reads).
    async fn tx_checkpoint(
        &self,
        tx: TransactionDigest,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        if let Some(seq) = self.cache.tx_checkpoints.get(&tx).await {
            return Ok(seq);
        }
        let seq = self.raw.get_transaction_checkpoint(tx).await?;
        self.cache.tx_checkpoints.insert(tx, seq).await;
        Ok(seq)
    }

    async fn current_head_seq(&self) -> Result<CheckpointSequenceNumber, TransportError> {
        let latest = self.raw.get_latest_checkpoint().await?;
        Ok(*latest.sequence_number())
    }

    fn record_build_failure(&self, kind: &str, err: &TransportError) {
        let reason = match err {
            TransportError::NotFound(_) => "not_found",
            TransportError::Encoding(_) => "encoding",
            TransportError::Network(_) => "network",
        };
        self.metrics
            .proof_build_failures_total
            .with_label_values(&[kind, reason])
            .inc();
    }
}

#[async_trait]
impl ProofProvider for LocalProofProvider {
    async fn verified_object(
        &self,
        id: ObjectID,
    ) -> Result<VerifiedObjectResponse, TransportError> {
        let started = std::time::Instant::now();
        let object = match self.raw.get_object(id).await {
            Ok(o) => o,
            Err(e) => {
                self.record_build_failure("object", &e);
                return Err(e);
            }
        };
        let (_, entry, summary) = match self.build_object_entry(object).await {
            Ok(t) => t,
            Err(e) => {
                self.record_build_failure("object", &e);
                return Err(e);
            }
        };
        self.metrics
            .proof_built_total
            .with_label_values(&["object"])
            .inc();
        self.metrics
            .proof_build_latency_seconds
            .with_label_values(&["object"])
            .observe(started.elapsed().as_secs_f64());
        Ok(VerifiedObjectResponse {
            object: entry.object,
            summary,
            proof: entry.proof,
            claimed_latest_checkpoint_seq: self.current_head_seq().await?,
        })
    }

    async fn batch_verified_objects(
        &self,
        ids: &[ObjectID],
    ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
        let started = std::time::Instant::now();
        let head = self.current_head_seq().await?;
        let raw_objects = self.raw.batch_get_objects(ids).await?;
        let mut summaries: BTreeMap<CheckpointSequenceNumber, CertifiedCheckpointSummary> =
            BTreeMap::new();
        let mut results = Vec::with_capacity(raw_objects.len());
        for object in raw_objects {
            match self.build_object_entry(object).await {
                Ok((seq, entry, summary)) => {
                    summaries.entry(seq).or_insert(summary);
                    self.metrics
                        .proof_built_total
                        .with_label_values(&["batch_entry"])
                        .inc();
                    results.push(Some(entry));
                }
                Err(e) => {
                    self.record_build_failure("batch_entry", &e);
                    results.push(None);
                }
            }
        }
        self.metrics
            .proof_build_latency_seconds
            .with_label_values(&["batch"])
            .observe(started.elapsed().as_secs_f64());
        Ok(BatchVerifiedObjectsResponse {
            summaries,
            results,
            claimed_latest_checkpoint_seq: head,
        })
    }

    async fn verified_bag_page(
        &self,
        request: VerifiedBagPageRequest,
    ) -> Result<VerifiedBagPageResponse, TransportError> {
        let started = std::time::Instant::now();
        // We deliberately do NOT fetch the bag object itself. A Move
        // `Bag { id: UID, size: u64 }` lives inlined inside its parent
        // (e.g. `DWalletCoordinatorInner`), so its `id` is wrapped and
        // `get_object(bag_id)` 404s. The dynamic-field index still works
        // via that same id, which is enough to enumerate the children.
        // Bag-size omission detection is therefore deferred to the
        // consumer via the parent's verified state.
        let head = self.current_head_seq().await?;
        let page = self
            .raw
            .list_dynamic_fields(request.bag_id, request.page_size, request.page_token)
            .await?;

        let mut summaries: BTreeMap<CheckpointSequenceNumber, CertifiedCheckpointSummary> =
            BTreeMap::new();
        let mut entries = Vec::with_capacity(page.entries.len());
        self.metrics
            .bag_walk_entries_seen_total
            .inc_by(page.entries.len() as u64);
        for entry in page.entries {
            // Children created very recently may not yet be resolvable
            // (object 404 because the indexer hasn't caught up; or
            // `get_transaction_checkpoint` 404 because the previous tx
            // isn't indexed in a checkpoint yet). Skip and let the next
            // tick pick them up — relayer's listing is untrusted anyway,
            // so dropping a child only delays delivery, never breaks
            // safety.
            let object = match self.raw.get_object(entry.object_id).await {
                Ok(o) => o,
                Err(TransportError::NotFound(_)) => {
                    self.metrics.bag_walk_entries_skipped_transient_total.inc();
                    continue;
                }
                Err(e) => {
                    self.record_build_failure("bag_page_entry", &e);
                    return Err(e);
                }
            };
            match self.build_object_entry(object).await {
                Ok((seq, verified_entry, summary)) => {
                    summaries.entry(seq).or_insert(summary);
                    self.metrics
                        .proof_built_total
                        .with_label_values(&["bag_page_entry"])
                        .inc();
                    self.metrics.bag_walk_entries_returned_total.inc();
                    entries.push(verified_entry);
                }
                Err(TransportError::NotFound(_)) => {
                    self.metrics.bag_walk_entries_skipped_transient_total.inc();
                    continue;
                }
                Err(e) => {
                    self.record_build_failure("bag_page_entry", &e);
                    return Err(e);
                }
            }
        }

        self.metrics
            .proof_build_latency_seconds
            .with_label_values(&["bag_page"])
            .observe(started.elapsed().as_secs_f64());
        Ok(VerifiedBagPageResponse {
            bag: None,
            summaries,
            entries,
            next_page_token: page.next_page_token,
            claimed_latest_checkpoint_seq: head,
        })
    }
}
