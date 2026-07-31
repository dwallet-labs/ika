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
use sui_types::base_types::{ObjectID, ObjectRef};
use sui_types::digests::TransactionDigest;
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointArtifacts, CheckpointSequenceNumber,
};
use sui_types::object::Object;

use ika_sui_client::grpc::SuiGrpcClient;
use ika_sui_client::transport::{SuiTransport, TransportError};

/// Serving-side cap on the number of object ids one `BatchVerifiedObjects`
/// request may carry — each id costs one inclusion-proof build, so this bounds
/// per-request work. Sized to comfortably exceed the largest legitimate batch
/// (the validator set, read whole by `get_validators` / `get_validator_inners`;
/// `max_validator_count` is configurable but realistically in the hundreds)
/// while still cutting off an abusive flood.
const MAX_BATCH_OBJECTS: usize = 4096;

/// Serving-side cap on `VerifiedDynamicFieldsPage` page size — one inclusion-proof build
/// per entry. The gRPC backend clamps too; this is the relay's own bound.
const MAX_DYNAMIC_FIELDS_PAGE_SIZE: u32 = 1000;

/// Producer-side metrics for the `ProofProvider` layer. sui-state-direct nodes
/// running [`LocalProofProvider`] populate the local-only counters
/// (`*_built_total`, `tree_cache_*`); sui-state-mirrored nodes running
/// `SuiMirrorProofProvider` populate the relay-call counters
/// (`relay_*`). Both share `dynamic_fields_walk_*` which counts at the wrapper
/// layer.
#[derive(Clone, Debug)]
pub struct ProofProviderMetrics {
    // -- LocalProofProvider (sui-state-direct) --
    /// Inclusion proofs successfully constructed, by request kind.
    pub proof_built_total: IntCounterVec, // labels: ["kind"="object"|"dynamic_fields_page_entry"|"batch_entry"]
    /// Proof construction failures, by kind and reason.
    pub proof_build_failures_total: IntCounterVec, // labels: ["kind", "reason"]
    /// Times we found the per-checkpoint `ModifiedObjectTree` in cache
    /// and didn't have to refetch + rebuild.
    pub proof_tree_cache_hits_total: IntCounter,
    /// Cache miss → had to fetch the full checkpoint and build the tree.
    pub proof_tree_cache_misses_total: IntCounter,
    /// Proofs reused from the durable verified-state snapshot cache after the
    /// current object's last-modifying checkpoint was pruned upstream.
    pub proof_snapshot_cache_hits_total: IntCounter,

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
    /// object/dynamic-fields/snapshot ops). Bounded-cardinality peer label.
    pub serve_request_by_peer_total: IntCounterVec, // labels: ["op", "peer"]
    /// Serving-side handler latency, by op.
    pub serve_latency_seconds: HistogramVec, // labels: ["op"]

    // -- Dynamic-field walk (both roles) --
    /// Children scanned in `verified_dynamic_fields_page` (across all pages).
    pub dynamic_fields_walk_entries_seen_total: IntCounter,
    /// Children successfully verified and returned.
    pub dynamic_fields_walk_entries_returned_total: IntCounter,
    /// Children skipped because their previous_transaction or object
    /// hadn't been indexed yet — picked up on the next tick.
    pub dynamic_fields_walk_entries_skipped_transient_total: IntCounter,

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
            proof_snapshot_cache_hits_total: register_int_counter_with_registry!(
                "ika_ocs_proof_snapshot_cache_hits_total",
                "OCS proofs reused from the durable verified-state snapshot cache after upstream pruning",
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
            dynamic_fields_walk_entries_seen_total: register_int_counter_with_registry!(
                "ika_ocs_dynamic_fields_walk_entries_seen_total",
                "Children scanned during a verified dynamic-field walk",
                registry,
            )
            .unwrap(),
            dynamic_fields_walk_entries_returned_total: register_int_counter_with_registry!(
                "ika_ocs_dynamic_fields_walk_entries_returned_total",
                "Children successfully verified and returned to the consumer",
                registry,
            )
            .unwrap(),
            dynamic_fields_walk_entries_skipped_transient_total: register_int_counter_with_registry!(
                "ika_ocs_dynamic_fields_walk_entries_skipped_transient_total",
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
    /// For entries surfaced by a dynamic-field walk (`verified_dynamic_fields_page`):
    /// the field's key — stringified `TypeTag` of the name and its BCS
    /// value. Lets the consumer bind a value object to its parent collection
    /// (an `ObjectTable`/`ObjectBag` value is owned by its `Field`, not the
    /// collection UID). Empty for direct/batch object reads.
    #[serde(default)]
    pub dynamic_field_name_type: String,
    #[serde(default)]
    pub dynamic_field_name_bcs: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchVerifiedObjectsResponse {
    pub summaries: BTreeMap<CheckpointSequenceNumber, CertifiedCheckpointSummary>,
    /// Parallel to request `ids`. `None` = couldn't construct (e.g.,
    /// upstream pruned the touching checkpoint).
    pub results: Vec<Option<VerifiedObjectEntry>>,
    pub claimed_latest_checkpoint_seq: CheckpointSequenceNumber,
}

/// Enumerate the dynamic-field children of `parent_id`, one verified page
/// at a time. `parent_id` is any dynamic-field-backed collection — `Bag`,
/// `Table`, `ObjectTable`, `ObjectBag`, or a raw dynamic / dynamic-object
/// field — since at the Sui level they are all dynamic fields hanging off a
/// `UID`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedDynamicFieldsPageRequest {
    pub parent_id: ObjectID,
    pub page_size: Option<u32>,
    pub page_token: Option<Vec<u8>>,
}

/// One verified page of a parent's dynamic-field children. `entries` are the
/// proven children (each an object plus its field key — see
/// `VerifiedObjectEntry`); `summaries` carries each distinct last-modifying
/// checkpoint summary once (BLS dedup); `next_page_token` continues the walk.
/// The parent object itself is **not** returned: it is inlined inside its own
/// parent struct and so isn't fetchable by id — a consumer that needs
/// omission detection reads the authenticated collection `size` from verified
/// parent state instead.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiedDynamicFieldsPageResponse {
    pub summaries: BTreeMap<CheckpointSequenceNumber, CertifiedCheckpointSummary>,
    pub entries: Vec<VerifiedObjectEntry>,
    pub next_page_token: Option<Vec<u8>>,
    pub claimed_latest_checkpoint_seq: CheckpointSequenceNumber,
    /// Children the upstream LISTED for this page but could not build a
    /// proof for — typically because the child's defining checkpoint was
    /// already pruned upstream, which is PERMANENT: the entry would be
    /// silently missing from every future page too. Being live-listed
    /// proves the child still exists on-chain, so the consumer can resolve
    /// each id through a verified object read, whose committee-verified
    /// cache fallback serves entries whose defining checkpoint is gone.
    /// `serde(default)` keeps wire compatibility with older relays.
    #[serde(default)]
    pub skipped_entry_ids: Vec<ObjectID>,
}

#[async_trait]
pub trait ProofProvider: Send + Sync {
    async fn verified_object(&self, id: ObjectID)
    -> Result<VerifiedObjectResponse, TransportError>;

    async fn batch_verified_objects(
        &self,
        ids: &[ObjectID],
    ) -> Result<BatchVerifiedObjectsResponse, TransportError>;

    /// Verified, paginated enumeration of a parent object's dynamic-field
    /// children. Generic over the collection kind — `Bag`, `Table`,
    /// `ObjectTable`, `ObjectBag`, and raw dynamic / dynamic-object fields are
    /// all dynamic fields under a `UID`, so this one call covers every
    /// dynamic-field-backed collection. Each child carries its own inclusion
    /// proof and field key; the caller binds it to `parent_id` via the
    /// proof-bound owner (`dynamic_field_child_owned_by`), since an inclusion
    /// proof alone shows the object existed, not that it belongs to the
    /// requested collection.
    async fn verified_dynamic_fields_page(
        &self,
        request: VerifiedDynamicFieldsPageRequest,
    ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError>;
}

/// Read-only bridge to the durable, already-verified object snapshots owned by
/// the connector. The producer consults it only after fetching the current Sui
/// object and requiring an exact object-reference match, so a stale snapshot
/// can never be served as current.
pub trait ProofSnapshotCache: Send + Sync {
    fn get_proof_snapshot(
        &self,
        id: ObjectID,
    ) -> Option<(VerifiedObjectEntry, CertifiedCheckpointSummary)>;
}

type ProofBuildResult = Result<
    (
        CheckpointSequenceNumber,
        VerifiedObjectEntry,
        CertifiedCheckpointSummary,
    ),
    TransportError,
>;

fn recover_pruned_proof(
    result: ProofBuildResult,
    proof_snapshot_cache: Option<&dyn ProofSnapshotCache>,
    current_object_ref: ObjectRef,
) -> (ProofBuildResult, bool) {
    let Err(TransportError::NotFound(reason)) = result else {
        return (result, false);
    };
    let recovered = proof_snapshot_cache
        .and_then(|cache| cache.get_proof_snapshot(current_object_ref.0))
        .filter(|(entry, _)| entry.object.compute_object_reference() == current_object_ref)
        .map(|(entry, summary)| (entry.checkpoint_seq, entry, summary));
    match recovered {
        Some(recovered) => (Ok(recovered), true),
        None => (Err(TransportError::NotFound(reason)), false),
    }
}

#[derive(Clone, Debug)]
pub struct ProofCacheConfig {
    /// Entry-count capacity for the per-checkpoint tree cache. Sized by
    /// count, not bytes, deliberately: an entry is a checkpoint summary plus
    /// a `ModifiedObjectTree` (object refs + hashes — tens of KB for a busy
    /// checkpoint, not the full `CheckpointData`), so 32 entries is a few MB
    /// worst-case, and `tree_ttl` already bounds residency. Revisit with a
    /// moka weigher only if entries ever start carrying object contents.
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
    /// The node's own direct gRPC client. Concrete (not `Arc<dyn SuiTransport>`)
    /// because proof building needs `get_transaction_checkpoint`, which is an
    /// inherent `SuiGrpcClient` method rather than part of the relay-able
    /// `SuiTransport` surface. A `LocalProofProvider` only ever runs on a
    /// sui-state-direct node over its own fullnode, so the concrete type fits.
    raw: Arc<SuiGrpcClient>,
    cache: ProofCache,
    proof_snapshot_cache: Option<Arc<dyn ProofSnapshotCache>>,
    metrics: Arc<ProofProviderMetrics>,
}

impl LocalProofProvider {
    pub fn new(
        raw: Arc<SuiGrpcClient>,
        cfg: &ProofCacheConfig,
        metrics: Arc<ProofProviderMetrics>,
    ) -> Self {
        Self {
            raw,
            cache: ProofCache::new(cfg),
            proof_snapshot_cache: None,
            metrics,
        }
    }

    pub fn with_proof_snapshot_cache(mut self, cache: Arc<dyn ProofSnapshotCache>) -> Self {
        self.proof_snapshot_cache = Some(cache);
        self
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
        let object_ref = object.compute_object_reference();
        let result = async {
            let cp_seq = self.tx_checkpoint(object.previous_transaction).await?;
            let cached = self.cached_checkpoint(cp_seq).await?;
            let proof = cached.tree.get_inclusion_proof(object_ref).map_err(|e| {
                TransportError::NotFound(format!("inclusion proof for {object_ref:?}: {e}"))
            })?;
            Ok((
                cp_seq,
                VerifiedObjectEntry {
                    object,
                    checkpoint_seq: cp_seq,
                    proof,
                    // Populated by the dynamic-fields-page walk (which has the field key);
                    // empty for direct/batch object reads.
                    dynamic_field_name_type: String::new(),
                    dynamic_field_name_bcs: Vec::new(),
                },
                cached.summary.clone(),
            ))
        }
        .await;

        let (result, recovered) =
            recover_pruned_proof(result, self.proof_snapshot_cache.as_deref(), object_ref);
        if recovered {
            self.metrics.proof_snapshot_cache_hits_total.inc();
        }
        result
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
        // Bound per-request work: the serving side builds one inclusion proof
        // per id, so an unbounded id list is unbounded server work. Reject
        // (rather than truncate) — the response is positional, so a silent
        // truncation would mis-align results with the caller's ids.
        if ids.len() > MAX_BATCH_OBJECTS {
            return Err(TransportError::Network(format!(
                "batch_verified_objects request has {} ids, over the {MAX_BATCH_OBJECTS} cap",
                ids.len()
            )));
        }
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

    async fn verified_dynamic_fields_page(
        &self,
        request: VerifiedDynamicFieldsPageRequest,
    ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
        let started = std::time::Instant::now();
        // We deliberately do NOT fetch the parent collection object itself.
        // A Move collection (e.g. `Bag { id: UID, size: u64 }`) lives inlined
        // inside its owning struct (e.g. `DWalletCoordinatorInner`), so its
        // `id` is wrapped and `get_object(parent_id)` 404s. The dynamic-field
        // index still works via that same id, which is enough to enumerate the
        // children. Size-based omission detection is therefore deferred to the
        // consumer via the parent's verified state.
        let head = self.current_head_seq().await?;
        // Cap page size (the serving side builds one proof per entry). The
        // gRPC backend already clamps, but don't rely on the upstream's cap.
        // `None` keeps the backend default; a `Some` is clamped to our max.
        let page_size = request
            .page_size
            .map(|n| n.min(MAX_DYNAMIC_FIELDS_PAGE_SIZE));
        let page = self
            .raw
            .list_dynamic_fields(request.parent_id, page_size, request.page_token)
            .await?;

        let mut summaries: BTreeMap<CheckpointSequenceNumber, CertifiedCheckpointSummary> =
            BTreeMap::new();
        let mut entries = Vec::with_capacity(page.entries.len());
        let mut skipped_entry_ids = Vec::new();
        self.metrics
            .dynamic_fields_walk_entries_seen_total
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
                    self.metrics
                        .dynamic_fields_walk_entries_skipped_transient_total
                        .inc();
                    skipped_entry_ids.push(entry.object_id);
                    continue;
                }
                Err(e) => {
                    self.record_build_failure("dynamic_fields_page_entry", &e);
                    return Err(e);
                }
            };
            match self.build_object_entry(object).await {
                Ok((seq, mut verified_entry, summary)) => {
                    // Carry the field key so the consumer can bind this entry
                    // to `parent_id` even when it's an `ObjectTable`/`ObjectBag`
                    // value object (owned by its `Field`, not the collection).
                    verified_entry.dynamic_field_name_type = entry.name_type;
                    verified_entry.dynamic_field_name_bcs = entry.name_value_bcs;
                    summaries.entry(seq).or_insert(summary);
                    self.metrics
                        .proof_built_total
                        .with_label_values(&["dynamic_fields_page_entry"])
                        .inc();
                    self.metrics
                        .dynamic_fields_walk_entries_returned_total
                        .inc();
                    entries.push(verified_entry);
                }
                Err(TransportError::NotFound(_)) => {
                    self.metrics
                        .dynamic_fields_walk_entries_skipped_transient_total
                        .inc();
                    skipped_entry_ids.push(entry.object_id);
                    continue;
                }
                Err(e) => {
                    self.record_build_failure("dynamic_fields_page_entry", &e);
                    return Err(e);
                }
            }
        }

        self.metrics
            .proof_build_latency_seconds
            .with_label_values(&["dynamic_fields_page"])
            .observe(started.elapsed().as_secs_f64());
        Ok(VerifiedDynamicFieldsPageResponse {
            summaries,
            entries,
            next_page_token: page.next_page_token,
            claimed_latest_checkpoint_seq: head,
            skipped_entry_ids,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sui_light_client::proof::ocs::ModifiedObjectTree;
    use sui_types::base_types::SequenceNumber;
    use sui_types::committee::Committee as SuiCommittee;
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::digests::CheckpointContentsDigest;
    use sui_types::gas::GasCostSummary;
    use sui_types::messages_checkpoint::{
        CheckpointArtifacts, CheckpointCommitment, CheckpointSummary,
    };
    use sui_types::object::Owner;

    struct StaticSnapshotCache {
        entry: VerifiedObjectEntry,
        summary: CertifiedCheckpointSummary,
    }

    impl ProofSnapshotCache for StaticSnapshotCache {
        fn get_proof_snapshot(
            &self,
            id: ObjectID,
        ) -> Option<(VerifiedObjectEntry, CertifiedCheckpointSummary)> {
            (id == self.entry.object.id()).then(|| {
                let entry = bcs::from_bytes(
                    &bcs::to_bytes(&self.entry).expect("verified entry must serialize"),
                )
                .expect("verified entry must deserialize");
                (entry, self.summary.clone())
            })
        }
    }

    fn snapshot_cache(
        committee: &SuiCommittee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        object: &Object,
    ) -> StaticSnapshotCache {
        let (id, version, digest) = object.compute_object_reference();
        let artifacts =
            CheckpointArtifacts::from_object_states(BTreeMap::from([(id, (version, digest))]));
        let artifacts_digest = artifacts.digest().expect("artifacts digest");
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: CheckpointContentsDigest::new([0; 32]),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![CheckpointCommitment::from(artifacts_digest)],
            end_of_epoch_data: None,
            version_specific_data: Vec::new(),
        };
        let summary =
            CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keys, committee);
        let proof = ModifiedObjectTree::new(&artifacts)
            .expect("modified object tree")
            .get_inclusion_proof(object.compute_object_reference())
            .expect("inclusion proof");
        StaticSnapshotCache {
            entry: VerifiedObjectEntry {
                object: object.clone(),
                checkpoint_seq: seq,
                proof,
                dynamic_field_name_type: String::new(),
                dynamic_field_name_bcs: Vec::new(),
            },
            summary,
        }
    }

    #[test]
    fn pruned_proof_reuses_only_an_exact_current_snapshot() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let id = ObjectID::from_single_byte(0xA1);
        let owner = Owner::ObjectOwner(ObjectID::from_single_byte(0xB2).into());
        let cached_object = Object::with_id_owner_version_for_testing(
            id,
            SequenceNumber::from(7u64),
            owner.clone(),
        );
        let cache = snapshot_cache(&committee, &keys, 42, &cached_object);

        let (recovered, cache_hit) = recover_pruned_proof(
            Err(TransportError::NotFound("checkpoint pruned".into())),
            Some(&cache),
            cached_object.compute_object_reference(),
        );
        assert!(cache_hit);
        let (_, entry, _) = recovered.expect("exact-current snapshot must recover the proof");
        assert_eq!(
            entry.object.compute_object_reference(),
            cached_object.compute_object_reference()
        );

        let newer_object =
            Object::with_id_owner_version_for_testing(id, SequenceNumber::from(8u64), owner);
        let (rejected, cache_hit) = recover_pruned_proof(
            Err(TransportError::NotFound("checkpoint pruned".into())),
            Some(&cache),
            newer_object.compute_object_reference(),
        );
        assert!(!cache_hit);
        assert!(matches!(rejected, Err(TransportError::NotFound(_))));
    }
}
