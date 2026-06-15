// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Consumer-facing verified-read surface.
//!
//! [`OcsVerifiedReader`] wraps a [`ProofProvider`] (local or remote-anemo)
//! and bolts on the three checks we need to safely consume Ika objects
//! served from an untrusted relay:
//!
//! 1. Inclusion-proof verification against [`CommitteeStore`].
//! 2. Per-object version monotonicity (rejects stale-state attacks).
//! 3. Optional freshness bound (proof seq vs relay's claimed head).
//!
//! Plus a bag-omission detector when the response carries the parent bag's
//! own object: compare `bag.size` against accumulated children.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use sui_light_client::proof::base::{
    Proof, ProofContents, ProofContentsVerifier, ProofTarget, ProofVerifier,
};
use sui_light_client::proof::ocs::{OCSInclusionProof, OCSProof};
use sui_types::base_types::{ObjectID, SequenceNumber};
use sui_types::dynamic_field::Field;
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointSequenceNumber, VerifiedCheckpoint,
};
use sui_types::object::{Object, Owner};

use ika_sui_client::transport::{TransportError, derive_object_field_wrapper_id};

use ika_network::proof_provider::{ProofProvider, VerifiedBagPageRequest, VerifiedObjectResponse};

use ika_types::sui::system_inner_v1::{DWalletCoordinatorInnerV1, SystemInnerV1};
use ika_types::sui::{DWalletCoordinator, DWalletCoordinatorInner, System, SystemInner};

use crate::sui_connector::committee_store::{CommitteeStore, SummaryVerifyError};
use crate::sui_connector::ocs_metrics::OcsMetrics;
use crate::sui_connector::verified_state_cache::SharedVerifiedStateCache;
use ika_network::proof_provider::VerifiedObjectEntry;

#[derive(thiserror::Error, Debug)]
pub enum ReaderError {
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("proof verify: {0}")]
    InvalidProof(String),
    #[error("missing committee for epoch {0}")]
    MissingCommittee(u64),
    #[error("stale: object {id} version {got:?} < high-water {cached:?}")]
    StaleVersion {
        id: ObjectID,
        got: SequenceNumber,
        cached: SequenceNumber,
    },
    #[error(
        "stale: proof at checkpoint {object_seq} is {gap} behind claimed head \
         {head}, bound {bound}"
    )]
    StaleCheckpoint {
        object_seq: CheckpointSequenceNumber,
        head: CheckpointSequenceNumber,
        gap: u64,
        bound: u64,
    },
    #[error("decode: {0}")]
    Decode(String),
    #[error("unsupported version {kind}={version}")]
    UnsupportedVersion { kind: &'static str, version: u64 },
    #[error(
        "bag membership: entry {entry} in a page for bag {bag_id} is owned by \
         {owner} — not a dynamic-field child of the requested bag"
    )]
    BagMembership {
        bag_id: ObjectID,
        entry: ObjectID,
        owner: String,
    },
}

#[derive(Debug, Clone)]
pub struct VerifiedObject {
    pub object: Object,
    pub source_checkpoint_seq: CheckpointSequenceNumber,
}

#[derive(Debug)]
pub struct VerifiedBagPage {
    pub entries: Vec<VerifiedObject>,
    pub next_page_token: Option<Vec<u8>>,
}

pub struct OcsVerifiedReader {
    provider: Arc<dyn ProofProvider>,
    committees: Arc<CommitteeStore>,
    metrics: Arc<OcsMetrics>,
    /// Per well-known object id, the highest version we've ever accepted.
    /// Bag-entry children are intentionally *not* tracked — their ids are
    /// short-lived (dynamic fields), so tracking would just leak memory.
    high_water: RwLock<HashMap<ObjectID, SequenceNumber>>,
    /// Reject any proof whose checkpoint is more than this many behind the
    /// provider's claimed head. None disables the bound.
    freshness_bound: Option<u64>,
    /// Verified-state cache. Always shadow-populated on the network path.
    /// When `cache_first` is set we also *serve* `verified_object` reads
    /// from it (see [`Self::try_cache_hit`]).
    cache: SharedVerifiedStateCache,
    /// Serve `verified_object` from `cache` before hitting the network.
    /// Sound only where the cache is complete and contiguous — i.e. on
    /// sui-state-direct, where the local `IkaCheckpointPusher` folds every
    /// Ika-modified object of every checkpoint, in order, into the cache.
    /// Left off on sui-state-mirrored: that cache is a read-through memo of
    /// an untrusted relay and can lag arbitrarily, so reads must stay on
    /// the (per-read verified) relay path.
    cache_first: bool,
    /// Highest upstream checkpoint seq we've observed from a provider response
    /// (`claimed_latest_checkpoint_seq`). Updated on every network read/bag
    /// walk — and bag walks run every pump tick independently of the pusher —
    /// so this stays fresh even if the pusher stalls. Used by the cache-first
    /// staleness tripwire below.
    observed_upstream_head: AtomicU64,
    /// Cache-first staleness tripwire: if the cache head lags
    /// `observed_upstream_head` by more than this many checkpoints, the cache
    /// is too stale (e.g. a stalled pusher), so `try_cache_hit` falls through
    /// to the network instead of serving frozen state. `None` disables it.
    staleness_bound: Option<u64>,
}

impl OcsVerifiedReader {
    pub fn new(
        provider: Arc<dyn ProofProvider>,
        committees: Arc<CommitteeStore>,
        metrics: Arc<OcsMetrics>,
        freshness_bound: Option<u64>,
        cache: SharedVerifiedStateCache,
        cache_first: bool,
        staleness_bound: Option<u64>,
    ) -> Self {
        Self {
            provider,
            committees,
            metrics,
            high_water: RwLock::new(HashMap::new()),
            freshness_bound,
            cache,
            cache_first,
            observed_upstream_head: AtomicU64::new(0),
            staleness_bound,
        }
    }

    /// Fold a provider-reported upstream head into `observed_upstream_head`
    /// (monotonic). Called on every network read so the cache-first staleness
    /// tripwire has a fresh reference even when cache-first short-circuits.
    fn note_upstream_head(&self, seq: CheckpointSequenceNumber) {
        self.observed_upstream_head
            .fetch_max(seq, Ordering::Relaxed);
    }

    pub async fn verified_object(&self, id: ObjectID) -> Result<VerifiedObject, ReaderError> {
        let started = std::time::Instant::now();
        if self.cache_first
            && let Some(hit) = self.try_cache_hit(id)
        {
            self.observe_verify_latency("object_cache_hit", started);
            return Ok(hit);
        }
        let resp = self.provider.verified_object(id).await?;
        let result = self.verify_response(id, resp);
        self.record_verify_outcome("object", &result);
        self.observe_verify_latency("object", started);
        result
    }

    /// Batch counterpart of [`Self::verified_object`]: one provider
    /// round-trip for all `ids`, then the same per-object guarantees —
    /// freshness against the monotonic observed head, inclusion proof
    /// against a BLS-verified summary (verified once per distinct
    /// checkpoint, as in [`Self::verified_bag_page`]), high-water version
    /// tracking, and cache shadow-population. Errors if any id is missing
    /// from the response: callers ask for objects that must exist (e.g.
    /// the validator set), so a hole is a failed read, not an empty slot.
    pub async fn verified_objects(
        &self,
        ids: &[ObjectID],
    ) -> Result<Vec<VerifiedObject>, ReaderError> {
        let started = std::time::Instant::now();
        let resp = self.provider.batch_verified_objects(ids).await?;
        self.note_upstream_head(resp.claimed_latest_checkpoint_seq);
        let observed_head = self.observed_upstream_head.load(Ordering::Relaxed);

        let mut verified_summaries: HashMap<CheckpointSequenceNumber, VerifiedCheckpoint> =
            HashMap::new();
        let mut out = Vec::with_capacity(ids.len());
        for (id, slot) in ids.iter().zip(resp.results) {
            let entry = slot.ok_or_else(|| {
                ReaderError::Transport(TransportError::NotFound(format!(
                    "object {id} missing from batch response"
                )))
            })?;
            if entry.object.id() != *id {
                let entry_result: Result<(), ReaderError> =
                    Err(ReaderError::InvalidProof(format!(
                        "batch response slot for {id} carries object {}",
                        entry.object.id()
                    )));
                self.record_verify_outcome_unit("batch_objects", &entry_result);
                entry_result?;
            }
            let seq = entry.checkpoint_seq;
            self.check_freshness(seq, observed_head)
                .map_err(|e| self.record_fail("batch_objects", e))?;
            // Verify each distinct checkpoint's summary once, then reuse it.
            let verified_summary = match verified_summaries.entry(seq) {
                Entry::Occupied(e) => e.into_mut(),
                Entry::Vacant(e) => {
                    let summary = resp
                        .summaries
                        .get(&seq)
                        .ok_or_else(|| {
                            self.record_fail(
                                "batch_objects",
                                ReaderError::Decode(format!(
                                    "missing summary {seq} for batch entry {id}"
                                )),
                            )
                        })?
                        .clone();
                    let verified_summary = self
                        .verify_summary(summary)
                        .map_err(|e| self.record_fail("batch_objects", e))?;
                    e.insert(verified_summary)
                }
            };

            let cache_proof = clone_inclusion_proof(&entry.proof);
            let cache_object = entry.object.clone();
            let entry_result =
                self.verify_ocs_inclusion(&entry.object, entry.proof, verified_summary);
            self.record_verify_outcome_unit("batch_objects", &entry_result);
            entry_result?;
            self.record_high_water(entry.object.id(), entry.object.version())
                .map_err(|e| self.record_fail("batch_objects", e))?;
            if let Some(proof) = cache_proof {
                let cache_summary = resp
                    .summaries
                    .get(&seq)
                    .expect("summary present for entry")
                    .clone();
                let cache_entry = VerifiedObjectEntry {
                    object: cache_object,
                    checkpoint_seq: seq,
                    proof,
                    dynamic_field_name_type: String::new(),
                    dynamic_field_name_bcs: Vec::new(),
                };
                self.cache.absorb_entries(&cache_summary, &[cache_entry]);
            }
            out.push(VerifiedObject {
                object: entry.object,
                source_checkpoint_seq: seq,
            });
        }
        self.observe_verify_latency("batch_objects", started);
        Ok(out)
    }

    /// Cache-first fast path for [`Self::verified_object`]. Returns `Some`
    /// only when the object is present in the locally pusher-populated
    /// cache and passes version-monotonicity. The cache only ever holds
    /// committee-verified state (folded post-verification by the pusher,
    /// push handler, or our own network reads), so we deliberately do
    /// *not* re-run the inclusion proof here — skipping that round-trip
    /// plus re-verify is the whole point. `None` means "fall through to
    /// the network": the object is absent, or a stale-version tripwire
    /// fired (the cached copy is older than one we've already served, so
    /// we re-fetch a fresh one).
    fn try_cache_hit(&self, id: ObjectID) -> Option<VerifiedObject> {
        // Staleness tripwire: if the cache head has fallen too far behind the
        // observed upstream head (e.g. a stalled pusher), don't serve frozen
        // state — fall through to the per-read-verified network path. This
        // strictly *adds* verification, so there's no stale-read regression.
        if let Some(bound) = self.staleness_bound {
            let upstream = self.observed_upstream_head.load(Ordering::Relaxed);
            let cache_head = self.cache.head_seq();
            if upstream.saturating_sub(cache_head) > bound {
                self.metrics.cache_first_stale_total.inc();
                self.metrics
                    .cache_read_total
                    .with_label_values(&["miss"])
                    .inc();
                return None;
            }
        }
        let Some(snapshot) = self.cache.get(id) else {
            self.metrics
                .cache_read_total
                .with_label_values(&["miss"])
                .inc();
            return None;
        };
        let object_id = snapshot.object.id();
        let version = snapshot.object.version();
        match self.record_high_water(object_id, version) {
            Ok(()) => {
                self.metrics
                    .cache_read_total
                    .with_label_values(&["hit"])
                    .inc();
                Some(VerifiedObject {
                    object: snapshot.object,
                    source_checkpoint_seq: snapshot.source_checkpoint_seq,
                })
            }
            Err(_) => {
                self.metrics.high_water_violations_total.inc();
                self.metrics
                    .cache_read_total
                    .with_label_values(&["miss"])
                    .inc();
                None
            }
        }
    }

    pub async fn verified_bag_page(
        &self,
        bag_id: ObjectID,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
    ) -> Result<VerifiedBagPage, ReaderError> {
        let started = std::time::Instant::now();
        let resp = self
            .provider
            .verified_bag_page(VerifiedBagPageRequest {
                bag_id,
                page_size,
                page_token,
            })
            .await?;
        let head = resp.claimed_latest_checkpoint_seq;
        self.note_upstream_head(head);

        // No freshness bound on bag entries: a session event can sit in
        // the bag across many checkpoints, so its proof's checkpoint seq
        // legitimately lags far behind the relay's head. The freshness
        // bound applies to objects we expect to advance frequently
        // (coordinator/system); per-entry monotonicity protections are
        // out of scope here because bag-entry ObjectIDs are short-lived.
        //
        // The bag's parent object isn't fetchable (it's wrapped inside
        // its parent struct), so we don't verify the bag itself here.
        // Bag-omission detection lives in the consumer, which has the
        // expected `Bag.size` from a verified parent state and can
        // accumulate child counts across pages.
        let _ = head;
        let mut verified = Vec::with_capacity(resp.entries.len());
        // Per-summary BLS dedup: a bag page's entries usually all anchor to a
        // handful of checkpoints, and the committee BLS verify is the dominant
        // cost. The page's `summaries` map is 1:1 with checkpoint seq, so
        // verifying each distinct summary once (→ `VerifiedCheckpoint`) and
        // reusing it for every entry at that seq is safe — each entry still
        // gets its own Merkle/artifacts-digest check below. Drops BLS verifies
        // from O(entries) to O(distinct checkpoints).
        let mut verified_summaries: HashMap<CheckpointSequenceNumber, VerifiedCheckpoint> =
            HashMap::new();
        for entry in resp.entries {
            let seq = entry.checkpoint_seq;
            // Verify each distinct checkpoint's summary once, then reuse it.
            let verified_summary = match verified_summaries.entry(seq) {
                Entry::Occupied(e) => e.into_mut(),
                Entry::Vacant(e) => {
                    let summary = resp
                        .summaries
                        .get(&seq)
                        .ok_or_else(|| {
                            self.record_fail(
                                "bag_entry",
                                ReaderError::Decode("missing summary for bag entry".into()),
                            )
                        })?
                        .clone();
                    let verified_summary = self
                        .verify_summary(summary)
                        .map_err(|e| self.record_fail("bag_entry", e))?;
                    e.insert(verified_summary)
                }
            };

            let cache_proof = clone_inclusion_proof(&entry.proof);
            let cache_object = entry.object.clone();
            // The cache stores `(object, proof, summary)`; reconstruct the
            // unverified summary from the page map for absorption.
            let cache_summary = resp
                .summaries
                .get(&seq)
                .expect("summary present for entry")
                .clone();
            let entry_result =
                self.verify_ocs_inclusion(&entry.object, entry.proof, verified_summary);
            self.record_verify_outcome_unit("bag_entry", &entry_result);
            entry_result?;
            // Bind the entry to the requested collection. The inclusion proof
            // above only attests that this object existed on-chain at a
            // verified checkpoint — NOT that it is a member of `bag_id`. The
            // binding is the entry's owner, which is part of the
            // proof-verified object digest, and depends on the collection
            // kind:
            //   - A plain `Bag`/`Table` stores the value inline in a
            //     `Field<K, V>` owned directly by the collection UID:
            //     `Owner::ObjectOwner(bag_id)`.
            //   - An `ObjectTable`/`ObjectBag` resolves to the wrapped value
            //     object, which is owned by its `Field<Wrapper<K>, ID>`
            //     wrapper, whose id is
            //     `derive_dynamic_field_id(bag_id, Wrapper<K>, key)`. The
            //     relay's key is untrusted, but the derivation is
            //     collision-resistant against the proven owner, so a relay
            //     cannot supply a name that derives to a *foreign* object's
            //     owner.
            // Without this a malicious relay could return a validly-proven
            // dynamic field of a *different* collection (e.g. replayed session
            // events), which the count-only omission detector wouldn't catch.
            let bound_to_collection = match entry.object.owner() {
                Owner::ObjectOwner(addr) => {
                    let owner_id = ObjectID::from(*addr);
                    owner_id == bag_id
                        || derive_object_field_wrapper_id(
                            bag_id,
                            &entry.dynamic_field_name_type,
                            &entry.dynamic_field_name_bcs,
                        )
                        .is_some_and(|field_id| owner_id == field_id)
                }
                _ => false,
            };
            if !bound_to_collection {
                return Err(self.record_fail(
                    "bag_entry",
                    ReaderError::BagMembership {
                        bag_id,
                        entry: entry.object.id(),
                        owner: format!("{:?}", entry.object.owner()),
                    },
                ));
            }
            if let Some(proof) = cache_proof {
                let cache_entry = VerifiedObjectEntry {
                    object: cache_object,
                    checkpoint_seq: seq,
                    proof,
                    dynamic_field_name_type: String::new(),
                    dynamic_field_name_bcs: Vec::new(),
                };
                self.cache.absorb_entries(&cache_summary, &[cache_entry]);
            }
            verified.push(VerifiedObject {
                object: entry.object,
                source_checkpoint_seq: seq,
            });
        }

        self.observe_verify_latency("bag_page", started);
        Ok(VerifiedBagPage {
            entries: verified,
            next_page_token: resp.next_page_token,
        })
    }

    pub fn forget_high_water(&self, id: &ObjectID) {
        self.high_water.write().remove(id);
    }

    /// Whether bag walks served by this reader come from an *untrusted
    /// relay*, so a consumer should police `Bag.size`-vs-listed-children
    /// omission (a relay could hide entries). True on sui-state-mirrored.
    ///
    /// False on sui-state-direct (`cache_first`): there bag pages come
    /// from the local trusted gRPC provider — nothing to omit — while the
    /// parent's `Bag.size` is served cache-first and therefore lags the
    /// (fresh) bag walk by up to the pusher's poll interval. A
    /// size-greater-than-listed mismatch there is an expected freshness
    /// artifact (entries removed on session completion), not misbehavior,
    /// so policing it would just cry wolf.
    pub fn bag_source_is_untrusted(&self) -> bool {
        !self.cache_first
    }

    fn record_verify_outcome<T>(&self, kind: &'static str, result: &Result<T, ReaderError>) {
        match result {
            Ok(_) => {
                self.metrics
                    .proof_verify_total
                    .with_label_values(&[kind])
                    .inc();
            }
            Err(e) => self.record_verify_failure(kind, e),
        }
    }

    /// Count one verify failure under `(kind, reason)`, plus the high-water
    /// violation gauge for a stale version.
    fn record_verify_failure(&self, kind: &'static str, e: &ReaderError) {
        let reason = classify_verify_error(e);
        self.metrics
            .proof_verify_failures_total
            .with_label_values(&[kind, reason])
            .inc();
        if matches!(e, ReaderError::StaleVersion { .. }) {
            self.metrics.high_water_violations_total.inc();
        }
    }

    fn record_verify_outcome_unit(&self, kind: &'static str, result: &Result<(), ReaderError>) {
        self.record_verify_outcome(kind, result);
    }

    /// Record a verify failure under `kind` (lands in
    /// `proof_verify_failures_total`, and `high_water_violations_total` for a
    /// stale version) and return it. For failure points on the batch/bag
    /// paths that would otherwise `?`-propagate or return *around* the
    /// per-entry [`Self::record_verify_outcome`] — the summary BLS verify, the
    /// missing-summary decode, the freshness/high-water checks, and the
    /// bag-membership binding — so no verified-read failure mode is silent.
    fn record_fail(&self, kind: &'static str, e: ReaderError) -> ReaderError {
        self.record_verify_failure(kind, &e);
        e
    }

    fn observe_verify_latency(&self, kind: &'static str, started: std::time::Instant) {
        self.metrics
            .verify_latency_seconds
            .with_label_values(&[kind])
            .observe(started.elapsed().as_secs_f64());
    }

    /// OCS-verified read of the `DWalletCoordinator` outer + its versioned
    /// inner. Outer carries a `u64 version` field; the actual data lives
    /// at `Field<u64, DWalletCoordinatorInnerV1>` whose object id is
    /// derived deterministically from `(coordinator_id, version)` — we
    /// never trust a relayer's listing for which child backs a given
    /// version.
    pub async fn verified_dwallet_coordinator_inner(
        &self,
        coordinator_id: ObjectID,
    ) -> Result<(DWalletCoordinator, DWalletCoordinatorInner), ReaderError> {
        let outer_obj = self.verified_object(coordinator_id).await?;
        let outer_bcs = move_object_contents(&outer_obj.object)?;
        let outer: DWalletCoordinator = bcs::from_bytes(outer_bcs)
            .map_err(|e| ReaderError::Decode(format!("DWalletCoordinator: {e}")))?;

        match outer.version {
            1 | 2 => {
                let child_id = derive_versioned_child_id(coordinator_id, outer.version)?;
                let child_obj = self.verified_object(child_id).await?;
                let child_bcs = move_object_contents(&child_obj.object)?;
                let field: Field<u64, DWalletCoordinatorInnerV1> = bcs::from_bytes(child_bcs)
                    .map_err(|e| {
                        ReaderError::Decode(format!("Field<u64, DWalletCoordinatorInnerV1>: {e}"))
                    })?;
                Ok((outer, DWalletCoordinatorInner::V1(field.value)))
            }
            v => Err(ReaderError::UnsupportedVersion {
                kind: "DWalletCoordinator",
                version: v,
            }),
        }
    }

    /// OCS-verified read of the `System` outer + its versioned inner.
    /// Same versioned-dynamic-field pattern as
    /// [`Self::verified_dwallet_coordinator_inner`].
    pub async fn verified_system_inner(
        &self,
        system_id: ObjectID,
    ) -> Result<(System, SystemInner), ReaderError> {
        let outer_obj = self.verified_object(system_id).await?;
        let outer_bcs = move_object_contents(&outer_obj.object)?;
        let outer: System =
            bcs::from_bytes(outer_bcs).map_err(|e| ReaderError::Decode(format!("System: {e}")))?;

        match outer.version {
            1 | 2 => {
                let child_id = derive_versioned_child_id(system_id, outer.version)?;
                let child_obj = self.verified_object(child_id).await?;
                let child_bcs = move_object_contents(&child_obj.object)?;
                let field: Field<u64, SystemInnerV1> = bcs::from_bytes(child_bcs)
                    .map_err(|e| ReaderError::Decode(format!("Field<u64, SystemInnerV1>: {e}")))?;
                Ok((outer, SystemInner::V1(field.value)))
            }
            v => Err(ReaderError::UnsupportedVersion {
                kind: "System",
                version: v,
            }),
        }
    }

    fn verify_response(
        &self,
        requested_id: ObjectID,
        resp: VerifiedObjectResponse,
    ) -> Result<VerifiedObject, ReaderError> {
        // Bind the response to the request: the inclusion proof attests that
        // the returned object existed on-chain, NOT that it is the object we
        // asked for. Without this a malicious relay could answer `get(X)` with
        // any other validly-proven object `Y`. (The batch path does the same
        // per-entry check.)
        if resp.object.id() != requested_id {
            return Err(ReaderError::InvalidProof(format!(
                "verified_object response for {requested_id} carries object {}",
                resp.object.id()
            )));
        }
        let proof_seq = *resp.summary.sequence_number();
        self.note_upstream_head(resp.claimed_latest_checkpoint_seq);
        // Freshness is measured against the locally-monotonic observed head,
        // not the response's claimed head: the claimed head is the relay's
        // word, so a malicious relay could under-report it to make a stale
        // proof look fresh. `observed_upstream_head` only ratchets up
        // (fetch_max in `note_upstream_head`), so once any response has shown
        // a newer head, no later response can talk us back below it.
        let observed_head = self.observed_upstream_head.load(Ordering::Relaxed);
        self.check_freshness(proof_seq, observed_head)?;
        // Clone the proof + summary for cache absorption before the
        // verifier consumes them. The proof isn't `Clone`; bcs round-trip.
        let cache_proof = clone_inclusion_proof(&resp.proof);
        let cache_summary = resp.summary.clone();
        let cache_object = resp.object.clone();
        self.verify_proof_inner(&resp.object, resp.proof, resp.summary)?;
        self.record_high_water(resp.object.id(), resp.object.version())?;
        // Shadow-populate the cache with the just-verified entry. Step 2
        // only writes; readers still hit the network.
        if let Some(proof) = cache_proof {
            let entry = VerifiedObjectEntry {
                object: cache_object,
                checkpoint_seq: proof_seq,
                proof,
                dynamic_field_name_type: String::new(),
                dynamic_field_name_bcs: Vec::new(),
            };
            self.cache.absorb_entries(&cache_summary, &[entry]);
        }
        Ok(VerifiedObject {
            object: resp.object,
            source_checkpoint_seq: proof_seq,
        })
    }

    fn verify_proof_inner(
        &self,
        object: &Object,
        proof: OCSInclusionProof,
        summary: CertifiedCheckpointSummary,
    ) -> Result<(), ReaderError> {
        let epoch = summary.epoch();
        let committee = self
            .committees
            .committee(epoch)
            .ok_or(ReaderError::MissingCommittee(epoch))?;
        let object_ref = object.compute_object_reference();
        let full_proof = Proof {
            targets: ProofTarget::new_ocs_inclusion(object_ref),
            checkpoint_summary: summary,
            proof_contents: ProofContents::ObjectCheckpointStateProof(OCSProof::Inclusion(proof)),
        };
        full_proof
            .verify(&committee)
            .map_err(|e| ReaderError::InvalidProof(format!("{e:?}")))
    }

    /// BLS-verify a checkpoint summary against its epoch committee, yielding a
    /// [`VerifiedCheckpoint`] that the per-entry inclusion check below reuses.
    /// This is the deduped first half of [`Self::verify_proof_inner`].
    fn verify_summary(
        &self,
        summary: CertifiedCheckpointSummary,
    ) -> Result<VerifiedCheckpoint, ReaderError> {
        self.committees
            .verify_summary(summary)
            .map_err(|e| match e {
                SummaryVerifyError::MissingCommittee(epoch) => ReaderError::MissingCommittee(epoch),
                bad @ SummaryVerifyError::BadSignature { .. } => {
                    ReaderError::InvalidProof(bad.to_string())
                }
            })
    }

    /// Verify one object's OCS inclusion proof (Merkle path + artifacts-digest
    /// binding) against an already-BLS-verified summary. Cheap relative to the
    /// BLS verify, so it stays per-entry; pairs with [`Self::verify_summary`].
    fn verify_ocs_inclusion(
        &self,
        object: &Object,
        proof: OCSInclusionProof,
        verified_summary: &VerifiedCheckpoint,
    ) -> Result<(), ReaderError> {
        let object_ref = object.compute_object_reference();
        ProofContents::ObjectCheckpointStateProof(OCSProof::Inclusion(proof))
            .verify(
                &ProofTarget::new_ocs_inclusion(object_ref),
                verified_summary,
            )
            .map_err(|e| ReaderError::InvalidProof(format!("{e:?}")))
    }

    // Eclipse residual: `head` is the relay's *claimed* upstream head (folded
    // monotonically into `observed_upstream_head`). A fresh peer-only node
    // talking to a single malicious relay can be pinned to a self-consistent
    // stale world — the relay simply under-reports the head so nothing looks
    // stale. The bound below catches a relay that *later* lies low after a
    // higher head was seen, not a from-boot eclipse. Mitigations: an enabled
    // `freshness_bound` and/or multiple independent relays; the real fix is the
    // changeset-stream currency design. See `dev-docs/specs/ocs-verified-sui-reads.md`
    // (Freshness and rollback protection → Eclipse residual).
    fn check_freshness(
        &self,
        proof_seq: CheckpointSequenceNumber,
        head: CheckpointSequenceNumber,
    ) -> Result<(), ReaderError> {
        let Some(bound) = self.freshness_bound else {
            return Ok(());
        };
        let gap = head.saturating_sub(proof_seq);
        if gap > bound {
            return Err(ReaderError::StaleCheckpoint {
                object_seq: proof_seq,
                head,
                gap,
                bound,
            });
        }
        Ok(())
    }

    fn record_high_water(&self, id: ObjectID, version: SequenceNumber) -> Result<(), ReaderError> {
        let mut hw = self.high_water.write();
        if let Some(&cached) = hw.get(&id)
            && version < cached
        {
            return Err(ReaderError::StaleVersion {
                id,
                got: version,
                cached,
            });
        }
        hw.insert(id, version);
        Ok(())
    }
}

fn classify_verify_error(e: &ReaderError) -> &'static str {
    match e {
        ReaderError::Transport(_) => "transport",
        ReaderError::InvalidProof(_) => "invalid_proof",
        ReaderError::MissingCommittee(_) => "missing_committee",
        ReaderError::StaleVersion { .. } => "stale_version",
        ReaderError::StaleCheckpoint { .. } => "stale_checkpoint",
        ReaderError::Decode(_) => "decode",
        ReaderError::UnsupportedVersion { .. } => "unsupported_version",
        ReaderError::BagMembership { .. } => "bag_membership",
    }
}

fn move_object_contents(object: &Object) -> Result<&[u8], ReaderError> {
    ika_sui_client::transport::move_object_contents(object).ok_or_else(|| {
        ReaderError::Decode(format!(
            "expected Move object, got package at {}",
            object.id()
        ))
    })
}

/// Derive the dynamic-field child id for a `Field<u64, V>` whose name is
/// `version`. Used to walk from a versioned outer wrapper (e.g.
/// `DWalletCoordinator`) into its inner versioned data.
fn derive_versioned_child_id(parent: ObjectID, version: u64) -> Result<ObjectID, ReaderError> {
    ika_sui_client::transport::derive_versioned_child_id(parent, version)
        .map_err(ReaderError::Decode)
}

/// `OCSInclusionProof` isn't `Clone`. We need a copy so the verifier
/// can take ownership while we still hand the original to the cache.
/// Returns `None` if the round-trip fails — never poisons the cache
/// with bogus data.
fn clone_inclusion_proof(
    p: &sui_light_client::proof::ocs::OCSInclusionProof,
) -> Option<sui_light_client::proof::ocs::OCSInclusionProof> {
    let bytes = bcs::to_bytes(p).ok()?;
    bcs::from_bytes(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use crate::sui_connector::committee_store::CommitteeBootstrap;
    use crate::sui_connector::verified_state_cache::VerifiedStateCache;
    use async_trait::async_trait;
    use ika_network::proof_provider::{BatchVerifiedObjectsResponse, VerifiedBagPageResponse};
    use parking_lot::Mutex;
    use std::collections::BTreeMap;
    use sui_light_client::proof::ocs::ModifiedObjectTree;
    use sui_types::base_types::ObjectDigest;
    use sui_types::committee::Committee as SuiCommittee;
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::digests::CheckpointContentsDigest;
    use sui_types::gas::GasCostSummary;
    use sui_types::messages_checkpoint::{
        CheckpointArtifacts, CheckpointCommitment, CheckpointSummary,
    };

    /// The two rejection gates exercised below — high-water rollback and
    /// freshness — are pure local checks that never reach the network, so the
    /// provider must never be called. Every method panics to prove that.
    struct UnusedProvider;

    #[async_trait]
    impl ProofProvider for UnusedProvider {
        async fn verified_object(
            &self,
            _id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            unreachable!("provider must not be hit by a local rejection test")
        }
        async fn batch_verified_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            unreachable!("provider must not be hit by a local rejection test")
        }
        async fn verified_bag_page(
            &self,
            _request: VerifiedBagPageRequest,
        ) -> Result<VerifiedBagPageResponse, TransportError> {
            unreachable!("provider must not be hit by a local rejection test")
        }
    }

    /// A reader wired to a never-called provider and an empty cache. The
    /// committee is an unsafe-genesis test committee — irrelevant to the
    /// rollback/freshness gates, which touch neither committees nor the cache,
    /// but required to construct the store.
    fn test_reader(freshness_bound: Option<u64>) -> (tempfile::TempDir, OcsVerifiedReader) {
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let (committee, _keys) = SuiCommittee::new_simple_test_committee_of_size(4);
        let committees = Arc::new(
            CommitteeStore::open(tables, Some(CommitteeBootstrap::UnsafeGenesis(committee)))
                .unwrap(),
        );
        let reader = OcsVerifiedReader::new(
            Arc::new(UnusedProvider),
            committees,
            OcsMetrics::new_for_testing(),
            freshness_bound,
            Arc::new(VerifiedStateCache::new()),
            false,
            None,
        );
        (dir, reader)
    }

    /// Per-object version monotonicity: once we've accepted version N for an
    /// id, a later response carrying an older version is a rollback (a relay
    /// replaying stale state) and must be rejected — without lowering the mark.
    #[tokio::test]
    async fn high_water_rejects_a_version_rollback() {
        let (_dir, reader) = test_reader(None);
        let id = ObjectID::from_single_byte(0x07);

        // First sight sets the mark; same-or-newer is always fine.
        reader
            .record_high_water(id, SequenceNumber::from(5u64))
            .unwrap();
        reader
            .record_high_water(id, SequenceNumber::from(5u64))
            .unwrap();
        reader
            .record_high_water(id, SequenceNumber::from(9u64))
            .unwrap();

        let err = reader
            .record_high_water(id, SequenceNumber::from(8u64))
            .unwrap_err();
        match err {
            ReaderError::StaleVersion {
                id: got_id,
                got,
                cached,
            } => {
                assert_eq!(got_id, id);
                assert_eq!(got, SequenceNumber::from(8u64));
                assert_eq!(cached, SequenceNumber::from(9u64));
            }
            other => panic!("expected StaleVersion, got {other:?}"),
        }

        // The rejected rollback must not have lowered the mark: 9 still holds,
        // so an even-older version is still rejected.
        reader
            .record_high_water(id, SequenceNumber::from(9u64))
            .unwrap();
        assert!(matches!(
            reader.record_high_water(id, SequenceNumber::from(0u64)),
            Err(ReaderError::StaleVersion { .. })
        ));

        // A different id has its own independent mark.
        let other = ObjectID::from_single_byte(0x08);
        reader
            .record_high_water(other, SequenceNumber::from(1u64))
            .unwrap();
    }

    /// A proof anchored more than `freshness_bound` checkpoints behind the
    /// provider's claimed head is too stale to trust and must be rejected.
    #[tokio::test]
    async fn freshness_rejects_a_checkpoint_too_far_behind_the_head() {
        let (_dir, reader) = test_reader(Some(10));

        // gap <= bound is accepted (10 == bound is the boundary, still ok).
        reader.check_freshness(100, 100).unwrap();
        reader.check_freshness(90, 100).unwrap();

        let err = reader.check_freshness(89, 100).unwrap_err();
        match err {
            ReaderError::StaleCheckpoint {
                object_seq,
                head,
                gap,
                bound,
            } => {
                assert_eq!(object_seq, 89);
                assert_eq!(head, 100);
                assert_eq!(gap, 11);
                assert_eq!(bound, 10);
            }
            other => panic!("expected StaleCheckpoint, got {other:?}"),
        }
    }

    /// `freshness_bound: None` disables the gate entirely — an arbitrarily old
    /// proof passes. (Production peer-only readers run with no bound.)
    #[tokio::test]
    async fn freshness_is_disabled_when_no_bound_is_set() {
        let (_dir, reader) = test_reader(None);
        reader.check_freshness(0, 1_000_000).unwrap();
    }

    // ===== End-to-end crypto-fixture tests =====
    //
    // These build a *self-consistent* OCS fixture: a test committee signs a
    // checkpoint summary that commits (via its `CheckpointArtifactsDigest`) to a
    // `ModifiedObjectTree` of synthesized objects, plus the matching inclusion
    // proof. The reader, bootstrapped with the same committee, accepts the valid
    // fixture and rejects every tampered variant — exercising the BLS, Merkle,
    // id-binding, and bag-membership gates the local-only tests above can't
    // reach. No chain data or real checkpoint files are needed.

    /// A provider that hands back one pre-staged response, then is empty.
    struct StagedProvider {
        object: Mutex<Option<VerifiedObjectResponse>>,
        bag: Mutex<Option<VerifiedBagPageResponse>>,
    }

    impl StagedProvider {
        fn object(resp: VerifiedObjectResponse) -> Arc<Self> {
            Arc::new(Self {
                object: Mutex::new(Some(resp)),
                bag: Mutex::new(None),
            })
        }
        fn bag(resp: VerifiedBagPageResponse) -> Arc<Self> {
            Arc::new(Self {
                object: Mutex::new(None),
                bag: Mutex::new(Some(resp)),
            })
        }
    }

    #[async_trait]
    impl ProofProvider for StagedProvider {
        async fn verified_object(
            &self,
            _id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            Ok(self
                .object
                .lock()
                .take()
                .expect("no staged verified_object response"))
        }
        async fn batch_verified_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            unreachable!("batch path not exercised by these fixtures")
        }
        async fn verified_bag_page(
            &self,
            _request: VerifiedBagPageRequest,
        ) -> Result<VerifiedBagPageResponse, TransportError> {
            Ok(self
                .bag
                .lock()
                .take()
                .expect("no staged verified_bag_page response"))
        }
    }

    fn reader_with(
        provider: Arc<dyn ProofProvider>,
        committee: SuiCommittee,
        freshness_bound: Option<u64>,
    ) -> (tempfile::TempDir, OcsVerifiedReader, Arc<OcsMetrics>) {
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(tables, Some(CommitteeBootstrap::UnsafeGenesis(committee)))
                .unwrap(),
        );
        let metrics = OcsMetrics::new_for_testing();
        let reader = OcsVerifiedReader::new(
            provider,
            committees,
            metrics.clone(),
            freshness_bound,
            Arc::new(VerifiedStateCache::new()),
            false,
            None,
        );
        (dir, reader, metrics)
    }

    fn test_object(id: ObjectID, version: u64, owner: Owner) -> Object {
        Object::with_id_owner_version_for_testing(id, SequenceNumber::from(version), owner)
    }

    fn address_owner(byte: u8) -> Owner {
        Owner::AddressOwner(ObjectID::from_single_byte(byte).into())
    }

    /// Build a committee-signed summary committing to a tree of `leaves`, plus
    /// the inclusion proof for `target`. Summary + proof verify together against
    /// `committee` — the digest linkage holds because both the summary's
    /// commitment and the proof's tree root come from the *same* artifacts.
    fn sign_inclusion(
        committee: &SuiCommittee,
        keypairs: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        leaves: &[&Object],
        target: &Object,
    ) -> (CertifiedCheckpointSummary, OCSInclusionProof) {
        let object_states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)> = leaves
            .iter()
            .map(|o| {
                let (id, version, digest) = o.compute_object_reference();
                (id, (version, digest))
            })
            .collect();
        let artifacts = CheckpointArtifacts::from_object_states(object_states);
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
        let cert =
            CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keypairs, committee);
        let proof = ModifiedObjectTree::new(&artifacts)
            .expect("modified object tree")
            .get_inclusion_proof(target.compute_object_reference())
            .expect("inclusion proof");
        (cert, proof)
    }

    fn object_response(
        object: Object,
        summary: CertifiedCheckpointSummary,
        proof: OCSInclusionProof,
        seq: CheckpointSequenceNumber,
    ) -> VerifiedObjectResponse {
        VerifiedObjectResponse {
            object,
            summary,
            proof,
            claimed_latest_checkpoint_seq: seq,
        }
    }

    fn bag_entry(
        object: Object,
        proof: OCSInclusionProof,
        seq: CheckpointSequenceNumber,
        name_type: &str,
        name_bcs: Vec<u8>,
    ) -> VerifiedObjectEntry {
        VerifiedObjectEntry {
            object,
            checkpoint_seq: seq,
            proof,
            dynamic_field_name_type: name_type.to_string(),
            dynamic_field_name_bcs: name_bcs,
        }
    }

    fn bag_response(
        summary: CertifiedCheckpointSummary,
        entry: VerifiedObjectEntry,
        seq: CheckpointSequenceNumber,
    ) -> VerifiedBagPageResponse {
        VerifiedBagPageResponse {
            bag: None,
            summaries: BTreeMap::from([(seq, summary)]),
            entries: vec![entry],
            next_page_token: None,
            claimed_latest_checkpoint_seq: seq,
        }
    }

    fn failure_count(metrics: &Arc<OcsMetrics>, kind: &str, reason: &str) -> u64 {
        metrics
            .proof_verify_failures_total
            .with_label_values(&[kind, reason])
            .get()
    }

    /// The fixture itself is sound: a committee-signed summary + matching
    /// inclusion proof verifies through the full BLS + Merkle path. Without
    /// this, every rejection test below would be vacuous.
    #[tokio::test]
    async fn a_valid_inclusion_proof_is_accepted() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let id = ObjectID::from_single_byte(0x21);
        let object = test_object(id, 7, address_owner(0xAA));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&object], &object);
        let provider = StagedProvider::object(object_response(object, summary, proof, 100));
        let (_dir, reader, _metrics) = reader_with(provider, committee, None);

        let verified = reader
            .verified_object(id)
            .await
            .expect("a committee-signed, correctly-proven object must verify");
        assert_eq!(verified.object.id(), id);
        assert_eq!(verified.source_checkpoint_seq, 100);
    }

    /// A proof for object X is cryptographically valid, but the relay is
    /// answering `get(Y)` with it. The id binding must reject the substitution.
    #[tokio::test]
    async fn an_object_id_substitution_is_rejected() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let proven_id = ObjectID::from_single_byte(0x21);
        let requested_id = ObjectID::from_single_byte(0x99);
        let object = test_object(proven_id, 1, address_owner(0xAA));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&object], &object);
        let provider = StagedProvider::object(object_response(object, summary, proof, 100));
        let (_dir, reader, metrics) = reader_with(provider, committee, None);

        let err = reader.verified_object(requested_id).await.unwrap_err();
        assert!(matches!(err, ReaderError::InvalidProof(_)), "got {err:?}");
        assert_eq!(failure_count(&metrics, "object", "invalid_proof"), 1);
    }

    /// The summary is well-formed and the proof matches it, but it is signed by
    /// a committee the reader does not trust — the BLS gate must reject it.
    /// (The test committees are seeded deterministically, so the "foreign" one
    /// is given a different size to guarantee a divergent authority set.)
    #[tokio::test]
    async fn a_summary_signed_by_a_foreign_committee_is_rejected() {
        let (store_committee, _) = SuiCommittee::new_simple_test_committee_of_size(4);
        let (foreign_committee, foreign_keys) = SuiCommittee::new_simple_test_committee_of_size(7);
        let id = ObjectID::from_single_byte(0x21);
        let object = test_object(id, 1, address_owner(0xAA));
        let (summary, proof) =
            sign_inclusion(&foreign_committee, &foreign_keys, 100, &[&object], &object);
        let provider = StagedProvider::object(object_response(object, summary, proof, 100));
        let (_dir, reader, metrics) = reader_with(provider, store_committee, None);

        let err = reader.verified_object(id).await.unwrap_err();
        assert!(matches!(err, ReaderError::InvalidProof(_)), "got {err:?}");
        assert_eq!(failure_count(&metrics, "object", "invalid_proof"), 1);
    }

    /// Prove version 1, but serve the *same* id at version 2: the id binding
    /// passes, but the served object's ref isn't the one the tree commits to —
    /// the Merkle path must reject the substituted state.
    #[tokio::test]
    async fn a_substituted_object_state_is_rejected() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let id = ObjectID::from_single_byte(0x21);
        let proven = test_object(id, 1, address_owner(0xAA));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&proven], &proven);
        let lied = test_object(id, 2, address_owner(0xAA));
        let provider = StagedProvider::object(object_response(lied, summary, proof, 100));
        let (_dir, reader, metrics) = reader_with(provider, committee, None);

        let err = reader.verified_object(id).await.unwrap_err();
        assert!(matches!(err, ReaderError::InvalidProof(_)), "got {err:?}");
        assert_eq!(failure_count(&metrics, "object", "invalid_proof"), 1);
    }

    /// Plain `Bag`/`Table`: the value `Field` is owned directly by the bag UID.
    #[tokio::test]
    async fn a_bag_entry_owned_by_the_bag_is_accepted() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let bag_id = ObjectID::from_single_byte(0x55);
        let entry_id = ObjectID::from_single_byte(0x56);
        let object = test_object(entry_id, 1, Owner::ObjectOwner(bag_id.into()));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&object], &object);
        let provider = StagedProvider::bag(bag_response(
            summary,
            bag_entry(object, proof, 100, "", vec![]),
            100,
        ));
        let (_dir, reader, _metrics) = reader_with(provider, committee, None);

        let page = reader
            .verified_bag_page(bag_id, None, None)
            .await
            .expect("an entry owned by the bag must be accepted");
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].object.id(), entry_id);
    }

    /// `ObjectTable`/`ObjectBag`: the value object is owned by its
    /// `Field<Wrapper<K>, ID>` wrapper, whose id derives from `(bag_id, key)`.
    #[tokio::test]
    async fn a_bag_entry_owned_via_the_object_field_wrapper_is_accepted() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let bag_id = ObjectID::from_single_byte(0x55);
        let entry_id = ObjectID::from_single_byte(0x56);
        let name_type = "u64";
        let name_bcs = bcs::to_bytes(&7u64).unwrap();
        let field_id = derive_object_field_wrapper_id(bag_id, name_type, &name_bcs)
            .expect("wrapper id derivation");
        let object = test_object(entry_id, 1, Owner::ObjectOwner(field_id.into()));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&object], &object);
        let provider = StagedProvider::bag(bag_response(
            summary,
            bag_entry(object, proof, 100, name_type, name_bcs),
            100,
        ));
        let (_dir, reader, _metrics) = reader_with(provider, committee, None);

        let page = reader
            .verified_bag_page(bag_id, None, None)
            .await
            .expect("an ObjectTable entry owned by its derived field must be accepted");
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].object.id(), entry_id);
    }

    /// Validly proven, but owned by a *different* collection — a relay replaying
    /// a foreign dynamic field. `foreign_id` is neither `bag_id` nor the derived
    /// field id, so the binding must reject it.
    #[tokio::test]
    async fn a_bag_entry_owned_by_a_foreign_object_is_rejected() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let bag_id = ObjectID::from_single_byte(0x55);
        let entry_id = ObjectID::from_single_byte(0x56);
        let foreign_id = ObjectID::from_single_byte(0x77);
        let object = test_object(entry_id, 1, Owner::ObjectOwner(foreign_id.into()));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&object], &object);
        let provider = StagedProvider::bag(bag_response(
            summary,
            bag_entry(object, proof, 100, "u64", bcs::to_bytes(&7u64).unwrap()),
            100,
        ));
        let (_dir, reader, metrics) = reader_with(provider, committee, None);

        let err = reader
            .verified_bag_page(bag_id, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ReaderError::BagMembership { .. }),
            "got {err:?}"
        );
        assert_eq!(failure_count(&metrics, "bag_entry", "bag_membership"), 1);
    }

    /// Address-owned (not object-owned at all): a dynamic-field child is always
    /// object-owned, so this can never be a member of the bag.
    #[tokio::test]
    async fn a_bag_entry_owned_by_an_address_is_rejected() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let bag_id = ObjectID::from_single_byte(0x55);
        let entry_id = ObjectID::from_single_byte(0x56);
        let object = test_object(entry_id, 1, address_owner(0x77));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&object], &object);
        let provider = StagedProvider::bag(bag_response(
            summary,
            bag_entry(object, proof, 100, "", vec![]),
            100,
        ));
        let (_dir, reader, metrics) = reader_with(provider, committee, None);

        let err = reader
            .verified_bag_page(bag_id, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ReaderError::BagMembership { .. }),
            "got {err:?}"
        );
        assert_eq!(failure_count(&metrics, "bag_entry", "bag_membership"), 1);
    }
}
