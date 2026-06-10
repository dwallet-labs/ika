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
use sui_types::object::Object;

use ika_sui_client::transport::TransportError;

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
        let result = self.verify_response(resp);
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
            self.check_freshness(seq, observed_head)?;
            if !verified_summaries.contains_key(&seq) {
                let summary = resp
                    .summaries
                    .get(&seq)
                    .ok_or_else(|| {
                        ReaderError::Decode(format!("missing summary {seq} for batch entry {id}"))
                    })?
                    .clone();
                let verified_summary = self.verify_summary(summary)?;
                verified_summaries.insert(seq, verified_summary);
            }
            // unwrap: inserted just above for this `seq`.
            let verified_summary = verified_summaries.get(&seq).expect("summary present");

            let cache_proof = clone_inclusion_proof(&entry.proof);
            let cache_object = entry.object.clone();
            let entry_result =
                self.verify_ocs_inclusion(&entry.object, entry.proof, verified_summary);
            self.record_verify_outcome_unit("batch_objects", &entry_result);
            entry_result?;
            self.record_high_water(entry.object.id(), entry.object.version())?;
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
            if !verified_summaries.contains_key(&seq) {
                let summary = resp
                    .summaries
                    .get(&seq)
                    .ok_or_else(|| ReaderError::Decode("missing summary for bag entry".into()))?
                    .clone();
                let verified_summary = self.verify_summary(summary)?;
                verified_summaries.insert(seq, verified_summary);
            }
            // unwrap: inserted just above for this `seq`.
            let verified_summary = verified_summaries.get(&seq).expect("summary present");

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
            if let Some(proof) = cache_proof {
                let cache_entry = VerifiedObjectEntry {
                    object: cache_object,
                    checkpoint_seq: seq,
                    proof,
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
            Err(e) => {
                let reason = classify_verify_error(e);
                self.metrics
                    .proof_verify_failures_total
                    .with_label_values(&[kind, reason])
                    .inc();
                if matches!(e, ReaderError::StaleVersion { .. }) {
                    self.metrics.high_water_violations_total.inc();
                }
            }
        }
    }

    fn record_verify_outcome_unit(&self, kind: &'static str, result: &Result<(), ReaderError>) {
        self.record_verify_outcome(kind, result);
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

    fn verify_response(&self, resp: VerifiedObjectResponse) -> Result<VerifiedObject, ReaderError> {
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
