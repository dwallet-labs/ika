// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! A `sui-state-direct` node's fallback for an object it cannot prove itself:
//! read it the way a `sui-state-mirrored` node reads everything — over the
//! existing `SuiStateMirror` relay surface, from the direct peers it is
//! connected to — and accept it only after every check a mirrored node
//! applies, plus the currency check a direct node owes its own reads.
//!
//! # When
//!
//! A direct node proves an object from its own fullnode: the checkpoint that
//! wrote the object's current version, or its verified cache's snapshot at
//! exactly that reference (`recover_pruned_proof`). When the fullnode has
//! pruned that checkpoint and the cache has no such snapshot, the local proof
//! provider answers `NotFound`. In the mainnet epoch-463 incident a direct node
//! that never folded the `System` anchor's checkpoint — a new operator, a
//! resynced database, a node that fast-forwarded past it — hung at the
//! `verified_system_inner` boot barrier on exactly that `NotFound`. Every
//! up-to-date direct peer can still prove the object: its own proof provider
//! reuses its cached snapshot. So the verified reader on a direct node, on its
//! own reads only (never on relay requests it serves), asks one peer at a time
//! before giving up ([`PeerFallback::verified_object`]).
//!
//! # Verification parity
//!
//! Each peer's answer goes through an [`OcsVerifiedReader`] configured as a
//! mirrored node configures its own (relay provider, `cache_first` off), so it
//! passes the very code a mirrored node runs on a relayed object
//! (`verify_response`):
//!
//! - the response carries the requested id;
//! - the summary is BLS-verified against the committee of its epoch from this
//!   node's `CommitteeStore`;
//! - the inclusion proof's tree root reproduces the summary's committed
//!   artifacts digest, and the object's full reference is a leaf under it;
//! - the freshness bound and the reader's version high-water;
//! - `check_currency`, which is a no-op here exactly as on every direct read:
//!   a direct node keeps no changeset index (see below).
//!
//! # Currency
//!
//! A mirrored node proves currency from its committee-signed changeset index,
//! and gets no verdict (`Unknown`, accepted) for an anchor below that index's
//! window. A direct node's currency source is its own fullnode, as it is for
//! every read it serves: the cache folds that fullnode's checkpoints, the proof
//! provider proves the object that fullnode reports, and `recover_pruned_proof`
//! and the archive backfill reuse a snapshot only at that fullnode's exact
//! current reference. The fallback applies the same rule: a peer's object is
//! accepted only if its reference equals the one this node's fullnode reports
//! now, else `NotCurrent`. A rolled-back version (older), a deleted object (the
//! fullnode reports none, so no peer is asked) and a version this node's
//! fullnode has not reached yet (newer) are all refused, whatever the peer's
//! proof says. Unlike the index, the check has no window: it also refuses a
//! rollback of an anchor older than any changeset retention, which is exactly
//! the population this fallback serves. It trusts the fullnode for nothing a
//! direct node does not already trust it for.
//!
//! # Afterwards
//!
//! The direct reader applies its own high-water to the result, serves it, and
//! shadow-writes the verified snapshot into its cache like any network-verified
//! read (not persisted; the pusher's folds supersede it), so the next read is a
//! cache hit instead of another fallback.
//!
//! # A frozen fullnode
//!
//! The currency check is only as current as the fullnode. While the checkpoint
//! pusher reports this node's own fullnode frozen — its latest checkpoint has
//! not moved for `UPSTREAM_FROZEN_AFTER` — the fullnode's reference is a past
//! one, and a genuine but superseded version would match it. The fallback asks
//! no peer until the fullnode advances again; reads fail as they would without
//! it.
//!
//! The state is the pusher's own (`IkaCheckpointPusher::upstream_frozen`, a
//! watch flipped where its frozen ERROR / recovery INFO latch flips), attached
//! once the pusher is built. Until then — the pusher is still being built, or
//! there is none (a node without an OCS anchor builds no fallback either) —
//! nothing is known frozen and the fallback runs. If the pusher task stops, the
//! watch keeps its last value: a fallback that was standing down stays down, one
//! that was running keeps running with no further frozen report.
//!
//! # Bounds
//!
//! A few fallbacks at once; a per-peer deadline and one for the whole attempt;
//! at most a handful of peers per attempt; and an object whose fallback failed
//! is not tried again for a while.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use ika_network::proof_provider::{ProofProviderMetrics, VerifiedObjectEntry};
use ika_network::sui_state_mirror::{SuiMirrorPeers, SuiMirrorProofProvider};
use ika_sui_client::transport::{SuiTransport, TransportError};
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use sui_types::base_types::ObjectID;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::sui_connector::committee_store::CommitteeStore;
use crate::sui_connector::ocs_metrics::OcsMetrics;
use crate::sui_connector::verified_reader::{OcsVerifiedReader, ReaderError, VerifiedObject};
use crate::sui_connector::verified_state_cache::{VerifiedSnapshot, VerifiedStateCache};

/// The limits on the fallback. `Default` is production; tests shrink them.
#[derive(Clone, Debug)]
pub struct FallbackBounds {
    /// Fallbacks running at once; a read past it fails as it did before.
    pub max_concurrent: usize,
    /// Peers asked per attempt, in random order, one at a time.
    pub max_peers: usize,
    /// Deadline of one peer's answer. A relay read is one proof build on the
    /// serving side, so this only has to outlast a round trip and that build.
    pub peer_timeout: Duration,
    /// Deadline of a whole attempt, across every peer it asks: the fallback
    /// runs inside a read, which may be an epoch-loop anchor read, so peers
    /// that accept a request and never answer must not hold it for
    /// `max_peers * peer_timeout`.
    pub attempt_timeout: Duration,
    /// An object whose fallback found no acceptable answer is not tried again
    /// before this has passed; reads of it fail fast meanwhile.
    pub retry_after: Duration,
    /// Objects whose failure time is remembered at once.
    pub max_tracked_failures: usize,
}

impl Default for FallbackBounds {
    fn default() -> Self {
        Self {
            max_concurrent: 2,
            max_peers: 16,
            peer_timeout: Duration::from_secs(5),
            attempt_timeout: Duration::from_secs(15),
            retry_after: Duration::from_secs(30),
            max_tracked_failures: 1_024,
        }
    }
}

/// Whether this node's own Sui fullnode is frozen, as the checkpoint pusher
/// reports it — its latest checkpoint has not moved for the frozen threshold.
/// The fallback reads it through this interface so the pusher can share the
/// state in whichever form it keeps it.
pub trait UpstreamFrozen: Send + Sync {
    fn is_frozen(&self) -> bool;
}

impl UpstreamFrozen for AtomicBool {
    fn is_frozen(&self) -> bool {
        self.load(Ordering::Relaxed)
    }
}

impl UpstreamFrozen for tokio::sync::watch::Receiver<bool> {
    fn is_frozen(&self) -> bool {
        *self.borrow()
    }
}

/// A peer-proved object that passed every check, with the snapshot the
/// direct reader caches once its own high-water accepts it.
pub struct PeerVerified {
    pub object: VerifiedObject,
    pub snapshot: VerifiedSnapshot,
}

impl PeerVerified {
    pub fn cache_entry(&self) -> VerifiedObjectEntry {
        VerifiedObjectEntry {
            object: self.snapshot.object.clone(),
            checkpoint_seq: self.snapshot.source_checkpoint_seq,
            proof: self.snapshot.clone().proof,
            dynamic_field_name_type: String::new(),
            dynamic_field_name_bcs: Vec::new(),
        }
    }
}

/// How one fallback ended; the `outcome` label of
/// `ika_ocs_direct_peer_fallback_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// A peer's answer passed every check.
    Served,
    /// Some peer's answer was authentic but not this node's fullnode's current
    /// reference, and none was acceptable.
    NotCurrent,
    /// Some peer's answer failed verification, and none was acceptable.
    Unverified,
    /// No peer served the object (none serves the relay, none could prove it,
    /// or none answered in time).
    Unavailable,
    /// The fullnode no longer reports the object: nothing to ask for.
    NotLive,
    /// The fullnode could not say what the object's current reference is.
    FullnodeError,
    /// Not tried: the network is not attached yet, the concurrency cap is
    /// reached, or the object failed recently.
    Skipped,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::NotCurrent => "not_current",
            Self::Unverified => "unverified",
            Self::Unavailable => "unavailable",
            Self::NotLive => "not_live",
            Self::FullnodeError => "fullnode_error",
            Self::Skipped => "skipped",
        }
    }
}

/// See the module docs. Built with the connector stack on a direct node; the
/// p2p network is attached once it is up ([`Self::attach_network`]).
pub struct PeerFallback {
    /// This node's own fullnode: the object's current reference.
    fullnode: Arc<dyn SuiTransport>,
    committees: Arc<CommitteeStore>,
    network: OnceLock<anemo::Network>,
    bounds: FallbackBounds,
    permits: Semaphore,
    failed_at: Mutex<HashMap<ObjectID, Instant>>,
    /// Whether this node's own fullnode is frozen, as the checkpoint pusher
    /// reports it ([`Self::attach_upstream_frozen`]). While it is, its
    /// "current" reference is the last one it saw, so the currency check would
    /// accept a genuine but superseded version: the fallback stands down
    /// instead. Unattached (no pusher yet, or none) reads as not frozen; a
    /// stopped pusher's watch keeps its last value (see the module docs).
    upstream_frozen: OnceLock<Arc<dyn UpstreamFrozen>>,
    metrics: Arc<OcsMetrics>,
    provider_metrics: Arc<ProofProviderMetrics>,
}

impl PeerFallback {
    pub fn new(
        fullnode: Arc<dyn SuiTransport>,
        committees: Arc<CommitteeStore>,
        bounds: FallbackBounds,
        metrics: Arc<OcsMetrics>,
        provider_metrics: Arc<ProofProviderMetrics>,
    ) -> Self {
        let permits = Semaphore::new(bounds.max_concurrent);
        Self {
            fullnode,
            committees,
            network: OnceLock::new(),
            bounds,
            permits,
            failed_at: Mutex::new(HashMap::new()),
            upstream_frozen: OnceLock::new(),
            metrics,
            provider_metrics,
        }
    }

    /// Attach the checkpoint pusher's report of whether this node's own
    /// fullnode is frozen (`IkaCheckpointPusher::upstream_frozen`), once the
    /// pusher is built.
    pub fn attach_upstream_frozen(&self, state: Arc<dyn UpstreamFrozen>) {
        if self.upstream_frozen.set(state).is_err() {
            debug!("peer fallback: upstream frozen state already attached");
        }
    }

    /// Attach the p2p network the peers are asked over, once it is up. Reads
    /// before that fail as they did without a fallback.
    pub fn attach_network(&self, network: anemo::Network) {
        if self.network.set(network).is_err() {
            debug!("peer fallback: network already attached");
        }
    }

    /// Prove `id` from a connected direct peer, verified as a mirrored node
    /// verifies a relayed object and current per this node's fullnode (see the
    /// module docs). An `Err` leaves the caller where it was without the
    /// fallback; the error is the most telling one seen.
    pub async fn verified_object(&self, id: ObjectID) -> Result<PeerVerified, ReaderError> {
        let (outcome, result) = self.attempt(id).await;
        self.metrics
            .direct_peer_fallback_total
            .with_label_values(&[outcome.label()])
            .inc();
        match outcome {
            Outcome::Served => {
                self.failed_at.lock().remove(&id);
            }
            Outcome::Skipped => {}
            _ => self.note_failure(id),
        }
        result
    }

    async fn attempt(&self, id: ObjectID) -> (Outcome, Result<PeerVerified, ReaderError>) {
        let skipped = |why: &str| {
            (
                Outcome::Skipped,
                Err(ReaderError::Transport(TransportError::NotFound(format!(
                    "peer fallback for {id} skipped: {why}"
                )))),
            )
        };
        let Some(network) = self.network.get() else {
            return skipped("the p2p network is not attached yet");
        };
        // The currency check below compares a peer's answer with what this
        // node's fullnode reports now. A frozen fullnode reports a past state,
        // and a genuine old version would match it: ask nobody until it
        // advances again.
        if self
            .upstream_frozen
            .get()
            .is_some_and(|state| state.is_frozen())
        {
            return skipped("this node's own Sui fullnode is frozen");
        }
        if self.failed_recently(id) {
            return skipped("it failed recently");
        }
        let Ok(_permit) = self.permits.try_acquire() else {
            return skipped("the concurrency cap is reached");
        };

        let current = match self.fullnode.get_object(id).await {
            Ok(object) => object.compute_object_reference(),
            Err(e @ TransportError::NotFound(_)) => {
                return (Outcome::NotLive, Err(ReaderError::Transport(e)));
            }
            Err(e) => return (Outcome::FullnodeError, Err(ReaderError::Transport(e))),
        };

        let mut peers = network.peers();
        peers.shuffle(&mut rand::rng());
        peers.truncate(self.bounds.max_peers);
        let mut outcome = Outcome::Unavailable;
        let mut last_error = ReaderError::Transport(TransportError::NotFound(format!(
            "peer fallback for {id}: no connected peer served it"
        )));
        let deadline = tokio::time::Instant::now() + self.bounds.attempt_timeout;
        for peer in peers {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                debug!(?id, "peer fallback: the attempt deadline passed");
                break;
            }
            // A reader configured as a mirrored node's, over this one peer: the
            // answer passes the mirrored verification before anything else
            // looks at it. Its cache is its own, so nothing reaches this node's
            // cache before the currency check and the direct reader's
            // high-water below.
            let scratch = Arc::new(VerifiedStateCache::new());
            let reader = OcsVerifiedReader::new(
                Arc::new(SuiMirrorProofProvider::new(
                    SuiMirrorPeers::scoped(
                        network.clone(),
                        vec![peer],
                        self.provider_metrics.clone(),
                    ),
                    self.provider_metrics.clone(),
                )),
                self.committees.clone(),
                self.metrics.clone(),
                None,
                scratch.clone(),
                false,
                None,
            );
            let verified = match tokio::time::timeout(
                self.bounds.peer_timeout.min(remaining),
                Box::pin(reader.verified_object(id)),
            )
            .await
            {
                Ok(Ok(verified)) => verified,
                Ok(Err(ReaderError::Transport(e))) => {
                    // The peer does not serve the relay (an older or mirrored
                    // node answers a route miss), could not prove the object,
                    // or failed: a "don't know", never an error that stops the
                    // fallback.
                    debug!(%peer, ?id, error = %e, "peer fallback: the peer did not serve the object");
                    continue;
                }
                Ok(Err(e)) => {
                    warn!(
                        %peer,
                        ?id,
                        error = %e,
                        "peer fallback: the peer's answer failed verification; asking the next peer"
                    );
                    if outcome != Outcome::NotCurrent {
                        outcome = Outcome::Unverified;
                    }
                    last_error = e;
                    continue;
                }
                Err(_elapsed) => {
                    debug!(%peer, ?id, "peer fallback: the peer did not answer in time");
                    continue;
                }
            };
            let served = verified.object.compute_object_reference();
            if served != current {
                warn!(
                    %peer,
                    ?id,
                    ?served,
                    ?current,
                    "peer fallback: the peer proved another version than this node's fullnode \
                     reports as current; refusing it and asking the next peer"
                );
                outcome = Outcome::NotCurrent;
                last_error = ReaderError::NotCurrent {
                    id,
                    anchored_seq: verified.source_checkpoint_seq,
                    verdict: "not the reference this node's fullnode reports as current",
                };
                continue;
            }
            let Some(snapshot) = scratch.get(id) else {
                last_error = ReaderError::Decode(format!(
                    "peer fallback for {id}: the verified snapshot is missing from the reader's cache"
                ));
                continue;
            };
            info!(
                %peer,
                ?id,
                version = verified.object.version().value(),
                checkpoint = verified.source_checkpoint_seq,
                "peer fallback: proved an object this node could not prove itself, from a direct \
                 peer, verified as a mirrored node verifies a relayed object"
            );
            return (
                Outcome::Served,
                Ok(PeerVerified {
                    object: verified,
                    snapshot,
                }),
            );
        }
        (outcome, Err(last_error))
    }

    fn failed_recently(&self, id: ObjectID) -> bool {
        self.failed_at
            .lock()
            .get(&id)
            .is_some_and(|at| at.elapsed() < self.bounds.retry_after)
    }

    fn note_failure(&self, id: ObjectID) {
        let mut failed_at = self.failed_at.lock();
        if failed_at.len() >= self.bounds.max_tracked_failures {
            let retry_after = self.bounds.retry_after;
            failed_at.retain(|_, at| at.elapsed() < retry_after);
        }
        if failed_at.len() < self.bounds.max_tracked_failures {
            failed_at.insert(id, Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use fastcrypto::traits::KeyPair;
    use ika_network::proof_provider::{
        BatchVerifiedObjectsResponse, ProofProvider, VerifiedDynamicFieldsPageRequest,
        VerifiedDynamicFieldsPageResponse, VerifiedObjectResponse,
    };
    use ika_network::sui_state_mirror::{SuiMirrorTransport, make_server};
    use ika_sui_client::transport::{DynamicFieldPage, ExecutedTransaction};
    use ika_types::sui::system_inner_v1::{
        BlsCommittee, ProtocolTreasuryV1, SystemInnerV1, SystemObjectCap, ValidatorSetV1,
    };
    use ika_types::sui::{ExtendedField, System, SystemInnerTrait};
    use sui_light_client::proof::ocs::ModifiedObjectTree;
    use sui_types::TypeTag;
    use sui_types::balance::{Balance, Supply};
    use sui_types::base_types::{
        AuthorityName, MoveObjectType, ObjectDigest, SequenceNumber, TransactionDigest,
    };
    use sui_types::coin::TreasuryCap;
    use sui_types::collection_types::{Bag, Table, VecMap};
    use sui_types::committee::Committee;
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::digests::CheckpointDigest;
    use sui_types::dynamic_field::Field;
    use sui_types::full_checkpoint_content::CheckpointData;
    use sui_types::gas::GasCostSummary;
    use sui_types::id::UID;
    use sui_types::messages_checkpoint::{
        CertifiedCheckpointSummary, CheckpointArtifacts, CheckpointCommitment, CheckpointContents,
        CheckpointSequenceNumber, CheckpointSummary,
    };
    use sui_types::object::{MoveObject, Object, Owner};
    use sui_types::parse_sui_type_tag;

    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use crate::sui_connector::committee_store::CommitteeBootstrap;
    use crate::sui_connector::verified_state_cache::SharedVerifiedStateCache;

    /// This node's fullnode head, claimed in every peer answer.
    const HEAD: CheckpointSequenceNumber = 1_000;

    // -- fixtures ---------------------------------------------------------------------------

    /// This node's own fullnode: reports `live` as the current objects and
    /// counts the lookups.
    struct Fullnode {
        live: HashMap<ObjectID, Object>,
        lookups: AtomicUsize,
    }

    impl Fullnode {
        fn reporting(live: &[&Object]) -> Arc<Self> {
            Arc::new(Self {
                live: live.iter().map(|o| (o.id(), (*o).clone())).collect(),
                lookups: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl SuiTransport for Fullnode {
        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            unimplemented!()
        }
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            unimplemented!()
        }
        async fn get_committee(&self, _: Option<u64>) -> Result<Committee, TransportError> {
            unimplemented!()
        }
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn get_full_checkpoint(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            Err(TransportError::NotFound(format!("checkpoint {seq} pruned")))
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            _: CheckpointDigest,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn last_checkpoint_of_epoch(
            &self,
            _: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            unimplemented!()
        }
        async fn get_object(&self, id: ObjectID) -> Result<Object, TransportError> {
            self.lookups.fetch_add(1, Ordering::Relaxed);
            self.live
                .get(&id)
                .cloned()
                .ok_or_else(|| TransportError::NotFound(format!("object {id} not found")))
        }
        async fn get_object_with_version(
            &self,
            _: ObjectID,
            _: SequenceNumber,
        ) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn batch_get_objects(&self, _: &[ObjectID]) -> Result<Vec<Object>, TransportError> {
            unimplemented!()
        }
        async fn list_dynamic_fields(
            &self,
            _: ObjectID,
            _: Option<u32>,
            _: Option<Vec<u8>>,
        ) -> Result<DynamicFieldPage, TransportError> {
            unimplemented!()
        }
        async fn get_transaction(
            &self,
            _: TransactionDigest,
        ) -> Result<ExecutedTransaction, TransportError> {
            unimplemented!()
        }
    }

    /// What a peer's relay answers `verified_object` with, built fresh per
    /// request (the proof is not `Clone`).
    type Answer =
        Arc<dyn Fn(ObjectID) -> Result<VerifiedObjectResponse, TransportError> + Send + Sync>;

    /// A peer's proof provider, behind the real `SuiStateMirror` server.
    struct PeerProvider {
        answer: Answer,
        requests: Arc<AtomicUsize>,
        /// How long the peer sits on a request before answering.
        delay: Duration,
    }

    #[async_trait]
    impl ProofProvider for PeerProvider {
        async fn verified_object(
            &self,
            id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            self.requests.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(self.delay).await;
            (self.answer)(id)
        }
        async fn batch_verified_objects(
            &self,
            _: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            unimplemented!()
        }
        async fn verified_dynamic_fields_page(
            &self,
            _: VerifiedDynamicFieldsPageRequest,
        ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
            unimplemented!()
        }
    }

    fn network(router: anemo::Router) -> anemo::Network {
        anemo::Network::bind("localhost:0")
            .private_key(rand::random::<[u8; 32]>())
            .server_name("test")
            .start(router)
            .unwrap()
    }

    /// A direct peer serving the real `SuiStateMirror` server (as `make_server`
    /// builds it on every direct node), whose provider answers `answer`.
    fn direct_peer(answer: Answer) -> (anemo::Network, Arc<AtomicUsize>) {
        slow_direct_peer(answer, Duration::ZERO)
    }

    /// [`direct_peer`] that sits on every request for `delay` first.
    fn slow_direct_peer(answer: Answer, delay: Duration) -> (anemo::Network, Arc<AtomicUsize>) {
        let requests = Arc::new(AtomicUsize::new(0));
        let metrics = ProofProviderMetrics::new_for_testing();
        let unused = SuiMirrorPeers::new(network(anemo::Router::new()), vec![], metrics.clone());
        let server = make_server(
            Arc::new(SuiMirrorTransport::new(unused)),
            Arc::new(PeerProvider {
                answer,
                requests: requests.clone(),
                delay,
            }),
            metrics,
        );
        (
            network(anemo::Router::new().add_rpc_service(server)),
            requests,
        )
    }

    /// A node that does not serve `SuiStateMirror` — a mirrored or peer-only
    /// node; an older binary's unknown route answers the same bare NotFound.
    fn non_serving_peer() -> anemo::Network {
        network(anemo::Router::new())
    }

    async fn connected(peers: &[&anemo::Network]) -> anemo::Network {
        let node = network(anemo::Router::new());
        for peer in peers {
            node.connect(peer.local_addr()).await.unwrap();
        }
        node
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        committee: Committee,
        keys: Arc<Vec<AuthorityKeyPair>>,
        committees: Arc<CommitteeStore>,
        metrics: Arc<OcsMetrics>,
    }

    fn fixture() -> Fixture {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual,
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );
        Fixture {
            _dir: dir,
            committee,
            keys: Arc::new(keys),
            committees,
            metrics: OcsMetrics::new_for_testing(),
        }
    }

    fn fallback(
        fx: &Fixture,
        fullnode: Arc<Fullnode>,
        node: &anemo::Network,
        bounds: FallbackBounds,
    ) -> Arc<PeerFallback> {
        let fallback = Arc::new(PeerFallback::new(
            fullnode,
            fx.committees.clone(),
            bounds,
            fx.metrics.clone(),
            ProofProviderMetrics::new_for_testing(),
        ));
        fallback.attach_network(node.clone());
        fallback
    }

    fn outcome(fx: &Fixture, label: &str) -> u64 {
        fx.metrics
            .direct_peer_fallback_total
            .with_label_values(&[label])
            .get()
    }

    fn object(byte: u8, version: u64) -> Object {
        let ika =
            parse_sui_type_tag(&format!("{}::ika::IKA", ObjectID::from_single_byte(0x1A))).unwrap();
        Object::new_move(
            MoveObject::new_coin(
                ika,
                SequenceNumber::from(version),
                ObjectID::from_single_byte(byte),
                1,
            ),
            Owner::AddressOwner(ObjectID::from_single_byte(0x01).into()),
            TransactionDigest::ZERO,
        )
    }

    fn summary_committing_to(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        commitment: CheckpointCommitment,
    ) -> CertifiedCheckpointSummary {
        let contents = CheckpointContents::new_with_digests_only_for_tests(vec![]);
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: *contents.digest(),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![commitment],
            end_of_epoch_data: None,
            version_specific_data: Vec::new(),
        };
        CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keys, committee)
    }

    fn tree_over(objects: &[&Object]) -> ModifiedObjectTree {
        let states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)> = objects
            .iter()
            .map(|o| {
                let (id, version, digest) = o.compute_object_reference();
                (id, (version, digest))
            })
            .collect();
        ModifiedObjectTree::new(&CheckpointArtifacts::from_object_states(states)).unwrap()
    }

    fn artifacts_digest_over(objects: &[&Object]) -> CheckpointCommitment {
        let states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)> = objects
            .iter()
            .map(|o| {
                let (id, version, digest) = o.compute_object_reference();
                (id, (version, digest))
            })
            .collect();
        CheckpointCommitment::from(
            CheckpointArtifacts::from_object_states(states)
                .digest()
                .unwrap(),
        )
    }

    /// A genuine answer: `object` proven at checkpoint `seq`, whose
    /// committee-signed summary commits to the artifacts of `written`.
    fn genuine(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        object: &Object,
        written: &[&Object],
    ) -> VerifiedObjectResponse {
        VerifiedObjectResponse {
            object: object.clone(),
            summary: summary_committing_to(committee, keys, seq, artifacts_digest_over(written)),
            proof: tree_over(written)
                .get_inclusion_proof(object.compute_object_reference())
                .unwrap(),
            claimed_latest_checkpoint_seq: HEAD,
        }
    }

    fn answering(build: impl Fn() -> VerifiedObjectResponse + Send + Sync + 'static) -> Answer {
        Arc::new(move |_| Ok(build()))
    }

    fn not_proving() -> Answer {
        Arc::new(|id| {
            Err(TransportError::NotFound(format!(
                "the defining checkpoint of {id} is pruned and no snapshot matches"
            )))
        })
    }

    /// The fallback with one peer giving `answer`, and this node's fullnode
    /// reporting `current`.
    async fn ask_one_peer(
        fx: &Fixture,
        current: &Object,
        answer: Answer,
    ) -> Result<PeerVerified, ReaderError> {
        let (peer, _) = direct_peer(answer);
        let node = connected(&[&peer]).await;
        fallback(
            fx,
            Fullnode::reporting(&[current]),
            &node,
            FallbackBounds::default(),
        )
        .verified_object(current.id())
        .await
    }

    // -- verification parity: each step rejects an answer that fails it --------------------

    /// A genuine answer — the object at the fullnode's current reference,
    /// proven against a summary Sui's committee signed — is served, with the
    /// verified snapshot the direct reader caches.
    #[tokio::test]
    async fn a_genuine_current_answer_is_served() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let (c, k) = (fx.committee.clone(), fx.keys.clone());
        let x2 = x.clone();
        let served = ask_one_peer(
            &fx,
            &x,
            answering(move || genuine(&c, &k, 400, &x2, &[&x2])),
        )
        .await
        .unwrap();
        assert_eq!(
            served.object.object.compute_object_reference(),
            x.compute_object_reference()
        );
        assert_eq!(served.object.source_checkpoint_seq, 400);
        assert_eq!(served.snapshot.source_checkpoint_seq, 400);
        assert_eq!(*served.snapshot.summary.sequence_number(), 400);
        assert_eq!(outcome(&fx, "served"), 1);
    }

    /// Bad signature: a genuine signature carried over to a summary whose
    /// contents were altered after signing.
    #[tokio::test]
    async fn an_answer_with_a_bad_signature_is_rejected() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let (c, k) = (fx.committee.clone(), fx.keys.clone());
        let x2 = x.clone();
        let result = ask_one_peer(
            &fx,
            &x,
            answering(move || {
                let mut answer = genuine(&c, &k, 400, &x2, &[&x2]);
                let signature = answer.summary.auth_sig().clone();
                let mut altered = answer.summary.data().clone();
                altered.timestamp_ms += 1;
                answer.summary =
                    CertifiedCheckpointSummary::new_from_data_and_sig(altered, signature);
                answer
            }),
        )
        .await;
        assert!(
            matches!(result, Err(ReaderError::InvalidProof(_))),
            "{:?}",
            result.err()
        );
        assert_eq!(outcome(&fx, "unverified"), 1);
    }

    /// Wrong committee: a well-formed summary for the same epoch, signed by a
    /// committee that is not Sui's.
    #[tokio::test]
    async fn an_answer_signed_by_another_committee_is_rejected() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let (foreign, foreign_keys) = Committee::new_simple_test_committee_of_size(7);
        let foreign_keys = Arc::new(foreign_keys);
        let x2 = x.clone();
        let result = ask_one_peer(
            &fx,
            &x,
            answering(move || genuine(&foreign, &foreign_keys, 400, &x2, &[&x2])),
        )
        .await;
        assert!(
            matches!(result, Err(ReaderError::InvalidProof(_))),
            "{:?}",
            result.err()
        );
    }

    /// A summary of an epoch this node holds no committee for cannot be
    /// verified at all.
    #[tokio::test]
    async fn an_answer_from_an_unknown_epoch_is_rejected() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let keys = fx.keys.clone();
        let later = Committee::new_for_testing_with_normalized_voting_power(
            5,
            keys.iter()
                .map(|key| (AuthorityName::from(key.public()), 1))
                .collect(),
        );
        let x2 = x.clone();
        let result = ask_one_peer(
            &fx,
            &x,
            answering(move || genuine(&later, &keys, 400, &x2, &[&x2])),
        )
        .await;
        assert!(
            matches!(result, Err(ReaderError::MissingCommittee(5))),
            "{:?}",
            result.err()
        );
    }

    /// Proof for the wrong id: a genuine, verifiable answer for another object
    /// than the one asked for.
    #[tokio::test]
    async fn an_answer_for_another_object_is_rejected() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let y = object(0xB2, 7);
        let (c, k) = (fx.committee.clone(), fx.keys.clone());
        let result =
            ask_one_peer(&fx, &x, answering(move || genuine(&c, &k, 400, &y, &[&y]))).await;
        match result {
            Err(ReaderError::InvalidProof(reason)) => {
                assert!(reason.contains("carries object"), "{reason}")
            }
            other => panic!(
                "expected the id binding to refuse it, got {:?}",
                other.err()
            ),
        }
    }

    /// Artifacts-digest mismatch: the proof is a genuine path in a tree whose
    /// root is not the artifacts digest the committee signed.
    #[tokio::test]
    async fn an_answer_whose_tree_is_not_the_signed_one_is_rejected() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let other = object(0xC3, 2);
        let (c, k) = (fx.committee.clone(), fx.keys.clone());
        let x2 = x.clone();
        let result = ask_one_peer(
            &fx,
            &x,
            answering(move || VerifiedObjectResponse {
                object: x2.clone(),
                // Signed: the artifacts of a checkpoint that wrote X and another object.
                summary: summary_committing_to(&c, &k, 400, artifacts_digest_over(&[&x2, &other])),
                // Shipped: a path in a tree over X alone.
                proof: tree_over(&[&x2])
                    .get_inclusion_proof(x2.compute_object_reference())
                    .unwrap(),
                claimed_latest_checkpoint_seq: HEAD,
            }),
        )
        .await;
        assert!(
            matches!(result, Err(ReaderError::InvalidProof(_))),
            "{:?}",
            result.err()
        );
    }

    /// Stale-but-authentic: a genuine proof of an older version of the object
    /// is refused `NotCurrent`, and so is a newer one this node's fullnode has
    /// not reached. Nothing a peer proves is served unless it is exactly what
    /// the fullnode reports now.
    #[tokio::test]
    async fn an_authentic_answer_that_is_not_current_is_rejected() {
        let fx = fixture();
        let current = object(0xA1, 7);
        for (version, seq) in [(6, 350), (8, 450)] {
            let other_version = object(0xA1, version);
            let (c, k) = (fx.committee.clone(), fx.keys.clone());
            let result = ask_one_peer(
                &fx,
                &current,
                answering(move || genuine(&c, &k, seq, &other_version, &[&other_version])),
            )
            .await;
            assert!(
                matches!(result, Err(ReaderError::NotCurrent { anchored_seq, .. }) if anchored_seq == seq),
                "version {version}: {:?}",
                result.err()
            );
        }
        assert_eq!(outcome(&fx, "not_current"), 2);
        assert_eq!(outcome(&fx, "served"), 0);
    }

    // -- peers ----------------------------------------------------------------------------------

    /// Each peer is asked on its own, so a peer whose answer fails a check
    /// never hides one whose answer passes, whichever is asked first.
    #[tokio::test]
    async fn a_failing_answer_does_not_hide_a_good_one() {
        for _ in 0..6 {
            let fx = fixture();
            let current = object(0xA1, 7);
            let stale = object(0xA1, 6);
            let (c, k) = (fx.committee.clone(), fx.keys.clone());
            let (stale_peer, _) =
                direct_peer(answering(move || genuine(&c, &k, 350, &stale, &[&stale])));
            let (c, k) = (fx.committee.clone(), fx.keys.clone());
            let x = current.clone();
            let (good_peer, _) = direct_peer(answering(move || genuine(&c, &k, 400, &x, &[&x])));
            let node = connected(&[&stale_peer, &good_peer]).await;
            let served = fallback(
                &fx,
                Fullnode::reporting(&[&current]),
                &node,
                FallbackBounds::default(),
            )
            .verified_object(current.id())
            .await
            .unwrap();
            assert_eq!(served.object.source_checkpoint_seq, 400);
        }
    }

    /// A peer that does not serve the relay (a mirrored node, or an older
    /// binary's unknown route) and a peer that cannot prove the object are
    /// "don't know": the fallback moves on, and with only such peers it ends
    /// without an answer, never with an error that stops anything.
    #[tokio::test]
    async fn a_non_serving_or_unknowing_peer_is_a_dont_know() {
        for _ in 0..6 {
            let fx = fixture();
            let current = object(0xA1, 7);
            let non_serving = non_serving_peer();
            let (unknowing, _) = direct_peer(not_proving());
            let (c, k) = (fx.committee.clone(), fx.keys.clone());
            let x = current.clone();
            let (good_peer, _) = direct_peer(answering(move || genuine(&c, &k, 400, &x, &[&x])));
            let node = connected(&[&non_serving, &unknowing, &good_peer]).await;
            assert!(
                fallback(
                    &fx,
                    Fullnode::reporting(&[&current]),
                    &node,
                    FallbackBounds::default()
                )
                .verified_object(current.id())
                .await
                .is_ok()
            );
        }
        let fx = fixture();
        let current = object(0xA1, 7);
        let non_serving = non_serving_peer();
        let (unknowing, _) = direct_peer(not_proving());
        let node = connected(&[&non_serving, &unknowing]).await;
        let result = fallback(
            &fx,
            Fullnode::reporting(&[&current]),
            &node,
            FallbackBounds::default(),
        )
        .verified_object(current.id())
        .await;
        assert!(matches!(result, Err(ReaderError::Transport(_))));
        assert_eq!(outcome(&fx, "unavailable"), 1);
    }

    // -- bounds ---------------------------------------------------------------------------------

    /// Not attached yet, a deleted object, the concurrency cap, a recent
    /// failure: none of them asks a peer.
    #[tokio::test]
    async fn the_fallback_is_bounded() {
        let fx = fixture();
        let current = object(0xA1, 7);
        let (c, k) = (fx.committee.clone(), fx.keys.clone());
        let x = current.clone();
        let (peer, requests) = direct_peer(answering(move || genuine(&c, &k, 400, &x, &[&x])));
        let node = connected(&[&peer]).await;
        let fullnode = Fullnode::reporting(&[&current]);

        // Not attached: nothing is asked, not even the fullnode.
        let detached = PeerFallback::new(
            fullnode.clone(),
            fx.committees.clone(),
            FallbackBounds::default(),
            fx.metrics.clone(),
            ProofProviderMetrics::new_for_testing(),
        );
        assert!(detached.verified_object(current.id()).await.is_err());
        assert_eq!(fullnode.lookups.load(Ordering::Relaxed), 0);

        // A deleted object: the fullnode reports none, so no peer is asked.
        let bounded = fallback(&fx, fullnode.clone(), &node, FallbackBounds::default());
        assert!(
            bounded
                .verified_object(ObjectID::from_single_byte(0xDD))
                .await
                .is_err()
        );
        assert_eq!(outcome(&fx, "not_live"), 1);
        assert_eq!(requests.load(Ordering::Relaxed), 0);

        // The concurrency cap: with every permit taken, the read fails fast.
        let capped = fallback(
            &fx,
            fullnode.clone(),
            &node,
            FallbackBounds {
                max_concurrent: 1,
                ..FallbackBounds::default()
            },
        );
        let held = capped.permits.try_acquire().unwrap();
        assert!(capped.verified_object(current.id()).await.is_err());
        assert_eq!(requests.load(Ordering::Relaxed), 0);
        drop(held);
        assert!(capped.verified_object(current.id()).await.is_ok());
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        assert!(outcome(&fx, "skipped") >= 2);
    }

    /// An object whose fallback failed is not asked for again before
    /// `retry_after`; after it, it is.
    #[tokio::test]
    async fn a_failed_object_is_not_retried_before_retry_after() {
        let fx = fixture();
        let current = object(0xA1, 7);
        let (peer, requests) = direct_peer(not_proving());
        let node = connected(&[&peer]).await;
        let retry_after = Duration::from_millis(300);
        let bounded = fallback(
            &fx,
            Fullnode::reporting(&[&current]),
            &node,
            FallbackBounds {
                retry_after,
                ..FallbackBounds::default()
            },
        );
        assert!(bounded.verified_object(current.id()).await.is_err());
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        assert!(bounded.verified_object(current.id()).await.is_err());
        assert_eq!(requests.load(Ordering::Relaxed), 1, "within retry_after");
        tokio::time::sleep(retry_after).await;
        assert!(bounded.verified_object(current.id()).await.is_err());
        assert_eq!(requests.load(Ordering::Relaxed), 2);
    }

    /// A whole attempt ends at `attempt_timeout`, however many peers are left
    /// and however long each may take: peers that accept a request and never
    /// answer cannot hold the read for `max_peers * peer_timeout`.
    #[tokio::test]
    async fn an_attempt_ends_at_its_deadline() {
        let fx = fixture();
        let current = object(0xA1, 7);
        // Peers that accept the request and sit on it far past every deadline.
        let peers: Vec<_> = (0..4)
            .map(|_| slow_direct_peer(not_proving(), Duration::from_secs(60)))
            .collect();
        let node = connected(&peers.iter().map(|(n, _)| n).collect::<Vec<_>>()).await;
        let bounded = fallback(
            &fx,
            Fullnode::reporting(&[&current]),
            &node,
            FallbackBounds {
                peer_timeout: Duration::from_secs(1),
                attempt_timeout: Duration::from_millis(1_500),
                ..FallbackBounds::default()
            },
        );
        let started = Instant::now();
        assert!(bounded.verified_object(current.id()).await.is_err());
        let took = started.elapsed();
        // The first peer gets its full second, the second only the half second
        // left; no peer is asked once the deadline has passed.
        assert!(
            took < Duration::from_millis(1_900),
            "4 peers at 1 s each, but the attempt is bounded at 1.5 s: took {took:?}"
        );
        let asked: usize = peers.iter().map(|(_, r)| r.load(Ordering::Relaxed)).sum();
        assert_eq!(asked, 2, "no peer is asked after the deadline");
    }

    /// While the checkpoint pusher reports this node's own fullnode frozen,
    /// the fallback asks nobody — neither a peer nor the fullnode, whose
    /// "current" reference is a past one. Once it advances again, asking
    /// resumes.
    #[tokio::test]
    async fn a_frozen_fullnode_stands_the_fallback_down() {
        let fx = fixture();
        let current = object(0xA1, 7);
        let (c, k) = (fx.committee.clone(), fx.keys.clone());
        let x = current.clone();
        let (peer, requests) = direct_peer(answering(move || genuine(&c, &k, 400, &x, &[&x])));
        let node = connected(&[&peer]).await;
        let fullnode = Fullnode::reporting(&[&current]);
        let guarded = fallback(&fx, fullnode.clone(), &node, FallbackBounds::default());
        let frozen = Arc::new(AtomicBool::new(false));
        guarded.attach_upstream_frozen(frozen.clone());

        frozen.store(true, Ordering::Relaxed);
        assert!(guarded.verified_object(current.id()).await.is_err());
        assert_eq!(requests.load(Ordering::Relaxed), 0, "no peer is asked");
        assert_eq!(
            fullnode.lookups.load(Ordering::Relaxed),
            0,
            "nor the fullnode"
        );
        assert_eq!(outcome(&fx, "skipped"), 1);

        frozen.store(false, Ordering::Relaxed);
        assert!(guarded.verified_object(current.id()).await.is_ok());
        assert_eq!(requests.load(Ordering::Relaxed), 1);
    }

    /// The pusher's state may be shared as a flag or as a watch; both read the
    /// same.
    #[test]
    fn upstream_frozen_reads_a_flag_and_a_watch() {
        let flag = AtomicBool::new(false);
        assert!(!flag.is_frozen());
        flag.store(true, Ordering::Relaxed);
        assert!(flag.is_frozen());
        let (sender, receiver) = tokio::sync::watch::channel(false);
        assert!(!receiver.is_frozen());
        sender.send(true).unwrap();
        assert!(receiver.is_frozen());
    }

    /// A fullnode whose latest checkpoint the test sets, and which serves no
    /// checkpoint contents.
    struct WatermarkFullnode {
        height: std::sync::atomic::AtomicU64,
    }

    #[async_trait]
    impl SuiTransport for WatermarkFullnode {
        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            unimplemented!()
        }
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            unimplemented!()
        }
        async fn get_committee(&self, _: Option<u64>) -> Result<Committee, TransportError> {
            unimplemented!()
        }
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!("the pusher probes the watermark")
        }
        async fn get_latest_checkpoint_sequence(
            &self,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            Ok(self.height.load(Ordering::Relaxed))
        }
        async fn get_full_checkpoint(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            Err(TransportError::NotFound(format!(
                "checkpoint {seq} not served"
            )))
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            _: CheckpointDigest,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn last_checkpoint_of_epoch(
            &self,
            _: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            unimplemented!()
        }
        async fn get_object(&self, _: ObjectID) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn get_object_with_version(
            &self,
            _: ObjectID,
            _: SequenceNumber,
        ) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn batch_get_objects(&self, _: &[ObjectID]) -> Result<Vec<Object>, TransportError> {
            unimplemented!()
        }
        async fn list_dynamic_fields(
            &self,
            _: ObjectID,
            _: Option<u32>,
            _: Option<Vec<u8>>,
        ) -> Result<DynamicFieldPage, TransportError> {
            unimplemented!()
        }
        async fn get_transaction(
            &self,
            _: TransactionDigest,
        ) -> Result<ExecutedTransaction, TransportError> {
            unimplemented!()
        }
    }

    /// The checkpoint pusher raises the shared flag when it reports this
    /// node's fullnode frozen — no advance for five minutes — and clears it
    /// when the fullnode advances again.
    #[tokio::test(start_paused = true)]
    async fn the_pusher_raises_and_clears_the_frozen_flag() {
        use crate::sui_connector::push_worker::IkaCheckpointPusher;
        use ika_types::messages_dwallet_mpc::IkaPackageConfig;

        let dir = tempfile::tempdir().unwrap();
        let (committee, _) = Committee::new_simple_test_committee();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee)),
            )
            .unwrap(),
        );
        perpetual.put_sui_pusher_last_seq(100).unwrap();
        let fullnode = Arc::new(WatermarkFullnode {
            height: std::sync::atomic::AtomicU64::new(100),
        });
        let packages = IkaPackageConfig {
            ika_package_id: ObjectID::from_single_byte(0x1A),
            ika_common_package_id: ObjectID::from_single_byte(0x1B),
            ika_dwallet_2pc_mpc_package_id: ObjectID::from_single_byte(0x1C),
            ika_dwallet_2pc_mpc_package_id_v2: None,
            ika_system_package_id: ObjectID::from_single_byte(0x1D),
        };
        let pusher = IkaCheckpointPusher::new(
            fullnode.clone(),
            perpetual,
            OcsMetrics::new_for_testing(),
            &packages,
            Duration::from_secs(1),
            Arc::new(VerifiedStateCache::new()),
            committees,
            None,
        )
        .await
        .unwrap();
        let frozen = pusher.upstream_frozen();
        tokio::spawn(pusher.run());

        // The pusher checks every few seconds, so allow it one check past each
        // transition.
        tokio::time::sleep(Duration::from_secs(285)).await;
        assert!(!frozen.is_frozen(), "under five minutes");
        tokio::time::sleep(Duration::from_secs(35)).await;
        assert!(frozen.is_frozen(), "no advance for five minutes");

        fullnode.height.store(101, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(15)).await;
        assert!(!frozen.is_frozen(), "advancing again");
    }

    /// At most `max_peers` peers are asked per attempt.
    #[tokio::test]
    async fn at_most_max_peers_are_asked() {
        let fx = fixture();
        let current = object(0xA1, 7);
        let peers: Vec<_> = (0..3).map(|_| direct_peer(not_proving())).collect();
        let node = connected(&peers.iter().map(|(n, _)| n).collect::<Vec<_>>()).await;
        let bounded = fallback(
            &fx,
            Fullnode::reporting(&[&current]),
            &node,
            FallbackBounds {
                max_peers: 2,
                ..FallbackBounds::default()
            },
        );
        assert!(bounded.verified_object(current.id()).await.is_err());
        let asked: usize = peers.iter().map(|(_, r)| r.load(Ordering::Relaxed)).sum();
        assert_eq!(asked, 2);
    }

    // -- the direct reader ----------------------------------------------------------------------

    /// The direct node's own provider: it cannot prove anything (its fullnode
    /// pruned every defining checkpoint), and its batch answers carry an empty
    /// slot for such an object.
    struct PrunedLocalProvider;

    #[async_trait]
    impl ProofProvider for PrunedLocalProvider {
        async fn verified_object(
            &self,
            id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            Err(TransportError::NotFound(format!(
                "the defining checkpoint of {id} is pruned and no snapshot matches"
            )))
        }
        async fn batch_verified_objects(
            &self,
            ids: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            Ok(BatchVerifiedObjectsResponse {
                summaries: BTreeMap::new(),
                results: ids.iter().map(|_| None).collect(),
                claimed_latest_checkpoint_seq: HEAD,
            })
        }
        async fn verified_dynamic_fields_page(
            &self,
            _: VerifiedDynamicFieldsPageRequest,
        ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
            unimplemented!()
        }
    }

    fn reader(
        fx: &Fixture,
        cache: SharedVerifiedStateCache,
        cache_first: bool,
        fallback: Arc<PeerFallback>,
    ) -> OcsVerifiedReader {
        OcsVerifiedReader::new(
            Arc::new(PrunedLocalProvider),
            fx.committees.clone(),
            fx.metrics.clone(),
            None,
            cache,
            cache_first,
            None,
        )
        .with_peer_fallback(Some(fallback))
    }

    /// The direct reader serves a peer-verified object for a single read and
    /// for an empty batch slot, and caches it: the next read is a cache hit
    /// that asks no peer. A mirrored reader never falls back.
    #[tokio::test]
    async fn the_direct_reader_serves_and_caches_a_peer_verified_object() {
        let fx = fixture();
        let x = object(0xA1, 7);
        let y = object(0xB2, 3);
        let (c, k) = (fx.committee.clone(), fx.keys.clone());
        let (x2, y2) = (x.clone(), y.clone());
        let (peer, requests) = direct_peer(Arc::new(move |id| {
            let wanted = if id == x2.id() { &x2 } else { &y2 };
            Ok(genuine(&c, &k, 400, wanted, &[&x2, &y2]))
        }));
        let node = connected(&[&peer]).await;
        let fullnode = Fullnode::reporting(&[&x, &y]);

        let mirrored_cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let mirrored = reader(
            &fx,
            mirrored_cache,
            false,
            fallback(&fx, fullnode.clone(), &node, FallbackBounds::default()),
        );
        assert!(mirrored.verified_object(x.id()).await.is_err());
        assert!(mirrored.verified_objects(&[x.id()]).await.is_err());
        assert_eq!(
            requests.load(Ordering::Relaxed),
            0,
            "a mirrored node never falls back"
        );

        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let direct = reader(
            &fx,
            cache.clone(),
            true,
            fallback(&fx, fullnode, &node, FallbackBounds::default()),
        );
        let read = direct.verified_object(x.id()).await.unwrap();
        assert_eq!(
            read.object.compute_object_reference(),
            x.compute_object_reference()
        );
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        assert_eq!(cache.get(x.id()).unwrap().source_checkpoint_seq, 400);
        direct.verified_object(x.id()).await.unwrap();
        assert_eq!(
            requests.load(Ordering::Relaxed),
            1,
            "the second read is a cache hit"
        );

        let batch = direct.verified_objects(&[y.id()]).await.unwrap();
        assert_eq!(
            batch[0].object.compute_object_reference(),
            y.compute_object_reference()
        );
        assert_eq!(requests.load(Ordering::Relaxed), 2);
    }

    /// The direct reader's own high-water still applies: a peer-verified
    /// object below a version this reader has already served is neither
    /// served nor cached.
    #[tokio::test]
    async fn the_direct_readers_high_water_applies_to_a_fallback_answer() {
        let fx = fixture();
        let x7 = object(0xA1, 7);
        let x8 = object(0xA1, 8);
        let (c, k) = (fx.committee.clone(), fx.keys.clone());
        let x = x7.clone();
        let (peer, _) = direct_peer(answering(move || genuine(&c, &k, 400, &x, &[&x])));
        let node = connected(&[&peer]).await;
        // The fullnode lags: it reports version 7 after version 8 was served.
        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let direct = reader(
            &fx,
            cache.clone(),
            true,
            fallback(
                &fx,
                Fullnode::reporting(&[&x7]),
                &node,
                FallbackBounds::default(),
            ),
        );
        direct.record_high_water(x8.id(), x8.version()).unwrap();
        assert!(direct.verified_object(x7.id()).await.is_err());
        assert!(
            cache.get(x7.id()).is_none(),
            "a refused answer is never cached"
        );
        assert_eq!(outcome(&fx, "served"), 1, "the fallback itself verified it");
    }

    // -- the incident, end to end ---------------------------------------------------------------

    /// A direct peer's proof provider as it serves a pruned anchor: from its
    /// verified cache's snapshot (`recover_pruned_proof`).
    fn served_from_cache(cache: SharedVerifiedStateCache) -> Answer {
        Arc::new(move |id| {
            let snapshot = cache
                .get(id)
                .ok_or_else(|| TransportError::NotFound(format!("{id} pruned and not cached")))?;
            Ok(VerifiedObjectResponse {
                object: snapshot.object,
                summary: snapshot.summary,
                proof: snapshot.proof,
                claimed_latest_checkpoint_seq: HEAD,
            })
        })
    }

    fn move_object(type_tag: &str, version: u64, contents: Vec<u8>, owner: Owner) -> Object {
        let TypeTag::Struct(tag) = parse_sui_type_tag(type_tag).unwrap() else {
            panic!("{type_tag} is a struct type");
        };
        // `MoveObject`'s fields are private and its constructor for an
        // arbitrary type is `unsafe`; its serialized layout is public. Neither
        // anchor type has `store`, so `has_public_transfer` is false.
        let layout = (
            MoveObjectType::from(*tag),
            false,
            SequenceNumber::from(version),
            contents,
        );
        let object: MoveObject = bcs::from_bytes(&bcs::to_bytes(&layout).unwrap()).unwrap();
        Object::new_move(object, owner, TransactionDigest::ZERO)
    }

    fn empty_bls_committee() -> BlsCommittee {
        BlsCommittee {
            members: vec![],
            aggregated_protocol_pubkey: bcs::from_bytes(&bcs::to_bytes(&Vec::<u8>::new()).unwrap())
                .unwrap(),
            quorum_threshold: 0,
            validity_threshold: 0,
        }
    }

    fn system_inner(epoch: u64) -> SystemInnerV1 {
        let oid = ObjectID::from_single_byte;
        SystemInnerV1 {
            epoch,
            epoch_start_tx_digest: vec![7; 32],
            system_object_cap: SystemObjectCap { id: oid(0x31) },
            protocol_version: 1,
            next_protocol_version: None,
            upgrade_caps: vec![],
            approved_upgrades: VecMap { contents: vec![] },
            validator_set: ValidatorSetV1 {
                total_stake: 0,
                reward_slashing_rate: 0,
                validators: Table::default(),
                active_committee: empty_bls_committee(),
                next_epoch_committee: None,
                previous_committee: empty_bls_committee(),
                pending_active_set: ExtendedField { id: oid(0x32) },
                validator_report_records: VecMap { contents: vec![] },
                extra_fields: Bag::default(),
            },
            epoch_duration_ms: 86_400_000,
            stake_subsidy_start_epoch: 1,
            protocol_treasury: ProtocolTreasuryV1 {
                treasury_cap: TreasuryCap {
                    id: UID::new(oid(0x33)),
                    total_supply: Supply { value: 0 },
                },
                stake_subsidy_distribution_counter: 0,
                stake_subsidy_rate: 0,
                stake_subsidy_amount_per_distribution: 0,
                stake_subsidy_period_length: 0,
                total_supply_at_period_start: 0,
                extra_fields: Bag::default(),
            },
            epoch_start_timestamp_ms: 0,
            last_processed_checkpoint_sequence_number: 0,
            previous_epoch_last_checkpoint_sequence_number: 0,
            total_messages_processed: 0,
            remaining_rewards: Balance::new(0),
            authorized_protocol_cap_ids: vec![],
            witness_approving_advance_epoch: vec![],
            received_end_of_publish: false,
            extra_fields: Bag::default(),
        }
    }

    /// The `System` anchor and its versioned inner, both written at object
    /// version `version` and holding Ika epoch `epoch`.
    fn system_anchor(system_id: ObjectID, version: u64, epoch: u64) -> (Object, Object) {
        let package = ObjectID::from_single_byte(0x1D);
        let outer = System {
            id: system_id,
            version: 1,
            package_id: package,
            new_package_id: None,
            migration_epoch: None,
        };
        let inner_id = ika_sui_client::transport::derive_versioned_child_id(system_id, 1).unwrap();
        let inner = Field {
            id: UID::new(inner_id),
            name: 1u64,
            value: system_inner(epoch),
        };
        (
            move_object(
                &format!("{package}::system::System"),
                version,
                bcs::to_bytes(&outer).unwrap(),
                Owner::Shared {
                    initial_shared_version: SequenceNumber::from(1u64),
                },
            ),
            move_object(
                &format!("0x2::dynamic_field::Field<u64, {package}::system_inner::SystemInner>"),
                version,
                bcs::to_bytes(&inner).unwrap(),
                Owner::ObjectOwner(system_id.into()),
            ),
        )
    }

    /// Fold `objects`, written together at `seq`, into `cache` as a direct
    /// node's pusher would have while the checkpoint was live.
    fn folded(
        fx: &Fixture,
        cache: &SharedVerifiedStateCache,
        seq: CheckpointSequenceNumber,
        objects: &[&Object],
    ) {
        let tree = tree_over(objects);
        let summary =
            summary_committing_to(&fx.committee, &fx.keys, seq, artifacts_digest_over(objects));
        let entries: Vec<VerifiedObjectEntry> = objects
            .iter()
            .map(|o| VerifiedObjectEntry {
                object: (*o).clone(),
                checkpoint_seq: seq,
                proof: tree
                    .get_inclusion_proof(o.compute_object_reference())
                    .unwrap(),
                dynamic_field_name_type: String::new(),
                dynamic_field_name_bcs: Vec::new(),
            })
            .collect();
        cache.absorb_entries(&summary, &entries);
    }

    /// The incident shape, end to end over real anemo networks. A fresh direct
    /// node — empty cache — whose fullnode reports the `System` anchor but has
    /// pruned the checkpoint that wrote it is stuck at the
    /// `verified_system_inner` boot barrier. Its peers: an up-to-date direct
    /// node serving the anchor from its own verified cache (as every direct
    /// node, v1.4.x included, already does), a malicious one serving the
    /// previous, genuinely signed version of the anchor, and a node that does
    /// not serve the relay. The fresh node reads the anchor from the honest
    /// peer, verified as a mirrored node would, and gets past the barrier;
    /// the malicious answer is refused whichever peer is asked first.
    #[tokio::test]
    async fn a_fresh_direct_node_gets_past_the_system_barrier_through_a_direct_peer() {
        for _ in 0..4 {
            let fx = fixture();
            let system_id = ObjectID::from_single_byte(0x5A);
            let (outer, inner) = system_anchor(system_id, 11, 463);
            let (old_outer, old_inner) = system_anchor(system_id, 10, 462);

            let honest_cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
            folded(&fx, &honest_cache, 700, &[&outer, &inner]);
            let (honest, _) = direct_peer(served_from_cache(honest_cache));
            let stale_cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
            folded(&fx, &stale_cache, 650, &[&old_outer, &old_inner]);
            let (malicious, _) = direct_peer(served_from_cache(stale_cache));
            let non_serving = non_serving_peer();
            let node = connected(&[&honest, &malicious, &non_serving]).await;

            let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
            let direct = reader(
                &fx,
                cache.clone(),
                true,
                fallback(
                    &fx,
                    Fullnode::reporting(&[&outer, &inner]),
                    &node,
                    FallbackBounds::default(),
                ),
            );
            let (system, inner_state) = direct.verified_system_inner(system_id).await.unwrap();
            assert_eq!(system.id, system_id);
            assert_eq!(inner_state.epoch(), 463);
            assert_eq!(cache.get(outer.id()).unwrap().source_checkpoint_seq, 700);
            assert_eq!(cache.get(inner.id()).unwrap().source_checkpoint_seq, 700);
        }
    }
}
