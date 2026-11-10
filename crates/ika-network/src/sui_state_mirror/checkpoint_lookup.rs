// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Direct-to-direct checkpoint lookup: "which Sui checkpoint proves object X at
//! exactly reference R?"
//!
//! A `sui-state-direct` node that cannot prove an object — its fullnode reports
//! the object at `R` but has pruned the checkpoint that wrote it, and its
//! verified cache holds no snapshot at `R` — asks the other direct nodes on the
//! p2p mesh. A peer answers from its own verified cache: the source checkpoint
//! of its snapshot at exactly `R`, or "don't know".
//!
//! The answer is a bare sequence number and is UNTRUSTED. The asker never folds
//! anything a peer sends (no object data crosses this wire at all): it fetches
//! that checkpoint from the Sui checkpoint archive and runs its own archive
//! verification and exact-reference match before folding. A wrong answer costs
//! one archive download, so there is no quorum, no stake weighting and no
//! protocol gate.
//!
//! Mixed fleets: the method rides the existing `SuiStateMirror` service, which
//! every `sui-state-direct` node serves on the p2p mesh by default. A peer that
//! does not know the method — an older binary, or a node that does not serve
//! `SuiStateMirror` at all — answers anemo's bare route-miss `NotFound`, which
//! counts as "don't know" and never as an error.

use std::collections::BTreeMap;
use std::time::Duration;

use anemo::{Network, PeerId, Request};
use async_trait::async_trait;
use futures::future::join_all;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use sui_types::base_types::ObjectRef;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use tracing::debug;

use super::SuiStateMirrorClient;
use super::client::is_service_unimplemented;

/// Ask one peer which checkpoint proves `object_ref`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectCheckpointLookupRequest {
    pub object_ref: ObjectRef,
}

/// A peer's answer: the checkpoint its verified snapshot of the object at
/// exactly the requested reference came from, or `None` for "don't know".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectCheckpointLookupResponse {
    pub checkpoint_seq: Option<CheckpointSequenceNumber>,
}

/// The serving side of the lookup: a node's own verified state, indexed by
/// object id. Implementations must be a point lookup, never a scan — the
/// method is served to any connected peer.
pub trait ObjectCheckpointLocator: Send + Sync {
    /// The checkpoint whose committee-signed artifacts attest `object_ref`, if
    /// this node holds a verified snapshot of the object at exactly that
    /// reference.
    fn checkpoint_proving(&self, object_ref: ObjectRef) -> Option<CheckpointSequenceNumber>;
}

/// Per-peer deadline of one lookup. A lookup is a cache point read on the
/// serving side, so this only has to outlast the network round trip; a peer
/// that does not answer in time counts as "don't know".
pub const OBJECT_CHECKPOINT_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Most peers asked per lookup, chosen at random among the connected ones —
/// above the committee's size, so in practice every connected peer is asked:
/// the direct nodes may be a small share of the committee, and any one honest
/// direct peer holding the snapshot is enough. A lookup is a cache point read
/// on the serving side and the asker runs a few a minute at most, so the
/// fan-out is cheap; the cap only bounds a node with an unusually large
/// connection set.
pub const MAX_PEERS_PER_LOOKUP: usize = 128;

/// One peer's reply, classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerReply {
    /// The peer named a checkpoint.
    Named(CheckpointSequenceNumber),
    /// The peer serves the lookup and does not know.
    Unknown,
    /// The peer does not serve the lookup: an older binary, or a node that
    /// does not serve `SuiStateMirror` (anemo's bare route-miss `NotFound`).
    /// Counted as "don't know".
    Unimplemented,
    /// Any other error, a rate-limit refusal or a timeout. Counted as "don't
    /// know".
    Failed,
}

/// Every reply to one lookup.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PeerCheckpointAnswers {
    /// The distinct checkpoints peers named, the most-named first (ties in
    /// ascending order). Untrusted pointers: each is only a candidate for the
    /// asker's own archive verification.
    pub candidates: Vec<CheckpointSequenceNumber>,
    pub asked: usize,
    pub named: usize,
    pub unknown: usize,
    pub unimplemented: usize,
    pub failed: usize,
}

impl PeerCheckpointAnswers {
    pub fn from_replies(replies: impl IntoIterator<Item = PeerReply>) -> Self {
        let mut answers = Self::default();
        let mut votes: BTreeMap<CheckpointSequenceNumber, usize> = BTreeMap::new();
        for reply in replies {
            answers.asked += 1;
            match reply {
                PeerReply::Named(seq) => {
                    answers.named += 1;
                    *votes.entry(seq).or_default() += 1;
                }
                PeerReply::Unknown => answers.unknown += 1,
                PeerReply::Unimplemented => answers.unimplemented += 1,
                PeerReply::Failed => answers.failed += 1,
            }
        }
        let mut ranked: Vec<(CheckpointSequenceNumber, usize)> = votes.into_iter().collect();
        // Stable: equal vote counts keep the ascending order of the map.
        ranked.sort_by_key(|(_, votes)| std::cmp::Reverse(*votes));
        answers.candidates = ranked.into_iter().map(|(seq, _)| seq).collect();
        answers
    }
}

/// Classify one peer's reply. A route miss — the peer has no such method or
/// no `SuiStateMirror` service — is "unimplemented", which the asker treats
/// exactly like "don't know".
pub fn classify_reply(
    result: Result<
        Result<anemo::Response<ObjectCheckpointLookupResponse>, anemo::rpc::Status>,
        tokio::time::error::Elapsed,
    >,
) -> PeerReply {
    match result {
        Ok(Ok(response)) => match response.into_inner().checkpoint_seq {
            Some(seq) => PeerReply::Named(seq),
            None => PeerReply::Unknown,
        },
        Ok(Err(status)) if is_service_unimplemented(&status) => PeerReply::Unimplemented,
        Ok(Err(_)) | Err(_) => PeerReply::Failed,
    }
}

/// The asking side, as the connector sees it. A trait so the recovery logic in
/// `ika-core` can be driven by a fake peer set in tests.
#[async_trait]
pub trait ObjectCheckpointPeers: Send + Sync {
    /// Ask the peers which checkpoint proves `object_ref`. Never fails: a peer
    /// that cannot answer — for any reason — is a "don't know".
    async fn ask(&self, object_ref: ObjectRef) -> PeerCheckpointAnswers;
}

/// [`ObjectCheckpointPeers`] over the p2p mesh: asks up to
/// [`MAX_PEERS_PER_LOOKUP`] of the currently-connected peers at once. Discovery
/// keeps a direct node connected to the committee, so the direct nodes among
/// them — the ones that serve `SuiStateMirror` — are reachable without any
/// configuration.
pub struct MirrorCheckpointPeers {
    network: Network,
}

impl MirrorCheckpointPeers {
    pub fn new(network: Network) -> Self {
        Self { network }
    }

    async fn ask_one(&self, peer_id: PeerId, object_ref: ObjectRef) -> PeerReply {
        let Some(peer) = self.network.peer(peer_id) else {
            return PeerReply::Failed;
        };
        let mut client = SuiStateMirrorClient::new(peer);
        let request = Request::new(ObjectCheckpointLookupRequest { object_ref });
        let reply = classify_reply(
            tokio::time::timeout(
                OBJECT_CHECKPOINT_LOOKUP_TIMEOUT,
                client.object_checkpoint_lookup(request),
            )
            .await,
        );
        debug!(%peer_id, ?object_ref, ?reply, "object checkpoint lookup reply");
        reply
    }
}

#[async_trait]
impl ObjectCheckpointPeers for MirrorCheckpointPeers {
    async fn ask(&self, object_ref: ObjectRef) -> PeerCheckpointAnswers {
        let mut peers = self.network.peers();
        peers.shuffle(&mut rand::thread_rng());
        peers.truncate(MAX_PEERS_PER_LOOKUP);
        let replies = join_all(
            peers
                .into_iter()
                .map(|peer_id| self.ask_one(peer_id, object_ref)),
        )
        .await;
        PeerCheckpointAnswers::from_replies(replies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anemo::rpc::Status;
    use anemo::types::response::StatusCode;

    #[test]
    fn answers_rank_the_most_named_checkpoint_first_and_count_every_kind() {
        let answers = PeerCheckpointAnswers::from_replies([
            PeerReply::Named(7),
            PeerReply::Unknown,
            PeerReply::Named(9),
            PeerReply::Unimplemented,
            PeerReply::Named(9),
            PeerReply::Failed,
            PeerReply::Named(5),
        ]);
        assert_eq!(answers.candidates, vec![9, 5, 7]);
        assert_eq!(
            (
                answers.asked,
                answers.named,
                answers.unknown,
                answers.unimplemented,
                answers.failed
            ),
            (7, 4, 1, 1, 1)
        );
        assert_eq!(
            PeerCheckpointAnswers::from_replies([]),
            PeerCheckpointAnswers::default()
        );
    }

    /// A route miss (no such method on an older binary, or no service at all)
    /// is "unimplemented"; the service's own errors, a rate-limit refusal and
    /// a timeout are "failed". Both are "don't know" to the asker — neither
    /// is ever an error that blocks anything.
    #[tokio::test]
    async fn replies_are_classified_and_a_route_miss_is_unimplemented() {
        let named = Ok(Ok(anemo::Response::new(ObjectCheckpointLookupResponse {
            checkpoint_seq: Some(42),
        })));
        assert_eq!(classify_reply(named), PeerReply::Named(42));
        let unknown = Ok(Ok(anemo::Response::new(ObjectCheckpointLookupResponse {
            checkpoint_seq: None,
        })));
        assert_eq!(classify_reply(unknown), PeerReply::Unknown);
        assert_eq!(
            classify_reply(Ok(Err(Status::new(StatusCode::NotFound)))),
            PeerReply::Unimplemented
        );
        // The service's own errors carry the `status-message` header on the
        // wire, which is what tells them apart from a route miss.
        assert_eq!(
            classify_reply(Ok(Err(Status::new(StatusCode::NotFound)
                .with_header(anemo::types::header::STATUS_MESSAGE, "gone")))),
            PeerReply::Failed
        );
        assert_eq!(
            classify_reply(Ok(Err(Status::new(StatusCode::TooManyRequests)))),
            PeerReply::Failed
        );
        let elapsed = tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
            .await
            .unwrap_err();
        assert_eq!(classify_reply(Err(elapsed)), PeerReply::Failed);
    }

    use crate::proof_provider::ProofProviderMetrics;
    use crate::sui_state_mirror::{
        SuiMirrorPeers, SuiMirrorProofProvider, SuiMirrorTransport, make_server,
    };
    use crate::utils::build_network;
    use std::collections::HashMap;
    use std::sync::Arc;
    use sui_types::base_types::{ObjectDigest, ObjectID, SequenceNumber};

    struct FixedLocator(HashMap<ObjectRef, CheckpointSequenceNumber>);

    impl ObjectCheckpointLocator for FixedLocator {
        fn checkpoint_proving(&self, object_ref: ObjectRef) -> Option<CheckpointSequenceNumber> {
            self.0.get(&object_ref).copied()
        }
    }

    fn locator<const N: usize>(
        entries: [(ObjectRef, CheckpointSequenceNumber); N],
    ) -> Option<Arc<dyn ObjectCheckpointLocator>> {
        Some(Arc::new(FixedLocator(HashMap::from(entries))))
    }

    fn object_ref(byte: u8, version: u64) -> ObjectRef {
        (
            ObjectID::from_single_byte(byte),
            SequenceNumber::from(version),
            ObjectDigest::new([byte; 32]),
        )
    }

    /// A network serving the real `SuiStateMirror` server, built by
    /// [`make_server`] as a direct node builds it, with `locator` answering
    /// the lookup. The transport and provider are never reached by it.
    fn serving_network(
        locator: Option<Arc<dyn ObjectCheckpointLocator>>,
    ) -> (anemo::Network, Arc<ProofProviderMetrics>) {
        let metrics = ProofProviderMetrics::new_for_testing();
        let unused = build_network(|router| router);
        let peers = SuiMirrorPeers::new(unused, vec![], metrics.clone());
        let transport = Arc::new(SuiMirrorTransport::new(peers.clone()));
        let provider = Arc::new(SuiMirrorProofProvider::new(peers, metrics.clone()));
        let server_metrics = metrics.clone();
        let network = build_network(move |router| {
            router.add_rpc_service(make_server(transport, provider, server_metrics, locator))
        });
        (network, metrics)
    }

    /// Over real anemo networks: a peer holding the snapshot names its
    /// checkpoint, a serving peer without it says it doesn't know, and an
    /// older binary — which has no route for the method and answers anemo's
    /// bare route-miss `NotFound`, exactly as a node without the service
    /// does — counts as "don't know" without failing the lookup. A lookup
    /// that reaches only old peers yields no candidate and no error.
    #[tokio::test]
    async fn a_mixed_fleet_names_the_checkpoint_and_an_old_peer_counts_as_dont_know() {
        let target = object_ref(0xA1, 7);
        let (holder, holder_metrics) = serving_network(locator([(target, 42)]));
        let (without, _) = serving_network(None);
        let old_binary = build_network(|router| router);
        let asker = build_network(|router| router);
        for peer in [&holder, &without, &old_binary] {
            asker.connect(peer.local_addr()).await.unwrap();
        }

        let answers = MirrorCheckpointPeers::new(asker.clone()).ask(target).await;
        assert_eq!(answers.candidates, vec![42]);
        assert_eq!(
            (
                answers.asked,
                answers.named,
                answers.unknown,
                answers.unimplemented,
                answers.failed
            ),
            (3, 1, 1, 1, 0)
        );
        assert_eq!(
            holder_metrics
                .serve_object_checkpoint_lookup_total
                .with_label_values(&["named"])
                .get(),
            1
        );

        // Another version of the same object is not what the holder has.
        let answers = MirrorCheckpointPeers::new(asker.clone())
            .ask(object_ref(0xA1, 8))
            .await;
        assert!(answers.candidates.is_empty());
        assert_eq!((answers.unknown, answers.unimplemented), (2, 1));

        let only_old = build_network(|router| router);
        only_old.connect(old_binary.local_addr()).await.unwrap();
        let answers = MirrorCheckpointPeers::new(only_old).ask(target).await;
        assert!(answers.candidates.is_empty());
        assert_eq!((answers.asked, answers.unimplemented), (1, 1));
    }

    /// The serving side refuses a requester past its burst with
    /// `TooManyRequests` (a "don't know" to the asker), while another
    /// requester is still served.
    #[tokio::test]
    async fn the_serving_side_rate_limits_each_requester() {
        let target = object_ref(0xB2, 3);
        let (holder, _) = serving_network(locator([(target, 9)]));
        let greedy = build_network(|router| router);
        let greedy_id = greedy.connect(holder.local_addr()).await.unwrap();
        let mut client = SuiStateMirrorClient::new(greedy.peer(greedy_id).unwrap());
        let mut replies = Vec::new();
        for _ in 0..(OBJECT_CHECKPOINT_LOOKUP_BURST_FOR_TESTS + 4) {
            replies.push(classify_reply(Ok(client
                .object_checkpoint_lookup(Request::new(ObjectCheckpointLookupRequest {
                    object_ref: target,
                }))
                .await)));
        }
        let named = replies
            .iter()
            .filter(|reply| **reply == PeerReply::Named(9))
            .count();
        assert!(
            (OBJECT_CHECKPOINT_LOOKUP_BURST_FOR_TESTS
                ..=OBJECT_CHECKPOINT_LOOKUP_BURST_FOR_TESTS + 1)
                .contains(&named),
            "the burst is served, then refused: {replies:?}"
        );
        assert_eq!(replies.last(), Some(&PeerReply::Failed));

        let other = build_network(|router| router);
        other.connect(holder.local_addr()).await.unwrap();
        let answers = MirrorCheckpointPeers::new(other).ask(target).await;
        assert_eq!(answers.candidates, vec![9], "another requester is served");
    }

    const OBJECT_CHECKPOINT_LOOKUP_BURST_FOR_TESTS: usize =
        crate::sui_state_mirror::OBJECT_CHECKPOINT_LOOKUP_PER_PEER_BURST.get() as usize;
}
