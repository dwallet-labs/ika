// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Peer-to-peer data synchronization of checkpoints.
//!
//! This StateSync module is responsible for the synchronization and dissemination of checkpoints
//! and the transactions, and their effects, contained within. This module is *not* responsible for
//! the execution of the transactions included in a checkpoint, that process is left to another
//! component in the system.
//!
//! # High-level Overview of StateSync
//!
//! StateSync discovers new checkpoints via a few different sources:
//! 1. If this node is a Validator, checkpoints will be produced via consensus at which point
//!    consensus can notify state-sync of the new checkpoint via [Handle::send_dwallet_checkpoint].
//! 2. A peer notifies us of the latest checkpoint which they have synchronized. State-Sync will
//!    also periodically query its peers to discover what their latest checkpoint is.
//!
//! We keep track of two different watermarks:
//! * highest_verified_checkpoint - This is the highest checkpoint header that we've locally
//!   verified. This indicated that we have in our persistent store (and have verified) all
//!   checkpoint headers up to and including this value.
//! * highest_synced_checkpoint - This is the highest checkpoint that we've fully synchronized,
//!   meaning we've downloaded and have in our persistent stores all of the transactions, and their
//!   effects (but not the objects), for all checkpoints up to and including this point. This is
//!   the watermark that is shared with other peers, either via notification or when they query for
//!   our latest checkpoint, and is intended to be used as a guarantee of data availability.
//!
//! The `PeerHeights` struct is used to track the highest_synced_checkpoint watermark for all of
//! our peers.
//!
//! When a new checkpoint is discovered, and we've determined that it is higher than our
//! highest_verified_checkpoint, then StateSync will kick off a task to synchronize and verify all
//! checkpoints between our highest_synced_checkpoint and the newly discovered checkpoint. This
//! process is done by querying one of our peers for the checkpoints we're missing (using the
//! `PeerHeights` struct as a way to intelligently select which peers have the data available for
//! us to query) at which point we will locally verify the signatures on the checkpoint header with
//! the appropriate committee (based on the epoch). As checkpoints are verified, the
//! highest_synced_checkpoint watermark will be ratcheted up.
//!
//! Once we've ratcheted up our highest_verified_checkpoint, and if it is higher than
//! highest_synced_checkpoint, StateSync will then kick off a task to synchronize the contents of
//! all of the checkpoints from highest_synced_checkpoint..=highest_verified_checkpoint. After the
//! contents of each checkpoint is fully downloaded, StateSync will update our
//! highest_synced_checkpoint watermark and send out a notification on a broadcast channel
//! indicating that a new checkpoint has been fully downloaded. Notifications on this broadcast
//! channel will always be made in order. StateSync will also send out a notification to its peers
//! of the newly synchronized checkpoint so that it can help other peers synchronize.

use anemo::{PeerId, Request, Response, Result, types::PeerEvent};
use futures::{FutureExt, StreamExt};
use ika_config::p2p::StateSyncConfig;
use ika_types::{
    committee::{Committee, EpochId},
    digests::DWalletCheckpointMessageDigest,
    messages_dwallet_checkpoint::{
        CertifiedDWalletCheckpointMessage, DWalletCheckpointSequenceNumber,
        VerifiedDWalletCheckpointMessage,
    },
    storage::WriteStore,
};
use rand::Rng;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tap::{Pipe, TapFallible, TapOptional};
use tokio::sync::oneshot;
use tokio::{
    sync::{broadcast, mpsc, watch},
    task::{AbortHandle, JoinSet},
};
use tracing::{debug, error, info, instrument, trace, warn};

/// Live feed of the highest checkpoint sequence numbers the chain has already
/// PROCESSED (the coordinator's / system's `last_processed_checkpoint_sequence_number`),
/// fed by the node's Sui connector. `None` until the first successful chain
/// read of a cursor.
///
/// Pull-mode state sync (notifiers/fullnodes — nodes that don't build
/// checkpoints from consensus) uses this as a sync FLOOR: checkpoints at or
/// below the cursor have already landed on Sui and are useless to a writer,
/// and on a long-lived network no peer can serve deep history anyway —
/// validators only ever hold what consensus gave them since their own last
/// (re)deploy, and there is no backfill. Without the floor, a notifier
/// deployed on a fresh database chases checkpoint 1 forever ("no peers were
/// able to help sync checkpoint 1"), synced pinned at 0 while known grows —
/// the 2026-07 epoch-close outage shape (issue #1892).
/// Ceiling on peer-pushed checkpoint bodies held per stream.
///
/// Generous relative to any legitimate backlog — sync advances sequentially,
/// so the useful entries are the ones near our current position — while
/// bounding what an unauthenticated push can pin in memory.
const MAX_UNPROCESSED_CHECKPOINTS: usize = 10_000;

#[derive(Clone)]
pub struct OnChainCheckpointCursors {
    pub dwallet: watch::Receiver<Option<DWalletCheckpointSequenceNumber>>,
    pub system: watch::Receiver<Option<SystemCheckpointSequenceNumber>>,
}

/// The committees pull-mode sync verifies peer-supplied certificates against.
///
/// A WINDOW of recent committees, not just the current one, because the
/// epoch a certificate was signed in is set by where sync starts — and sync
/// starts at the on-chain processed cursor, i.e. at whatever the notifier has
/// last landed on Sui. Every epoch that cursor trails by is an epoch whose
/// committee must still be held:
///
/// - Current only would stall sync across every boundary.
/// - Current plus previous still strands a node that BOOTS while the cursor
///   trails a boundary: the outgoing committee is only ever installed by
///   `reconfigure`, so a fresh process holds nothing to verify the tail of
///   the epoch it just missed, and sync cannot move until the next boundary
///   happens to repopulate the window — a full epoch of stall on a node whose
///   sync is the point of running it.
///
/// The window is therefore seeded from the committees the node already has on
/// disk, and advanced (not replaced) at each boundary.
#[derive(Clone, Debug)]
pub struct SyncCommittees {
    by_epoch: BTreeMap<EpochId, Arc<Committee>>,
}

impl SyncCommittees {
    /// How many recent committees the window keeps.
    ///
    /// Sized well past the case it exists for: at 24h epochs this tolerates a
    /// week of cursor lag, and a `Committee` is a validator list, so the whole
    /// window is negligible beside what sync already buffers per peer. Beyond
    /// it, verification fails closed and sync defers rather than trusting an
    /// unverifiable certificate.
    pub const WINDOW: usize = 8;

    /// Builds a window from `committees`, keeping the most recent [`Self::WINDOW`].
    pub fn new(committees: impl IntoIterator<Item = Arc<Committee>>) -> Self {
        let mut by_epoch: BTreeMap<EpochId, Arc<Committee>> = committees
            .into_iter()
            .map(|committee| (committee.epoch(), committee))
            .collect();
        while by_epoch.len() > Self::WINDOW {
            by_epoch.pop_first();
        }
        Self { by_epoch }
    }

    /// The window advanced to a new epoch, RETAINING the outgoing committees —
    /// certificates signed just before the boundary stay verifiable.
    pub fn advanced_to(&self, current: Arc<Committee>) -> Self {
        Self::new(
            self.by_epoch
                .values()
                .cloned()
                .chain(std::iter::once(current)),
        )
    }

    /// The committee that signed at `epoch`, if this node holds it.
    pub fn for_epoch(&self, epoch: EpochId) -> Option<&Committee> {
        self.by_epoch.get(&epoch).map(Arc::as_ref)
    }

    /// Epochs currently verifiable, oldest first — for diagnostics when a
    /// certificate falls outside the window.
    pub fn epochs(&self) -> impl Iterator<Item = EpochId> + '_ {
        self.by_epoch.keys().copied()
    }
}

/// Live feed of [`SyncCommittees`], fed by the node on boot and on every
/// reconfiguration.
///
/// `None` until the node has read its first committee. That window is real
/// rather than theoretical: a peer-only node builds the p2p stack *in order
/// to* read the committee over the OCS relay, so it necessarily starts with
/// nothing to check against. Sync defers while the feed is `None`; bootstrap
/// itself does not depend on pull-mode sync, so deferring costs nothing.
pub type CommitteeSource = watch::Receiver<Option<SyncCommittees>>;

mod generated {
    include!(concat!(env!("OUT_DIR"), "/ika.StateSync.rs"));
}
mod builder;
mod metrics;
mod server;

use self::{metrics::Metrics, server::CheckpointMessageDownloadLimitLayer};
pub use crate::state_sync::server::GetChainIdentifierResponse;
use crate::state_sync::server::{
    GetSystemCheckpointAvailabilityResponse, GetSystemCheckpointRequest,
    SystemCheckpointDownloadLimitLayer,
};
pub use builder::{Builder, UnstartedStateSync};
pub use generated::{
    state_sync_client::StateSyncClient,
    state_sync_server::{StateSync, StateSyncServer},
};
use ika_archival::reader::ArchiveReaderBalancer;
use ika_types::digests::{ChainIdentifier, SystemCheckpointMessageDigest};
use ika_types::messages_system_checkpoints::{
    CertifiedSystemCheckpointMessage, SystemCheckpointSequenceNumber,
    VerifiedSystemCheckpointMessage,
};
pub use server::GetCheckpointMessageRequest;
pub use server::GetDWalletCheckpointAvailabilityResponse;

/// A handle to the StateSync subsystem.
///
/// This handle can be cloned and shared. Once all copies of a StateSync system's Handle have been
/// dropped, the StateSync system will be gracefully shutdown.
#[derive(Clone, Debug)]
pub struct Handle {
    sender: mpsc::Sender<StateSyncMessage>,
    dwallet_checkpoint_event_sender: broadcast::Sender<VerifiedDWalletCheckpointMessage>,
    system_checkpoint_event_sender: broadcast::Sender<VerifiedSystemCheckpointMessage>,
}

impl Handle {
    /// Send a newly minted checkpoint from Consensus to StateSync so that it can be disseminated
    /// to other nodes on the network.
    ///
    /// # Invariant
    ///
    /// Consensus must only notify StateSync of new checkpoints that have been fully committed to
    /// persistent storage. This includes CheckpointContents and all Transactions and
    /// TransactionEffects included therein.
    pub async fn send_dwallet_checkpoint(&self, checkpoint: VerifiedDWalletCheckpointMessage) {
        self.sender
            .send(StateSyncMessage::VerifiedDWalletCheckpointMessage(
                Box::new(checkpoint),
            ))
            .await
            .unwrap()
    }

    /// Subscribe to the stream of checkpoints that have been fully synchronized and downloaded.
    pub fn subscribe_to_synced_checkpoints(
        &self,
    ) -> broadcast::Receiver<VerifiedDWalletCheckpointMessage> {
        self.dwallet_checkpoint_event_sender.subscribe()
    }

    pub async fn send_system_checkpoint(&self, system_checkpoint: VerifiedSystemCheckpointMessage) {
        self.sender
            .send(StateSyncMessage::VerifiedSystemCheckpointMessage(Box::new(
                system_checkpoint,
            )))
            .await
            .unwrap()
    }

    pub fn subscribe_to_synced_system_checkpoints(
        &self,
    ) -> broadcast::Receiver<VerifiedSystemCheckpointMessage> {
        self.system_checkpoint_event_sender.subscribe()
    }
}

struct PeerHeights {
    /// Table used to track the highest checkpoint for each of our peers.
    peers: HashMap<PeerId, PeerStateSyncInfo>,
    unprocessed_checkpoints:
        HashMap<DWalletCheckpointMessageDigest, CertifiedDWalletCheckpointMessage>,
    sequence_number_to_digest:
        HashMap<DWalletCheckpointSequenceNumber, DWalletCheckpointMessageDigest>,

    unprocessed_system_checkpoint:
        HashMap<SystemCheckpointMessageDigest, CertifiedSystemCheckpointMessage>,
    sequence_number_to_digest_system_checkpoint:
        HashMap<SystemCheckpointSequenceNumber, SystemCheckpointMessageDigest>,

    #[allow(unused)]
    // The amount of time to wait before retry if there are no peers to sync content from.
    wait_interval_when_no_peer_to_sync_content: Duration,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct PeerStateSyncInfo {
    /// The digest of the Peer's chain identifier.
    chain_identifier: ChainIdentifier,
    /// Indicates if this Peer is on the same chain as us.
    on_same_chain_as_us: bool,
    /// Highest dwallet checkpoint sequence number we know of for this Peer.
    dwallet_checkpoint_height: Option<DWalletCheckpointSequenceNumber>,
    /// Highest system checkpoint sequence number we know of for this Peer.
    system_checkpoint_height: Option<SystemCheckpointSequenceNumber>,
}

impl PeerHeights {
    pub fn highest_known_checkpoint(&self) -> Option<&CertifiedDWalletCheckpointMessage> {
        self.highest_known_checkpoint_sequence_number()
            .and_then(|s| self.sequence_number_to_digest.get(&s))
            .and_then(|digest| self.unprocessed_checkpoints.get(digest))
    }

    pub fn highest_known_checkpoint_sequence_number(
        &self,
    ) -> Option<DWalletCheckpointSequenceNumber> {
        self.peers
            .values()
            .filter_map(|info| {
                info.on_same_chain_as_us
                    .then_some(info.dwallet_checkpoint_height)
            })
            .max()?
    }

    pub fn highest_known_system_checkpoint(&self) -> Option<&CertifiedSystemCheckpointMessage> {
        self.highest_known_system_checkpoint_sequence_number()
            .and_then(|s| self.sequence_number_to_digest_system_checkpoint.get(&s))
            .and_then(|digest| self.unprocessed_system_checkpoint.get(digest))
    }

    pub fn highest_known_system_checkpoint_sequence_number(
        &self,
    ) -> Option<DWalletCheckpointSequenceNumber> {
        self.peers
            .values()
            .filter_map(|info| {
                info.on_same_chain_as_us
                    .then_some(info.system_checkpoint_height)
            })
            .max()?
    }

    pub fn peers_on_same_chain(&self) -> impl Iterator<Item = (&PeerId, &PeerStateSyncInfo)> {
        self.peers
            .iter()
            .filter(|(_peer_id, info)| info.on_same_chain_as_us)
    }

    // Returns a bool that indicates if the update was done successfully.
    //
    // This will return false if the given peer doesn't have an entry or is not on the same chain
    // as us
    #[instrument(level = "debug", skip_all, fields(peer_id=?peer_id, checkpoint=?checkpoint.sequence_number()))]
    pub fn update_peer_info(
        &mut self,
        peer_id: PeerId,
        checkpoint: CertifiedDWalletCheckpointMessage,
    ) -> bool {
        debug!("Update peer info");

        let info = match self.peers.get_mut(&peer_id) {
            Some(info) if info.on_same_chain_as_us => info,
            _ => return false,
        };

        info.dwallet_checkpoint_height = std::cmp::max(
            Some(*checkpoint.sequence_number()),
            info.dwallet_checkpoint_height,
        );
        self.insert_checkpoint(checkpoint);

        true
    }

    pub fn update_peer_info_with_system_checkpoint(
        &mut self,
        peer_id: PeerId,
        system_checkpoint: CertifiedSystemCheckpointMessage,
    ) -> bool {
        debug!("Update peer info with params message");

        let info = match self.peers.get_mut(&peer_id) {
            Some(info) if info.on_same_chain_as_us => info,
            _ => return false,
        };

        info.system_checkpoint_height = std::cmp::max(
            Some(*system_checkpoint.sequence_number()),
            info.system_checkpoint_height,
        );
        self.insert_system_checkpoint(system_checkpoint);

        true
    }

    #[instrument(level = "debug", skip_all, fields(peer_id=?peer_id,
        dwallet_checkpoint_height = ?info.dwallet_checkpoint_height,
        system_checkpoint_height = ?info.system_checkpoint_height))
    ]
    pub fn insert_peer_info(&mut self, peer_id: PeerId, info: PeerStateSyncInfo) {
        use std::collections::hash_map::Entry;
        debug!("Insert peer info");

        match self.peers.entry(peer_id) {
            Entry::Occupied(mut entry) => {
                // If there's already an entry and the genesis checkpoint digests match then update
                // the maximum height. Otherwise we'll use the more recent one
                let entry = entry.get_mut();
                if entry.chain_identifier == info.chain_identifier {
                    entry.dwallet_checkpoint_height = std::cmp::max(
                        entry.dwallet_checkpoint_height,
                        info.dwallet_checkpoint_height,
                    );
                    entry.system_checkpoint_height = std::cmp::max(
                        entry.system_checkpoint_height,
                        info.system_checkpoint_height,
                    );
                } else {
                    *entry = info;
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(info);
            }
        }
    }

    #[allow(unused)]
    pub fn mark_peer_as_not_on_same_chain(&mut self, peer_id: PeerId) {
        if let Some(info) = self.peers.get_mut(&peer_id) {
            info.on_same_chain_as_us = false;
        }
    }

    pub fn cleanup_old_checkpoints(&mut self, sequence_number: DWalletCheckpointSequenceNumber) {
        self.unprocessed_checkpoints
            .retain(|_digest, checkpoint| *checkpoint.sequence_number() > sequence_number);
        self.sequence_number_to_digest
            .retain(|&s, _digest| s > sequence_number);
    }

    // TODO: also record who gives this checkpoint info for peer quality measurement?
    pub fn insert_checkpoint(&mut self, checkpoint: CertifiedDWalletCheckpointMessage) {
        let digest = *checkpoint.digest();
        let sequence_number = *checkpoint.sequence_number();
        self.unprocessed_checkpoints.insert(digest, checkpoint);
        Self::displace_previous_body(
            &mut self.unprocessed_checkpoints,
            &mut self.sequence_number_to_digest,
            sequence_number,
            digest,
        );
        Self::evict_beyond(
            &mut self.unprocessed_checkpoints,
            &mut self.sequence_number_to_digest,
        );
    }

    /// Points `sequence_number` at `digest`, dropping the body it displaces.
    ///
    /// Without this the two maps drift apart and the ceiling below counts the
    /// wrong thing. Bodies are keyed by DIGEST and the index by SEQUENCE, and
    /// the push RPC verifies no signature — the only gate is that the sender
    /// is a registered same-chain peer. So one peer can push many bodies that
    /// all claim a single far-ahead sequence number with distinct digests:
    /// each adds a body while merely overwriting the same index key, leaving
    /// the counted map at one entry while the bodies grow without limit.
    ///
    /// Keeping only the newest body per sequence is safe: two valid
    /// certificates for one sequence would mean the committee equivocated,
    /// and the fetch path re-checks against pinned digests regardless.
    fn displace_previous_body<D, S, T>(
        bodies: &mut HashMap<D, T>,
        by_sequence: &mut HashMap<S, D>,
        sequence_number: S,
        digest: D,
    ) where
        D: Copy + Eq + std::hash::Hash,
        S: Copy + Eq + std::hash::Hash,
    {
        if let Some(previous) = by_sequence.insert(sequence_number, digest)
            && previous != digest
        {
            bodies.remove(&previous);
        }
    }

    /// Bounds the stored bodies by dropping the FURTHEST-ahead entries.
    ///
    /// These maps are fed directly by an unauthenticated push RPC whose rate
    /// limit defaults to `None`, and are pruned only by
    /// `cleanup_old_checkpoints`, which removes entries at or below a synced
    /// target — so entries far ahead of us are never reached by that pruning
    /// and accumulate without limit.
    ///
    /// Evicting from the top is deliberate: sync advances upward from where we
    /// are, so the entries closest to our position are the useful ones, and a
    /// peer pushing an implausibly high sequence number is exactly the case
    /// worth discarding. A peer's reported HEIGHT is kept regardless — that is
    /// one `u64`, it is what tells us how far behind we are, and bounding it
    /// would blind the sync target.
    fn evict_beyond<D, S, T>(bodies: &mut HashMap<D, T>, by_sequence: &mut HashMap<S, D>)
    where
        D: Copy + Eq + std::hash::Hash,
        S: Copy + Ord + std::hash::Hash,
    {
        while by_sequence.len() > MAX_UNPROCESSED_CHECKPOINTS {
            let Some(highest) = by_sequence.keys().copied().max() else {
                break;
            };
            if let Some(digest) = by_sequence.remove(&highest) {
                bodies.remove(&digest);
            }
        }
    }

    #[allow(unused)]
    pub fn remove_checkpoint(&mut self, digest: &DWalletCheckpointMessageDigest) {
        if let Some(checkpoint) = self.unprocessed_checkpoints.remove(digest) {
            self.sequence_number_to_digest
                .remove(checkpoint.sequence_number());
        }
    }

    pub fn get_dwallet_checkpoint_by_sequence_number(
        &self,
        sequence_number: DWalletCheckpointSequenceNumber,
    ) -> Option<&CertifiedDWalletCheckpointMessage> {
        self.sequence_number_to_digest
            .get(&sequence_number)
            .and_then(|digest| self.get_dwallet_checkpoint_by_digest(digest))
    }

    pub fn get_dwallet_checkpoint_by_digest(
        &self,
        digest: &DWalletCheckpointMessageDigest,
    ) -> Option<&CertifiedDWalletCheckpointMessage> {
        self.unprocessed_checkpoints.get(digest)
    }

    pub fn cleanup_old_system_checkpoints(
        &mut self,
        sequence_number: SystemCheckpointSequenceNumber,
    ) {
        self.unprocessed_system_checkpoint
            .retain(|_digest, system_checkpoint| {
                *system_checkpoint.sequence_number() > sequence_number
            });
        self.sequence_number_to_digest_system_checkpoint
            .retain(|&s, _digest| s > sequence_number);
    }

    // TODO: also record who gives this system_checkpoint info for peer quality measurement?
    pub fn insert_system_checkpoint(
        &mut self,
        system_checkpoint: CertifiedSystemCheckpointMessage,
    ) {
        let digest = *system_checkpoint.digest();
        let sequence_number = *system_checkpoint.sequence_number();
        self.unprocessed_system_checkpoint
            .insert(digest, system_checkpoint);
        Self::displace_previous_body(
            &mut self.unprocessed_system_checkpoint,
            &mut self.sequence_number_to_digest_system_checkpoint,
            sequence_number,
            digest,
        );
        Self::evict_beyond(
            &mut self.unprocessed_system_checkpoint,
            &mut self.sequence_number_to_digest_system_checkpoint,
        );
    }

    #[allow(unused)]
    pub fn remove_system_checkpoint(&mut self, digest: &SystemCheckpointMessageDigest) {
        if let Some(system_checkpoint) = self.unprocessed_system_checkpoint.remove(digest) {
            self.sequence_number_to_digest_system_checkpoint
                .remove(system_checkpoint.sequence_number());
        }
    }

    pub fn get_system_checkpoint_by_sequence_number(
        &self,
        sequence_number: SystemCheckpointSequenceNumber,
    ) -> Option<&CertifiedSystemCheckpointMessage> {
        self.sequence_number_to_digest_system_checkpoint
            .get(&sequence_number)
            .and_then(|digest| self.get_system_checkpoint_by_digest(digest))
    }

    pub fn get_system_checkpoint_by_digest(
        &self,
        digest: &SystemCheckpointMessageDigest,
    ) -> Option<&CertifiedSystemCheckpointMessage> {
        self.unprocessed_system_checkpoint.get(digest)
    }

    #[allow(unused)]
    pub fn wait_interval_when_no_peer_to_sync_content(&self) -> Duration {
        self.wait_interval_when_no_peer_to_sync_content
    }
}

// PeerBalancer is an Iterator that selects peers based on RTT with some added randomness.
#[derive(Clone)]
struct PeerBalancer {
    peers: VecDeque<(anemo::Peer, PeerStateSyncInfo)>,
    requested_dwallet_checkpoint: Option<DWalletCheckpointSequenceNumber>,
    requested_system_checkpoint: Option<SystemCheckpointSequenceNumber>,
}

impl PeerBalancer {
    pub fn new(network: &anemo::Network, peer_heights: Arc<RwLock<PeerHeights>>) -> Self {
        let mut peers: Vec<_> = peer_heights
            .read()
            .unwrap()
            .peers_on_same_chain()
            // Filter out any peers who we aren't connected with.
            .filter_map(|(peer_id, info)| {
                network
                    .peer(*peer_id)
                    .map(|peer| (peer.connection_rtt(), peer, *info))
            })
            .collect();
        peers.sort_by_key(|(rtt_a, _, _)| *rtt_a);
        Self {
            peers: peers
                .into_iter()
                .map(|(_, peer, info)| (peer, info))
                .collect(),
            requested_dwallet_checkpoint: None,
            requested_system_checkpoint: None,
        }
    }

    pub fn with_checkpoint(mut self, checkpoint: DWalletCheckpointSequenceNumber) -> Self {
        self.requested_dwallet_checkpoint = Some(checkpoint);
        self
    }

    pub fn with_system_checkpoint(
        mut self,
        system_checkpoint: SystemCheckpointSequenceNumber,
    ) -> Self {
        self.requested_system_checkpoint = Some(system_checkpoint);
        self
    }
}

impl Iterator for PeerBalancer {
    type Item = StateSyncClient<anemo::Peer>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.peers.is_empty() {
            const SELECTION_WINDOW: usize = 2;
            let idx =
                rand::thread_rng().gen_range(0..std::cmp::min(SELECTION_WINDOW, self.peers.len()));
            let (peer, info) = self.peers.remove(idx).unwrap();
            let requested_checkpoint = self.requested_dwallet_checkpoint.unwrap_or(1);
            let requested_system_checkpoint = self.requested_system_checkpoint.unwrap_or(1);
            if info.dwallet_checkpoint_height >= Some(requested_checkpoint)
                || info.system_checkpoint_height >= Some(requested_system_checkpoint)
            {
                return Some(StateSyncClient::new(peer));
            }
        }
        None
    }
}

#[allow(unused)]
#[derive(Clone, Debug)]
enum StateSyncMessage {
    StartSyncJob,
    // Validators will send this to the StateSyncEventLoop in order to kick off notifying our peers
    // of the new checkpoint.
    VerifiedDWalletCheckpointMessage(Box<VerifiedDWalletCheckpointMessage>),
    // Notification that the checkpoint content sync task will send to the event loop in the event
    // it was able to successfully sync a checkpoint's contents. If multiple checkpoints were
    // synced at the same time, only the highest checkpoint is sent.
    SyncedDWalletCheckpoint(Box<VerifiedDWalletCheckpointMessage>),

    VerifiedSystemCheckpointMessage(Box<VerifiedSystemCheckpointMessage>),

    SyncedSystemCheckpoint(Box<VerifiedSystemCheckpointMessage>),
}

struct StateSyncEventLoop<S> {
    is_notifier: bool,
    config: StateSyncConfig,

    mailbox: mpsc::Receiver<StateSyncMessage>,
    /// Weak reference to our own mailbox
    weak_sender: mpsc::WeakSender<StateSyncMessage>,

    tasks: JoinSet<()>,
    sync_checkpoint_messages_task: Option<AbortHandle>,
    download_limit_layer: Option<CheckpointMessageDownloadLimitLayer>,

    store: S,
    peer_heights: Arc<RwLock<PeerHeights>>,
    checkpoint_event_sender: broadcast::Sender<VerifiedDWalletCheckpointMessage>,
    network: anemo::Network,
    metrics: Metrics,

    archive_readers: ArchiveReaderBalancer,
    sync_checkpoint_from_archive_task: Option<AbortHandle>,
    chain_identifier: ChainIdentifier,

    system_checkpoint_event_sender: broadcast::Sender<VerifiedSystemCheckpointMessage>,
    sync_system_checkpoints_task: Option<AbortHandle>,
    system_checkpoint_download_limit_layer: Option<SystemCheckpointDownloadLimitLayer>,
    sync_system_checkpoint_from_archive_task: Option<AbortHandle>,
    on_chain_cursors: Option<OnChainCheckpointCursors>,
    committees: CommitteeSource,
}

impl<S> StateSyncEventLoop<S>
where
    S: WriteStore + Clone + Send + Sync + 'static,
{
    // Note: A great deal of care is taken to ensure that all event handlers are non-asynchronous
    // and that the only "await" points are from the select macro picking which event to handle.
    // This ensures that the event loop is able to process events at a high speed and reduce the
    // chance for building up a backlog of events to process.
    pub async fn start(mut self) {
        info!("State-Synchronizer started");

        self.config.pinned_dwallet_checkpoints.sort();
        self.config.pinned_system_checkpoints.sort();

        let mut interval = tokio::time::interval(self.config.interval_period());
        let mut peer_events = {
            let (subscriber, peers) = self.network.subscribe().unwrap();
            for peer_id in peers {
                self.spawn_get_latest_from_peer(peer_id);
            }
            subscriber
        };

        // Spawn tokio task to update metrics periodically in the background
        let (_sender, receiver) = oneshot::channel();
        tokio::spawn(update_checkpoint_watermark_metrics(
            receiver,
            self.store.clone(),
            self.peer_heights.clone(),
            self.metrics.clone(),
        ));

        let (_sender, receiver) = oneshot::channel();
        tokio::spawn(update_system_checkpoint_watermark_metrics(
            receiver,
            self.store.clone(),
            self.peer_heights.clone(),
            self.metrics.clone(),
        ));

        // Start archive based checkpoint content sync loop.
        // TODO: Consider switching to sync from archive only on startup.
        // Right now because the peer set is fixed at startup, a node may eventually
        // end up with peers who have all purged their local state. In such a scenario it will be
        // stuck until restart when it ends up with a different set of peers. Once the discovery
        // mechanism can dynamically identify and connect to other peers on the network, we will rely
        // on sync from archive as a fall back.
        let task =
            sync_checkpoint_messages_from_archive(self.archive_readers.clone(), self.store.clone());
        let task_handle = self.tasks.spawn(task);
        self.sync_checkpoint_from_archive_task = Some(task_handle);

        let task = sync_system_checkpoint_messages_from_archive(
            self.archive_readers.clone(),
            self.store.clone(),
        );
        let task_handle = self.tasks.spawn(task);
        self.sync_system_checkpoint_from_archive_task = Some(task_handle);

        // Start main loop.
        loop {
            tokio::select! {
                now = interval.tick() => {
                    self.handle_tick(now.into_std());
                },
                maybe_message = self.mailbox.recv() => {
                    // Once all handles to our mailbox have been dropped this
                    // will yield `None` and we can terminate the event loop
                    if let Some(message) = maybe_message {
                        self.handle_message(message);
                    } else {
                        break;
                    }
                },
                peer_event = peer_events.recv() => {
                    self.handle_peer_event(peer_event);
                },
                Some(task_result) = self.tasks.join_next() => {
                    match task_result {
                        Ok(()) => {},
                        Err(e) => {
                            if e.is_cancelled() {
                                // avoid crashing on ungraceful shutdown
                            } else if e.is_panic() {
                                // propagate panics.
                                std::panic::resume_unwind(e.into_panic());
                            } else {
                                panic!("task failed: {e}");
                            }
                        },
                    };

                    if matches!(&self.sync_checkpoint_messages_task, Some(t) if t.is_finished()) {
                        self.sync_checkpoint_messages_task = None;
                    }

                    if matches!(&self.sync_checkpoint_from_archive_task, Some(t) if t.is_finished()) {
                        panic!("sync_checkpoint_from_archive task unexpectedly terminated")
                    }

                    if matches!(&self.sync_system_checkpoints_task, Some(t) if t.is_finished()) {
                        self.sync_system_checkpoints_task = None;
                    }

                    if matches!(&self.sync_system_checkpoint_from_archive_task, Some(t) if t.is_finished()) {
                        panic!("sync_system_checkpoint_from_archive task unexpectedly terminated")
                    }
                },
            }

            if self.is_notifier {
                self.maybe_start_system_checkpoint_summary_sync_task();
                self.maybe_start_checkpoint_summary_sync_task();
            }
        }

        info!("State-Synchronizer ended");
    }

    fn handle_message(&mut self, message: StateSyncMessage) {
        debug!("Received message: {:?}", message);
        match message {
            StateSyncMessage::StartSyncJob => {
                if self.is_notifier {
                    self.maybe_start_checkpoint_summary_sync_task();
                    self.maybe_start_system_checkpoint_summary_sync_task();
                }
            }
            StateSyncMessage::VerifiedDWalletCheckpointMessage(checkpoint) => {
                self.handle_dwallet_checkpoint_from_consensus(checkpoint)
            }
            // After we've successfully synced a checkpoint we can notify our peers
            StateSyncMessage::SyncedDWalletCheckpoint(checkpoint) => {
                self.spawn_notify_peers_of_checkpoint(*checkpoint)
            }
            StateSyncMessage::VerifiedSystemCheckpointMessage(msg) => {
                self.handle_system_checkpoint_from_consensus(msg)
            }
            StateSyncMessage::SyncedSystemCheckpoint(msg) => {
                self.spawn_notify_peers_of_system_checkpoint(*msg)
            }
        }
    }

    // Handle a checkpoint that we received from consensus
    #[instrument(level = "debug", skip_all)]
    fn handle_dwallet_checkpoint_from_consensus(
        &mut self,
        checkpoint: Box<VerifiedDWalletCheckpointMessage>,
    ) {
        let latest_checkpoint_sequence_number = self
            .store
            .get_highest_verified_dwallet_checkpoint()
            .expect("store operation should not fail")
            .map(|checkpoint| *checkpoint.sequence_number());

        // If this is an older checkpoint, just ignore it
        if latest_checkpoint_sequence_number.as_ref() >= Some(checkpoint.sequence_number()) {
            return;
        }

        let checkpoint = *checkpoint;
        let next_sequence_number = latest_checkpoint_sequence_number
            .map(|s| s.checked_add(1).expect("exhausted u64"))
            .unwrap_or(1);
        if *checkpoint.sequence_number() > next_sequence_number {
            debug!(
                "consensus sent too new of a checkpoint, expecting: {}, got: {}",
                next_sequence_number,
                checkpoint.sequence_number()
            );
        }

        self.store
            .update_highest_verified_dwallet_checkpoint(&checkpoint)
            .expect("store operation should not fail");
        self.store
            .update_highest_synced_dwallet_checkpoint(&checkpoint)
            .expect("store operation should not fail");

        // We don't care if no one is listening as this is a broadcast channel
        let _ = self.checkpoint_event_sender.send(checkpoint.clone());

        self.spawn_notify_peers_of_checkpoint(checkpoint);
    }

    #[instrument(level = "debug", skip_all)]
    fn handle_system_checkpoint_from_consensus(
        &mut self,
        system_checkpoint: Box<VerifiedSystemCheckpointMessage>,
    ) {
        let latest_system_checkpoint_sequence_number = self
            .store
            .get_highest_verified_system_checkpoint()
            .expect("store operation should not fail")
            .map(|system_checkpoint| *system_checkpoint.sequence_number());

        // If this is an older system_checkpoint, ignore it.
        if latest_system_checkpoint_sequence_number >= Some(*system_checkpoint.sequence_number()) {
            return;
        }

        let system_checkpoint = *system_checkpoint;
        let next_sequence_number = latest_system_checkpoint_sequence_number
            .map(|s| s.checked_add(1).expect("exhausted u64"))
            .unwrap_or(1);
        if *system_checkpoint.sequence_number() > next_sequence_number {
            debug!(
                "consensus sent too new of a system_checkpoint, expecting: {}, got: {}",
                next_sequence_number,
                system_checkpoint.sequence_number()
            );
        }

        self.store
            .update_highest_verified_system_checkpoint(&system_checkpoint)
            .expect("store operation should not fail");
        self.store
            .update_highest_synced_system_checkpoint(&system_checkpoint)
            .expect("store operation should not fail");

        // We don't care if no one is listening as this is a broadcast channel
        let _ = self
            .system_checkpoint_event_sender
            .send(system_checkpoint.clone());

        self.spawn_notify_peers_of_system_checkpoint(system_checkpoint);
    }

    fn handle_peer_event(&mut self, peer_event: Result<PeerEvent, broadcast::error::RecvError>) {
        use tokio::sync::broadcast::error::RecvError;

        match peer_event {
            Ok(PeerEvent::NewPeer(peer_id)) => {
                if self.is_notifier {
                    self.spawn_get_latest_from_peer(peer_id);
                }
            }
            Ok(PeerEvent::LostPeer(peer_id, _)) => {
                self.peer_heights.write().unwrap().peers.remove(&peer_id);
            }

            Err(RecvError::Closed) => {
                panic!("PeerEvent channel shouldn't be able to be closed");
            }

            Err(RecvError::Lagged(_)) => {
                trace!("State-Sync fell behind processing PeerEvents");
            }
        }
    }

    fn spawn_get_latest_from_peer(&mut self, peer_id: PeerId) {
        if let Some(peer) = self.network.peer(peer_id) {
            let task = get_latest_from_peer(
                self.chain_identifier,
                peer.clone(),
                self.peer_heights.clone(),
                self.config.timeout(),
            );
            self.tasks.spawn(task);

            let task = get_latest_from_peer_system_checkpoint(
                self.chain_identifier,
                peer,
                self.peer_heights.clone(),
                self.config.timeout(),
            );
            self.tasks.spawn(task);
        }
    }

    fn handle_tick(&mut self, _now: std::time::Instant) {
        let task = query_peers_for_their_latest_checkpoint(
            self.network.clone(),
            self.peer_heights.clone(),
            self.weak_sender.clone(),
            self.config.timeout(),
        );
        self.tasks.spawn(task);

        if let Some(layer) = self.download_limit_layer.as_ref() {
            layer.maybe_prune_map();
        }

        let task = query_peers_for_their_latest_system_checkpoint(
            self.network.clone(),
            self.peer_heights.clone(),
            self.weak_sender.clone(),
            self.config.timeout(),
        );
        self.tasks.spawn(task);

        if let Some(layer) = self.system_checkpoint_download_limit_layer.as_ref() {
            layer.maybe_prune_map();
        }
    }

    fn maybe_start_checkpoint_summary_sync_task(&mut self) {
        // Only run one sync task at a time
        if self.sync_checkpoint_messages_task.is_some() {
            return;
        }

        let highest_processed_checkpoint = self
            .store
            .get_highest_verified_dwallet_checkpoint()
            .expect("store operation should not fail");

        let highest_known_checkpoint = self
            .peer_heights
            .read()
            .unwrap()
            .highest_known_checkpoint()
            .cloned();

        // Sync floor from the chain: checkpoints at or below the on-chain
        // processed cursor are useless to a pull-mode node (they already
        // landed on Sui), and on a long-lived network no peer can serve deep
        // history anyway. With a cursor feed configured but no reading yet
        // and an EMPTY local store, defer the first sync job until the
        // cursor is known — otherwise it would chase full history from
        // sequence 1 and wedge forever on unfetchable checkpoints (issue
        // #1892's notifier cold-start stall). At genesis the first read
        // yields Some(0) quickly, so a brand-new network is never blocked.
        let on_chain_cursor = match &self.on_chain_cursors {
            Some(cursors) => {
                let cursor = *cursors.dwallet.borrow();
                if cursor.is_none() && highest_processed_checkpoint.is_none() {
                    debug!(
                        "deferring dwallet checkpoint sync from an empty store until the \
                         on-chain processed cursor is known"
                    );
                    return;
                }
                cursor.unwrap_or(0)
            }
            None => 0,
        };

        if highest_processed_checkpoint
            .as_ref()
            .map(|x| x.sequence_number())
            < highest_known_checkpoint
                .as_ref()
                .map(|x| x.sequence_number())
        {
            debug!(
                local_highest = ?highest_processed_checkpoint.as_ref().map(|x| x.sequence_number()),
                target = ?highest_known_checkpoint.as_ref().map(|x| x.sequence_number()),
                on_chain_cursor,
                "starting dwallet checkpoint sync job"
            );
            // Start a sync job.
            let task = sync_to_checkpoint(
                self.network.clone(),
                self.store.clone(),
                self.peer_heights.clone(),
                self.metrics.clone(),
                self.config.pinned_dwallet_checkpoints.clone(),
                self.config.dwallet_checkpoint_header_download_concurrency(),
                self.config.timeout(),
                on_chain_cursor,
                self.committees.clone(),
                // The if condition should ensure that this is Some
                highest_known_checkpoint.unwrap(),
            )
            .map(|result| match result {
                Ok(()) => {}
                Err(e) => {
                    debug!("error syncing checkpoint {e}");
                }
            });
            let task_handle = self.tasks.spawn(task);
            self.sync_checkpoint_messages_task = Some(task_handle);
        }
    }

    fn maybe_start_system_checkpoint_summary_sync_task(&mut self) {
        // Only run one sync task at a time
        if self.sync_system_checkpoints_task.is_some() {
            return;
        }

        let highest_processed_system_checkpoint = self
            .store
            .get_highest_verified_system_checkpoint()
            .expect("store operation should not fail");

        let highest_known_system_checkpoint = self
            .peer_heights
            .read()
            .unwrap()
            .highest_known_system_checkpoint()
            .cloned();

        // Same floor/deferral logic as the dwallet stream — see
        // `maybe_start_checkpoint_summary_sync_task`.
        let on_chain_cursor = match &self.on_chain_cursors {
            Some(cursors) => {
                let cursor = *cursors.system.borrow();
                if cursor.is_none() && highest_processed_system_checkpoint.is_none() {
                    debug!(
                        "deferring system checkpoint sync from an empty store until the \
                         on-chain processed cursor is known"
                    );
                    return;
                }
                cursor.unwrap_or(0)
            }
            None => 0,
        };

        if highest_processed_system_checkpoint
            .as_ref()
            .map(|x| x.sequence_number())
            < highest_known_system_checkpoint
                .as_ref()
                .map(|x| x.sequence_number())
        {
            // start sync job
            let task = sync_to_system_checkpoint(
                self.network.clone(),
                self.store.clone(),
                self.peer_heights.clone(),
                self.metrics.clone(),
                self.config.pinned_system_checkpoints.clone(),
                self.config.system_checkpoint_header_download_concurrency(),
                self.config.timeout(),
                on_chain_cursor,
                self.committees.clone(),
                // The if condition should ensure that this is Some
                highest_known_system_checkpoint.unwrap(),
            )
            .map(|result| match result {
                Ok(()) => {}
                Err(e) => {
                    debug!("error syncing system_checkpoint {e}");
                }
            });
            let task_handle = self.tasks.spawn(task);
            self.sync_system_checkpoints_task = Some(task_handle);
        }
    }

    fn spawn_notify_peers_of_checkpoint(&mut self, checkpoint: VerifiedDWalletCheckpointMessage) {
        let task = notify_peers_of_checkpoint(
            self.network.clone(),
            self.peer_heights.clone(),
            checkpoint,
            self.config.timeout(),
        );
        self.tasks.spawn(task);
    }

    fn spawn_notify_peers_of_system_checkpoint(
        &mut self,
        system_checkpoint: VerifiedSystemCheckpointMessage,
    ) {
        let task = notify_peers_of_system_checkpoint(
            self.network.clone(),
            self.peer_heights.clone(),
            system_checkpoint,
            self.config.timeout(),
        );
        self.tasks.spawn(task);
    }
}

async fn notify_peers_of_checkpoint(
    network: anemo::Network,
    peer_heights: Arc<RwLock<PeerHeights>>,
    checkpoint: VerifiedDWalletCheckpointMessage,
    timeout: Duration,
) {
    let futs = peer_heights
        .read()
        .unwrap()
        .peers_on_same_chain()
        // Filter out any peers who we aren't connected with
        .flat_map(|(peer_id, _)| network.peer(*peer_id))
        .map(StateSyncClient::new)
        .map(|mut client| {
            let request = Request::new(checkpoint.inner().clone()).with_timeout(timeout);
            async move { client.push_dwallet_checkpoint_message(request).await }
        })
        .collect::<Vec<_>>();
    futures::future::join_all(futs).await;
}

async fn notify_peers_of_system_checkpoint(
    network: anemo::Network,
    peer_heights: Arc<RwLock<PeerHeights>>,
    system_checkpoint: VerifiedSystemCheckpointMessage,
    timeout: Duration,
) {
    let futs = peer_heights
        .read()
        .unwrap()
        .peers_on_same_chain()
        // Filter out any peers who we aren't connected with
        .flat_map(|(peer_id, _)| network.peer(*peer_id))
        .map(StateSyncClient::new)
        .map(|mut client| {
            let request = Request::new(system_checkpoint.inner().clone()).with_timeout(timeout);
            async move { client.push_system_checkpoint(request).await }
        })
        .collect::<Vec<_>>();
    futures::future::join_all(futs).await;
}

async fn get_latest_from_peer(
    our_chain_identifier: ChainIdentifier,
    peer: anemo::Peer,
    peer_heights: Arc<RwLock<PeerHeights>>,
    timeout: Duration,
) {
    let peer_id = peer.peer_id();
    let mut client = StateSyncClient::new(peer);

    let info = {
        let maybe_info = peer_heights.read().unwrap().peers.get(&peer_id).copied();

        if let Some(info) = maybe_info {
            info
        } else {
            let request = Request::new(()).with_timeout(timeout);
            let response = client
                .get_chain_identifier(request)
                .await
                .map(Response::into_inner);

            let info = match response {
                Ok(GetChainIdentifierResponse { chain_identifier }) => PeerStateSyncInfo {
                    chain_identifier,
                    on_same_chain_as_us: our_chain_identifier == chain_identifier,
                    dwallet_checkpoint_height: None,
                    system_checkpoint_height: None,
                },
                Err(status) => {
                    trace!("get_chain_identifier request failed: {status:?}");
                    return;
                }
            };
            peer_heights
                .write()
                .unwrap()
                .insert_peer_info(peer_id, info);
            info
        }
    };

    // Bail early if this node isn't on the same chain as us
    if !info.on_same_chain_as_us {
        info!(?info, "Peer {peer_id} not on same chain as us");
        return;
    }
    let Some(highest_checkpoint) = query_peer_for_latest_info(&mut client, timeout).await else {
        return;
    };
    peer_heights
        .write()
        .unwrap()
        .update_peer_info(peer_id, highest_checkpoint);
}

/// Queries a peer for their highest_synced_checkpoint and low checkpoint watermark
async fn query_peer_for_latest_info(
    client: &mut StateSyncClient<anemo::Peer>,
    timeout: Duration,
) -> Option<CertifiedDWalletCheckpointMessage> {
    let request = Request::new(()).with_timeout(timeout);
    let response = client
        .get_dwallet_checkpoint_availability(request)
        .await
        .map(Response::into_inner);
    match response {
        Ok(GetDWalletCheckpointAvailabilityResponse {
            highest_synced_checkpoint,
        }) => highest_synced_checkpoint,
        Err(status) => {
            trace!("get_dwallet_checkpoint_availability request failed: {status:?}");
            None
        }
    }
}

#[instrument(level = "debug", skip_all)]
async fn query_peers_for_their_latest_checkpoint(
    network: anemo::Network,
    peer_heights: Arc<RwLock<PeerHeights>>,
    sender: mpsc::WeakSender<StateSyncMessage>,
    timeout: Duration,
) {
    let peer_heights = &peer_heights;
    let futs = peer_heights
        .read()
        .unwrap()
        .peers_on_same_chain()
        // Filter out any peers who we aren't connected with
        .flat_map(|(peer_id, _info)| network.peer(*peer_id))
        .map(|peer| {
            let peer_id = peer.peer_id();
            let mut client = StateSyncClient::new(peer);

            async move {
                let response = query_peer_for_latest_info(&mut client, timeout).await;
                match response {
                    Some(highest_checkpoint) => peer_heights
                        .write()
                        .unwrap()
                        .update_peer_info(peer_id, highest_checkpoint.clone())
                        .then_some(highest_checkpoint),
                    None => None,
                }
            }
        })
        .collect::<Vec<_>>();

    debug!("Query {} peers for latest checkpoint", futs.len());

    let checkpoints = futures::future::join_all(futs).await.into_iter().flatten();

    let highest_checkpoint = checkpoints.max_by_key(|checkpoint| *checkpoint.sequence_number());

    let our_highest_checkpoint = peer_heights
        .read()
        .unwrap()
        .highest_known_checkpoint()
        .cloned();

    debug!(
        "Our highest checkpoint {:?}, peers highest checkpoint {:?}",
        our_highest_checkpoint.as_ref().map(|c| c.sequence_number()),
        highest_checkpoint.as_ref().map(|c| c.sequence_number())
    );

    let _new_checkpoint = match (highest_checkpoint, our_highest_checkpoint) {
        (Some(theirs), None) => theirs,
        (Some(theirs), Some(ours)) if theirs.sequence_number() > ours.sequence_number() => theirs,
        _ => return,
    };

    if let Some(sender) = sender.upgrade() {
        let _ = sender.send(StateSyncMessage::StartSyncJob).await;
    }
}

async fn sync_to_checkpoint<S>(
    network: anemo::Network,
    store: S,
    peer_heights: Arc<RwLock<PeerHeights>>,
    metrics: Metrics,
    pinned_checkpoints: Vec<(
        DWalletCheckpointSequenceNumber,
        DWalletCheckpointMessageDigest,
    )>,
    checkpoint_header_download_concurrency: usize,
    timeout: Duration,
    on_chain_processed_cursor: DWalletCheckpointSequenceNumber,
    committees: CommitteeSource,
    checkpoint: CertifiedDWalletCheckpointMessage,
) -> Result<()>
where
    S: WriteStore,
{
    metrics.set_highest_known_dwallet_checkpoint(*checkpoint.sequence_number());

    let current = store
        .get_highest_verified_dwallet_checkpoint()
        .expect("store operation should not fail");
    let current_sequence_number = current.as_ref().map(|c| c.sequence_number);
    if current_sequence_number.as_ref() >= Some(checkpoint.sequence_number()) {
        return Err(anyhow::anyhow!(
            "target checkpoint {} is older than highest verified checkpoint {:?}",
            checkpoint.sequence_number(),
            current_sequence_number,
        ));
    }

    // Start from the on-chain processed cursor when it is ahead of the local
    // store: everything at or below it already landed on Sui (useless to a
    // writer), and on a long-lived network no peer can serve deep history —
    // without this floor a fresh/lagging store chases checkpoint 1 forever
    // ("no peers were able to help sync checkpoint 1"; issue #1892).
    let local_next_sequence_number = current_sequence_number
        .map(|s| s.checked_add(1).expect("exhausted u64"))
        .unwrap_or(1);
    let start_sequence_number = local_next_sequence_number.max(
        on_chain_processed_cursor
            .checked_add(1)
            .expect("exhausted u64"),
    );
    if start_sequence_number > *checkpoint.sequence_number() {
        // Everything peers advertise has already been processed on Sui.
        return Ok(());
    }
    if start_sequence_number > local_next_sequence_number {
        info!(
            local_next_sequence_number,
            on_chain_processed_cursor,
            start_sequence_number,
            "starting dwallet checkpoint sync from the on-chain processed cursor; \
             older checkpoints already landed on Sui and are skipped (peers on a \
             long-lived network cannot serve deep history)",
        );
    }
    let mut expected_sequence_number = start_sequence_number;

    let peer_balancer = PeerBalancer::new(&network, peer_heights.clone());
    // range of the next sequence_numbers to fetch
    let mut request_stream = (start_sequence_number
        ..=*checkpoint.sequence_number())
        .map(|next| {
            let peers = peer_balancer.clone().with_checkpoint(next);
            let peer_heights = peer_heights.clone();
            let pinned_checkpoints = &pinned_checkpoints;
            async move {
                if let Some(checkpoint) = peer_heights
                    .read()
                    .unwrap()
                    .get_dwallet_checkpoint_by_sequence_number(next)
                {
                    return (Some(checkpoint.to_owned()), next, None);
                }

                // Iterate through peers trying each one in turn until we're able to
                // successfully get the target checkpoint
                for mut peer in peers {
                    let request = Request::new(GetCheckpointMessageRequest::BySequenceNumber(next))
                        .with_timeout(timeout);
                    if let Some(checkpoint) = peer
                        .get_dwallet_checkpoint_message(request)
                        .await
                        .tap_err(|e| trace!("{e:?}"))
                        .ok()
                        .and_then(Response::into_inner)
                        .tap_none(|| trace!("peer unable to help sync"))
                    {
                        // peer didn't give us a checkpoint with the height that we requested
                        if *checkpoint.sequence_number() != next {
                            debug!(
                                "peer returned checkpoint with wrong sequence number: expected {next}, got {}",
                                checkpoint.sequence_number()
                            );
                            continue;
                        }

                        // peer gave us a checkpoint whose digest does not match pinned digest
                        let checkpoint_digest = checkpoint.digest();
                        if let Ok(pinned_digest_index) = pinned_checkpoints.binary_search_by_key(
                            checkpoint.sequence_number(),
                            |(seq_num, _digest)| *seq_num
                        )
                            && pinned_checkpoints[pinned_digest_index].1 != *checkpoint_digest {
                                debug!(
                                    "peer returned checkpoint with digest that does not match pinned digest: expected {:?}, got {:?}",
                                    pinned_checkpoints[pinned_digest_index].1,
                                    checkpoint_digest
                                );
                                continue;
                        }

                        // Insert in our store in the event that things fail and we need to retry
                        peer_heights
                            .write()
                            .unwrap()
                            .insert_checkpoint(checkpoint.clone());
                        return (Some(checkpoint), next, Some(peer.inner().peer_id()));
                    }
                }
                (None, next, None)
            }
        })
        .pipe(futures::stream::iter)
        .buffered(checkpoint_header_download_concurrency);

    while let Some((maybe_checkpoint, next, maybe_peer_id)) = request_stream.next().await {
        assert_eq!(expected_sequence_number, next);
        expected_sequence_number = next.checked_add(1).expect("exhausted u64");

        let certified = maybe_checkpoint
            .ok_or_else(|| anyhow::anyhow!("no peers were able to help sync checkpoint {next}"))?;

        // Check the committee signature before the certificate reaches the
        // store. Everything downstream treats a stored certificate as
        // authoritative: it is persisted, it moves the highest-verified
        // watermark, and those rows are read back to build on-chain
        // submissions.
        let checkpoint = verify_certified_dwallet_checkpoint(
            certified,
            &committees,
            &peer_heights,
            maybe_peer_id,
            next,
        )?;

        debug!(checkpoint_seq = ?checkpoint.sequence_number(), "verified checkpoint summary");

        // Insert the newly verified checkpoint into our store, which will bump our highest
        // verified checkpoint watermark as well.
        store
            .insert_dwallet_checkpoint(&checkpoint)
            .expect("store operation should not fail");
    }

    peer_heights
        .write()
        .unwrap()
        .cleanup_old_checkpoints(*checkpoint.sequence_number());

    Ok(())
}

/// Verifies a peer-supplied dWallet checkpoint certificate against the
/// committee that actually signed it.
///
/// On failure the row is dropped from `peer_heights` and the serving peer is
/// marked as not on our chain, so the retry reaches for a different one — the
/// same handling upstream Sui applies to a failed summary.
fn verify_certified_dwallet_checkpoint(
    certified: CertifiedDWalletCheckpointMessage,
    committees: &CommitteeSource,
    peer_heights: &Arc<RwLock<PeerHeights>>,
    maybe_peer_id: Option<PeerId>,
    sequence_number: DWalletCheckpointSequenceNumber,
) -> Result<VerifiedDWalletCheckpointMessage> {
    let signature_epoch = certified.auth_sig().epoch;
    let Some(committees) = committees.borrow().clone() else {
        return Err(anyhow::anyhow!(
            "no committee known yet; deferring verification of checkpoint {sequence_number}"
        ));
    };
    let Some(committee) = committees.for_epoch(signature_epoch) else {
        // Naming the window matters: this is the one verification failure the
        // peer is not at fault for, and it says sync cannot advance until the
        // node holds that epoch's committee.
        return Err(anyhow::anyhow!(
            "no committee for epoch {signature_epoch} available to verify checkpoint \
             {sequence_number}; verifiable epochs are {:?}",
            committees.epochs().collect::<Vec<_>>()
        ));
    };
    let digest = *certified.digest();
    certified.try_into_verified(committee).map_err(|e| {
        let mut peer_heights = peer_heights.write().unwrap();
        peer_heights.remove_checkpoint(&digest);
        if let Some(peer_id) = maybe_peer_id {
            peer_heights.mark_peer_as_not_on_same_chain(peer_id);
        }
        anyhow::anyhow!(
            "peer-supplied checkpoint {sequence_number} failed committee verification: {e}"
        )
    })
}

/// System-checkpoint twin of [`verify_certified_dwallet_checkpoint`].
fn verify_certified_system_checkpoint(
    certified: CertifiedSystemCheckpointMessage,
    committees: &CommitteeSource,
    peer_heights: &Arc<RwLock<PeerHeights>>,
    maybe_peer_id: Option<PeerId>,
    sequence_number: SystemCheckpointSequenceNumber,
) -> Result<VerifiedSystemCheckpointMessage> {
    let signature_epoch = certified.auth_sig().epoch;
    let Some(committees) = committees.borrow().clone() else {
        return Err(anyhow::anyhow!(
            "no committee known yet; deferring verification of system_checkpoint \
             {sequence_number}"
        ));
    };
    let Some(committee) = committees.for_epoch(signature_epoch) else {
        return Err(anyhow::anyhow!(
            "no committee for epoch {signature_epoch} available to verify system_checkpoint \
             {sequence_number}; verifiable epochs are {:?}",
            committees.epochs().collect::<Vec<_>>()
        ));
    };
    let digest = *certified.digest();
    certified.try_into_verified(committee).map_err(|e| {
        let mut peer_heights = peer_heights.write().unwrap();
        peer_heights.remove_system_checkpoint(&digest);
        if let Some(peer_id) = maybe_peer_id {
            peer_heights.mark_peer_as_not_on_same_chain(peer_id);
        }
        anyhow::anyhow!(
            "peer-supplied system_checkpoint {sequence_number} failed committee verification: {e}"
        )
    })
}

async fn sync_checkpoint_messages_from_archive<S>(archive_readers: ArchiveReaderBalancer, store: S)
where
    S: WriteStore + Clone + Send + Sync + 'static,
{
    loop {
        let highest_synced = store
            .get_highest_synced_dwallet_checkpoint()
            .expect("store operation should not fail")
            .map(|checkpoint| checkpoint.sequence_number)
            .unwrap_or(1);
        debug!("Syncing checkpoint messages from archive, highest_synced: {highest_synced}");
        let start = highest_synced
            .checked_add(1)
            .expect("Checkpoint seq num overflow");
        let checkpoint_range = start..u64::MAX;
        if let Some(archive_reader) = archive_readers
            .pick_one_random(checkpoint_range.clone())
            .await
        {
            let action_counter = Arc::new(AtomicU64::new(0));
            let checkpoint_counter = Arc::new(AtomicU64::new(0));
            if let Err(err) = archive_reader
                .read(
                    store.clone(),
                    checkpoint_range,
                    action_counter.clone(),
                    checkpoint_counter.clone(),
                )
                .await
            {
                warn!("State sync from archive failed with error: {:?}", err);
            } else {
                info!(
                    "State sync from archive is complete. Checkpoints downloaded = {:?}, Txns downloaded = {:?}",
                    checkpoint_counter.load(Ordering::Relaxed),
                    action_counter.load(Ordering::Relaxed)
                );
            }
        } else {
            debug!("Failed to find an archive reader to complete the state sync request");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// A checkpoint-sync stall must persist this long before it is reported
/// (gauge + error log). Long enough that ordinary sync-job scheduling and
/// peer churn never trip it; a genuine wedge (the 2026-07 testnet epoch-close
/// incidents: synced pinned while peers advertised thousands more) exceeds it
/// within minutes of onset.
const SYNC_STALL_REPORT_AFTER: Duration = Duration::from_secs(120);
/// Once stalled, re-log at most this often.
const SYNC_STALL_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Tracks whether checkpoint sync is making progress toward what peers
/// advertise. "Stalled" means peers are known to be ahead of our VERIFIED
/// watermark, yet that watermark has not advanced. (The verified watermark is
/// the one the pull path bumps per fetched checkpoint; the synced watermark
/// is fed only by the consensus output path and never moves on
/// notifiers/fullnodes.) This is the writer-side self-report for a wedged
/// sync pipeline: on the notifier a stalled sync leaves NOTHING to submit,
/// so the submission-failure log never fires and, without this signal, a
/// fully-stalled writer is indistinguishable from an idle one while it
/// silently blocks the network's epoch close.
#[derive(Default)]
struct SyncStallTracker {
    last_verified: Option<u64>,
    last_progress: Option<Instant>,
    last_log: Option<Instant>,
}

impl SyncStallTracker {
    /// Feed one observation; returns `(stall_seconds, should_log)`.
    /// `stall_seconds` is 0 while healthy or until the stall has lasted
    /// `SYNC_STALL_REPORT_AFTER`; `should_log` rate-limits the error log to
    /// once per `SYNC_STALL_LOG_INTERVAL`.
    fn observe(&mut self, known: Option<u64>, verified: Option<u64>, now: Instant) -> (u64, bool) {
        let verified_advanced = verified != self.last_verified;
        self.last_verified = verified;
        // `known` is the max height advertised by same-chain peers; `None`
        // means no peer has told us anything yet, which is a peering problem,
        // not a sync stall.
        let peers_are_ahead = known.is_some_and(|known| known > verified.unwrap_or(0));
        if verified_advanced || !peers_are_ahead {
            self.last_progress = Some(now);
            self.last_log = None;
            return (0, false);
        }
        let last_progress = *self.last_progress.get_or_insert(now);
        let stalled_for = now.duration_since(last_progress);
        if stalled_for < SYNC_STALL_REPORT_AFTER {
            return (0, false);
        }
        let should_log = self
            .last_log
            .is_none_or(|last| now.duration_since(last) >= SYNC_STALL_LOG_INTERVAL);
        if should_log {
            self.last_log = Some(now);
        }
        (stalled_for.as_secs(), should_log)
    }
}

async fn update_checkpoint_watermark_metrics<S>(
    mut recv: oneshot::Receiver<()>,
    store: S,
    peer_heights: Arc<RwLock<PeerHeights>>,
    metrics: Metrics,
) -> Result<()>
where
    S: WriteStore + Clone + Send + Sync,
{
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    let mut stall_tracker = SyncStallTracker::default();
    loop {
        tokio::select! {
             _now = interval.tick() => {
                let highest_verified_checkpoint = store.get_highest_verified_dwallet_checkpoint()
                    .expect("store operation should not fail")
                    .map(|checkpoint| checkpoint.sequence_number);
                if let Some(highest_verified_checkpoint) = highest_verified_checkpoint {
                    metrics.set_highest_verified_dwallet_checkpoint(highest_verified_checkpoint);
                }
                let highest_synced_checkpoint = store.get_highest_synced_dwallet_checkpoint()
                    .expect("store operation should not fail")
                    .map(|checkpoint| checkpoint.sequence_number);

                if let Some(highest_synced_checkpoint) = highest_synced_checkpoint {
                    metrics.set_highest_synced_dwallet_checkpoint(highest_synced_checkpoint);
                }
                // Refresh "known" from peer heights every tick — the sync-job
                // path only updates it when a job actually runs, which is
                // exactly what stops happening during the stall this detects.
                let highest_known_checkpoint = peer_heights
                    .read()
                    .unwrap()
                    .highest_known_checkpoint_sequence_number();
                if let Some(highest_known_checkpoint) = highest_known_checkpoint {
                    metrics.set_highest_known_dwallet_checkpoint(highest_known_checkpoint);
                }
                // The tracker watches the VERIFIED watermark: it is the one
                // the pull path bumps on every fetched checkpoint. The synced
                // watermark is fed only by the consensus output path, so on a
                // notifier/fullnode it never advances even when sync is
                // perfectly healthy — tracking it would report a permanent
                // false stall on exactly the node this detector protects.
                let (stall_seconds, should_log) = stall_tracker.observe(
                    highest_known_checkpoint,
                    highest_verified_checkpoint,
                    Instant::now(),
                );
                metrics.set_dwallet_checkpoint_sync_stall_seconds(stall_seconds);
                if should_log {
                    error!(
                        highest_known = ?highest_known_checkpoint,
                        highest_verified = ?highest_verified_checkpoint,
                        stall_seconds,
                        "dwallet-checkpoint sync is STALLED: peers advertise checkpoints \
                         we are not syncing. On the notifier this silently blocks the \
                         network's epoch close (nothing reaches the submission path, so \
                         no submission-failure log will fire) — restart/investigate \
                         state sync now",
                    );
                }
             },
            _ = &mut recv => break,
        }
    }
    Ok(())
}

async fn get_latest_from_peer_system_checkpoint(
    our_chain_identifier: ChainIdentifier,
    peer: anemo::Peer,
    peer_heights: Arc<RwLock<PeerHeights>>,
    timeout: Duration,
) {
    let peer_id = peer.peer_id();
    let mut client = StateSyncClient::new(peer);

    let info = {
        let maybe_info = peer_heights.read().unwrap().peers.get(&peer_id).copied();

        if let Some(info) = maybe_info {
            info
        } else {
            let request = Request::new(()).with_timeout(timeout);
            let response = client
                .get_chain_identifier(request)
                .await
                .map(Response::into_inner);

            let info = match response {
                Ok(GetChainIdentifierResponse { chain_identifier }) => PeerStateSyncInfo {
                    chain_identifier,
                    on_same_chain_as_us: our_chain_identifier == chain_identifier,
                    dwallet_checkpoint_height: None,
                    system_checkpoint_height: None,
                },
                Err(status) => {
                    trace!("get_chain_identifier request failed: {status:?}");
                    return;
                }
            };
            peer_heights
                .write()
                .unwrap()
                .insert_peer_info(peer_id, info);
            info
        }
    };

    // Bail early if this node isn't on the same chain as us
    if !info.on_same_chain_as_us {
        info!(?info, "Peer {peer_id} not on same chain as us");
        return;
    }
    let Some(highest_system_checkpoint) =
        query_peer_for_latest_info_system_checkpoint(&mut client, timeout).await
    else {
        return;
    };
    peer_heights
        .write()
        .unwrap()
        .update_peer_info_with_system_checkpoint(peer_id, highest_system_checkpoint);
}

/// Queries a peer for their highest_synced_system_checkpoint and low system_checkpoint watermark
async fn query_peer_for_latest_info_system_checkpoint(
    client: &mut StateSyncClient<anemo::Peer>,
    timeout: Duration,
) -> Option<CertifiedSystemCheckpointMessage> {
    let request = Request::new(()).with_timeout(timeout);
    let response = client
        .get_system_checkpoint_availability(request)
        .await
        .map(Response::into_inner);
    match response {
        Ok(GetSystemCheckpointAvailabilityResponse {
            highest_synced_system_checkpoint,
        }) => highest_synced_system_checkpoint,
        Err(status) => {
            trace!("get_system_checkpoint_availability request failed: {status:?}");
            None
        }
    }
}

#[instrument(level = "debug", skip_all)]
async fn query_peers_for_their_latest_system_checkpoint(
    network: anemo::Network,
    peer_heights: Arc<RwLock<PeerHeights>>,
    sender: mpsc::WeakSender<StateSyncMessage>,
    timeout: Duration,
) {
    let peer_heights = &peer_heights;
    let futs = peer_heights
        .read()
        .unwrap()
        .peers_on_same_chain()
        // Filter out any peers who we aren't connected with
        .flat_map(|(peer_id, _info)| network.peer(*peer_id))
        .map(|peer| {
            let peer_id = peer.peer_id();
            let mut client = StateSyncClient::new(peer);

            async move {
                let response =
                    query_peer_for_latest_info_system_checkpoint(&mut client, timeout).await;
                match response {
                    Some(highest_system_checkpoint) => peer_heights
                        .write()
                        .unwrap()
                        .update_peer_info_with_system_checkpoint(
                            peer_id,
                            highest_system_checkpoint.clone(),
                        )
                        .then_some(highest_system_checkpoint),
                    None => None,
                }
            }
        })
        .collect::<Vec<_>>();

    debug!("Query {} peers for latest system_checkpoint", futs.len());

    let system_checkpoints = futures::future::join_all(futs).await.into_iter().flatten();

    let highest_system_checkpoint =
        system_checkpoints.max_by_key(|system_checkpoint| *system_checkpoint.sequence_number());

    let our_highest_system_checkpoint = peer_heights
        .read()
        .unwrap()
        .highest_known_system_checkpoint()
        .cloned();

    debug!(
        "Our highest system_checkpoint {:?}, peers highest system_checkpoint {:?}",
        our_highest_system_checkpoint
            .as_ref()
            .map(|c| c.sequence_number()),
        highest_system_checkpoint
            .as_ref()
            .map(|c| c.sequence_number())
    );

    let _new_system_checkpoint = match (highest_system_checkpoint, our_highest_system_checkpoint) {
        (Some(theirs), None) => theirs,
        (Some(theirs), Some(ours)) if theirs.sequence_number() > ours.sequence_number() => theirs,
        _ => return,
    };

    if let Some(sender) = sender.upgrade() {
        let _ = sender.send(StateSyncMessage::StartSyncJob).await;
    }
}

async fn sync_to_system_checkpoint<S>(
    network: anemo::Network,
    store: S,
    peer_heights: Arc<RwLock<PeerHeights>>,
    metrics: Metrics,
    pinned_system_checkpoints: Vec<(
        SystemCheckpointSequenceNumber,
        SystemCheckpointMessageDigest,
    )>,
    system_checkpoint_header_download_concurrency: usize,
    timeout: Duration,
    on_chain_processed_cursor: SystemCheckpointSequenceNumber,
    committees: CommitteeSource,
    system_checkpoint: CertifiedSystemCheckpointMessage,
) -> Result<()>
where
    S: WriteStore,
{
    metrics.set_highest_known_system_checkpoint(*system_checkpoint.sequence_number());

    let current = store
        .get_highest_verified_system_checkpoint()
        .expect("store operation should not fail");
    let current_sequence_number = current.as_ref().map(|c| c.sequence_number);
    if current_sequence_number.as_ref() >= Some(system_checkpoint.sequence_number()) {
        return Err(anyhow::anyhow!(
            "target system_checkpoint {} is older than highest verified system_checkpoint {:?}",
            system_checkpoint.sequence_number(),
            current_sequence_number,
        ));
    }

    // Same on-chain floor as `sync_to_checkpoint` — see the comment there.
    let local_next_sequence_number = current_sequence_number
        .map(|s| s.checked_add(1).expect("exhausted u64"))
        .unwrap_or(1);
    let start_sequence_number = local_next_sequence_number.max(
        on_chain_processed_cursor
            .checked_add(1)
            .expect("exhausted u64"),
    );
    if start_sequence_number > *system_checkpoint.sequence_number() {
        // Everything peers advertise has already been processed on Sui.
        return Ok(());
    }
    if start_sequence_number > local_next_sequence_number {
        info!(
            local_next_sequence_number,
            on_chain_processed_cursor,
            start_sequence_number,
            "starting system checkpoint sync from the on-chain processed cursor; \
             older system checkpoints already landed on Sui and are skipped",
        );
    }
    let mut expected_sequence_number = start_sequence_number;

    let peer_balancer = PeerBalancer::new(&network, peer_heights.clone());
    // range of the next sequence_numbers to fetch
    let mut request_stream = (start_sequence_number
        ..=*system_checkpoint.sequence_number())
        .map(|next| {
            let peers = peer_balancer.clone().with_system_checkpoint(next);
            let peer_heights = peer_heights.clone();
            let pinned_system_checkpoints = &pinned_system_checkpoints;
            async move {
                if let Some(system_checkpoint) = peer_heights
                    .read()
                    .unwrap()
                    .get_system_checkpoint_by_sequence_number(next)
                {
                    return (Some(system_checkpoint.to_owned()), next, None);
                }

                // Iterate through peers trying each one in turn until we're able to
                // successfully get the target system_checkpoint
                for mut peer in peers {
                    let request = Request::new(GetSystemCheckpointRequest::BySequenceNumber(next))
                        .with_timeout(timeout);
                    if let Some(system_checkpoint) = peer
                        .get_system_checkpoint(request)
                        .await
                        .tap_err(|e| trace!("{e:?}"))
                        .ok()
                        .and_then(Response::into_inner)
                        .tap_none(|| trace!("peer unable to help sync"))
                    {
                        // peer didn't give us a system_checkpoint with the height that we requested
                        if *system_checkpoint.sequence_number() != next {
                            debug!(
                                "peer returned system_checkpoint with wrong sequence number: expected {next}, got {}",
                                system_checkpoint.sequence_number()
                            );
                            continue;
                        }

                        // peer gave us a system_checkpoint whose digest does not match pinned digest
                        let system_checkpoint_digest = system_checkpoint.digest();
                        if let Ok(pinned_digest_index) = pinned_system_checkpoints.binary_search_by_key(
                            system_checkpoint.sequence_number(),
                            |(seq_num, _digest)| *seq_num
                        )
                            && pinned_system_checkpoints[pinned_digest_index].1 != *system_checkpoint_digest {
                                debug!(
                                    "peer returned system_checkpoint with digest that does not match pinned digest: expected {:?}, got {:?}",
                                    pinned_system_checkpoints[pinned_digest_index].1,
                                    system_checkpoint_digest
                                );
                                continue;
                        }

                        // Insert in our store in the event that things fail and we need to retry
                        peer_heights
                            .write()
                            .unwrap()
                            .insert_system_checkpoint(system_checkpoint.clone());
                        return (Some(system_checkpoint), next, Some(peer.inner().peer_id()));
                    }
                }
                (None, next, None)
            }
        })
        .pipe(futures::stream::iter)
        .buffered(system_checkpoint_header_download_concurrency);

    while let Some((maybe_system_checkpoint, next, maybe_peer_id)) = request_stream.next().await {
        assert_eq!(expected_sequence_number, next);
        expected_sequence_number = next.checked_add(1).expect("exhausted u64");

        let certified = maybe_system_checkpoint.ok_or_else(|| {
            anyhow::anyhow!("no peers were able to help sync system_checkpoint {next}")
        })?;

        // Same trust boundary as the dWallet path: check the committee
        // signature before the certificate is persisted and allowed to move
        // the highest-verified watermark.
        let system_checkpoint = verify_certified_system_checkpoint(
            certified,
            &committees,
            &peer_heights,
            maybe_peer_id,
            next,
        )?;

        debug!(system_checkpoint_seq = ?system_checkpoint.sequence_number(), "verified system_checkpoint summary");

        // Insert the newly verified system_checkpoint into our store, which will bump our highest
        // verified system_checkpoint watermark as well.
        store
            .insert_system_checkpoint(&system_checkpoint)
            .expect("store operation should not fail");
    }

    peer_heights
        .write()
        .unwrap()
        .cleanup_old_system_checkpoints(*system_checkpoint.sequence_number());

    Ok(())
}

async fn sync_system_checkpoint_messages_from_archive<S>(
    archive_readers: ArchiveReaderBalancer,
    store: S,
) where
    S: WriteStore + Clone + Send + Sync + 'static,
{
    loop {
        let highest_synced = store
            .get_highest_synced_system_checkpoint()
            .expect("store operation should not fail")
            .map(|system_checkpoint| system_checkpoint.sequence_number)
            .unwrap_or(1);
        debug!("Syncing system_checkpoint messages from archive, highest_synced: {highest_synced}");
        let start = highest_synced
            .checked_add(1)
            .expect("SystemCheckpoint seq num overflow");
        let system_checkpoint_range = start..u64::MAX;
        if let Some(archive_reader) = archive_readers
            .pick_one_random(system_checkpoint_range.clone())
            .await
        {
            let action_counter = Arc::new(AtomicU64::new(0));
            let system_checkpoint_counter = Arc::new(AtomicU64::new(0));
            if let Err(err) = archive_reader
                .read_system_checkpoints(
                    store.clone(),
                    system_checkpoint_range,
                    action_counter.clone(),
                    system_checkpoint_counter.clone(),
                )
                .await
            {
                warn!(error=?err, "State sync from an archive failed with error");
            } else {
                info!(
                    system_checkpoints = system_checkpoint_counter.load(Ordering::Relaxed),
                    transactions = action_counter.load(Ordering::Relaxed),
                    "State sync from an archive is complete"
                );
            }
        } else {
            debug!("Failed to find an archive reader to complete the state sync request");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn update_system_checkpoint_watermark_metrics<S>(
    mut recv: oneshot::Receiver<()>,
    store: S,
    peer_heights: Arc<RwLock<PeerHeights>>,
    metrics: Metrics,
) -> Result<()>
where
    S: WriteStore + Clone + Send + Sync,
{
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    let mut stall_tracker = SyncStallTracker::default();
    loop {
        tokio::select! {
             _now = interval.tick() => {
                let highest_verified_system_checkpoint = store.get_highest_verified_system_checkpoint()
                    .expect("store operation should not fail")
                    .map(|system_checkpoint| system_checkpoint.sequence_number);
                if let Some(highest_verified_system_checkpoint) = highest_verified_system_checkpoint {
                    metrics.set_highest_verified_system_checkpoint(highest_verified_system_checkpoint);
                }
                let highest_synced_system_checkpoint = store.get_highest_synced_system_checkpoint()
                    .expect("store operation should not fail")
                    .map(|system_checkpoint| system_checkpoint.sequence_number);

                if let Some(highest_synced_system_checkpoint) = highest_synced_system_checkpoint {
                    metrics.set_highest_synced_system_checkpoint(highest_synced_system_checkpoint);
                }
                let highest_known_system_checkpoint = peer_heights
                    .read()
                    .unwrap()
                    .highest_known_system_checkpoint_sequence_number();
                if let Some(highest_known_system_checkpoint) = highest_known_system_checkpoint {
                    metrics.set_highest_known_system_checkpoint(highest_known_system_checkpoint);
                }
                // VERIFIED watermark, not synced — see the dwallet twin above.
                let (stall_seconds, should_log) = stall_tracker.observe(
                    highest_known_system_checkpoint,
                    highest_verified_system_checkpoint,
                    Instant::now(),
                );
                metrics.set_system_checkpoint_sync_stall_seconds(stall_seconds);
                if should_log {
                    error!(
                        highest_known = ?highest_known_system_checkpoint,
                        highest_verified = ?highest_verified_system_checkpoint,
                        stall_seconds,
                        "system-checkpoint sync is STALLED: peers advertise system \
                         checkpoints we are not syncing. On the notifier this silently \
                         blocks the network's epoch close — restart/investigate state \
                         sync now",
                    );
                }
             },
            _ = &mut recv => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod peer_heights_bounds_tests {
    use super::*;

    /// The bound counts the SEQUENCE index, but bodies are keyed by digest.
    /// The push RPC verifies no signature, so one peer can push many crafted
    /// bodies that all claim a single far-ahead sequence number with distinct
    /// digests — each adding a body while merely overwriting one index entry.
    /// Displacing the previous body is what keeps the two in step.
    #[test]
    fn same_sequence_distinct_digests_cannot_grow_the_body_map() {
        let mut bodies: HashMap<u64, ()> = HashMap::new();
        let mut by_sequence: HashMap<u64, u64> = HashMap::new();
        const FAR_AHEAD: u64 = 9_999_999;

        for digest in 0..50_000u64 {
            bodies.insert(digest, ());
            PeerHeights::displace_previous_body(&mut bodies, &mut by_sequence, FAR_AHEAD, digest);
            PeerHeights::evict_beyond(&mut bodies, &mut by_sequence);
        }

        assert_eq!(by_sequence.len(), 1, "one sequence was ever claimed");
        assert_eq!(
            bodies.len(),
            1,
            "bodies must not outgrow the index they are counted by"
        );
    }

    /// Across distinct sequences the ceiling applies, and it discards the
    /// furthest-ahead — sync advances upward, so the entries nearest our
    /// position are the ones worth keeping.
    #[test]
    fn distinct_sequences_are_capped_and_evict_from_the_top() {
        let mut bodies: HashMap<u64, ()> = HashMap::new();
        let mut by_sequence: HashMap<u64, u64> = HashMap::new();

        for sequence in 0..(MAX_UNPROCESSED_CHECKPOINTS as u64 + 5_000) {
            bodies.insert(sequence, ());
            PeerHeights::displace_previous_body(&mut bodies, &mut by_sequence, sequence, sequence);
            PeerHeights::evict_beyond(&mut bodies, &mut by_sequence);
        }

        assert_eq!(by_sequence.len(), MAX_UNPROCESSED_CHECKPOINTS);
        assert_eq!(bodies.len(), MAX_UNPROCESSED_CHECKPOINTS);
        assert!(by_sequence.contains_key(&0), "the nearest entry is kept");
        assert!(
            !by_sequence.contains_key(&(MAX_UNPROCESSED_CHECKPOINTS as u64 + 4_999)),
            "the furthest-ahead entry is the one dropped"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(start: Instant, secs: u64) -> Instant {
        start + Duration::from_secs(secs)
    }

    #[test]
    fn sync_stall_tracker_stays_quiet_while_synced_advances() {
        let start = Instant::now();
        let mut tracker = SyncStallTracker::default();
        for tick in 0..100u64 {
            let observation = tracker.observe(Some(1_000), Some(tick), at(start, tick * 5));
            assert_eq!(observation, (0, false));
        }
    }

    #[test]
    fn sync_stall_tracker_stays_quiet_when_caught_up_or_ahead() {
        let start = Instant::now();
        let mut tracker = SyncStallTracker::default();
        assert_eq!(tracker.observe(Some(5), Some(5), start), (0, false));
        assert_eq!(
            tracker.observe(Some(5), Some(5), at(start, 600)),
            (0, false)
        );
        assert_eq!(
            tracker.observe(Some(4), Some(5), at(start, 1200)),
            (0, false)
        );
    }

    #[test]
    fn sync_stall_tracker_stays_quiet_with_no_peer_heights() {
        let start = Instant::now();
        let mut tracker = SyncStallTracker::default();
        assert_eq!(tracker.observe(None, Some(5), start), (0, false));
        assert_eq!(tracker.observe(None, Some(5), at(start, 600)), (0, false));
    }

    #[test]
    fn sync_stall_tracker_reports_after_grace_and_rate_limits_logs() {
        let start = Instant::now();
        let mut tracker = SyncStallTracker::default();
        // First observation records the baseline.
        assert_eq!(tracker.observe(Some(100), Some(5), start), (0, false));
        // Still within the grace period: quiet.
        assert_eq!(
            tracker.observe(Some(100), Some(5), at(start, 119)),
            (0, false)
        );
        // Grace elapsed: report and log.
        assert_eq!(
            tracker.observe(Some(100), Some(5), at(start, 120)),
            (120, true)
        );
        // Logged 30s ago: gauge updates, log suppressed.
        assert_eq!(
            tracker.observe(Some(150), Some(5), at(start, 150)),
            (150, false)
        );
        // A minute after the last log: log again.
        assert_eq!(
            tracker.observe(Some(150), Some(5), at(start, 181)),
            (181, true)
        );
    }

    #[test]
    fn sync_stall_tracker_reports_when_nothing_ever_synced() {
        // The bootstrap-failure shape: peers advertise thousands of
        // checkpoints while our synced watermark never leaves `None`.
        let start = Instant::now();
        let mut tracker = SyncStallTracker::default();
        assert_eq!(tracker.observe(Some(21_000), None, start), (0, false));
        assert_eq!(
            tracker.observe(Some(21_000), None, at(start, 120)),
            (120, true)
        );
    }

    #[test]
    fn sync_stall_tracker_resets_on_recovery_then_logs_a_new_stall_promptly() {
        let start = Instant::now();
        let mut tracker = SyncStallTracker::default();
        assert_eq!(tracker.observe(Some(100), Some(5), start), (0, false));
        assert_eq!(
            tracker.observe(Some(100), Some(5), at(start, 120)),
            (120, true)
        );
        // Sync recovered: healthy again.
        assert_eq!(
            tracker.observe(Some(100), Some(90), at(start, 125)),
            (0, false)
        );
        // A fresh stall re-reports after its own grace period, and logs
        // immediately (the previous stall's rate limit must not carry over).
        assert_eq!(
            tracker.observe(Some(100), Some(90), at(start, 130)),
            (0, false)
        );
        assert_eq!(
            tracker.observe(Some(100), Some(90), at(start, 245)),
            (120, true)
        );
    }

    /// A committee at `epoch`, membership irrelevant — these tests are about
    /// which epochs the window answers for, not signature checking.
    fn committee_at(epoch: EpochId) -> Arc<Committee> {
        let (base, _keys) = Committee::new_simple_test_committee_of_size(4);
        Arc::new(Committee::new(
            epoch,
            base.voting_rights.clone(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            base.quorum_threshold,
            base.validity_threshold,
        ))
    }

    /// The boot case: a node restarting while the on-chain cursor still trails
    /// an epoch boundary must be able to verify certificates signed BEFORE the
    /// boundary, from committees it already holds on disk.
    ///
    /// Seeding the window with the current committee alone (the pre-fix
    /// behaviour, and what `previous: None` amounted to at boot) leaves those
    /// certificates unverifiable until the NEXT boundary repopulates the
    /// window — a full epoch of stalled sync.
    #[test]
    fn committee_window_verifies_epochs_the_cursor_still_trails() {
        let booted_at = 10;
        let seeded = SyncCommittees::new((5..=booted_at).map(committee_at));

        assert!(
            seeded.for_epoch(booted_at).is_some(),
            "the current epoch must verify"
        );
        for trailing in 5..booted_at {
            assert!(
                seeded.for_epoch(trailing).is_some(),
                "epoch {trailing} is inside the window and must verify: a cursor that trails \
                 the boundary makes its certificates the ones sync actually walks"
            );
        }
        assert!(
            seeded.for_epoch(booted_at + 1).is_none(),
            "a future epoch must NOT verify"
        );
        assert!(
            SyncCommittees::new([committee_at(booted_at)])
                .for_epoch(booted_at - 1)
                .is_none(),
            "control: with only the current committee the trailing epoch is unverifiable — \
             the stall this window exists to prevent"
        );
    }

    /// Crossing a boundary must ADVANCE the window, not replace it: the epoch
    /// just left stays verifiable, and the window stays bounded.
    #[test]
    fn committee_window_advances_without_dropping_the_outgoing_epoch() {
        let mut committees = SyncCommittees::new([committee_at(1)]);
        for epoch in 2..=(SyncCommittees::WINDOW as u64 + 3) {
            committees = committees.advanced_to(committee_at(epoch));
            assert!(
                committees.for_epoch(epoch).is_some(),
                "the new current epoch must verify"
            );
            assert!(
                committees.for_epoch(epoch - 1).is_some(),
                "the epoch just left must stay verifiable across the boundary"
            );
        }

        let held: Vec<_> = committees.epochs().collect();
        assert_eq!(
            held.len(),
            SyncCommittees::WINDOW,
            "the window must stay bounded as epochs advance"
        );
        assert_eq!(
            *held.last().unwrap(),
            SyncCommittees::WINDOW as u64 + 3,
            "the newest committee is retained"
        );
        assert!(
            committees.for_epoch(1).is_none(),
            "committees older than the window are evicted"
        );
    }
}
