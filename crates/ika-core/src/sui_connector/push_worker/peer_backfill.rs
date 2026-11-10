// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! The pusher's intake for checkpoints a direct peer named (see
//! `sui_connector::peer_checkpoint_lookup`). A child module of `push_worker` so
//! it can reach the pusher's backfill state while staying out of that file.

use std::time::Instant;

use tokio::sync::mpsc;
use tracing::info;

use super::{BackfillState, IkaCheckpointPusher};
use crate::sui_connector::peer_checkpoint_lookup::PeerBackfillRequest;

impl IkaCheckpointPusher {
    /// Take the checkpoints `peer_checkpoint_lookup` names, on every tick (see
    /// [`Self::take_peer_backfill_requests`]).
    pub fn with_peer_backfill_requests(
        mut self,
        requests: Option<mpsc::Receiver<PeerBackfillRequest>>,
    ) -> Self {
        self.peer_backfill_requests = requests;
        self
    }

    /// Schedule each checkpoint a peer named for the archive backfill, as a
    /// lost checkpoint: recorded and pinned first, then fetched, verified and
    /// folded only for objects the fullnode reports at exactly the archived
    /// reference — the peer supplied only the number. The requester is woken
    /// when the backfill settles or is abandoned, or at once for a seq this
    /// does not take: one ahead of the scan, a pending gap (the gap retry owns
    /// it), one the cache already holds snapshots from, or one
    /// `record_lost_checkpoint` refuses (no archive, or the record is full).
    pub(super) fn take_peer_backfill_requests(&mut self) {
        let Some(receiver) = self.peer_backfill_requests.as_mut() else {
            return;
        };
        let mut requests = Vec::new();
        while let Ok(request) = receiver.try_recv() {
            requests.push(request);
        }
        for PeerBackfillRequest { seq, settled } in requests {
            if !self.archive_backfill.contains_key(&seq) {
                if seq > self.cursor
                    || self.pending_gaps.contains_key(&seq)
                    || self.cache.snapshots_from_checkpoint(seq) > 0
                    || !self.record_lost_checkpoint(seq, "peer_named")
                {
                    continue;
                }
                self.archive_backfill
                    .insert(seq, BackfillState::due(Instant::now()));
                self.metrics
                    .pusher_backfill_pending
                    .set(self.archive_backfill.len() as i64);
                info!(
                    seq,
                    "a direct peer named this checkpoint for an object this node cannot prove; \
                     backfilling it from the archive"
                );
            }
            self.peer_backfill_waiters
                .entry(seq)
                .or_default()
                .push(settled);
        }
    }
}
