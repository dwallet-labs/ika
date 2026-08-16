// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! The consensus fold hands each round's inputs to the MPC drain over a
//! bounded channel, and BLOCKS when that channel is full.
//!
//! This replaces the eight per-round projection tables
//! (`dwallet_mpc_messages` and friends), which no longer exist. The two
//! fold-OUTPUT tables (`verified_dwallet_checkpoint_messages`,
//! `verified_system_checkpoint_messages`) are still written, because
//! checkpoint construction reads them independently of the drain — the drain
//! receives their content over the channel like everything else.
//!
//! # What blocking buys and what it costs
//!
//! Measured on a 50k-commit fixture with the drain throttled five times
//! slower than commit production (`#2058`):
//!
//! - the epoch database shrinks about 30% (10.35 MiB → 7.25 MiB), which is
//!   the write amplification this design deletes;
//!   time to drain the whole backlog is unchanged (122.6s → 123.1s), because
//!   both designs are bounded by the drain, not by the transport;
//! - but the fold takes about 50% longer to reach the store head (80.3s →
//!   120.6s), because it now waits for the drain.
//!
//! The cost that does NOT show up in a local benchmark is where the backlog
//! goes. The fold cannot absorb it any more, so it accumulates one queue
//! upstream — in consensus-core's commit channel, which is UNBOUNDED. The
//! same run measured a peak of 15,446 commits queued there, against 1 for the
//! table design. In the harness those were synthetic commits at roughly a
//! kilobyte each; a real `CommittedSubDag` carries every validator's blocks
//! including class-groups MPC payloads, so the production figure is larger by
//! a factor this repo has not yet measured. See
//! `dev-docs/specs/event-sourced-epoch.md` for the standing risk and the
//! cluster measurement that would close it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_consensus::Round;
use ika_types::messages_dwallet_mpc::{
    ConsensusGlobalPresignRequest, ConsensusNOAObservation, ConsensusNOAPresignDemand,
    DWalletInternalMPCOutput, DWalletMPCMessage, DWalletMPCOutput, IdleStatusUpdate,
    SuiChainObservationUpdate,
};
use ika_types::messages_system_checkpoints::SystemCheckpointMessageKind;
use tokio::sync::mpsc::error::{TryRecvError, TrySendError};
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tracing::warn;

/// How many rounds the fold may run ahead of the drain before it blocks.
///
/// A real dial across its whole range, not a step function. Measured on the
/// 50k fixture with a 5×-slow drain, rounds the fold had to wait on and time
/// for the fold to reach the store head:
///
/// | cap  | blocked rounds | fold to head |
/// |------|----------------|--------------|
/// | 64   | 9,752 / 10,000 | 24.6s        |
/// | 256  | 9,130          | 24.1s        |
/// | 1024 | 6,376          | 21.7s        |
/// | 4096 | 0              | 15.7s        |
///
/// Smaller means the fold is pinned to the drain sooner; larger means more
/// rounds resident in memory, and — once the cap exceeds the burst depth —
/// no blocking at all, which is the table design's behaviour bought with RAM
/// instead of disk. 1024 is roughly a few seconds of consensus at mainnet
/// commit rates: enough that ordinary jitter does not couple the two, small
/// enough that a sustained backlog is felt rather than hoarded.
pub const DEFAULT_ROUND_CHANNEL_CAPACITY: usize = 1024;

/// One consensus round's inputs to the MPC drain — exactly what
/// `process_consensus_rounds_from_storage` reads from the ten per-round
/// tables today, in one message.
///
/// Deliberately owned rather than referenced: it crosses a channel, and the
/// point of the experiment is to find out what carrying it costs.
pub struct ConsensusRoundPayload {
    pub round: Round,
    pub mpc_messages: Vec<DWalletMPCMessage>,
    pub mpc_outputs: Vec<DWalletMPCOutput>,
    pub internal_mpc_outputs: Vec<DWalletInternalMPCOutput>,
    pub verified_dwallet_checkpoint_messages: Vec<DWalletCheckpointMessageKind>,
    pub verified_system_checkpoint_messages: Vec<SystemCheckpointMessageKind>,
    pub idle_status_updates: Vec<IdleStatusUpdate>,
    pub sui_chain_observation_updates: Vec<SuiChainObservationUpdate>,
    pub global_presign_requests: Vec<ConsensusGlobalPresignRequest>,
    pub noa_observations: Vec<ConsensusNOAObservation>,
    pub noa_presign_demands: Vec<ConsensusNOAPresignDemand>,
}

/// The sending half, held by the epoch store and used by the commit boundary.
pub struct RoundTransportSender {
    sender: Sender<ConsensusRoundPayload>,
    /// Set once the drain is gone. See [`Self::send`].
    drain_gone: AtomicBool,
    /// Rounds the fold blocked on because the channel was full — the
    /// coupling the benchmark is looking for, counted rather than inferred.
    blocked_sends: AtomicU64,
    /// Total rounds handed over, so queue depth is `sent - received`.
    sent: AtomicU64,
}

impl RoundTransportSender {
    /// Hands one round to the drain, BLOCKING while the channel is full.
    ///
    /// Blocking is the design under test, not an implementation detail: it is
    /// what makes the fold unable to outrun the drain, which is the whole
    /// reason the tables could be deleted. It is deliberately not softened
    /// with a spill file or a drop policy — either would answer a different
    /// question.
    ///
    /// The one exception is a drain that has EXITED. The MPC service breaks
    /// its loop permanently when it recognises itself as malicious (#1978,
    /// #1980), and a fold blocked forever on a departed drain would take
    /// consensus down with it — converting a single-node MPC stop into a
    /// consensus stop. So a closed channel is treated as "drain gone": log
    /// loudly, stop feeding, let the fold continue.
    ///
    /// EXPERIMENT-GRADE. A merged version would need a real answer to "the
    /// drain is gone but the node is still a validator" — most likely the
    /// same self-stop that already exits the drain should also stop the node,
    /// rather than leaving a validator folding commits it will never act on.
    pub async fn send(&self, payload: ConsensusRoundPayload) {
        if self.drain_gone.load(Ordering::Relaxed) {
            return;
        }
        // Distinguish "would have blocked" from "did not", without changing
        // the semantics: try first, and only count a block when the fast path
        // fails.
        match self.sender.try_send(payload) {
            Ok(()) => {
                self.sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(payload)) => {
                self.blocked_sends.fetch_add(1, Ordering::Relaxed);
                if self.sender.send(payload).await.is_err() {
                    self.mark_drain_gone();
                } else {
                    self.sent.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(TrySendError::Closed(_)) => self.mark_drain_gone(),
        }
    }

    fn mark_drain_gone(&self) {
        if !self.drain_gone.swap(true, Ordering::Relaxed) {
            warn!(
                "the MPC drain has exited; the consensus fold will stop feeding it round \
                 payloads and continue without it. Derived state that only the drain \
                 produces will not advance for the rest of this epoch."
            );
        }
    }

    /// Rounds the fold had to wait on. Zero means the drain kept up.
    pub fn blocked_sends(&self) -> u64 {
        self.blocked_sends.load(Ordering::Relaxed)
    }

    /// Rounds handed over so far.
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
}

/// The receiving half, held by the drain.
pub struct RoundTransportReceiver {
    receiver: Receiver<ConsensusRoundPayload>,
    received: Arc<AtomicU64>,
}

impl RoundTransportReceiver {
    /// The next round, or `None` once the fold has dropped its sender.
    pub async fn recv(&mut self) -> Option<ConsensusRoundPayload> {
        let payload = self.receiver.recv().await;
        if payload.is_some() {
            self.received.fetch_add(1, Ordering::Relaxed);
        }
        payload
    }

    /// The next round if one is already queued.
    ///
    /// The drain uses this rather than `recv` because it runs inside a
    /// service iteration with other work to do; blocking here would stall
    /// that work behind the fold. Falling behind is expressed by the fold
    /// blocking on US, not by us waiting on it.
    pub fn try_recv(&mut self) -> Result<ConsensusRoundPayload, TryRecvError> {
        let payload = self.receiver.try_recv();
        if payload.is_ok() {
            self.received.fetch_add(1, Ordering::Relaxed);
        }
        payload
    }

    /// Rounds consumed so far. Paired with the sender's `sent`, this is the
    /// in-flight queue depth — the memory the cap is supposed to bound.
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }
}

/// Creates a bounded round transport with the given capacity.
pub fn round_transport(capacity: usize) -> (Arc<RoundTransportSender>, RoundTransportReceiver) {
    let (sender, receiver) = channel(capacity);
    let received = Arc::new(AtomicU64::new(0));
    (
        Arc::new(RoundTransportSender {
            sender,
            drain_gone: AtomicBool::new(false),
            blocked_sends: AtomicU64::new(0),
            sent: AtomicU64::new(0),
        }),
        RoundTransportReceiver { receiver, received },
    )
}
