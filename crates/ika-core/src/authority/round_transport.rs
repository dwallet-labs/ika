// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! The consensus fold hands each round's inputs to the MPC drain over a
//! bounded channel, and BLOCKS when that channel is full.
//!
//! This replaces all ten per-round projection tables
//! (`dwallet_mpc_messages` and friends), none of which exist any more. That
//! includes the two the fold itself produced,
//! `verified_dwallet_checkpoint_messages` and
//! `verified_system_checkpoint_messages`: checkpoint construction never read
//! either table — it takes the same values in memory, on the pending-checkpoint
//! path — so once the drain reads them off this channel nothing was left that
//! read the rows.
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
// `tokio::time::Instant`, not `std`: identical to the system clock under a
// live runtime, and advanced by the test runtime's clock under
// `start_paused`. Park accounting is the only signal a wedged drain has, so
// it has to be assertable deterministically rather than by sleeping in real
// time and hoping.
use tokio::time::Instant;

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
/// instead of disk. 1024 is roughly a minute of consensus at mainnet commit
/// rates (~19.5 rounds/s): enough that ordinary jitter does not couple the two, small
/// enough that a sustained backlog is felt rather than hoarded.
pub const DEFAULT_ROUND_CHANNEL_CAPACITY: usize = 1024;

/// One consensus round's inputs to the MPC drain, in one message — the whole
/// of what `drain_consensus_rounds` consumes.
///
/// Owned rather than referenced, because it crosses a channel: the fold is
/// free of it the moment the drain has it, and its cost is bounded by the
/// channel capacity rather than by how far behind the drain has fallen.
///
/// `Clone` is for the integration harness only: production hands each payload
/// to the drain exactly once. The harness keeps a copy so a restarted service
/// can be re-fed the epoch's rounds, which is what the boot replay does on a
/// real node — see `integration_tests::utils::replay_recorded_rounds`.
#[derive(Clone)]
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
    /// True while the fold is parked waiting for room in the channel.
    ///
    /// Shared with the commit-liveness watchdog, which must not read a
    /// blocked fold as consensus silence: a fold parked here is holding a
    /// commit it received and waiting on the DRAIN, which is the opposite of
    /// the isolation the watchdog exists to catch. Without this the watchdog
    /// kills a healthy-but-busy node after one deep burst — the crash loop
    /// this whole design removes, reintroduced one hop down from where it
    /// was fixed.
    fold_blocked: Arc<AtomicBool>,
    /// Rounds the fold blocked on because the channel was full — the
    /// coupling the benchmark is looking for, counted rather than inferred.
    blocked_sends: AtomicU64,
    /// Total rounds handed over, so queue depth is `sent - received`.
    sent: AtomicU64,
    /// The drain's consumed count, shared so the sender can report depth.
    received: Arc<AtomicU64>,
    /// Nanoseconds spent in parks that have ENDED. The park in progress is
    /// added on read — see [`Self::blocked_nanos`], where it matters.
    blocked_nanos: AtomicU64,
    /// Monotonic origin for park timestamps. `Instant` cannot live in an
    /// atomic, so a park is stamped as nanos since this.
    started_at: Instant,
    /// When the current park began, as a [`RoundTransportSender::park_stamp`],
    /// or zero when the fold is not parked.
    parked_since_nanos: AtomicU64,
}

/// Holds the parked-fold state for exactly as long as the fold is parked.
///
/// A guard rather than a pair of stores around the await, because the await
/// can be CANCELLED: epoch teardown aborts the task the fold runs in, and an
/// abort lands wherever the task is suspended — which, under a full channel,
/// is precisely inside the parked send. A manual clear placed after the await
/// never runs on that path, leaving `fold_blocked` latched true with nothing
/// to ever clear it: the flag is one process-lifetime `Arc` shared with the
/// commit-liveness watchdog, so a single aborted park would disable the
/// isolation watchdog for the rest of the process — and an isolated node,
/// which never parks, would never clear it by accident either.
struct ParkGuard<'a> {
    sender: &'a RoundTransportSender,
}

impl<'a> ParkGuard<'a> {
    fn park(sender: &'a RoundTransportSender) -> Self {
        sender
            .parked_since_nanos
            .store(sender.park_stamp(), Ordering::Release);
        sender.fold_blocked.store(true, Ordering::Release);
        Self { sender }
    }
}

impl Drop for ParkGuard<'_> {
    fn drop(&mut self) {
        let stamp = self.sender.parked_since_nanos.swap(0, Ordering::AcqRel);
        self.sender
            .blocked_nanos
            .fetch_add(self.sender.park_elapsed(stamp), Ordering::Relaxed);
        self.sender.fold_blocked.store(false, Ordering::Release);
    }
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
    /// #1980), and a fold that waited forever on a departed drain would take
    /// consensus down with it — converting a single-node MPC stop into a
    /// consensus stop.
    ///
    /// Be precise about what prevents that: tokio resolves both `try_send`
    /// and a parked `send` with an error once the receiver drops, so the fold
    /// cannot wedge on a departed drain whatever this code does. What the
    /// `drain_gone` latch adds is the LOUD LOG — a validator silently doing
    /// no MPC for the rest of an epoch is the failure mode worth naming — and
    /// a short-circuit so later commits skip the doomed send.
    ///
    /// The node then keeps folding for the rest of the epoch: checkpoints,
    /// votes and the epoch close all come out of the fold and none of them
    /// need the drain. What it stops doing is MPC, which is what the
    /// self-stop decided. Detaching rather than exiting is deliberate — a
    /// validator that stops folding also stops contributing checkpoint
    /// signatures, which turns one node's MPC stop into a withdrawal of its
    /// stake from checkpoint certification for the remainder of the epoch.
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
                let sent = {
                    let _parked = ParkGuard::park(self);
                    self.sender.send(payload).await
                };
                if sent.is_err() {
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

    /// Total nanoseconds the fold has spent parked on a full channel,
    /// INCLUDING the park currently in progress.
    ///
    /// The named signal for a WEDGED drain, which nothing else catches: the
    /// commit-liveness watchdog deliberately holds while the fold is parked
    /// (a parked fold is not an isolated node), so a drain that stops
    /// consuming entirely holds the watchdog indefinitely and correctly —
    /// isolation is not what has gone wrong. This climbing while
    /// `ika_last_process_mpc_consensus_round` is flat is that failure, and it is
    /// the only place it shows.
    ///
    /// Which is exactly why the park in progress has to count. Accruing only
    /// on the way out of a park would make this readable as "the fold has
    /// waited a while and recovered", and the one case it is named for — a
    /// fold parked FOREVER on a drain that never consumes again — would add
    /// nothing to it, ever. The permanent wedge would be the one wedge the
    /// wedge signal could not report.
    pub fn blocked_nanos(&self) -> u64 {
        let completed = self.blocked_nanos.load(Ordering::Relaxed);
        let stamp = self.parked_since_nanos.load(Ordering::Acquire);
        completed.saturating_add(self.park_elapsed(stamp))
    }

    /// Nanos since [`Self::started_at`], offset by one so that zero can mean
    /// "not parked" without costing a nanosecond of accuracy.
    fn park_stamp(&self) -> u64 {
        (self.started_at.elapsed().as_nanos() as u64).saturating_add(1)
    }

    /// How long a park stamped `stamp` has been running; zero for the
    /// not-parked sentinel.
    fn park_elapsed(&self, stamp: u64) -> u64 {
        match stamp {
            0 => 0,
            stamp => (self.started_at.elapsed().as_nanos() as u64)
                .saturating_sub(stamp.saturating_sub(1)),
        }
    }

    /// Rounds handed to the drain but not yet consumed — the in-flight depth
    /// the capacity bounds.
    pub fn queue_depth(&self) -> u64 {
        self.sent
            .load(Ordering::Relaxed)
            .saturating_sub(self.received.load(Ordering::Relaxed))
    }

    /// True while the fold is parked. Shared with the watchdog.
    pub fn fold_blocked(&self) -> bool {
        self.fold_blocked.load(Ordering::Acquire)
    }

    /// True once the drain has been observed gone. Latched.
    pub fn drain_gone(&self) -> bool {
        self.drain_gone.load(Ordering::Relaxed)
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
///
/// `fold_blocked` is shared with the commit-liveness watchdog so it can tell
/// a fold waiting on the drain from a node receiving nothing.
pub fn round_transport(
    capacity: usize,
    fold_blocked: Arc<AtomicBool>,
) -> (Arc<RoundTransportSender>, RoundTransportReceiver) {
    let (sender, receiver) = channel(capacity);
    let received = Arc::new(AtomicU64::new(0));
    (
        Arc::new(RoundTransportSender {
            sender,
            drain_gone: AtomicBool::new(false),
            fold_blocked,
            blocked_sends: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            received: received.clone(),
            blocked_nanos: AtomicU64::new(0),
            started_at: Instant::now(),
            parked_since_nanos: AtomicU64::new(0),
        }),
        RoundTransportReceiver { receiver, received },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn payload(round: Round) -> ConsensusRoundPayload {
        ConsensusRoundPayload {
            round,
            mpc_messages: Vec::new(),
            mpc_outputs: Vec::new(),
            internal_mpc_outputs: Vec::new(),
            verified_dwallet_checkpoint_messages: Vec::new(),
            verified_system_checkpoint_messages: Vec::new(),
            idle_status_updates: Vec::new(),
            sui_chain_observation_updates: Vec::new(),
            global_presign_requests: Vec::new(),
            noa_observations: Vec::new(),
            noa_presign_demands: Vec::new(),
        }
    }

    fn transport(capacity: usize) -> (Arc<RoundTransportSender>, RoundTransportReceiver) {
        round_transport(capacity, Arc::new(AtomicBool::new(false)))
    }

    /// At capacity one the fold provably waits: the second send cannot
    /// complete until the drain has taken the first. Nothing is lost and the
    /// order is preserved.
    #[tokio::test]
    async fn the_fold_waits_for_the_drain_and_loses_nothing() {
        let (sender, mut receiver) = transport(1);
        sender.send(payload(1)).await;

        // The channel is full, so these sends park until rounds are taken.
        let feeder = {
            let sender = sender.clone();
            tokio::spawn(async move {
                for round in 2..=6 {
                    sender.send(payload(round)).await;
                }
            })
        };

        let mut seen = Vec::new();
        for _ in 1..=6 {
            seen.push(
                receiver
                    .recv()
                    .await
                    .expect("the fold is still sending")
                    .round,
            );
        }
        feeder.await.unwrap();

        assert_eq!(
            seen,
            vec![1, 2, 3, 4, 5, 6],
            "every round must arrive exactly once, in order"
        );
        assert!(
            sender.blocked_sends() > 0,
            "at capacity 1 the fold must have waited at least once; a run with no blocking \
             means the channel is applying no backpressure and the design is inert"
        );
        assert_eq!(sender.queue_depth(), 0, "everything sent was consumed");
    }

    /// A drain that exits — the deliberate self-stop a validator performs when
    /// it recognises itself as malicious (#1978, #1980) — must not wedge the
    /// fold. The fold detaches and keeps going.
    ///
    /// The alternative is worse than losing MPC: a fold blocked forever stops
    /// producing checkpoints, votes and the epoch close, turning one node's
    /// MPC stop into the withdrawal of its stake from checkpoint
    /// certification for the rest of the epoch.
    #[tokio::test]
    async fn a_departed_drain_does_not_wedge_the_fold() {
        let (sender, receiver) = transport(1);
        sender.send(payload(1)).await;
        // The drain exits, dropping its receiver with a round still queued.
        drop(receiver);

        // Every subsequent send must return promptly rather than park. The
        // timeout is the assertion: without the drain-gone path these await
        // forever on a full channel.
        for round in 2..=100 {
            tokio::time::timeout(Duration::from_secs(5), sender.send(payload(round)))
                .await
                .expect("the fold must not block on a departed drain");
        }
        assert!(
            !sender.fold_blocked(),
            "the fold must not be left marked as parked once the drain is gone"
        );
        // The property above is tokio's — a closed channel resolves any send.
        // What this code owes is NOTICING, so the operator gets one loud line
        // rather than a validator that quietly does no MPC for an epoch.
        assert!(
            sender.drain_gone(),
            "the departure must be latched; without it nothing logs and the node looks \
             healthy while doing no MPC at all"
        );
    }

    /// A drain that stops CONSUMING without exiting — a wedge, as opposed to
    /// the deliberate stop above — parks the fold indefinitely, and that is
    /// correct: the commit-liveness watchdog holds while the fold is parked,
    /// because a parked fold is not an isolated node. Nothing exits.
    ///
    /// So the wedge has exactly one signal, and this asserts it exists:
    /// blocked time climbing while the queue sits at capacity.
    #[tokio::test(start_paused = true)]
    async fn a_wedged_drain_is_visible_only_on_the_blocked_time_gauge() {
        let (sender, _receiver) = transport(1);
        sender.send(payload(1)).await;
        assert_eq!(sender.blocked_nanos(), 0, "nothing has parked yet");

        // The drain never calls recv again. The fold parks on the next round.
        let feeder = {
            let sender = sender.clone();
            tokio::spawn(async move { sender.send(payload(2)).await })
        };
        tokio::time::sleep(Duration::from_secs(120)).await;

        assert!(
            sender.fold_blocked(),
            "the fold must still be parked on a drain that stopped consuming"
        );
        // Specifically the park IN PROGRESS. `blocked_sends` counts parks
        // entered, so it reads 1 the moment the fold parks and never moves
        // again — asserting on it (or on it as an alternative) would pass on
        // accounting that reports nothing at all about a drain wedged for
        // hours. The elapsed time is the signal.
        let blocked_for = sender.blocked_nanos();
        assert!(
            blocked_for >= Duration::from_secs(120).as_nanos() as u64,
            "a park still in progress must already count as blocked time; got {blocked_for}ns \
             after 120s parked"
        );
        assert_eq!(sender.queue_depth(), 1, "the queue sits at capacity");

        // And it must keep climbing, because that slope is what an operator
        // alerts on: seconds rising while the drain's progress metric is flat.
        tokio::time::sleep(Duration::from_secs(120)).await;
        assert!(
            sender.blocked_nanos() > blocked_for,
            "blocked time must keep climbing while the fold stays parked"
        );
        assert_eq!(
            sender.blocked_sends(),
            1,
            "one park, not many — which is exactly why the seconds gauge cannot be replaced \
             by this counter"
        );
        feeder.abort();
    }

    /// Blocked time is read while a park is open and again after it closes, so
    /// the two accounting paths meet at the moment the park ends. It must not
    /// go backwards there.
    ///
    /// This is the precondition the metrics publisher rests on: it exports
    /// blocked time as a process-lifetime COUNTER fed the difference between
    /// consecutive samples, because the transport is per-epoch and a gauge
    /// holding its absolute total would drop to zero at every boundary. A
    /// reading that dipped when a park closed would be silently swallowed by
    /// that subtraction — the counter would stall for as long as it took the
    /// open interval to make the loss back, on the one signal a wedged drain
    /// has.
    #[tokio::test(start_paused = true)]
    async fn blocked_time_never_goes_backwards_when_a_park_ends() {
        let (sender, mut receiver) = transport(1);
        sender.send(payload(1)).await;

        let feeder = {
            let sender = sender.clone();
            tokio::spawn(async move { sender.send(payload(2)).await })
        };
        while !sender.fold_blocked() {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
        let while_parked = sender.blocked_nanos();
        assert!(while_parked > 0, "the open park must already be counted");

        // The drain takes a round, the park ends, and the open interval has to
        // land in the completed total rather than be dropped with the stamp.
        receiver.recv().await.expect("a round is queued");
        feeder.await.unwrap();
        assert!(
            !sender.fold_blocked(),
            "the park has ended, so nothing may still read as parked"
        );

        let after_park = sender.blocked_nanos();
        assert!(
            after_park >= while_parked,
            "blocked time fell from {while_parked}ns to {after_park}ns when the park closed; \
             the metrics publisher subtracts consecutive samples, so a dip is exported as no \
             progress at all"
        );
    }

    /// Epoch teardown aborts the task the fold runs in, and an abort lands
    /// wherever the task is suspended — under a full channel, inside the
    /// parked send.
    ///
    /// The flag is one process-lifetime `Arc` shared with the commit-liveness
    /// watchdog, so a park that never cleared would hold that watchdog for the
    /// remaining life of the process, across every later epoch. Nothing would
    /// ever clear it: an isolated node — the one case the watchdog exists for
    /// — never parks.
    #[tokio::test]
    async fn an_aborted_park_still_releases_the_watchdog_hold() {
        let fold_blocked = Arc::new(AtomicBool::new(false));
        let (sender, _receiver) = round_transport(1, fold_blocked.clone());
        sender.send(payload(1)).await;

        let fold = {
            let sender = sender.clone();
            tokio::spawn(async move { sender.send(payload(2)).await })
        };
        while !fold_blocked.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }

        // Teardown, mid-park.
        fold.abort();
        let _ = fold.await;

        assert!(
            !fold_blocked.load(Ordering::Acquire),
            "an aborted park must clear the hold; leaving it set disables the isolation \
             watchdog for the rest of the process"
        );
        assert!(
            !sender.fold_blocked(),
            "the transport must agree that nothing is parked any more"
        );
    }
}
