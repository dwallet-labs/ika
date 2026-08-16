# The event-sourced epoch

**The consensus store is the only truth for epoch-scoped state. Everything
derived from it is deleted and rebuilt by replay on every restart.**

Actors: `ConsensusManager::start`, `consensus_manager::boot_replay`,
`ConsensusHandler::handle_consensus_commit`, `AuthorityEpochTables` and its
classification in `authority::derived_epoch_state`, the `DWalletMPCService`
round drain, and the checkpoint builders' signature outputs.

Table-by-table classification and its reasoning:
[`../derived-epoch-state-audit.md`](../derived-epoch-state-audit.md).

## The model

On every start, a node opening the current epoch's store:

1. **Wipes** every per-epoch table classified *derived*
   (`AuthorityEpochTables::wipe_derived_state`), before anything reads the
   store. The wipe is a startup invariant, asserted: if any derived table
   still holds a row, the process aborts rather than fold onto it. It is
   unconditional — every writer of a derived table lives inside the validator
   components, so on a node that does not run consensus those tables are
   already empty and the wipe is a no-op (see the audit).
2. **Replays** the epoch's commits from the consensus store, in bounded
   batches of 250 — read a batch, fold it through the same
   `handle_consensus_commit` that processes live commits, release it, read
   the next. Memory is flat in the epoch's age: one batch of commits and
   their blocks is resident at a time. The replay reads the store directly
   and does not go through consensus-core's commit channel, which is
   unbounded and would otherwise buffer the whole epoch between a producer
   that scans at disk speed and a consumer that folds at handler speed.
3. **Starts consensus** with the index the replay reached, as both
   `replay_after_commit_index` and `consumer_last_processed_commit_index`,
   and follows the live tail from there.

There is **no watermark**. The handler folds every commit of the epoch on
every boot. Exactly-once is replaced by *deterministic fold over wiped
state*: the double-apply failure shape requires surviving partial state, and
wipe-and-rebuild removes the category rather than defending against it.

## Why this is sound

Deterministic derivation from the commit stream is already a hard
cross-node requirement — every validator must reach identical checkpoints
and identical convictions from the same commits, or the network forks.
Relying on the same property *within* one node across restarts adds no new
assumption. If a table cannot be re-derived, that is not a replay problem;
it is a table that was never a function of consensus, and it belongs on the
preserved side of the audit.

It is also not a new architecture. **Sui is already event-sourced**; what it
keeps is a durable *snapshot* taken only at boundaries it has proven safe.
Its consensus output is quarantined and flushed only once the checkpoint
queue has drained below the certified watermark; everything above that
watermark is re-replayed on boot through a deliberately side-effect-free
path (`sui-core/src/consensus_handler.rs:1009`
`handle_prior_consensus_commit`), and it even *rewinds* its replay point by
`consensus_num_requested_prior_commits_at_startup`
(`sui-protocol-config/src/lib.rs:2283`, used at
`sui-core/src/consensus_manager/mod.rs:302`) to widen the window it
re-derives rather than trusts. Consensus-core does the same thing in
miniature for its own leader schedule: `LeaderScheduleV3::from_store`
(`consensus/core/src/leader_schedule_v3.rs:83`) rebuilds live state from
stored commits, and
`test_recovery_replay_produces_same_state_as_live` (:1088) is the property
test for it.

What this change does is remove the snapshot and set the replay horizon to
the epoch. The cost is restart latency; what is bought is that there is no
second record to disagree with the store.

(Upstream anchors here and below are at the pinned rev — `mainnet-v1.77.2`,
`51d177ad7d65102fc368b582408f466d97b31548`. Re-verify on a Sui bump; line
numbers move.)

## What the fold covers, and where it stops

The replay stops at the store's **last finalized** commit
(`Store::read_last_finalized_commit`), not its last commit.

An unfinalized commit has no stored set of rejected transaction indices. A
validator that folded one would treat as accepted a transaction its peers
reject, and its derived state would diverge from theirs on a technicality of
when it happened to restart. Those commits belong to consensus-core, which
delivers them through the commit finalizer once it starts. The tail
consensus itself has to recover is therefore bounded by how much
finalization was in flight when the process died, not by the epoch's age —
which is also what keeps that recovery clear of the unbounded-channel
problem above.

## Why the old watermark could brick a validator

The index handed to consensus used to come from the per-epoch store's own
record of how far the handler got. That put one logical fact — "how much of
this epoch has been consumed" — in two databases with no shared fsync
discipline, and `CommitObserver::recover_and_send_commits` asserts
`last_commit_index > replay_after_commit_index`. A storage incident that
cost the consensus store its unsynced tail while the per-epoch store kept
its record left the two out of order, and every boot aborted on that
assertion — a validator down for up to a full epoch (ika #2057).

Reading the index from the consensus store closes it structurally, not
tolerantly. **This one line is the fix**: `replay_after` now comes from
`Store::read_last_finalized_commit` on the same database consensus is about
to open, so both of the upstream assertions become unreachable rather than
merely unlikely — the store-behind one
(`consensus/core/src/commit_observer.rs:162`,
`assert!(last_commit_index > replay_after_commit_index)`) because the two
numbers are the same number, and the store-empty one (:147, `assert_eq!(
replay_after_commit_index, 0)`) because an empty store yields exactly 0.

Nothing else in this change is load-bearing for #2057. In particular the
replay's own gap assertion — that a batch scan returns as many commits as
the range asked for — guards a *different* failure (a store pruned or
truncated in the middle, which would silently drop a commit's effects from
every derived table). Useful, but not the #2057 guard; do not read it as
one.

## The determinism contract

Everything the fold does must be a function of the commits it folds.

- **No wall clock, no randomness** on the commit path. Grace countdowns are
  leader-round deltas, not elapsed time; the epoch's consensus clock is
  anchored on `epoch_first_commit_timestamp_ms`, itself a replayed commit's
  timestamp. Metrics and log lines may read the wall clock — they are not
  inputs to anything.
- **Aggregators that cap on arrival order rebuild correctly** because they
  rebuild from empty. `end_of_publish`'s aggregator stops accepting votes at
  quorum, so its membership is a prefix of consensus arrival order that the
  vote table does not record. Wiping both and refilling from the replayed
  commits reproduces the same prefix and re-pins the same
  `end_of_publish_quorum_voted_count` at the same commit — the divergence of
  ika #1917 removed at its root rather than compensated for.
### The epoch close is the one decision this changes the shape of

`handoff_signatures` rows are written only once this validator has installed
its expected handoff attestation, which depends on a background Sui poll,
not on the commit sequence. So the epoch-close gate has never been a pure
function of the sequence — peers can cross the handoff-cert quorum at
different commits, and the safety argument is buffered-quorum adoption plus
the grace-multiplied liveness backstop, not purity. See
[`epoch-close-session-lock.md`](epoch-close-session-lock.md) and
[`handoff.md`](handoff.md).

What this design changes is what a RESTART does with that. Before, a
restarted validator short-circuited: `epoch_close_emitted` survived, and the
store restored `RejectAllTx` without re-deciding anything. Now the marker is
derived like everything else, so the close is re-decided from the replayed
commits against whatever handoff state is installed at the time — bundles
that arrive before the install buffer and are staged when it completes, at
whichever commit the replay has reached.

The close round a restart picks is therefore no longer guaranteed to equal
the one the crashed run picked, **and it can move in either direction**:

- **Later**, if the replay reaches the original close commit before this
  validator's expected attestation installs. The bundles buffer, the gate
  does not see a quorum at that commit, and the close lands at a later
  commit or on the backstop.
- **Earlier**, which is the less obvious one. If the crashed run installed
  its attestation LATE, its buffered bundles were drained and staged at the
  install commit, so the gate counted quorum there — after the commits the
  bundles actually arrived in. A replay that installs EARLY records each
  bundle under its own commit instead, so the gate can reach quorum at a
  commit the original run had already passed, and the close lands earlier.

It is not a new divergence class — it is the same pre-existing non-purity
reached by a different route, and the rebuilt checkpoint stream is
self-consistent with whichever round this validator picks. But it is the
part of this change with the least margin, and the first thing to look at
if a restart near an epoch boundary produces a final checkpoint no peer
signs.

The case that deserves a cluster test rather than an argument is
**simultaneous restarts**. Pre-change, restarting validators kept their
recorded close round, so a correlated restart cost nothing. Now each one
re-rolls it independently, so restarting at least f+1 stake inside the
window between `end_of_publish_quorum_round` being set and the final
checkpoint certifying can scatter the close rounds and delay the final
checkpoint until the backstop reconverges them. The blast radius is
bounded — fork handling is log-and-metric, the settled-state suppression
still holds, and state sync supplies the certified stream — but "bounded"
is a traced argument, not a measurement.

Retiring all of this properly is the sequence-pure tally in
`../plans/handoff-barrier-escape-and-pure-close-gate.md`: once the gate is
a function of the sequence, the replay re-derives the same close round by
construction and none of the above can arise.

## Emission must be silent for settled work

Re-folding commit *N* re-triggers "send checkpoint signature *K*". Peers
deduplicate it, so it is harmless to correctness — but without suppression
every restart sprays an epoch of re-submissions into the DAG.

**The suppression key must be observed settled state, never a local
watermark.** "A stake quorum has already certified this sequence number" is
an observation about the network that every validator converges on from the
same certificates, in any order. "I already did this" is a second truth
beside the consensus store, which is the thing this design exists to delete.

The checkpoint signature outputs key on the greater of:

- the state-sync-verified watermark
  (`get_highest_verified_*_checkpoint`), bumped when a certificate verified
  against the committee arrives from a peer; and
- the head of the certificates this node aggregated itself
  (`certified_checkpoints`).

Both are needed. `insert_certified_checkpoint` deliberately leaves the
verified watermark alone so state sync still gets to process the checkpoint,
so a node that certified a checkpoint locally but has not synced past it
would re-sign an epoch's worth of them on the verified watermark alone.

### Submitting before consensus is up must be survivable, and rare

The replay runs *before* consensus starts, and plenty of things submit in
that window: the capability notification, both epoch-task senders on their
timers, and — because the replay regenerates their whole input queue — the
checkpoint builders.

Two changes make that window safe:

- **`UpdatableConsensusClient` waits instead of aborting.** It used to panic
  if the client was still unset 300 seconds after a submission was issued,
  and with `panic = "abort"` in the release profile a single such submission
  took the process down. A boot that rebuilds an old epoch is legitimately
  longer than that, so a recovering node could abort partway through its own
  recovery — the crash loop this design exists to remove, reintroduced by
  the fix for it. The wait is now unbounded, with an escalating error naming
  the replay gauge to check. It cannot leak: every caller reaches it through
  `submit_and_wait`, inside `within_alive_epoch`, which is dropped at the
  epoch boundary.
- **The checkpoint builders wait for the replay** before their first pass,
  on the same signal the MPC service waits on
  (`ConsensusManager::replay_waiter`), with their subscriptions taken before
  consensus start is spawned so the signal cannot be published into an empty
  subscriber set. This is about volume rather than safety: a builder that
  drained an epoch's rebuilt queue against an unset client would park one
  task per checkpoint and trip the adapter's in-flight limit, rejecting the
  live traffic that follows.

- **The MPC drain does NOT wait for the replay — it consumes during it.**
  This is the one component that must not be gated on the replay signal, and
  the reason is a circular wait. The replay's folds send each round into the
  bounded channel and block when it is full; the replay signal is published
  only after `replay_epoch_commits` returns; so a drain that waited for the
  signal would let the channel fill and park the replay forever. Any store
  holding more than the channel capacity of finalized commits — about a
  minute of mainnet — would hang on every boot, and hang silently, because a
  parked fold holds the commit-liveness watchdog. `DWalletMPCService::spawn`
  therefore runs `drain_while_replaying` first, which consumes rounds and
  nothing else until the replay completes.

  Only the drain runs there, and that is deliberate: the rest of the service
  iteration submits to consensus, which has not started, so it would park on
  the unbounded wait above and rebuild the same cycle one layer up. The
  drain itself submits nothing.

The general rule: a component whose work submits to consensus should be
gated on the replay signal, and the submission path must treat "consensus
has not started yet" as a wait, never as a fault. The drain is the
exception, and it is exempt precisely because it submits nothing.

The catch-up gate (`dwallet_mpc/catchup_gate.rs`) is the other
replay-aware emission gate, and it is a different tool: it keys on distance
behind the tip and suppresses *starting new cryptographic computations*, not
on whether a given piece of work is settled. Its gap is still store head
minus drain cursor — but **where the head comes from changed, and it had to.**

Under a blocking transport the fold cannot supply it. Arrivals are stamped in
the fold's own loop, and that loop stops advancing as soon as the drain falls
a channel's-worth behind, so any head derived from the fold is pinned within
the capacity (1,024) of the drain's own cursor — permanently below the gate's
entry threshold. A validator that fell a hundred thousand rounds behind
*without restarting* would never enter catch-up at all, which is the #2023
collapse the gate exists to prevent; only a restart would rescue it, through
the boot replay's head publication.

The head is therefore published from the **consensus store**, which
consensus-core writes as commits are decided and which nothing about that path
makes wait on the fold (`MysticetiConsensusHandler::spawn_observed_head_publisher`,
sampling `read_last_commit` every 5s). Two constraints on that task, both
load-bearing:

- it lives in the handler's own `JoinSet`, so `abort()` at the epoch boundary
  is exactly its lifetime;
- it holds the **store** handle from `ConsensusAuthority::store()`, never the
  authority — `ConsensusManager::shutdown` does `Arc::try_unwrap` on the
  authority and panics on any surviving reference.

### Where to draw the line

Not every re-emission is worth suppressing, and upstream's line is the one
to copy: **re-emit where peers deduplicate cheaply, suppress where it
floods.** Consensus-core itself re-broadcasts its last proposed block on
every reconnection for liveness, because one block per peer per reconnect is
nothing. An epoch's worth of checkpoint signatures on every restart is not.

Concretely in ika: the MPC message and output families keep re-deriving and
re-emitting on the drain's replay, as they did before this change — their
consensus keys deduplicate and their volume is bounded by live session
state. Checkpoint signatures are gated, because their volume is bounded by
the *epoch's age*. New submitters should be classified the same way, by
asking what the re-emission's volume scales with.

## The MPC drain

The drain receives each round's inputs from the fold over a **bounded blocking
channel** (`authority::round_transport`). There are no per-round tables: all
ten were deleted. When the drain falls behind, the channel fills and the fold
WAITS — that coupling is what makes the tables unnecessary rather than merely
unused.

The rules this establishes for every future consumer of consensus output are
[`../conventions/consensus-output-consumption.md`](../conventions/consensus-output-consumption.md).

**What it costs, measured.** On a 50k-commit fixture with the drain five times
slower than commit production: the epoch database shrank 30% and the time to
drain the backlog was unchanged, but the fold took 50% longer to reach the
store head. The cap is a dial across its whole range — at 64 the fold waited
on 9,752 of 10,000 rounds, at 4096 on none.

**Where the backlog goes instead — and why it is bounded.** The fold can no
longer absorb a backlog, so it accumulates one queue upstream, in
consensus-core's commit channel, which is unbounded. Two different paths feed
that queue and they have different bounds:

- **Deep lag (sync-fetched), bounded.** `commit_syncer` stops scheduling
  fetches when `highest_handled_index + threshold < range_end`
  (`commit_syncer.rs:238`), reading `commit_consumer_monitor.highest_handled_commit()`
  at `:205` — the value ika reports AFTER each fold. The threshold is
  `commit_sync_batch_size × commit_sync_batches_ahead` = 100 × 32 = 3,200
  (`consensus/config/src/parameters.rs:203`, `:220`). So a blocked fold stalls
  the watermark, which pauses fetching, which bounds the queue at roughly
  3,200 commits. **This is why `set_highest_handled_commit` must stay
  post-fold** — reporting it early removes the guard.
- **At tip (locally decided), unbounded in principle.** Commits the node
  decides itself are not gated on the consumer's watermark. In practice they
  arrive at the network's commit rate, a few per second, so a block of the
  watchdog's length accumulates a few thousand — comparable to the sync bound
  — but nothing enforces that. `ika_consensus_round_channel_depth`,
  `ika_consensus_fold_blocked_seconds_total` and
  `ika_consensus_fold_blocked_sends_total` are the monitoring for it.

Four things about those three series are load-bearing rather than incidental,
and each was a defect before it was a property:

- they are published by a task of their own
  (`DWalletMPCService::publish_round_transport_metrics`), not from inside the
  drain. A publisher living in the drain stops publishing in exactly the case
  they are named for, freezing at its last healthy values while an operator
  reads a node with nothing to do;
- the two `_total` series are process-lifetime **counters** fed the per-sample
  delta, not the transport's own figures copied over. The transport is
  per-epoch and its park accounting restarts at zero at every boundary, so a
  gauge holding its absolute value would fall to zero several times a day —
  destroying the slope reading below whenever a boundary lands in the alerting
  window. Depth stays a gauge; it is an instantaneous value and resetting with
  the epoch is correct for it;
- blocked seconds include the park **still in progress**, added on read from a
  stored park-start. Accruing only when a park ends would leave the one wedge
  worth alarming on — a fold parked forever — contributing nothing, ever;
- seconds and sends are read as a pair. Both climbing is a drain that is slow
  but alive; seconds climbing while sends stays flat is a single endless park.
  The reading table is in
  [`../playbooks/production-alerts.md`](../playbooks/production-alerts.md).

The threshold is consensus **node configuration**, not protocol: it can be
tuned per node and is not an invariant the network enforces.

**Unmeasured.** The 50k benchmark's synthetic commits are about a kilobyte
each; a real `CommittedSubDag` carries every validator's blocks including
class-groups MPC payloads. The queue's byte cost in production is therefore
larger than the harness showed by a factor this repo has not measured — and
the harness overstated the *deep-lag* case in the other direction, since its
producer never paused the way `commit_syncer` does. Closing both needs a
cluster measurement; see the remainder list.

## Consensus-store retention is load-bearing

The epoch's full commit history must survive until the epoch boundary, or
the rebuild is impossible. It does, and structurally rather than by policy:

- the consensus `Store` trait exposes **no delete or prune method at all**
  (`consensus/core/src/storage/mod.rs`), and `RocksDBStore` contains zero
  delete calls — a stored commit or block is never removed while the store
  is open;
- consensus-core's garbage collection is in-memory eviction from DAG state,
  not deletion from the store;
- pruning is whole-directory and only ever of *past* epochs:
  `ConsensusStorePruner::prune_old_epoch_data`
  (`crates/ika-core/src/epoch/consensus_store_pruner.rs:154`) removes epoch
  directories strictly below `current_epoch - epoch_retention`.

So nothing can prune the current epoch's commits out from under a replay.
The replay still asserts it — a batch scan that returns fewer commits than
its range aborts naming the condition — because the alternative to a cheap
startup check is derived state that is silently missing a commit's effects,
and because "no API exists to do this" is a property of the current pinned
revision rather than a guarantee.

## Restart latency

Restart-to-live is now O(epoch age) for the whole node, not just for the MPC
drain. This is an accepted cost, not an accident.

One term in it has not been measured. The wipe deletes in chunks, re-seeking
the table head each time, so on a table with millions of rows each chunk's
seek walks the tombstones the previous chunks left — super-linear in the row
count, though bounded by the same compaction that clears them. It is
correctness-neutral (the alternative, a RocksDB range delete, is the one
that leaves a row behind) and it runs once per boot against tables the
replay is about to rewrite anyway, so it was not worth optimising blind.
Benchmark it alongside the memory-flatness measurement on the same
million-round epoch; if it dominates, deleting by explicit key range with an
inclusive upper bound is the fix, not `schedule_delete_all`. Three gauges make it
observable: `ika_consensus_boot_replay_target_commit_index`,
`ika_consensus_boot_replay_folded_commit_index` (the two together are the
remaining boot work) and `ika_consensus_boot_replay_latency_seconds`. The
replay also logs progress per batch, because a boot that legitimately takes
tens of minutes must be distinguishable from one that is stuck.

## Rolling back

**The clean-rollback property is gone.** It was an artefact of the tables: an
older binary could resume from them because they were still there. They are
not.

A binary rolled back mid-epoch finds the per-round column families absent.
typed-store recreates missing column families empty, so it starts, and its
drain then sees no round history at all — it processes nothing until the epoch
boundary gives it a fresh epoch store and a live stream. Concretely: degraded
MPC for the remainder of the epoch, with checkpoints and the epoch close still
produced by the fold. That is the outcome the issue's open question 1
anticipated and accepted.

`last_consensus_stats` is a separate matter and is fine: it holds the tally of
a full replay to the head, which is what the old binary would have written
itself.

This is an argument, not evidence. The upgrade matrix is where it gets tested;
until then treat a mid-epoch rollback as costing that node's MPC participation
for the rest of the epoch.

## What this is tested by, and what it is not

In-process, in `ika-core`:

| property | test |
|---|---|
| classification is complete | `every_epoch_table_is_classified` |
| classification is CORRECT | `every_table_the_consensus_fold_writes_is_classified_derived` — takes its answer from folding real commits, not from the declaration |
| the wipe is total, and reaches nothing preserved | `wipe_empties_every_derived_table_and_preserves_the_rest` |
| the fold is deterministic over wiped state | `folding_the_same_commits_twice_rebuilds_identical_derived_state` |
| the replay reaches the store head, stops below the unfinalized tail, crosses batch boundaries, and survives a lost tail | `consensus_manager::boot_replay::tests` |
| a finalization hole below the head stops the node | `a_finalization_hole_below_the_head_stops_the_replay` |
| replayed commits arm the commit-liveness watchdog | `replayed_commits_feed_the_commit_liveness_sink` |
| a settled checkpoint is not re-signed | `a_rebuilt_checkpoint_is_not_re_signed_once_a_quorum_has_certified_it` |
| a replay longer than the channel completes, and its drain submits nothing | `a_replay_longer_than_the_channel_still_finishes` |
| the catch-up head is published without folding anything | `the_head_publisher_reports_the_store_head_without_folding_anything` |
| an aborted park releases the watchdog hold | `an_aborted_park_still_releases_the_watchdog_hold` |
| a park still in progress already counts as blocked time | `a_wedged_drain_is_visible_only_on_the_blocked_time_gauge` |
| blocked time does not dip when a park ends (what the delta-fed counter rests on) | `blocked_time_never_goes_backwards_when_a_park_ends` |
| the watchdog holds off a real full round channel | `a_full_round_channel_holds_the_watchdog_while_commits_queue` (in `ika-node`) |

Every one of these was validated by injecting the fault it claims to catch
and confirming the predicted evidence
(`../playbooks/test-testing.md`) — which is how the first draft of the
classification tests was found to pass with a misclassification injected.

What in-process coverage cannot reach, and belongs on CI or a cluster:

- **Kill-storm** — repeated `kill -9` under load, including mid-replay and
  mid-batch. Consensus-core has the precedent to imitate:
  `consensus/simtests/tests/consensus_tests.rs`
  `test_consensus_crash_and_restart` (:135) and
  `test_consensus_rolling_restarts_all_validators` (:223) already drive
  full-replay-from-zero consumers through crash storms.
- **Memory flatness** over a >1M-round epoch, and the **restart-to-live
  latency budget** at ≥90% epoch age. Both are read off
  `ika_consensus_boot_replay_*`.
- **The real boot path end to end** — wipe, replay, consensus start,
  builders released — which only `ika-test-cluster` exercises
  (`restart_mid_grace`, `cluster_boots`).
- **Correlated restarts across the close window** (REQUIRED, not
  optional): kill at least f+1 stake after `end_of_publish_quorum_round` is
  set but before the final checkpoint certifies, and assert the epoch still
  advances. This is the scenario the close-round re-roll above makes newly
  reachable, and the one place a traced "bounded blast radius" should be
  replaced by a measurement.
- **Mixed old/new binaries sharing an epoch** (`ika-upgrade-test`), which is
  also where the rollback claim above gets tested rather than argued — and it
  is now an argument with teeth, since a rolled-back node loses MPC for the
  rest of the epoch.
- **Upstream queue bytes under a real burst** (REQUIRED): throttle the drain
  on a live cluster and record `ika_consensus_round_channel_depth`, RSS and
  the commit-channel backlog. This closes both directions the local harness
  got wrong — synthetic commits understate the per-commit byte cost, and a
  producer that never pauses overstates the deep-lag case that
  `commit_syncer` actually bounds at ~3,200 commits.
- **A wedged drain end to end** (REQUIRED): stop the drain consuming on a
  live validator and confirm the watchdog does NOT exit the node (the hold is
  correct) while blocked time and channel depth climb. The hold and the
  signal are separately tested in-process; that they behave that way together
  on a real node is not.

## What must never be reintroduced

- A persisted record of how far the handler got, used to skip commits. It is
  the second truth this design deletes, under any name.
- A second persisted copy of the commit stream that is not wiped on boot. A
  copy that survives a restart can hold rounds the consensus store no longer
  backs.
- Emission suppression keyed on local progress rather than on settled state.
