# The event-sourced epoch

**The consensus store is the only truth for epoch-scoped state. Everything
derived from it is held in memory and rebuilt by replay on every restart.**

Actors: `ConsensusManager::start`, `consensus_manager::boot_replay`,
`ConsensusHandler::handle_consensus_commit`, the in-memory derived state on
`AuthorityPerEpochStore`, the `DWalletMPCService` round drain, and the
checkpoint builders' signature outputs.

What the store still keeps on disk, and why:
[`../preserved-epoch-state-audit.md`](../preserved-epoch-state-audit.md).

## The model

On every start, a node opening the current epoch's store:

1. **Starts with nothing.** Derived state is in memory, so opening the store
   is the only state it can have. There is no deletion step and no
   post-deletion invariant to assert, because there is nothing to delete:
   the state that used to be wiped at boot is never written.
2. **Replays** the epoch's commits from the consensus store, in bounded
   batches of 250 — read a batch, fold it through the same
   `handle_consensus_commit` that processes live commits, release it, read
   the next. Memory is flat in the epoch's age for the commits themselves:
   one batch of commits and their blocks is resident at a time. What the
   fold ACCUMULATES is not flat, and is the subject of the memory section
   below. The replay reads the store directly and does not go through
   consensus-core's commit channel, which is unbounded and would otherwise
   buffer the whole epoch between a producer that scans at disk speed and a
   consumer that folds at handler speed.
3. **Starts consensus** with the index the replay reached, as both
   `replay_after_commit_index` and `consumer_last_processed_commit_index`,
   and follows the live tail from there.

There is **no watermark**. The handler folds every commit of the epoch on
every boot. Exactly-once is replaced by *deterministic fold from empty*: the
double-apply failure shape requires surviving partial state, and a restart
that keeps none removes the category rather than defending against it.

**The split is structural.** A `DBMap` field on `AuthorityEpochTables`
survives restarts by definition; an in-memory field on
`AuthorityPerEpochStore` is rebuilt by definition. There is no classification
to declare, no registry to keep in step with the struct, and no way to get
the two out of sync — which is the whole reason the earlier design's registry
macro, its wipe, and the three tests that enforced the classification are
gone rather than adapted. What remains is one test pinning the set of tables
that stay on disk, so adding one is a deliberate act.

## Why this is sound

Deterministic derivation from the commit stream is already a hard
cross-node requirement — every validator must reach identical checkpoints
and identical convictions from the same commits, or the network forks.
Relying on the same property *within* one node across restarts adds no new
assumption. If a piece of state cannot be re-derived, that is not a replay
problem; it was never a function of consensus, and it belongs on disk (see
the audit).

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
everything the fold derives). Useful, but not the #2057 guard; do not read
it as one.

The torn state is now unbuildable rather than merely handled: there is no
second number left to be ahead of the consensus store's, which is what
`a_consensus_store_that_lost_its_tail_replays_to_its_own_head` asserts.

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
  vote SET does not record. Both start empty on every boot, and refilling
  from the replayed commits reproduces the same prefix and re-pins the same
  quorum-voted count at the same commit — the divergence of ika #1917
  removed at its root rather than compensated for. This is the one place
  where re-derivation has no fallback: the count is not recoverable from the
  vote set, and there is no durable record left to read it from.
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
on 9,752 of 10,000 rounds, at 4096 on none. (That database figure is now
historical: the epoch database holds only the durable tables, and the ten
per-round tables it measured are two changes gone.)

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

## What the fold accumulates, and what bounds it

Holding derived state in memory moves a cost rather than removing one: what
RocksDB used to absorb, RSS now carries. Three things the fold accumulates grow
with the epoch's TRAFFIC rather than with its age, and each needed an answer
before this design was viable at all. A validator idles at roughly 7.5–8 GB RSS
([`../playbooks/ci-suites.md`](../playbooks/ci-suites.md)), so these are
budgets, not rounding.

**Checkpoint signatures and builder outputs — bounded by a prune.** The two
`pending_*_checkpoint_signatures` maps and the two builder-output maps were
never deleted within an epoch, and every signature row carries a FULL checkpoint
message. That is one copy of every checkpoint's content per signer, retained for
the epoch: at a committee of 30 and a kilobyte per checkpoint, ~31 KiB per
checkpoint, which is fine at a checkpoint a minute and fatal at a checkpoint a
second.

They are therefore pruned below the certified watermark
(`prune_dwallet_checkpoint_construction`, `prune_system_checkpoint_construction`,
called once per aggregator pass). Nothing below it is reachable: the aggregator
reads strictly forward from `next_checkpoint_to_certify()` and resets its
in-flight aggregator whenever it finds itself below the watermark. The prune is
LOCAL — both families' write discipline is `local-only`, so which quorum subset
this node aggregates and when a peer's row lands are not observable to peers and
feed no consensus-visible decision — which is what makes dropping them a memory
decision rather than a protocol one.

Two properties of the prune are load-bearing and each has a test that was
validated by breaking it:

- the boundary is `< next_to_certify`, never `<=`. The sequence being certified
  right now is the one still collecting signatures, and dropping it is a
  LIVENESS failure (this node stops certifying and waits for signatures peers
  have no reason to re-send), not a memory one;
- the HIGHEST built message is retained whatever the watermark says. State sync
  can certify past this node's own build progress, and that message is the
  sequence-number cursor `create_checkpoints` reads through
  `last_built_dwallet_checkpoint_message` — dropping it restarts the epoch's
  numbering at the previous epoch's anchor and every checkpoint built afterwards
  is byte-divergent from the committee's.

The residual is deliberate: **retention is now bounded by CERTIFICATION LAG, not
by the epoch.** A node whose certification stalls holds every signature since
the stall, which is correct — a signature must be kept until the checkpoint it
signs is certified — and it means growth here is the visible symptom of a
certification stall. `ika_epoch_pending_dwallet_checkpoint_signatures` and
`ika_epoch_pending_system_checkpoint_signatures` are that signal.

The prune also makes the REPLAY flat rather than the worst case. A boot
re-collects every checkpoint signature of the epoch against a watermark already
at the head, so each is dropped on the next pass instead of accumulating.

"Flat" means flat ACROSS the replay, not smooth within it: the fold re-inserts
at replay speed while the prune fires about once a second, so what an operator
sees during a boot is a SAWTOOTH whose teeth are one prune interval of the
fold's re-insertion rate — full checkpoint-message rows, so tens to hundreds of
megabytes on a deep replay of a busy epoch. It is bounded and self-draining,
and it is normal. The number that matters is the envelope, not the peak.

**That rests on the signature aggregator NOT being replay-gated**, which is an
asymmetry worth stating because it looks like an inconsistency. The checkpoint
BUILDER waits for the replay signal (`builder.run(replay_waiter)`); the
aggregator does not (`aggregator.run()`), on both families. The aggregator is
what prunes, so it has to be looping throughout the replay — it runs at least
once a second — for the drop-on-next-pass argument above to hold. Symmetrizing
the two spawns would look like tidying and would silently turn the boot replay
into the worst case for signature retention. The builder is gated for the
opposite reason: its output submits to consensus, which has not started yet.
The prune's own correctness does not depend on this; only the replay bound
does.

**The processed-transaction dedup set — unbounded, measured, watched.** One
entry per verified consensus transaction of the epoch, never pruned within it:
a duplicate can arrive at any later commit, and evicting would let it be
processed twice. The entry is `Blake2b256(bcs(key))` rather than the key,
because three `ConsensusTransactionKey` variants embed their whole MPC payload
(`ConsensusTransactionKey::embeds_payload`, which is already why the consensus
handler's LRU refuses to cache them) — a set of keys would be budgeted by entry
count times an unbounded per-entry size.

Measured with a counting allocator: a `HashSet<[u8; 32]>` costs **37.7–69.2
bytes per entry**, the spread being where in the doubling cycle the table sits;
budget the high end. Cardinality is the epoch's transaction count, dominated by
`N × (dwallet checkpoints + system checkpoints)` for a committee of N. At one
checkpoint of each per second over a 24h epoch and N = 30 that is ~5.2M entries,
~360 MiB. At one per consensus round (~19.5/s) it is ~100M entries and ~6.9 GiB,
which is not survivable. **The real rate is not measured**, which is why
`ika_epoch_processed_consensus_messages` exists and why the measurement is a
release condition rather than an assumption.

**Exhausting it is a DETERMINISTIC wedge, and that is what makes the
measurement a gate rather than a nice-to-have.** The set is a pure function of
the epoch's distinct verified transactions, so a node that runs out of memory
part-way through a replay re-accumulates the IDENTICAL set on the next boot,
reaches the same point, and dies again — a crash loop that lasts until the
epoch boundary hands it a fresh epoch, which is the same shape of outage as
ika #2057. There is no partial-progress escape: the replay cannot resume from
where the last attempt died, because not resuming is the whole design. The
durable version had the same cardinality but spent DISK for it, and disk
pressure degrades where memory pressure aborts.

Two consequences. The loaded-epoch RSS measurement below is a release gate,
not a follow-up: the failure it guards is unrecoverable-in-epoch rather than
slow. And any future eviction trigger has to be sized against the same
determinism — a threshold that fires on one node's replay must fire on every
node's, or the eviction itself becomes the divergence.

Two levers exist if that measurement comes back badly, neither taken here:

- **an LRU**, the same shape as the handler's existing 1,048,576-entry
  `processed_cache`. Eviction is deterministic over a deterministic stream so it
  stays consensus-uniform, but it changes fold semantics — a duplicate arriving
  after eviction is processed twice — and every arm's idempotence would have to
  be proven individually;
- **dropping the dominant family entirely.** The cardinality is dominated by MPC
  messages and outputs. If session-level handling is provably idempotent per
  `(party, session, round)`, that whole term could leave the dedup set. That is
  a semantics question deserving its own change, not a rider on a conversion.

**The builders' input queues — transient, and peaked by the replay.** In steady
state each queue is bounded by builder lag: the builder deletes everything at or
below the height it built from. During a BOOT REPLAY it is not. The checkpoint
builders wait for the replay signal while the MPC drain deliberately does not
(see above), so across a full-epoch replay the drain fills the queues and
nothing consumes them; each entry carries one consensus round's checkpoint
content.

This peak is accepted rather than defended against, for three reasons: it is
TRANSIENT (the queues drain as soon as the builders are released, unlike the
retention the prune fixed, which was permanent); it is bounded by the epoch's
MPC-output rounds rather than by all of them; and the mechanism that would
remove it is a change to a gate this document specifies. `ika_epoch_pending_dwallet_checkpoints`
and `ika_epoch_pending_system_checkpoints` measure it, sampled where the queues
are MUTATED — deliberately not on a builder pass, since a builder-sampled depth
reports nothing during exactly the window the queues grow without a consumer.

Two approaches were considered and rejected for this change:

- **prune the queue on arrival against the certified watermark**, the way the
  signatures are pruned. It does not work, twice over. The queue is keyed by
  consensus HEIGHT while the watermark is a checkpoint SEQUENCE NUMBER, and the
  only thing relating them is written by the builder as it builds — during a
  from-scratch replay there is nothing to test against. And even given a
  mapping, skipping already-certified heights would shift every later sequence
  number: the builder must BUILD every checkpoint of the epoch to reproduce the
  committee's numbering, and what it must not do is re-SIGN them, which the
  settled-state suppression already handles;
- **release the builders during the replay.** This is the mechanism that works,
  and it is the one to reach for if the measurement comes back badly. It was not
  taken here because it changes the builder gate this document specifies, on an
  argument (the parking flood) that the emission suppression has since covered,
  and coupling that re-specification into an already-large conversion is how
  riders become incidents. A bounded queue with a blocking producer is the same
  change wearing a different hat: it deadlocks under the current gate, since a
  blocked drain fills the round channel, which parks the replay, which never
  releases the builders.

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

The boot no longer pays a deletion pass before it starts — there is nothing
to delete — so restart-to-live is the replay and only the replay. Three
gauges make it observable: `ika_consensus_boot_replay_target_commit_index`,
`ika_consensus_boot_replay_folded_commit_index` (the two together are the
remaining boot work) and `ika_consensus_boot_replay_latency_seconds`. The
replay also logs progress per batch, because a boot that legitimately takes
tens of minutes must be distinguishable from one that is stuck.

What the boot pays instead is the memory it accumulates as it folds, which is
the section above rather than a latency term.

## Rolling back

**The clean-rollback property is gone**, and it costs more than it did when
only the per-round tables were deleted. An older binary rolled back mid-epoch
finds an epoch store holding NOTHING it recognises as progress: the per-round
column families are absent, and so now are every fold-side table and any
record of how far the handler got.

The consequence is one thing, not two, because the two run in sequence: the
old binary's fold starts from the epoch's first commit against empty tables and
re-derives the whole epoch through its own table-WRITING path — and the tables
it writes on the way are the same per-round tables its MPC drain reads. The
argument that used to cover the re-fold ("`last_consensus_stats` holds the tally
of a full replay, which is what the old binary would have written itself") is
dead: there is no tally to inherit. What replaces it is that the old binary's
own code rebuilds what it needs, so the drain is starved only for as long as the
re-derivation takes, not for the rest of the epoch.

Two things this costs, both of them transient:

- **restart-to-live, on the old binary too.** Its `replay_after` is
  `last_processed_subdag_index()`, read from the absent watermark, so it is 0
  and consensus re-sends the epoch from its first commit. The node follows
  consensus and produces checkpoints throughout; its MPC participation returns
  once the re-derivation reaches the round its peers have consumed.
- **re-emission into the DAG.** The re-fold runs against an empty
  `consensus_message_processed` table, so the old binary re-submits work it has
  already settled and peers discard it as already-folded. The dominant term is
  MPC messages and outputs replayed over the rebuilt rounds. It is NOT an
  epoch of checkpoint signatures: v1.3.1's own submission gate
  (`get_highest_verified_dwallet_checkpoint`) reads the perpetual checkpoint
  store, which a rollback does not touch, so it re-signs only the band between
  the verified watermark and what had been certified — the band this binary's
  broader `get_highest_settled_dwallet_checkpoint_seq` closed. Earlier drafts of
  this section claimed the old binary had no settled-state suppression at all;
  it has the narrower one.

Everything above is read off the two binaries' source; what MEASURES it is the
`mid_epoch_rollback` scenario in `ika-upgrade-test`, which runs the candidate
first and puts the v1.3.1 release back on one validator mid-epoch, on the same
stores. It asserts the re-derivation reaches the peers' consumed round (the
witness is `ika_last_process_mpc_consensus_round` on the rolled-back node,
which v1.3.1 sets from the tables its own fold writes), counts the re-emission
at the peers on `ika_skipped_consensus_txns` against a control window of
ordinary traffic, and requires a peer to witness an MPC output authored by the
rolled-back validator for a session created after the catch-up. The whole run
is bracketed by an epoch ceiling, because a boundary would hand the node a
fresh epoch store and make all three free.

Two numbers this section still owes, both of which that scenario produces on
its first green run and neither of which should be guessed in the meantime:
how many already-settled consensus transactions a rollback re-sends, and how
long the re-derivation leaves the node's MPC degraded.

**Release note, for lifting verbatim into operator notes:** rolling this binary
back mid-epoch puts that node through a full re-derivation of the epoch before
it is fully live again. It starts, follows consensus and keeps producing
checkpoints immediately, but its MPC drain has no round history until its own
fold rewrites it from the epoch's first commit — so expect degraded MPC
participation from that node for the length of the re-derivation, which scales
with how far into the epoch the rollback is taken. While it re-derives, it
re-submits work the network has already settled, and peers discard it as
already-folded: expect DAG noise, not corruption. A rollback taken *at* a
boundary is unaffected and costs neither. This must not be discovered
mid-incident: an operator rolling back to recover from something else needs to
know the recovery costs a re-derivation, and that the cost is paid once rather
than until the next boundary.

## What this is tested by, and what it is not

Three of the remainders below are **release conditions**, not follow-ups —
tracked in ika issue #2064: the real-payload upstream queue bytes (measured on
a cluster or bounded defensively), the wedged-but-alive drain end to end
together with the alerts that are its only detection, and the memory the fold
accumulates on a loaded node. The last one is three series off the same run:
`ika_epoch_processed_consensus_messages`, the two
`ika_epoch_pending_*_checkpoint_signatures`, and the two
`ika_epoch_pending_*_checkpoints` against RSS. Everything else here is ordinary
follow-up work.

In-process, in `ika-core`:

| property | test |
|---|---|
| only state no replay reproduces stays on disk | `the_epoch_store_keeps_only_state_no_replay_reproduces` — pins the table list, so adding one is deliberate |
| a reopen holds no derived state and keeps every durable table | `a_reopened_store_holds_no_derived_state_and_keeps_its_durable_tables` |
| releasing the store FREES the derived state, and reads then report the epoch ended | `derived_state_reads_fail_once_the_epoch_store_is_released` |
| the fold is deterministic from empty | `folding_the_same_commits_twice_rebuilds_identical_derived_state` |
| the checkpoint prune keeps the sequence being certified (`<`, not `<=`) | `the_checkpoint_prune_keeps_the_sequence_being_certified` |
| the checkpoint prune keeps the sequence-number cursor when state sync runs ahead | `the_checkpoint_prune_keeps_the_sequence_number_cursor` |
| a folded transaction is marked processed before its waiter wakes | `a_folded_transaction_is_marked_processed_before_its_waiter_wakes` |
| the `all_voted` count is the quorum-crossing membership, and a restart re-derives it | `the_pinned_all_voted_count_is_the_quorum_crossing_membership`, `a_restart_re_derives_the_same_pinned_count_and_grace_anchor` |
| a restart resets the freeze gauges, and the re-fold re-publishes them | `freeze_metrics_reset_on_restart_and_republished_by_the_refold` |
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
and confirming the predicted evidence (`../playbooks/test-testing.md`) — which
is how the prune's two boundary conditions were found to need tests at all:
neither the `<=` off-by-one nor the lost sequence-number cursor was visible
from the design, only from the call sites.

What in-process coverage cannot reach, and belongs on CI or a cluster:

- **Kill-storm** — repeated `kill -9` under load, including mid-replay and
  mid-batch. Consensus-core has the precedent to imitate:
  `consensus/simtests/tests/consensus_tests.rs`
  `test_consensus_crash_and_restart` (:135) and
  `test_consensus_rolling_restarts_all_validators` (:223) already drive
  full-replay-from-zero consumers through crash storms.
- **The restart-to-live latency budget** at ≥90% epoch age, read off
  `ika_consensus_boot_replay_*`.
- **What the fold accumulates over a >1M-round epoch** (REQUIRED): the five
  series named above against RSS. This replaces the old "memory flatness"
  remainder, which was about the replay's commit batches — those are still
  flat; what is not is the state the fold builds from them.
- **The real boot path end to end** — replay, consensus start, builders
  released — which only `ika-test-cluster` exercises (`restart_mid_grace`,
  `cluster_boots`).
- **Correlated restarts across the close window** (REQUIRED, not
  optional): kill at least f+1 stake after `end_of_publish_quorum_round` is
  set but before the final checkpoint certifies, and assert the epoch still
  advances. This is the scenario the close-round re-roll above makes newly
  reachable, and the one place a traced "bounded blast radius" should be
  replaced by a measurement.
- **Mixed old/new binaries sharing an epoch** (`ika-upgrade-test`). The
  forward direction is covered by `v131_rollout` / `v131_churn`; the BACKWARD
  direction — the rollback section above — is `mid_epoch_rollback`, which puts
  the v1.3.1 release back on one validator mid-epoch and asserts the
  re-derivation reaches the peers' consumed round, counts the already-settled
  work it re-sends, and requires a peer to witness it authoring MPC output
  again inside the same epoch.
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
- A durable copy of anything the commits determine. It survives a restart the
  replay does not rewind, so it can hold rows for commits the consensus store
  no longer backs — and because the split is structural, adding a `DBMap`
  field IS that decision, with no classification step in between to catch it.
  `the_epoch_store_keeps_only_state_no_replay_reproduces` is where the
  decision surfaces.
- Emission suppression keyed on local progress rather than on settled state.
- In-memory derived state that outlives its epoch. The store is held past the
  boundary, so anything not cleared in `release_db_handles` is an epoch's
  worth of RSS retained until the last `Arc` drops.
