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

On every start, a validator that will run consensus for the current epoch:

1. **Wipes** every per-epoch table classified *derived*
   (`AuthorityEpochTables::wipe_derived_state`), before anything reads the
   store. The wipe is a startup invariant, asserted: if any derived table
   still holds a row, the process aborts rather than fold onto it.
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
tolerantly: the two numbers are now the same number, so they cannot
disagree. The empty-store case lands on `replay_after == 0`, which is what
consensus asserts there.

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
the one the crashed run picked. It is not a new divergence class — it is the
same pre-existing non-purity, reached by a different route, and the rebuilt
checkpoint stream is self-consistent with whichever round this validator
does pick — but it is the part of this change with the least margin, and
the one to look at first if a restart near an epoch boundary produces a
final checkpoint no peer signs. Retiring it properly is the sequence-pure
tally in `../plans/handoff-barrier-escape-and-pure-close-gate.md`, which
would make the question moot.

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

### Nothing may submit before consensus is up

Suppression is not enough on its own, because of *when* the replay runs. The
checkpoint builders are started before consensus, and the consensus adapter's
client panics if it is still unset 300s after a submission is issued — under
`panic = "abort"`, that ends the process. Rebuilding an old epoch takes far
longer than 300s, and the replay regenerates the builders' whole input queue,
so a node that had not certified this epoch's early checkpoints would abort
partway through its own recovery.

Both builders therefore await the same replay signal the MPC service waits
on (`ConsensusManager::replay_waiter`) before their first pass. The
subscriptions are taken before consensus start is spawned, so the signal
cannot be published into an empty subscriber set. The rule generalises: any
component whose work submits to consensus must be gated on that signal, not
merely on having been constructed.

The catch-up gate (`dwallet_mpc/catchup_gate.rs`) is the other
replay-aware emission gate, and it is a different tool: it keys on distance
behind the tip and suppresses *starting new cryptographic computations*, not
on whether a given piece of work is settled. Its semantics are unchanged
here; its gap is still store head minus drain cursor.

## The MPC drain

The `DWalletMPCService` drain is unchanged: an in-memory round cursor
starting at the epoch's beginning, walking the per-round tables the fold
writes. Those tables are derived, so they are wiped and rebuilt with
everything else, and the drain re-reads what the fold has rebuilt.

This is what keeps the drain decoupled from the handler. The drain does
crypto and lags; the handler must reach the store head. The per-round tables
are the disk-backed slack between them, and because they are deleted and
re-derived on every boot they cannot survive a restart holding rounds the
consensus store no longer backs.

## Consensus-store retention is load-bearing

The epoch's full commit history must survive until the epoch boundary, or
the rebuild is impossible. Today it does — the consensus store is
per-epoch (a directory per epoch, dropped at the boundary) and
`RocksDBStore` prunes nothing within one — but the replay asserts it rather
than assuming it: a scan that returns fewer commits than the range it asked
for aborts with a message naming the condition, instead of silently
producing derived state that is missing a commit's effects.

## Restart latency

Restart-to-live is now O(epoch age) for the whole node, not just for the MPC
drain. This is an accepted cost, not an accident. Three gauges make it
observable: `ika_consensus_boot_replay_target_commit_index`,
`ika_consensus_boot_replay_folded_commit_index` (the two together are the
remaining boot work) and `ika_consensus_boot_replay_latency_seconds`. The
replay also logs progress per batch, because a boot that legitimately takes
tens of minutes must be distinguishable from one that is stuck.

## Rolling back to a binary that expects the watermark

An older binary reads `last_consensus_stats` to decide where to resume. After
this binary has run, that row holds the tally of a full replay to the head —
which is the same value the old binary would itself have written, so a
rollback *within the same epoch* resumes from the correct place and behaves
as it always did.

What the old binary does NOT get back is the guarantee that the row agrees
with the consensus store: it resumes trusting its own record again, so it is
once more exposed to ika #2057 if a storage incident costs the consensus
store its tail. The rollback is therefore safe in the ordinary case and
carries the original risk in the incident case — it does not add a new
failure mode, and it does not require an epoch boundary to be crossed first.

The per-round tables an older binary's MPC drain reads are also intact: they
are rebuilt by the replay, so a rolled-back binary finds a dense stream from
the epoch's first commit to the head, which is exactly what it expects.

## What must never be reintroduced

- A persisted record of how far the handler got, used to skip commits. It is
  the second truth this design deletes, under any name.
- A second persisted copy of the commit stream that is not wiped on boot. A
  copy that survives a restart can hold rounds the consensus store no longer
  backs.
- Emission suppression keyed on local progress rather than on settled state.
