# Consuming consensus output

The rules every subsystem follows to get data out of consensus. They are not
specific to any one consumer — a new subsystem that needs per-commit data
follows these, and reviewers hold new consumers to them.

## 1. The consensus store is the only durable truth for epoch-scoped state

Everything derived from it is deleted at boot and rebuilt by replaying the
epoch's commits. Nothing records how far the node got.

*Why:* one logical fact in two databases with no shared fsync discipline is a
brick waiting for a storage incident — a validator was down for most of an
epoch when its per-epoch watermark and the consensus store disagreed by one
commit (#2057). Deriving removes the disagreement; reconciling only shrinks
the window.

Model: [`../specs/event-sourced-epoch.md`](../specs/event-sourced-epoch.md).
Per-table classification:
[`../derived-epoch-state-audit.md`](../derived-epoch-state-audit.md).

## 2. The fold is the only reader of consensus output

A subsystem that needs per-commit data receives it **from the fold**, over a
bounded blocking channel. Never its own cursor into the consensus store, never
a new persisted round stream, never a watermark under any name.

*Why:* a second reader is a second interpretation of the same commits, and the
two can disagree in ways nothing detects. It is also not implementable as a
cursor — consensus-core holds the store as a RocksDB primary, and some of what
a consumer needs (checkpoint message sets) is fold *output*, not a projection
of the commit.

A new consumer is a new channel receiver. Its derived state joins the registry
as `Derived`, and the classification test will fail until it does.

## 3. Channel caps are named constants with the dial documented

Every transport declares its capacity as a named constant whose comment states
the trade, and every channel gets a depth gauge and a blocked-time gauge at
birth — not when someone first needs to debug it.

*Why:* the cap is a real dial across its whole range, not a threshold. Measured
on a 50k-commit fixture with the drain five times slower than commit
production, rounds the fold had to wait on: cap 64 → 9,752; 256 → 9,130;
1024 → 6,376; 4096 → 0. Smaller pins the fold to the consumer sooner; larger
holds more rounds in memory, and above the burst depth stops applying
backpressure at all.

## 4. Commit liveness is fed at ARRIVAL, before any channel

A blocked consumer must never look like consensus silence.

*Why:* the commit-liveness watchdog exits the node when commits stop, and it
exists to catch a validator whose subscriptions were lost at an epoch boundary
(#2054/#1864) — commits no longer *arriving*. A fold waiting on a slow
consumer is the opposite of that, and killing the node for it produces a
burst → kill → replay → burst loop.

Arrival reporting is not sufficient on its own: while the fold waits, the loop
is not receiving, so no arrivals are stamped either. The transport therefore
publishes a flag while the fold is parked, and the watchdog treats it as a
hold — the same input the reconfiguration phase feeds.

**This is not a wedge detector, deliberately.** A consumer that stops
consuming entirely parks the fold and holds the watchdog indefinitely. That is
correct for a watchdog scoped to isolation, and it means a wedged consumer has
exactly one signal: blocked time climbing while the consumer's progress metric
is flat. Alarm on that pair, not on the watchdog.

## 5. Two sinks, opposite placements — do not "fix" the asymmetry

| sink | fed | why |
|---|---|---|
| `ConsensusCommitSink::commit_received` (ika's liveness watchdog) | **arrival**, before the fold | a fold waiting on a consumer is busy, not isolated (rule 4) |
| `CommitConsumerMonitor::set_highest_handled_commit` (consensus-core) | **after the fold** | it is a memory guard: `commit_syncer` pauses fetch scheduling when `highest_handled_index + threshold < range_end` (`commit_syncer.rs:238`, reading `commit_consumer_monitor.highest_handled_commit()` at `:205`; threshold = `commit_sync_batch_size` × `commit_sync_batches_ahead` = 100 × 32 = 3,200 at `consensus/config/src/parameters.rs:203`/`:220`). Reporting it early would remove the backpressure that bounds sync-fed backlog. |

They will look confusable to the next reader, which is why both call sites say
so. Anchors are at the pinned rev
`51d177ad7d65102fc368b582408f466d97b31548`; re-verify on a Sui bump.

## 6. Emission of already-settled work is gated on convergent settled state

Suppress re-emission against observations about the network — certified
checkpoints, aggregated signatures, chain state — never against a record of
this node's own progress.

*Why:* a local progress counter is exactly the second truth rule 1 deletes.
"A stake quorum certified this" is something every validator converges on from
the same evidence, in any order.

Rule of thumb for a new submitter: **suppress where the re-emission's volume
scales with the epoch's age; re-emit where it scales with live session state
and peers deduplicate cheaply.**

## 7. A consumer that stops must detach, never wedge the fold

When a consumer deliberately exits — the self-stop a validator performs on
recognising itself as malicious (#1978, #1980) — the fold logs loudly, drops
its sender, and keeps folding.

*Why:* checkpoints, votes and the epoch close all come out of the fold and
none of them need the consumer. A fold that stopped would turn one
subsystem's stop into that validator withdrawing its stake from checkpoint
certification for the rest of the epoch.

(tokio already resolves a send once the receiver drops, so the fold cannot
wedge whatever the code does. What the code owes is *noticing* — one loud
line, so a node quietly doing no MPC for an epoch is visible.)

## 8. What must never be reintroduced

- A persisted record of how far the fold got, used to skip commits — under any
  name.
- A second persisted copy of the commit stream that is not wiped at boot. A
  copy that survives a restart can hold rounds the consensus store no longer
  backs.
- Emission suppression keyed on local progress rather than settled state.
- Commit-liveness reporting moved back after the fold (rule 4), or
  `set_highest_handled_commit` moved before it (rule 5).
