# Epoch-table write discipline

Every field of `AuthorityEpochTables`
(`crates/ika-core/src/authority/authority_per_epoch_store.rs`) declares,
in its doc comment, **how it is written** — one `write-discipline:` line.
CI enforces the presence of that line
(`scripts/check-epoch-table-write-discipline.sh`); review enforces that
it is true.

Every table here survives every restart, un-rewound by the boot replay —
that is what being a table MEANS now, and it is why the store holds only
state no replay reproduces. State the commits determine lives in memory on
`AuthorityPerEpochStore` instead. Adding a table is therefore a decision
before it is a discipline question:
[`../preserved-epoch-state-audit.md`](../preserved-epoch-state-audit.md) is
what to answer first, and
[`../specs/event-sourced-epoch.md`](../specs/event-sourced-epoch.md) is the
model behind it.

## The rule

**Writing.** A new table, or a new write site for an existing one, must
state its discipline in the table's doc comment:

```rust
/// write-discipline: commit-batched
/// write-discipline: direct — safe because <reason>: <consumer it protects>
/// write-discipline: direct — UNPROVEN (#issue)
```

**Reading.** A new consumer of a *direct-written* table must re-check
the stated reason still holds for it, and say so in the PR description.
This half is not optional and not secondary: #1917 was born on the
reader side. The write (`record_end_of_publish_vote`) was fine for years;
the bug arrived when `all_voted` started folding an **arrival-order-capped**
view of an **uncapped** table, which silently invalidated the
pure-function-of-table reason a screen away.

If the reason no longer covers the new consumer, you have two options,
in order of preference:

1. Move the write into `ConsensusCommitOutput` so the row lands in the
   commit's batch (the #1920 fix template), or
2. Pin the consumed value at the deciding commit and persist *that*
   through the commit batch (the `end_of_publish_quorum_voted_count`
   template, for when the table itself cannot move).

Do not weaken the consumer instead ("read it a bit later", "tolerate a
one-vote difference") — every one of these decisions is compared across
validators, so "usually equal" is a divergence with a longer fuse.

## The two disciplines

(The per-round streams this rule used to be mostly about are gone: the MPC
drain is fed from the fold over a channel. So is everything the commits
determine — votes, anchors, the freeze partition, checkpoint construction —
which now lives in memory. What is left on disk is the presign material, the
private VSS outputs, the output caches and the operator override, and every
one of them is `direct`.)

**`commit-batched`** still exists, but it describes the in-memory
commit-boundary group rather than a table. `ConsensusCommitOutput::apply_to_epoch_state`
applies everything a commit derived under ONE lock, which is what the single
RocksDB batch it replaced gave concurrent readers: no reader sees the freeze
partition without the freeze round, or the close marker without the votes
that justified it. It remains **required** for anything a consensus-visible
decision reads — the close round, the freeze partition, checkpoint content —
and the reason is unchanged even though the mechanism is a lock instead of a
batch. What DID change is the crash half of the argument: a crash no longer
tears a pair, it loses the whole epoch's derived state, and the replay
rebuilds it. Atomicity here is now purely about concurrent readers.

**`direct`** — written outside the commit boundary, with a stated reason.
Fixed vocabulary, so the reasons stay comparable:

| reason | means | check it by asking |
|---|---|---|
| `pure-function-of-table` | every consumer folds the WHOLE table, no arrival-order or size cap | does any reader take a prefix, a snapshot, a count-at-a-moment, or stop early? |
| `idempotent-replay` | re-running the producing work rewrites the same key with the same value | is the key derived from the input (round, digest, demand) rather than from the output? |
| `local-only` | nothing consensus-visible reads it — this node's own scheduling, secrets, or operator overrides | would two validators disagreeing about this row's presence change anything either one broadcasts? |
| `content-addressed` | the key is a hash of the value | can a rewrite ever store different bytes under the same key? |

**`direct — UNPROVEN (#issue)`** — a direct write whose argument does not
close. Tracked, not blessed. One exists today: the presign pools (#1928,
pops commit in their own batch, so a replay can bind a different presign
than peers). Adding a consumer that depends on the unproven property is a
blocker, not a judgement call.

`handoff_signatures` was the other one until #1927 moved all three of its
writers — the consensus arm, the buffered drain, and the stale-row
cleanup — onto `commit-batched`. It is in-memory state now rather than a
table, but the conversion is still worth reading as the worked example of
converting a writer rather than annotating it: the writers that were not
on the consensus thread had to stage into the epoch store and let the
next commit fold them in, and the gate had to start reading the
committed table *overlaid with the evaluating commit's own staged rows*,
or every row would have been visible one commit later than the binary
next to it in the rollout saw it. Note also what the conversion does not
buy: `commit-batched` says a row lands with a commit, not that the same
commit is the one peers land it under.

## Why this class earns a convention

Four findings in one month reduce to a reader/writer discipline mismatch
on these tables:

- **#1917 / #1920** — capped in-memory aggregator vs. uncapped table
  rebuilt on restart → different close rounds.
- **#1829** — freeze partition written per-row instead of in the commit
  batch → a partial write latched a shrunken frozen set permanently.
- **#1927** — handoff signatures drained into the table at local install
  time, read by a consensus-visible gate.
- **#1928** — pool pops committed in their own batch, ahead of the commit
  that consumed them.

None of these was a hard bug to see once someone asked "who writes this,
who reads it, and what happens if the process dies between them". The
convention exists to make that the *default* question at the table
definition, rather than something rediscovered per incident.

## Checking your work

```bash
./scripts/check-epoch-table-write-discipline.sh          # CI check
./scripts/check-epoch-table-write-discipline.sh --list   # field -> declaration inventory
```

The check is deliberately shallow — it verifies a line exists, not that
it is true. It catches the failure mode where a table is added and the
argument is never made at all.

To find every direct write site for a table, grep the field name in
`authority_per_epoch_store.rs`: any `.insert(`, `.remove(`,
`insert_batch(&self.<field>` / `(&tables.<field>` outside
`write_to_batch` is a direct write.
