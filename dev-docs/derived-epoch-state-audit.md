# Derived vs preserved: the per-epoch table audit

Every field of `AuthorityEpochTables`
(`crates/ika-core/src/authority/authority_per_epoch_store.rs`) is classified
**derived** — deleted on every boot and rebuilt by replaying the epoch's
consensus commits — or **preserved** — left alone, because no replay
reproduces it.

The model this serves is
[`specs/event-sourced-epoch.md`](specs/event-sourced-epoch.md). This file is
the reasoning; the machine-checked half is the `epoch_state_registry!`
invocation in `authority_per_epoch_store.rs`, which is the single list that
generates the wipe, the post-wipe emptiness check, and the row-level
snapshot the tests compare.

## Why misclassification is silent both ways

| mistake | what happens |
|---|---|
| derived table marked **preserved** | the replay rewrites most of its rows, so it usually looks fine — until a boot whose consensus store lost its tail (ika #2057) keeps rows for commits the store no longer has, and the MPC drain replays rounds no commit backs. Tables the fold *accumulates* into rather than overwrites double-count instead. |
| preserved table marked **derived** | it is deleted and nothing rebuilds it. Presign material, secret shares and idempotency markers simply vanish; the pool then re-serves presigns peers consider spent. |

Neither produces an error at the moment it is made.

## How the classification is enforced

Four tests in `authority_per_epoch_store.rs`'s `mod tests`, each
fault-validated against the mistake it claims to catch:

| test | catches |
|---|---|
| `every_epoch_table_is_classified` | a table added without a classification, by comparing the registry against the column families `DBMapUtils` generated |
| `every_table_the_consensus_fold_writes_is_classified_derived` | a **misclassification**, by taking the truth from behaviour: it folds real commits through the real commit boundary and requires every table that got written to be derived |
| `wipe_empties_every_derived_table_and_preserves_the_rest` | an incomplete wipe, or one that reaches a preserved table |
| `folding_the_same_commits_twice_rebuilds_identical_derived_state` | non-determinism, and a preserved table wiped by mistake, by reopening the store the way a validator boots and comparing every classified table byte for byte |

The middle one is load-bearing and easy to leave out. The double-fold test
alone does **not** catch a derived table marked preserved: the per-round
tables are keyed by round, so a second fold of the same commits simply
overwrites them and the comparison passes. Only the behaviour-derived check
notices.

## Derived — deleted on boot, rebuilt by replay

Grouped by why, not by declaration order.

**The fold's own bookkeeping.** `consensus_message_processed` is the
processed-marker set the fold writes as it goes; keeping it would make the
replay treat every transaction as already handled and produce an empty
epoch. `last_consensus_stats` is its running index and per-author tallies.
`epoch_first_commit_timestamp_ms` is the first replayed commit's timestamp —
directly re-observable now that replay starts at the epoch's first commit,
which is why the row's original justification ("replay resumes mid-epoch, so
this is otherwise unrecoverable") no longer applies.

**Filters of a commit's transactions.** `dwallet_mpc_messages`,
`dwallet_mpc_outputs`, `dwallet_internal_mpc_outputs`,
`idle_status_updates`, `sui_chain_observation_updates`,
`global_presign_requests`, `noa_observations`, `noa_presign_demands`. Each
row is a projection of one commit, written in that commit's batch.

**Outputs of the fold.** `verified_dwallet_checkpoint_messages` and
`verified_system_checkpoint_messages` are what the fold produces for a
commit, not inputs to it.

**Checkpoint construction.** `pending_dwallet_checkpoints` and
`pending_system_checkpoints` are built from the rebuilt per-round streams
and keyed by consensus round, so a rebuild lands identical heights.
`builder_dwallet_checkpoint_message_v1` and `builder_system_checkpoint_v1`
are the builders' output over that queue, deterministic in it.
`pending_dwallet_checkpoint_signatures` and
`pending_system_checkpoint_signatures` hold peers' signatures, which arrive
as sequenced `*CheckpointSignature` transactions.

**Votes and epoch-lifecycle anchors.** `authority_capabilities_v1`,
`end_of_publish`, `end_of_publish_quorum_round`,
`end_of_publish_quorum_voted_count`, `epoch_close_emitted`,
`mpc_data_ready_quorum_round`, `mpc_data_freeze_round`. Every row is decided
at a commit boundary from sequenced input, and the replay re-decides it at
the same commit. `end_of_publish_quorum_voted_count` is the interesting one:
it exists because the live aggregator caps at quorum while the vote table
does not, and wiping both is what makes the recomputed count exact rather
than merely close — see the spec.

**Off-chain metadata and the freeze.** `validator_mpc_data_announcements`
and `epoch_mpc_data_ready_signals` come from sequenced (or
sequenced-relayed) messages; `frozen_validator_mpc_data_input_set` and
`epoch_excluded_validators` are the two halves of a partition decided at one
commit boundary from those signals.

**`handoff_signatures`.** Rows come from sequenced `EndOfPublishV2` bundles.
This one is derived *because* the epoch-close gate reads it: preserving it
would let the gate see signatures the replayed commits have not re-counted,
which is the ika #1917 shape. The buffered-drain path re-stages every bundle
once this validator's expected attestation installs, so the replay rebuilds
it — though under a later commit than the original run, which is the residue
the spec documents.

## Preserved — no replay reproduces it

**Presign material and everything keyed to it.** The eight
`internal_presign_pool_*` tables hold presigns this node computed. The
replay does not re-run the cryptography — the catch-up gate deliberately
suppresses it — and the pops that consume the pool are not all
consensus-ordered, so a rebuilt pool would serve different presigns than
never-crashed peers bound (ika #1928). `internal_presign_pool_sizes` rides
the pools in their own batches; wiping it while the pools survive would
report empty pools and trigger endless top-ups.

Because the pools are preserved, so is everything that makes replay
idempotent against them:

- `filled_presign_pool_slots` — the marker consulted before absorbing a
  replayed internal-presign fill. Wiping it double-absorbs, which both
  inflates the size counter (suppressing top-ups until the pool physically
  starves) and resurrects already-served presigns (ika #1934).
- `served_global_presigns` — which presign was served for a request, read
  back instead of re-popping. Without it the replay serves a different
  presign than the committee put in its checkpoint message.
- `noa_presign_demand_resolutions` — the terminal outcome per demand,
  assigned or abandoned. Wiping it re-pops for demands the committee
  already gave up on.
- `used_presigns` — the monotone retirement marker; losing it lets one
  presign be consumed twice.
- the eight `assigned_presigns_*` tables — an assignment already carved out
  of the pool, so the pool row is gone and the assignment is the only
  remaining copy.
- `presign_private_outputs` — this validator's own secret nonce shares from
  VSS presign sessions. Never published, so no commit could carry them.

**Content-addressed protocol-output caches.**
`network_dkg_output_digests` and `network_reconfiguration_output_digests`
cache outputs this node computed or read from Sui and peers. The replay does
not re-run the cryptography, and the handoff attestation reads them.

**Operator state.** `override_protocol_upgrade_buffer_stake` is set by this
node's operator over the admin interface. No commit carries it, and the
protocol tolerates validators disagreeing about it.

## Non-determinism audit of the fold

The audit's third question is whether any handler side effect is not a
function of the commits. The set is empty for anything a decision reads:

- **Wall clock.** `Instant::now()` and `SystemTime` appear on the commit
  path only in metrics, log fields and latency histograms. The epoch's
  consensus clock is `commit_timestamp_ms`, carried in the commit itself and
  anchored at `epoch_first_commit_timestamp_ms`; the freeze and close graces
  are leader-round deltas, not durations. The one place the wall clock
  reaches a *decision* is the MPC service's per-iteration pacing (re-emit
  intervals, park bounds measured in consensus rounds but ticked by a
  timer) — which lives in the drain, not the fold, and whose durable
  outcomes are recorded per demand (`noa_presign_demand_resolutions`) for
  exactly this reason.
- **Randomness.** No sampling on the fold path. The nonces that make idle
  and observation updates unique are sampled by the *submitter* and travel
  inside the sequenced transaction, so the fold sees a fixed value.
- **Local state read by the fold.** Three, not two — the third is the one
  worth knowing about:
  1. The expected handoff attestation gates `handoff_signatures` writes.
     Documented residue; see the spec's close section.
  2. `should_accept_tx` reads `reconfig_state`, which the replay itself
     drives from `epoch_close_emitted` and the close decision.
  3. **The mpc_data freeze commit reads the PRIOR epoch's certified handoff
     attestation from the PERPETUAL store**, for carry-forward
     (`authority_per_epoch_store.rs:5060` → `prior_epoch_mpc_data_digests`,
     `:4954-4992`). That is a consensus-visible decision — the frozen set —
     taking an input from outside the commit stream.

     Its divergence window is one-directional and narrow. A read error or a
     missing perpetual handle FAILS the commit so it replays, rather than
     degrading to an empty map, which is deliberate: a silent empty would
     re-open the shrunken-set fork the function exists to close. What is not
     fenced is `Ok(None)` → `Ok(Some(cert))`: the certificate is never
     deleted, so the only possible skew is absent-then-present. A joiner
     that froze while the cert was still absent, crashed, and restarted
     after bootstrap fetched it re-decides the freeze with a LARGER
     carry-forward set.

     Traced consequence: benign to positive. Carry-forward only ADDS
     members the committee's own certificate attests to, so the re-decided
     set moves toward the committee's set, never away from it — the
     opposite of the shrunken-set hazard. It is listed here because the
     audit's job is to enumerate the inputs, not because this one is known
     to be harmful; a future change that makes the frozen set
     order-sensitive, or that ever deletes a certificate, would turn it
     into one.

## Why the wipe is unconditional

Every writer of a Derived table is inside the validator components, which only
start for a committee member running in validator mode:

| Derived table | writer outside the consensus fold |
|---|---|
| `pending_dwallet_checkpoints` | the MPC drain (`dwallet_mpc_service.rs:2113`) |
| `builder_dwallet_checkpoint_message_v1`, `builder_system_checkpoint_v1` | the checkpoint builders |
| `pending_dwallet_checkpoint_signatures`, `pending_system_checkpoint_signatures` | `notify_checkpoint_signature`, reached from the fold and from `IkaTxValidator` during block validation (`consensus_validator.rs:111`, `:130`) |

Everything else is written only by `ConsensusCommitOutput::write_to_batch`.

**State sync writes no per-epoch table at all** — `ika-network/src/state_sync`
has no reference to `AuthorityPerEpochStore`; its certificates and watermarks
live in `DWalletCheckpointStore` / `SystemCheckpointStore`, separate databases
outside this audit. So the preserved-class "state-sync artifacts" the issue
names are never at risk from the wipe, and no Derived table is fed by sync.

So on a notifier, a fullnode, a non-committee node, or a committee member
running in fullnode mode, every Derived table is already empty and the wipe is
a no-op. There is no node on which "wipe" and "leave alone" differ, which is
why the store has no policy parameter: `AuthorityPerEpochStore::new` always
wipes. The only exception is
`new_retaining_derived_state_for_testing`, for tests whose subject is the
durable write discipline itself — that a commit-batched row survives a crash
at any point and rehydrates the in-memory state built from it. That property
still holds within a boot; it is simply not what a production reopen
exercises.

## One thing outside this audit worth an eye

`locally_computed_checkpoints` (in `DWalletCheckpointStore` and
`SystemCheckpointStore`, not `AuthorityEpochTables`) is not wiped and is not
covered here, because those are separate databases. It exists for fork
DETECTION and logging; no decision path reads it. That is the only reason
its survival is safe: rows written before a divergence would be stale
relative to a rebuilt epoch. If a reader is ever added that acts on it,
revisit — it would need either wiping alongside the derived tables or an
argument for why stale rows cannot mislead it.

## Adding a table

1. Add the field with its `write-discipline:` line
   ([`conventions/epoch-table-write-discipline.md`](conventions/epoch-table-write-discipline.md)).
2. Add it to the `epoch_state_registry!` invocation with a one-line reason.
   `every_epoch_table_is_classified` fails until you do.
3. If it is preserved, say in the reason what a replay would have to redo to
   rebuild it, and check that
   `every_table_the_consensus_fold_writes_is_classified_derived` still
   passes — if the fold writes it, it is not preserved.
4. Add the row to the appropriate section above.
