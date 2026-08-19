# What the per-epoch store keeps on disk, and why

`AuthorityEpochTables`
(`crates/ika-core/src/authority/authority_per_epoch_store.rs`) holds **25
tables, and every one of them is state no replay reproduces.** Everything else
an epoch derives — the fold's own bookkeeping, checkpoint construction, votes,
lifecycle anchors, the freeze partition, the handoff signatures — lives in
memory on `AuthorityPerEpochStore` and is rebuilt by replaying the epoch's
commits on every boot ([`specs/event-sourced-epoch.md`](specs/event-sourced-epoch.md)).

The split is **structural**, not declared. A `DBMap` field survives restarts by
definition; an in-memory field is rebuilt by definition. There is no
classification to get wrong, no registry to drift, and no wipe: the state that
used to be deleted at boot is simply never written.

So this file answers one question per table — *what would a replay have to redo
to rebuild this?* — and the answer is what justifies the table existing.

## Presign material, and everything keyed to it

**The eight `internal_presign_pool_*` tables** hold presigns this node
computed. The replay does not re-run the cryptography — the catch-up gate
deliberately suppresses it — and the pops that consume the pool are not all
consensus-ordered, so a rebuilt pool would serve different presigns than
never-crashed peers bound (ika #1928). `internal_presign_pool_sizes` rides the
pools in their own batches; losing it while the pools survive would report
empty pools and trigger endless top-ups.

Because the pools are preserved, so is everything that makes replay idempotent
against them:

- `filled_presign_pool_slots` — the marker consulted before absorbing a
  replayed internal-presign fill. Losing it double-absorbs, which both inflates
  the size counter (suppressing top-ups until the pool physically starves) and
  resurrects already-served presigns (ika #1934).
- `served_global_presigns` — which presign was served for a request, read back
  instead of re-popping. Without it the replay serves a different presign than
  the committee put in its checkpoint message.
- `noa_presign_demand_resolutions` — the terminal outcome per demand, assigned
  or abandoned. Losing it re-pops for demands the committee already gave up on.
- `used_presigns` — the monotone retirement marker; losing it lets one presign
  be consumed twice.
- the eight `assigned_presigns_*` tables — an assignment already carved out of
  the pool, so the pool row is gone and the assignment is the only remaining
  copy.
- `presign_private_outputs` — this validator's own secret nonce shares from VSS
  presign sessions. Never published, so no commit could carry them.

**This group is why the split is safe at all.** The preserved side is written
in its own batches, independently of the commit boundary, so after a crash it
can be AHEAD of the derived side — and now always is, since the derived side
resets to nothing. That is precisely the direction these markers were built
for: they exist because the replay re-runs the demand stream against a pool it
does not rewind. Memory-only narrows the crash-state space to the one case
already handled rather than adding a case.

## Content-addressed protocol-output caches

`network_dkg_output_digests` and `network_reconfiguration_output_digests` cache
outputs this node computed or read from Sui and peers. The replay does not
re-run the cryptography, and the handoff attestation reads them.

## Operator state

`override_protocol_upgrade_buffer_stake` is set by this node's operator over
the admin interface. No commit carries it, and the protocol tolerates
validators disagreeing about it.

## Non-determinism audit of the fold

The other half of the question — is anything the fold derives NOT a function of
the commits? — matters more now that the fold is the only writer of that state.
The set is empty for anything a decision reads:

- **Wall clock.** `Instant::now()` and `SystemTime` appear on the commit path
  only in metrics, log fields and latency histograms. The epoch's consensus
  clock is `commit_timestamp_ms`, carried in the commit itself and anchored at
  the first commit's timestamp; the freeze and close graces are leader-round
  deltas, not durations. The one place the wall clock reaches a *decision* is
  the MPC service's per-iteration pacing (re-emit intervals, park bounds
  measured in consensus rounds but ticked by a timer) — which lives in the
  drain, not the fold, and whose durable outcomes are recorded per demand
  (`noa_presign_demand_resolutions`) for exactly this reason.
- **Randomness.** No sampling on the fold path. The nonces that make idle and
  observation updates unique are sampled by the *submitter* and travel inside
  the sequenced transaction, so the fold sees a fixed value.
- **Local state read by the fold.** Three, not two — the third is the one worth
  knowing about:
  1. The expected handoff attestation gates `handoff_signatures` writes.
     Documented residue; see the spec's close section.
  2. `should_accept_tx` reads `reconfig_state`, which the replay itself drives
     from the close decision.
  3. **The mpc_data freeze commit reads the PRIOR epoch's certified handoff
     attestation from the PERPETUAL store**, for carry-forward
     (`authority_per_epoch_store.rs` → `prior_epoch_mpc_data_digests`). That is
     a consensus-visible decision — the frozen set — taking an input from
     outside the commit stream.

     Its divergence window is one-directional and narrow. A read error or a
     missing perpetual handle FAILS the commit so it replays, rather than
     degrading to an empty map, which is deliberate: a silent empty would
     re-open the shrunken-set fork the function exists to close. What is not
     fenced is `Ok(None)` → `Ok(Some(cert))`: the certificate is never deleted,
     so the only possible skew is absent-then-present. A joiner that froze while
     the cert was still absent, crashed, and restarted after bootstrap fetched
     it re-decides the freeze with a LARGER carry-forward set.

     Traced consequence: benign to positive. Carry-forward only ADDS members the
     committee's own certificate attests to, so the re-decided set moves toward
     the committee's set, never away from it — the opposite of the shrunken-set
     hazard. It is listed here because the audit's job is to enumerate the
     inputs, not because this one is known to be harmful; a future change that
     makes the frozen set order-sensitive, or that ever deletes a certificate,
     would turn it into one.

## What is NOT in this store, and is not affected

**State sync writes no per-epoch table at all** — `ika-network/src/state_sync`
has no reference to `AuthorityPerEpochStore`; its certificates and watermarks
live in `DWalletCheckpointStore` / `SystemCheckpointStore`, separate databases
outside this audit. Those two databases are also where the certified watermark
lives that the in-memory checkpoint-construction state is pruned against.

`locally_computed_checkpoints` (in those same checkpoint stores) exists for fork
DETECTION and logging; no decision path reads it. That is the only reason its
survival is safe: rows written before a divergence would be stale relative to a
rebuilt epoch. If a reader is ever added that acts on it, revisit.

## Adding a table

Adding a field to `AuthorityEpochTables` is a decision to make something survive
every restart, un-rewound by the replay. Before you do:

1. Answer the question this file exists for: **what would a replay have to redo
   to rebuild this?** If the answer is "nothing, the commits carry it", it
   belongs in the epoch store's in-memory state instead — a durable copy of
   consensus-derived state is the second truth the whole design deletes, and it
   holds rows for commits the consensus store may no longer have (ika #2057).
2. Add the field's `write-discipline:` line
   ([`conventions/epoch-table-write-discipline.md`](conventions/epoch-table-write-discipline.md)).
3. Add it to `the_epoch_store_keeps_only_state_no_replay_reproduces`, which
   pins the table list, and to the appropriate section above with the answer
   from step 1.
