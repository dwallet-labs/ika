# OCS direct-validator self-sufficiency (finding 17 durable fix)

Status: plan, not yet implemented. Resolves review finding 17
([`../reviews/ocs-grpc-migration-review.md`](../reviews/ocs-grpc-migration-review.md)).

## Problem

The OCS verified-read path depends on the **separate Sui fullnode** retaining
history it no longer keeps. Two reaches break when the fullnode prunes:

- the committee **ratchet** fetches each end-of-epoch checkpoint *live*
  (`ocs_verifier.rs:163-164`) and hard-fails `ProofChainBroken` when it's gone
  (`allow_unverified_committee_fallback=false`);
- a verified read whose object's last-modifying checkpoint `M` was pruned can't
  build a proof — `tx_checkpoint(previous_transaction)` → `NotFound` — and
  `sui_executor` retries forever.

"The direct validator caches everything" is true only for Ika object *state*, and
that cache (`VerifiedStateCache`) is **in-memory only** (`RwLock<HashMap>`), so a
restart wipes it and forces a re-sync from the (possibly-pruned) fullnode.

## Goal & principle

Make the **direct** validator self-sufficient: capture everything the OCS
read/currency/committee subsystems need **the moment it streams past**, persist it
durably, and serve it to mirrored peers — so in steady state the Sui fullnode is
dispensable and a restart resumes from DB. The committee chain is already durable
once captured (`EndOfEpochData::next_epoch_committee` →
`record_sui_committee_transition` → `sui_committee_summaries`); the bug is
capturing it *late*.

**Accepted residual (by design):** you cannot capture what's already pruned. A
fresh node, or one that fell behind past the fullnode's retention, has an
unavoidable gap. The fix is to make those reads **degrade to `Unknown`/fallback**,
never hard-stall (Slice 4) — not to pretend the gap can't happen.

## Slices (independently reviewable / mergeable)

### Slice 1 — Eager end-of-epoch committee capture from the pusher (no DB change)

The pusher (`push_worker.rs`) already fetches every full checkpoint in order and
always processes end-of-epoch ones (`is_end_of_epoch`, `push_worker.rs:206-217`).
When it processes an EoE checkpoint, install `committee[E+1]` *then* — call the
same path the ratchet uses (`extract_new_committee_info(&summary)` →
`committees.install_next(next, Some(&summary))`, `ocs_verifier.rs:221-238`,
`committee_store.rs:246-259`) — instead of waiting for the 30s reach-back loop
(`lib.rs:913-921`) that races the prune.

- Keep the 30s ratchet loop as the **fallback** and as the *only* path on
  mirrored/peer-only nodes (which have no local pusher).
- **Skip-path hazard:** the pusher's fast-forward (`FAR_BEHIND_THRESHOLD=1000` →
  jump to `latest-100`) and skip-on-fetch-failure (`push_worker.rs:154-163`) can
  jump over an EoE checkpoint. Make capture EoE-aware: never fast-forward *past*
  an un-captured epoch boundary without either capturing its committee or
  recording the gap (→ Slice 4 degrade). The catch-up jump must stop at each
  intervening EoE.
- Tests: pusher installs `committee[E+1]` on EoE without the 30s tick;
  fast-forward does not silently skip an EoE boundary.

### Slice 2 — Persist the verified state cache to DB

Add a perpetual column (greenfield — the OCS tables are new in this unreleased
branch, **no migration**):

```rust
// authority_perpetual_tables.rs, alongside sui_committee_summaries
pub(crate) verified_object_cache: DBMap<ObjectID, VerifiedSnapshot>,
pub(crate) verified_object_cache_head: DBMap<(), CheckpointSequenceNumber>,
```

`VerifiedSnapshot { object, proof, summary, source_checkpoint_seq }` is
bcs-encodable (its manual `Clone` already round-trips the proof through
`bcs::to_bytes/from_bytes`, `verified_state_cache.rs:206`); derive
`Serialize`/`Deserialize` (or store the bcs bytes) so it lands in a `DBMap`.

- `VerifiedStateCache` becomes DB-backed: `absorb_entries` write-through (batch:
  `.batch()` → `insert_batch` → `write()`); on boot, load the head + read-through
  from DB so a restart resumes without touching the fullnode. The `children`
  parent→child index can be rebuilt on load (it's derivable from the objects' owners).
- Pruner driven by a **node-config** retention window (see *Node config* below):
  drop snapshots below `head - window`, never below
  `oldest_sui_committee_summary().seq` (the bootstrap floor). This window is also
  the **mirrored-peer bootstrap depth**.
- Tests: restart resumes from DB (cache non-empty, head preserved); a read served
  from DB after the fullnode "forgets" it (mock transport NotFound) still succeeds;
  pruner bounds the column.

### Slice 3 — Serve ratchet & read primitives to mirrored peers from the retained store

Today the mirror server proxies the **live fullnode** for the ratchet/stream
primitives (`sui_state_mirror/mod.rs`): `last_checkpoint_of_epoch` (:276),
`get_full_checkpoint` (:237), `changeset_page` (:248) all call `self.transport.*`
directly; only `verified_object`/batch/bag go through the in-memory `ProofCache`
(32 trees, `proof_provider.rs:367`). So a mirrored node's ratchet still depends on
the *direct* node's fullnode still holding the data.

- Source these from the direct node's retained DB store (Slice 2 + the persisted
  committee summaries already in `sui_committee_summaries`) so a mirrored node
  never reaches a live fullnode. Serving depth = the retain window.
- Tests: a mirrored node advances its committee and serves reads with the direct
  node's fullnode stubbed to prune everything past the window.

### Slice 4 — Graceful-degrade safety net (the accepted residual)

For the unavoidable gap (cold start, fast-forward jump, fell behind past
retention):

- Verified read on a pruned/uncaptured anchor → return per-read `Unknown` /
  fallback (currency), **not** retry-forever (`sui_executor` `must_get_*` loops,
  `push_worker.rs:106-114`).
- Ratchet on a pruned **and uncaptured** EoE with no installed committee →
  re-anchor / clamp to the servable floor rather than loop `ProofChainBroken`.
- Tests: a NotFound anchor yields `Unknown`+liveness (no stall); the ratchet
  recovers/re-anchors instead of wedging.

### Slice 5 — Regression test: short Sui-fullnode retention

Exercise the pruned-history path so this can't regress.

- The TS-integration localnet runs a **separate** `sui start --with-faucet
  --force-regenesis` (`ts-integration-tests.yaml:148`); give that process a Sui
  config with aggressive `authority-store-pruning-config` (low
  `num-epochs-to-retain`). The in-process `ika-test-cluster` (`lib.rs:1182`) needs
  the Sui node configs mutated post-`TestClusterBuilder` (Sui doesn't expose
  pruning as a builder param) — a dedicated cluster test.
- **Assert the right thing:** validators keep advancing (committee from captured
  EoE, in-window reads/currency succeed) and **degrade gracefully** (no
  hard-stall) out-of-window. Size retention *above* ika's worst-case catch-up lag,
  or assert "degrades, no stall" rather than "every read succeeds" — otherwise the
  test flakes on slow CI runners (the keep-up constraint is load-bearing).

## Sequencing

1 (standalone, smallest, unblocks the committee half) → 2 (DB; enables 3 +
restart) → 3 (depends on 2) → 4 (standalone safety net; can land early/parallel) →
5 (the guard, after 1–4). Quick CI unblock meanwhile:
`allow_unverified_committee_fallback=true` on localnet and/or longer localnet
epochs / raised fullnode retention.

## Node config

The retention/serving limits this feature introduces are **operator-tunable** via
`SuiConnectorConfig` (`ika-config/src/node.rs`), with the **default defined in node
config** following the existing `DEFAULT_AUTHORITY_DB_RETENTION_EPOCHS` pattern (a
`const` + `Option<T>` field + a getter that `unwrap_or`s the default) — not a magic
constant buried in `setup.rs` (where `CHANGESET_RETAIN_WINDOW` currently lives):

```rust
// ika-config/src/node.rs
pub const DEFAULT_VERIFIED_CACHE_RETENTION_CHECKPOINTS: u64 = 432_000; // ~a few epochs

// in SuiConnectorConfig
#[serde(default, skip_serializing_if = "Option::is_none")]
pub verified_cache_retention_checkpoints: Option<u64>,

pub fn verified_cache_retention_checkpoints(&self) -> u64 {
    self.verified_cache_retention_checkpoints
        .unwrap_or(DEFAULT_VERIFIED_CACHE_RETENTION_CHECKPOINTS)
}
```

This window is the persisted-cache prune depth (Slice 2) *and* the mirrored-peer
bootstrap/serving depth (Slice 3): larger = deeper history served to mirrored peers
and more reads answerable after the fullnode prunes, at more DB. `setup.rs` reads it
from config instead of the local `const`. (Other existing constants — the mirror
page/inflight caps — can be promoted the same way if we want them tunable; out of
scope unless asked.)

## Decisions

- **Children index:** rebuilt on load (not persisted) — simpler; one pass over the
  loaded objects' owners.
- **Retention limits:** node-config fields with defaults (above), not hardcoded.

## Decided: pusher fast-forward never skips an epoch boundary (option A)

When the direct node falls far behind the fullnode, the pusher *fast-forwards*:
it jumps its cursor ahead (skipping ~900 ordinary checkpoints) to catch up instead
of fetching each one. The committee handoff lives in **end-of-epoch checkpoints**,
so the fast-forward must **stop at every end-of-epoch checkpoint** to capture its
committee, then continue jumping. End-of-epoch checkpoints are sparse (one per
epoch), so this is cheap and keeps the committee chain unbroken; only object-state
for skipped *ordinary* checkpoints is missing, which Slice 4 degrades to `Unknown`.
(Implementation: the catch-up jump in `push_worker.rs:142-151` clamps its target to
the next end-of-epoch checkpoint at-or-after the gap rather than `latest-100`.)
