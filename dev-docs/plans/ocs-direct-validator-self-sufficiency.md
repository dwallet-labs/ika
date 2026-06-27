# OCS direct-validator self-sufficiency (finding 17 durable fix)

Status: **all slices done.** Slices 1, 2, 4, 5 resolve finding 17 for direct nodes
(cluster-validated). **Slice 3** (serve a mirrored peer's committee ratchet from
the direct node's retained store) is now done too, via **Option A** — a
`RetainedFullnodeTransport` decorator that serves the end-of-epoch
`get_full_checkpoint` / `last_checkpoint_of_epoch` from persisted state before the
fullnode, with no new cross-crate trait, anemo RPC, or ratchet change (Option B
was abandoned because `ika-network` can't depend on `ika-core`). Resolves review
finding 17
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

### Slice 3 — Serve a mirrored peer's ratchet from the retained store — DONE (Option A)

The mirror server proxied the **live fullnode** for the ratchet primitives
(`sui_state_mirror/mod.rs`: `last_checkpoint_of_epoch`, `get_full_checkpoint`,
`changeset_page` all call `self.transport.*`), so a mirrored node's ratchet still
depended on the *direct* node's fullnode still holding the end-of-epoch checkpoint.

**Option B (committee-summary RPC + ratchet `try_into_verified`) was abandoned:**
it needed the mirror `Server` to hold the `CommitteeStore`, but `ika-network` does
**not** depend on `ika-core` (the reverse), so that would require a new cross-crate
`CommitteeSummarySource` trait, a new anemo RPC, and a change to the shared,
security-critical ratchet — large and invasive.

**Built Option A instead** — fully contained in `ika-core`, no trait/RPC/ratchet
change:
- A new perpetual column `sui_end_of_epoch_checkpoints` retains the full
  end-of-epoch `CheckpointData`; the pusher persists each one (with its epoch→seq
  mapping in `sui_end_of_epoch_seqs`) as it streams past (`persist_end_of_epoch`),
  pruned with the verified-cache retention floor.
- `RetainedFullnodeTransport` decorates the direct node's mirror-server transport
  (`setup.rs`): `last_checkpoint_of_epoch` and `get_full_checkpoint` serve from the
  retained columns first, then the fullnode; everything else delegates. The
  mirrored peer's *existing* ratchet flow works unchanged and re-verifies the
  committee-signed summary, so this is a serving optimization, not a trust change.
- Tests: the pusher persists the end-of-epoch checkpoint + seq on capture
  (`pusher_eagerly_captures…`); the wrapper serves both primitives from the
  retained store without delegating to the fullnode (`serves_committee_primitives_
  from_the_retained_store`, a panicking inner proves no delegation), and the
  retention prune drops them below the floor.

### Slice 4 — Graceful-degrade safety net (the accepted residual) — DONE

For the unavoidable gap (cold start, fast-forward jump, fell behind past
retention) the degrade differs by read kind:

- **Currency gate (mirrored per-read):** already returns `Unknown` → per-read
  fallback when currency can't be established — no false `Current`, no stall.
  (Built with the changeset-currency work; nothing to add here.)
- **Mandatory inner reads (`sui_executor::must_get_system_inner` /
  `must_get_dwallet_coordinator_inner`):** these are *not* optional — the MPC
  pipeline needs the current System / Coordinator inner — so they cannot degrade
  to a fallback. Instead of spinning at 1/s and flooding the logs (the observed
  finding-17 symptom: 12k `verified_system_inner failed` lines), they now back
  off (`verified_read_retry_backoff`: 1,2,4,8,16, capped 30s) and, after a few
  attempts, escalate to a single clear "likely a Sui-fullnode retention gap;
  raise fullnode retention or re-anchor" diagnostic. The failures themselves are
  already metered by the reader's proof/cache failure counters.
  **Follow-on (separate from finding 17):** these same anchor reads run every
  ~120 ms, and were later found to *force* a network reach-back whenever the
  cache-staleness tripwire tripped under load — a self-reinforcing loop (the
  reach-backs slow the pusher, which keeps the tripwire tripped) that throttled
  dwallet throughput until the heaviest integration files timed out. Fixed by
  serving the two singleton anchors (System / Coordinator inner) from the
  verified cache *through* a tripped tripwire (`verified_anchor_object`); the
  backoff above stays the fallback on a genuine cache miss. Durable behavior:
  the OCS spec's *cache fast path*
  ([`../specs/ocs-verified-sui-reads.md`](../specs/ocs-verified-sui-reads.md)).
- **Ratchet:** a pruned-and-uncaptured EoE still returns `ProofChainBroken`
  (re-anchor required) — but with Slice 1 the pusher captures committees eagerly,
  so the ratchet rarely reaches back, and a wedge is already observable as the
  `committee_head_epoch` gauge stalling below `chain_latest_epoch`. No silent
  failure mode remains; the operator-action signal is intact.
- Test: `verified_read_backoff_doubles_then_caps_at_30s`.

### Slice 5 — Regression test: pruned-history path — DONE (mock-transport)

Exercise the pruned-history path so this can't regress.

**The real-Sui-pruning cluster test was infeasible** and abandoned: the in-process
Sui `TestClusterBuilder` does not expose `AuthorityStorePruningConfig`, and the
fullnode's retention is fixed at build time (not mutable post-build) —
`ika-swarm-config`'s `with_disable_pruning` only touches the *ika* fullnode, not
the Sui chain. Forcing it would mean patching the pinned Sui fork's
test-cluster/config (heavy, flaky — must size retention above the node's catch-up
lag). Confirmed instead: cluster validators *do* run the OCS path (`SuiStateDirect`
+ pusher + ratchet, genesis-committee anchored), so every green cluster run already
exercises the mechanism end-to-end.

**Built instead — deterministic mock-transport unit tests** (`push_worker.rs`
`mod tests`), driving the real `IkaCheckpointPusher::advance` through a `MockTransport`:
- `pusher_eagerly_captures_end_of_epoch_committee` — streaming the committee-signed
  end-of-epoch `CheckpointData` installs `committee[E+1]` (head `0 → 1`) with no
  ratchet reach-back (Slice 1).
- `pusher_skips_pruned_checkpoint_without_stalling` — a `NotFound` (pruned)
  checkpoint is skipped, the cursor advances past it, head unchanged, no stall
  (Slice 4, pusher half).

These guard the finding-17 mechanism with zero flakiness; the executor-degrade
(`verified_read_backoff…`) and restart-resume (`persisted_cache_rehydrates…`) /
retention-prune (`retain_window_prunes…`) tests cover the rest.

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
