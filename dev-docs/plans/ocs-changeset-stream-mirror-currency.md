# OCS changeset-stream currency for mirrored validators

**Status:** active — implementation started 2026-06-15 (Blocker 1, the
id-binding non-inclusion primitive, is built + tested). Successor to the
push-objects gossip removed in `53c1858abf` (audit review finding 10 in
[`../reviews/ocs-grpc-migration-review.md`](../reviews/ocs-grpc-migration-review.md)).
Read alongside
[`../specs/ocs-verified-sui-reads.md`](../specs/ocs-verified-sui-reads.md).

> **✅ Blockers 1–4 are built and unit-tested** in
> `ika_core::sui_connector::ocs_currency` (the deletion linchpin — does
> `object_states` tombstone deletes? — is **confirmed sound** at the Sui layer).
> Blocker 1 is closed at the ika layer with no upstream `fastcrypto` change (the
> proof carries the neighbor leaves, so the id is bound on already-public data;
> see below). Blockers 2/3/4 are the `ChangesetIndex` fold: it binds each
> shipped object-set to the verified summary's artifacts digest, enforces a
> forward-chained contiguous frontier (`highest_contiguous_seq`, +1 advance,
> `previous_digest` chaining, out-of-order queue + drain), folds a
> lifecycle-aware per-id `(seq, status)` index, and answers read-time currency
> (current / stale / not-live / unknown / inconsistent).
>
> The trust-anchor bridge is also built: `ChangesetIndex::absorb_verified`
> BLS-verifies each summary via `CommitteeStore::verify_summary` before folding,
> so an unsigned or foreign-signed changeset is rejected and never folded.
>
> The transport is built: a **`ChangesetPage` anemo RPC** on `SuiStateMirror`
> (pull-based — reuses the existing relay-peer selection, no new gossip mesh).
> The direct-side server extracts `(summary, object_states)` per checkpoint
> (`CheckpointArtifacts::from(&checkpoint).object_states()`) and ships ids, not
> bodies; the mirror client is `SuiMirrorTransport::changeset_page(from_seq,
> limit)`, returning a contiguous prefix from `from_seq`.
>
> **Still not wired into the read path** — remaining *integration*, not new
> invariants: (a) the mirror's **receiver loop** — a background task that pulls
> `changeset_page` from `highest_contiguous_seq + 1` and feeds each entry
> through `ChangesetIndex::absorb_verified`; (b) the **read path** calling
> `ChangesetIndex::currency(...)` alongside the inclusion proof (and
> `non_inclusion_binds_id` as the audit/fallback); (c) **bootstrap**
> (range-request back to the oldest in-store committee epoch). Until (a)–(c)
> land, no read path consumes a currency verdict.

## Problem

A mirrored / peer-only validator has no authoritative Sui access. It reads
Sui objects over the verified relay, checking each against its
`CommitteeStore`. The check proves **authenticity**, not **currency**:

- An OCS inclusion proof anchors at the object's *last-modifying* checkpoint
  `M` — the relay's `build_object_entry` uses
  `tx_checkpoint(object.previous_transaction)`, because the per-checkpoint
  `ModifiedObjectTree` only contains the objects *modified in that
  checkpoint*. So a proof attests "object `X` was at version `V` in
  checkpoint `M`", never "`V` is current at head `N`".
- A committee that signed `M` also signed `M+1 … N`. A peer holding an
  old-but-validly-signed checkpoint can prove an old version of `X` forever.
  Nothing in a single object read distinguishes a **legitimately-idle**
  current object from a **rolled-back** stale one.
- This is why the global `freshness_bound` was set to `None`: an idle object
  (e.g. `System` inner between epoch boundaries) legitimately anchors far
  behind head, indistinguishable from a rollback by anchor distance.

Direct validators don't have this problem: their pusher folds every modified
object of every checkpoint, in order, from authoritative direct access.
Mirrored nodes have no such folder; today they lean on per-object high-water
monotonicity + per-read re-querying + consumer logic — a self-healing but
unproven posture, with no committee-attested "this is the latest version".

## The intended enabler — and its sharp edge

`ModifiedObjectTree` (sui-light-client `proof/ocs.rs`) is keyed by
**`ObjectID`** (`object_pos_map`, one entry per id per checkpoint) and its
root is committed in the BLS-signed `CheckpointSummary`. It exposes
`get_inclusion_proof` and `get_non_inclusion_proof`. The intended currency
proof:

> `X@V` is current at head `N`  ⇔  inclusion of `X@V` at `M`  ∧
> **non-inclusion of `X`'s id at every checkpoint `M+1 … N`**.

**BLOCKER 1 — the non-inclusion primitive proves the wrong thing.**
`new_non_inclusion_target(id)` builds a *dummy* `ObjectRef`
`(id, SequenceNumber(0), ObjectDigest::MIN)` (ocs.rs:45–63). The Merkle
verifier (`fastcrypto` `merkle.rs`) only enforces `left < target < right`
plus Merkle membership of the neighbors — it does **not** check that a
neighbor's `ObjectID` differs from the target's. Since `(id, 0, MIN)` sorts
*below* any genuine `(id, v>0, d)` leaf, a byzantine prover presents the real
present leaf `(id, v, d)` as the right neighbor and yields a **valid**
non-inclusion proof for the dummy — proving "X not modified in K" while X
*was* modified to `v`. The prover-side `is_object_in_checkpoint` guard
(ocs.rs:161) does not help: a byzantine relay crafts the proof directly.

**Fix — RESOLVED at the ika layer (no fastcrypto change needed; implemented
2026-06-15).** The original worry was that this required an upstream
`fastcrypto` change. It does not: `MerkleNonInclusionProof` already *carries*
the neighbor leaves — `pub left_leaf` / `pub right_leaf`, each a full
`ObjectRef` — so the id can be bound at the ika layer by re-checking the
(already-public) neighbors. A genuine absence has neighbors with ids *different*
from the target; if either neighbor's id equals `target.id`, the id is in fact
present and the proof is rejected. In the attack above the forged right neighbor
*is* `(id, v, d)`, so the check rejects it. This is
`ika_core::sui_connector::ocs_currency::non_inclusion_binds_id`, run **in
addition to** the existing Merkle + artifacts-digest verify. The "single most
important test" (forged non-inclusion for a present id is rejected; the raw
Merkle verifier is shown to accept it) passes. The long pole is gone — the
remaining blockers (2/3/4) are all ika-side stream/fold logic.

## Architecture (target, once the primitive is fixed)

Split the **currency signal** (small, committee-signed, continuous) from the
**object data** (large, pulled lazily).

1. **Changeset stream (gossiped, committee-signed).** Direct validators gossip,
   per checkpoint, the `CertifiedCheckpointSummary` + the set of modified
   object ids (the `object_pos_map` keys, verifiable against the artifacts
   digest). Ids + signatures, not bodies. **Decision:** ship the modified-id
   sets; the receiver re-derives/verifies them against the artifacts digest.
2. **Mirror-side fold — lifecycle-aware.** Verify each summary (BLS) and fold
   into a per-id index `id → (last-modifying checkpoint, status)` where
   **status ∈ {Modified, Deleted, Wrapped}** (BLOCKER 4). Not merely
   last-modified-seq: delete-then-recreate within a gap must be detectable.
3. **Contiguity is an enforced invariant (BLOCKER 2/3).** Track
   `highest_seen_seq` separately from `highest_contiguous_seq`; advance the
   contiguous frontier **only at +1**, validating each summary's
   `previous_digest` forward-chain on absorb; reject/queue gap-creating
   inputs; recover gaps by refilling the **changeset id-sets** (not just
   bodies) and verifying each against its artifacts digest before advancing
   the frontier. **All currency reasoning uses `highest_contiguous_seq`,
   never the highest seen.** (Today `advance_head` CAS-bumps to *any* seq —
   verified_state_cache.rs:242 — which this design must replace.)
4. **Lazy body pull**, verified by inclusion at `M`.
5. **Currency at read time.** Serve `X@V` only if, across `M+1 …
   highest_contiguous_seq`, its id appears in **no** changeset (status never
   becomes Deleted/Wrapped, never re-Modified). With the per-id index this is
   O(1); the non-inclusion proof is the audit/fallback path. Add a
   defense-in-depth check that the served object's digest is not a
   marker (`OBJECT_DIGEST_DELETED` / `_WRAPPED`).
6. **Gossip mesh.** The stream is committee-signed and proofs are portable,
   so any node can re-serve them. A byzantine re-server can withhold or
   equivocate (an *availability* problem — multi-peer + contiguity + the
   committee-signed chain bound it) but cannot forge a stale-as-current
   object once Blockers 1–4 are closed.

## Trust model

Relay/gossip is fully untrusted. Every summary is BLS-verified; every body
is inclusion-proven; every currency claim is non-inclusion against
committee-signed digests **with id binding**. A byzantine peer can withhold,
delay, reorder, or cherry-pick — all defeated by `previous_digest`
forward-chaining + the contiguous frontier (it cannot advance the frontier
without a valid contiguous chain). It cannot forge absence once the
non-inclusion verifier binds the id.

## Critical correctness dependencies

1. **Deletions in the modified set — SATISFIED at the Sui layer (confirmed
   2026-06-14).** `effects_v2.rs` `written()` emits deleted ids with
   `OBJECT_DIGEST_DELETED` and wrapped with `OBJECT_DIGEST_WRAPPED`;
   `CheckpointArtifacts::from` folds every `written()` entry into
   `object_states` (messages_checkpoint.rs), whose doc states it "also
   includes objects that were deleted or wrapped". So a delete of `X` at `D`
   *does* put `X`'s id into `D`'s set. **Consumer obligation (not yet
   built):** the fold must record the tombstone status and the read path must
   refuse to serve any id whose latest status in the gap is Deleted/Wrapped;
   `verify_ocs_inclusion` should also reject marker digests explicitly.
2. **Id-binding non-inclusion** (Blocker 1) — the make-or-break primitive
   fix; everything else is moot without it.
3. **Enforced contiguity** (Blocker 2/3) — `highest_contiguous_seq`, +1
   advance, `previous_digest` chaining, id-set gap recovery.
4. **Lifecycle-aware fold** (Blocker 4) — per-id status, not just seq, or
   delete-then-recreate breaks the equivalence.
5. **Scope of coverage.** The Ika-filtered changeset stream covers Owned
   Ika objects. Bag / dynamic-field children and any non-Owned
   (Shared/Immutable/ConsensusAddressOwner) objects are **out of scope** for
   changeset currency — they stay on per-read verification — OR the stream
   must carry the *full* unfiltered modified set (bandwidth cost). The folder
   should assert/abort if it observes a non-Owned object in a folded
   checkpoint, so the assumption can't silently break.
6. **Bootstrap.** A freshly-joined mirrored node has no folded history and
   cannot prove currency for an object last modified before it booted. Define
   a committee-verified bootstrap: range-request the id-stream back to at
   least the oldest in-store committee epoch (the retention floor), or fall
   back to per-read verification until the frontier catches up.

## Cost / complexity

- New mirror-side component: verify + fold the changeset stream into a
  per-id `(seq, status)` index with enforced contiguity and id-set gap
  recovery. Bounded memory: one entry per live Ika object the node cares
  about.
- Per-read currency check O(1) against the index; non-inclusion proofs the
  audit/fallback path.
- Plus a **fastcrypto/sui-light-client change** (id-binding non-inclusion),
  which is upstream-adjacent and the long pole.

## Regression tests (pin to the Sui version in `Cargo.toml`)

- Deleted ids round-trip into `object_states` with `OBJECT_DIGEST_DELETED`;
  wrapped with `OBJECT_DIGEST_WRAPPED` (catches a Sui upstream change).
- A forged non-inclusion proof for a present-but-different-version id is
  **rejected** by the fixed verifier (catches a regression in the id-binding
  fix — the single most important test).
- Delete-then-recreate within a gap is detected (status-aware fold).

## Open questions (resolved as decisions above)

- Stream encoding → ship modified-id sets, re-derive/verify against the
  artifacts digest.
- Gap recovery → committee-verified range-request of the id-stream; full
  snapshot as fallback.
- Retention floor → keep the id-stream/index back to at least the oldest
  in-store committee epoch (interacts with S4 committee-table retention).
