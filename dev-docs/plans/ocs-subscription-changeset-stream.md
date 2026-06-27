# OCS Subscription-Based Changeset Stream — Design Specification

Status: design, **sound but not yet implementation-ready** (after 6
design/adversarial-review rounds). Successor to the full-set `changeset_page`
path documented in `dev-docs/plans/ocs-changeset-stream-mirror-currency.md`.
Branch: `feat/ocs-grpc-migration`.

> **Round 6 fixed the sub-head advancement *mechanism* (entries below the
> roots-driven `contiguous_head` now advance per-id `coverage.head(id)`, each gated
> by verifying that id's proof against the position-gated summary at the entry's
> `seq` and forward-chaining against the per-id `coverage.head_digest(id)`, not the
> global head) and the seeded-root bootstrap off-by-one. Fail-closed soundness is
> unchanged — no false `Current` is reachable.**
>
> **Known remaining gap (blocks implementation; liveness, not soundness — the
> anchor-coverage problem).** A fresh id only catches up *forward* from
> `subscribed_at_seq` (the head `H` at enrollment), so `floor(X) = subscribed_at_seq`.
> But a freshly-discovered dwallet is read at its **last-modifying checkpoint
> `M_last`**, which is generically **below** `H` (the roots/inners drive `H` ahead
> independently; `M_last == H` only if the dwallet was modified at the exact current
> head). Since `M_last < floor(X)`, `currency_subscribed` returns **Unknown
> permanently** for the common current-state read — the per-id interval
> `[subscribed_at_seq, head]` never brackets the enrollment-read anchor, and the
> global `currency()` (which *would* bracket it) is deliberately not consulted for
> Subscribed-mode ids (the S4/S7 fix). So the design's purpose — currency for the
> dynamic dwallet set — does not engage for the common case. **Fix direction
> (round 7):** a freshly-enrolled id's catch-up cohort must resume **below**
> `subscribed_at_seq` down to a bounded floor (`max(oldest_folded, head -
> retain_window)`) so `floor(X) ≤ M_last` and the interval brackets the anchor —
> anchored on the global chain the index has *already* folded (every such
> checkpoint's digest is already a trusted index record, so no new trust root). The
> §4.3 cohorting optimization avoided this rewind for *cost*; the spec conflated that
> cost optimization with a correctness gate. See §5.2 (CoverageInterval), §5.3
> (`currency_subscribed`), §8 (`absorb_subscribed` step 6).

This document specifies a per-id, subscription-keyed changeset stream that bounds
both bandwidth and `ChangesetIndex` memory by the subscribed id-set size rather
than by total chain activity, while keeping omission of a subscribed modification
provably impossible against a byzantine relay. It is the dynamic-read-set successor
the predecessor plan called for (filter=None today precisely because the bag/dwallet
read set is unbounded and dynamic).

---

## 1. Chosen design and rationale

### 1.1 The decision

The primary design is **per-id inclusion-or-non-inclusion proofs, one
`SubscribedIdProof` per subscribed id per checkpoint, folded through the existing
`ChangesetIndex` with an added per-id coverage-interval gate** (the design the
verification corpus labels *"Subscription-keyed per-id changeset stream
(SubscribedChangesetPage) with coverage-interval currency"*). The server ships,
for each requested `ObjectID` at each checkpoint in the returned contiguous prefix,
exactly one of:

- `Modified(OCSInclusionProof, (SequenceNumber, ObjectDigest))` — the id was
  modified that checkpoint (its new `(version, digest)` leaf), or
- `Absent(OCSNonInclusionProof)` — the id was not modified, an **id-bound**
  non-inclusion proof gated by `non_inclusion_binds_id`.

Each proof's `tree_root` is bound to the committee-BLS-signed
`summary.checkpoint_artifacts_digest()` exactly as `OCSProof::verify` does
(`CheckpointArtifactsDigest::from_artifact_digests(vec![tree_root])`), so the
artifacts-digest commitment is **not** silently dropped — it is re-anchored
per-proof instead of re-derived over the full set.

### 1.2 Why this design, from the red-team results

Four framings were designed and adversarially verified. Only the per-id framing
survived red-teaming:

| Design | Fatal refutations | Overall verdict |
|---|---|---|
| **SCS — batched gap-cover non-inclusion** | **4 fatal** (S1, S4, S5, S7) | `unsound` |
| **PerIdSub — per-id resumable stream** (as originally argued) | 2 fatal (S4, S7) | `unsound` |
| Per-id stream (third framing, "x") | 1 fatal (S1), 1 major (S8) | `unsound` |
| **SubscribedChangesetPage — per-id + coverage-interval currency** | **0 fatal, 4 major** | **`sound`** |

The decisive distinction is **tree-adjacency**. The SCS "batched gap-cover"
collapses the per-checkpoint non-inclusion witness into a flat, deduplicated set of
sorted boundary leaves and verifies a target by binary-searching it between two
*array-adjacent* boundaries. The red team produced a clean fatal counterexample
(refuted S1, S5, S7, and the omission argument): a byzantine server ships two
**genuine but non-tree-adjacent** boundary leaves (e.g. tree indices `i` and `i+2`)
and **omits** the real modified leaf that sits between them at index `i+1`. Every
stated batch check passes — strict `left.0 < target < right.0`, Merkle membership of
each boundary, and `non_inclusion_binds_id` (neither boundary carries the target id)
— yet a modified id is reported absent and the rolled-back version is served as
Current. The flat witness *drops the consecutive-index binding* that makes
single-target `MerkleNonInclusionProof::verify_proof` sound. fastcrypto's single
verifier gets adjacency for free: it threads ONE `index` field, verifying `right`
at slot `index` and `left` at slot `index-1` (`merkle.rs:262-269`), and sorted
order then forces "no leaf strictly between." The batch loses exactly that and
fastcrypto has **no Merkle multiproof primitive** to restore it
(`get_proof`/`compute_non_inclusion_proof`/`verify_proof` are the entire API,
byte-identical across both pinned revs). Recovering adjacency in the batch would
require shipping per-gap indices and re-checking `right_index == left_index + 1`
plus an `is_right_most` edge check — at which point the "batch" *is* K independent
single-target proofs with extra bookkeeping, and the bandwidth win it was sold on
evaporates. We therefore **reject the batched gap-cover** and ship one
**single-target** proof per id. This costs `O(K · log N)` per checkpoint with no
path sharing, which we accept as the honest price (see §7).

The per-id framing's two **fatal** refutations (S4 "premature Current", S7 "stalled
stream looks healthy") were both rooted in the SAME defect, and that defect is
**fixed** in the chosen design: those framings reused the GLOBAL
`currency()` bracket (`oldest_folded`, `contiguous_head`) for a freshly-subscribed
id whose own coverage starts much later than the global frontier. The chosen design
adds an explicit **per-id coverage floor** and a **per-id coverage-interval gate**
(§5) so the global frontier (driven by the long-lived static root/inner
subscription) can never bless an anchor that the id's own stream has not
contiguously covered. With that gate, all four refutations against the chosen design
are `major` and each is resolved below (§4).

### 1.3 Ideas grafted from the runners-up

- **Per-id contiguity / forward-chain (from PerIdSub).** A subscribed id cannot have
  a checkpoint silently skipped in its coverage interval: each checkpoint in
  `[coverage_floor(id), per_id_head]` must carry a verified inclusion-or-id-bound-
  non-inclusion for that id, and the summaries forward-chain via `previous_digest`.
  We adopt this as the *coverage-interval invariant* (§5.2), which is what actually
  discharges omission — not the global frontier.
- **Stateless, ids-resent-each-page RPC (all four).** Matches the codebase's
  existing unary `from_seq + limit` model and the 30s `RELAY_REQUEST_TIMEOUT`; no
  held-open stream (anemo has no streaming flag here). The server holds no
  per-subscription state and cannot leak memory per mirror.
- **Coexistence by single-writer-per-index (from SubscribedChangesetPage).** The
  red team's one *sound* design still had a live two-writer race; we promote
  "exactly one writer per `ChangesetIndex`" from a wiring convention to a
  **structurally enforced typestate** (§8). A node runs **one** driver — the
  full-set `absorb` path **or** the subscription `absorb_subscribed` path — over a
  single index, never a per-id two-index overlap; coexistence is node-level
  EITHER/OR, not a reconciled two-index split (§8).
- **Honest negative on idle-run compression (from PerIdSub).** "X unchanged in
  `[A,B]`" as a single range assertion is **not provable** under today's
  commitments; we document it as an accepted limitation, not a feature (§10).

---

## 2. Background: what currency must prove, and what breaks

A peer-only node reads Sui objects over an untrusted relay and verifies each against
its `CommitteeStore`. The OCS inclusion + membership-binding path proves
**authenticity** (the object existed in this form at its last-modifying checkpoint
`M`, via a Merkle inclusion proof over `M`'s `ModifiedObjectTree`, anchored to a
committee-signed `CertifiedCheckpointSummary.checkpoint_artifacts_digest()`). It
does **not** prove **currency** (that `M` is the latest modification as of head).
The currency gate (`verified_reader.rs::check_currency`, lines 699-721) closes that
gap, mapping `Current | Unknown => Ok`, `Stale | NotLive => Err NotCurrent`.

The full-set path (`ChangesetIndex::absorb`, `ocs_currency.rs:231-288`) proves
no-omission structurally: it re-derives
`CheckpointArtifacts::from_object_states(FULL set).digest()` and matches the
summary commitment (`ocs_currency.rs:241-249`). Because that digest commits to the
COMPLETE modified set, the server cannot add, drop, or alter any id at a checkpoint.

The full-set path's cost is that on a busy chain it downloads and folds the ENTIRE
Sui modified set every checkpoint (production runs `fold_filter=None`,
`setup.rs:330-344`, `retain_window=432_000`). The subscription replaces the
`O(N)`-per-checkpoint full set with `O(K · log N)` per-id proofs, where `K` is the
subscription size and `N` is the per-checkpoint modified-set size.

**The two things that break for a partial per-id delta** (grounded seam analysis):

1. **The artifacts-digest binding cannot be reproduced** from a partial delta (you
   ship only `K` of `N` leaves). Omission-proofing must move to per-id
   inclusion-or-id-bound-non-inclusion.
2. **The global frontier is no longer a per-id coverage proxy.** In the full-set
   path, "checkpoint `C` is folded" implies "every id modified at `C` was folded."
   With subscriptions, different ids enter at different times; the global
   `[oldest_folded, contiguous_head]` (driven by the always-present static set) may
   bracket an anchor `M` that a freshly-subscribed id's own stream never covered.
   This is the root cause of the fatal S4/S7 refutations and is fixed by the per-id
   coverage gate (§5).

---

## 3. Soundness primitives (grounded, unchanged)

These exist on-branch and are reused verbatim.

### 3.1 `non_inclusion_binds_id` (Blocker-1 fix)

`ocs_currency.rs:51-62`:

```rust
pub fn non_inclusion_binds_id(proof: &OCSNonInclusionProof, target_id: ObjectID) -> bool
```

Reads `proof.non_inclusion_proof.left_leaf` / `.right_leaf` (each
`Option<(ObjectRef, MerkleProof)>`), returns true iff **neither present neighbor's
`ObjectID` equals `target_id`**:
`left.is_none_or(|(r,_)| r.0 != target_id) && right.is_none_or(same)`.

It does **not** itself run any Merkle/ordering check. Per its doc (`44-50`), callers
MUST run it **in addition to** the existing Merkle + artifacts-digest verification,
never instead of it.

**Why it is necessary.** OCS targets the dummy ref
`(id, SequenceNumber::from_u64(0), ObjectDigest::MIN)` (`ocs.rs:61-63`, `MIN =
[0u8;32]`). `ObjectRef` Ord is lexicographic, so the dummy sorts strictly below any
genuine `(id, v>0, d)` leaf for the same id. (`v > 0` always holds: a real object's
first version is `OBJECT_START_VERSION = SequenceNumber::from_u64(1)`
(`object.rs:50`) and versions only increment, so no genuine leaf ever carries
`v == 0` — the dummy's `0` is strictly below every real version.) Without id-binding a byzantine prover
passes the REAL present leaf as the dummy's right neighbor: the raw
`MerkleNonInclusionProof::verify_proof` ACCEPTS it (ordering + membership hold)
while the id IS present. The load-bearing test
`a_forged_non_inclusion_for_a_present_id_is_rejected` (`ocs_currency.rs:455-494`)
constructs exactly this forgery and asserts the raw verifier accepts it and
`non_inclusion_binds_id` rejects it. This is a purely client-side fix needing no
fastcrypto change (`left_leaf`/`right_leaf` are already `pub`, carry full
`ObjectRef`s).

### 3.2 Tree-adjacency is intrinsic to the single-target verifier

`MerkleNonInclusionProof::verify_proof` (`merkle.rs:256-299`) derives BOTH neighbor
slots from one `index` field — right at `index`, left at `index-1`
(`left_leaf.zip(index.checked_sub(1))`). Because `ModifiedObjectTree` leaves are
id-sorted (BTreeMap order, `ocs.rs:85-104`, each id at most once with a duplicate-id
guard at `91-101`), consecutive slots `i-1, i` + sorted order forces "no leaf lies
strictly between." This is the property the rejected SCS batch dropped; we keep it by
using the single-target verifier per id.

The same `index` field also makes the verifier **exhaustive at the tree's
boundaries**, which the omission argument (§6) relies on. `verify_proof`
(`merkle.rs:256-299`) takes exactly four neighbor configurations, and each is
forced to a definite accept/reject — there is no unchecked path:

- **Both neighbors present** (interior gap): left verified at `index-1` with
  `left_leaf < target`, right verified at `index` with `right_leaf > target`
  (`merkle.rs:267-288`). Sorted order then forbids any leaf strictly between.
- **Right-only, `index == 0`** (target sorts **below all** real leaves):
  `left_leaf_with_idx` is `None` (`index.checked_sub(1)` is `None`,
  `merkle.rs:265`); the `else if` at `275-278` *requires* `right_leaf.is_some()`
  **and** `right_leaf_index == 0`, and `280-288` then verifies that right leaf at
  slot 0 with `right_leaf > target`. A forged `index != 0` with no left neighbor
  is rejected at `275`.
- **Left-only** (target sorts **above all** real leaves): `right_leaf` is `None`,
  so `289-292` *requires* the present left leaf to satisfy
  `is_right_most(left_leaf_index)` (`merkle.rs:159-173`, all right-siblings on its
  path are the empty node) — i.e. it must genuinely be the last leaf. A left
  neighbor that is not rightmost is rejected at `291`.
- **Neither neighbor** (`right_leaf` and `left_leaf` both `None`): rejected
  outright at `294-296`, *except* the one prior short-circuit — an **empty tree**
  (`root == EMPTY_NODE`) returns `Ok` at `258-260` before any neighbor logic runs.

Because each branch is closed, a byzantine server cannot manufacture an
"unverified region" at the high or low end of the id range: a non-inclusion that
omits the rightmost neighbor's `is_right_most` check, or claims `index == 0`
without a real slot-0 right neighbor, fails `verify_proof` outright — *before*
`non_inclusion_binds_id` is even consulted.

### 3.3 Artifacts-digest binding to the committee summary

The serving node's per-checkpoint `ModifiedObjectTree` (`ocs.rs:66-114`) is built
from `CheckpointArtifacts::from(&CheckpointData)` (`messages_checkpoint.rs:260`,
folding `tx.effects.written()` into a `BTreeMap<ObjectID,(SequenceNumber,
ObjectDigest)>`). Its `tree_root` is bound to the summary via the two-level digest:
the single `ObjectStates` artifact's Merkle root is wrapped by
`CheckpointArtifactsDigest::from_artifact_digests(vec![root])` =
`Blake2b256(bcs(Vec<Digest>))` (`digests.rs:1091-1095`) and compared to
`summary.checkpoint_artifacts_digest()`, exactly as `OCSProof::verify`
(`ocs.rs:239-264`) reconstructs it. The summary itself is BLS-verified via
`CommitteeStore::verify_summary` (`committee_store.rs:250`) before any proof is
trusted (the `absorb_verified` pattern, `ocs_currency.rs:296-306`).

> **Forward-compat constraint.** `from_artifact_digests(vec![single_root])` assumes
> exactly one `CheckpointArtifact` variant (only `ObjectStates` today). The wire
> format (§4.2) carries the proof's own `tree_root` and the client reconstructs the
> single-artifact digest; **if a second artifact variant is ever added, both
> `OCSProof::verify` and this binding break.** See §10.

### 3.4 Tombstones are inclusions, never non-inclusions

Delete/wrap are leaves `(id, new_seq, marker_digest)` PRESENT in the tree:
`OBJECT_DIGEST_DELETED = [99u8;32]`, `OBJECT_DIGEST_WRAPPED = [88u8;32]`
(`digests.rs:861-874`). They arrive as `Modified` entries; `IdStatus::from_digest`
(`ocs_currency.rs:77-87`) maps them to `Deleted`/`Wrapped` → `currency` returns
`NotLive`. A server **cannot** mask a tombstone as `Absent`: the marker leaf carries
the target id, so a dummy non-inclusion's neighbor would be that leaf and
`non_inclusion_binds_id` rejects it.

> **`OBJECT_DIGEST_CANCELLED = [77u8;32]` is NOT special-cased** by
> `from_digest` — it falls through to `Modified`. Whether `effects.written()` can
> ever emit a cancelled-tx object as an `ObjectStates` leaf is **unverified** and is
> an accepted open question shared with the full-set path (§10). It is **not**
> introduced by this design.

> **Wrapped is reversible; Deleted is terminal — they are *not* interchangeable
> for eviction.** Both map to `NotLive` here (`from_digest`, `ocs_currency.rs:78-86`)
> and both are read-rejected by `check_currency` (`NotLive => Err NotCurrent`,
> `verified_reader.rs:715-719`), which is correct *at the anchor that tombstoned
> them*. But in Sui a **wrapped** object can later be **unwrapped** and written
> again: `effects.unwrapped()` is `Vec<(ObjectRef, Owner)>` and feeds
> `all_changed_objects(.., WriteKind::Unwrap)` (`effects/mod.rs:207-226`), i.e. the
> object still exists after the unwrapping tx and emits a fresh `effects.written()`
> leaf `(id, v', d')` at some later checkpoint `M' > M`. A **deleted** object never
> returns under the same id (`unwrapped_then_deleted` is terminal,
> `effects/mod.rs:243-252`). The non-inclusion machinery is unaffected — a real
> unwrap leaf carries the id, so `non_inclusion_binds_id` still forbids masking it
> as `Absent`. The asymmetry only bites the **subscription path's local eviction**:
> stop watching a `Wrapped` id and you stop folding the checkpoint that revives it.
> §5.4 EVICT therefore treats `Deleted` and `Wrapped` differently.

---

## 4. RPC and wire shape

### 4.1 Transport choice

All `sui_state_mirror` RPCs are **unary anemo** — there is no streaming
(`build.rs` declares the `SuiStateMirror` service via
`anemo_build::manual::Service`; the manual `MethodBuilder` exposes no
`client_streaming`/`server_streaming` flag). The per-peer relay deadline is
`RELAY_REQUEST_TIMEOUT = 30s` (`client.rs:62`). Therefore the "subscription stream"
is **poll-based paging**, exactly like `changeset_page`, never a held-open stream.
The subscription id-set is **re-sent on every request** (stateless), matching the
existing `from_seq + limit` model and avoiding per-connection server state.

A new unary `Method` `subscribed_changeset_page` is added to the `SuiStateMirror`
service, declared in `crates/ika-network/build.rs` alongside `changeset_page`
(same `codec_path = mysten_network::codec::anemo::BcsSnappyCodec`), handler on
`Server` in `crates/ika-network/src/sui_state_mirror/mod.rs`, client method on
`SuiMirrorTransport` via `self.peers.try_peers` in `client.rs` (inheriting
round-robin failover, demotion, and the "all-NotFound only if every reached peer
said NotFound; a timeout is NOT folded into all-NotFound" semantics,
`client.rs:104-189`).

### 4.2 Types (new, in `crates/ika-network/src/sui_state_mirror/mod.rs`)

```rust
pub struct SubscribedChangesetPageRequest {
    pub from_seq: CheckpointSequenceNumber,
    pub limit: u32,
    pub ids: Vec<ObjectID>,            // re-sent each page (stateless)
}

pub struct SubscribedChangesetPageResponse {
    pub entries: Vec<SubscribedChangesetEntry>,
}

pub struct SubscribedChangesetEntry {
    pub summary: CertifiedCheckpointSummary,
    pub proofs: BTreeMap<ObjectID, SubscribedIdProof>,   // EXACTLY one per requested id
}

pub enum SubscribedIdProof {
    Modified(OCSInclusionProof, (SequenceNumber, ObjectDigest)),
    Absent(OCSNonInclusionProof),
}
```

`OCSInclusionProof` and `OCSNonInclusionProof` are both `Serialize`/`Deserialize`
(`sui-light-client/src/proof/ocs.rs:180,203`), so they ride the existing
`BcsSnappyCodec`. `VerifiedObjectResponse` already ships `OCSInclusionProof` over
this transport, so there is no new serialization risk.

> **Wire framing note.** `proofs` is a `BTreeMap` keyed by `ObjectID`, NOT a `Vec`,
> so the receiver can assert *exactly-once accounting* (§4.3) by key lookup and
> reject any entry whose `proofs` keyset ≠ the requested `ids`. A `Vec` form would
> permit silent duplicate/omission ambiguity.

> **Homogeneous-`from_seq` note (per-id progress is a receiver concern).** The
> request carries **one** `from_seq` for the **whole** `ids` list, and the
> response is a checkpoint-keyed `Vec<SubscribedChangesetEntry>` whose every
> entry's `proofs` keyset must equal the requested `ids` (§4.3). We deliberately
> do **not** add a per-id `from_seq` to the wire type: a ragged per-id start makes
> the per-checkpoint id-set ragged (an id that subscribed later is simply absent
> from earlier entries), which destroys the *exactly-one-proof-per-requested-id-
> per-entry* accounting that the omission defense (§6) keys on and reopens the
> gap-as-absence ambiguity the design forbids. Heterogeneous per-id progress is
> instead handled entirely **receiver-side** by partitioning the subscribed ids
> into cohorts that share a resume point and issuing one homogeneous request per
> cohort (§4.3 Resume, §5.4 step 2). The server stays stateless and keeps its
> single contiguous `from_seq..from_seq+limit` loop (`mod.rs:255`).

### 4.3 Paging, backpressure, resume, completeness

- **Paging.** `from_seq..from_seq+clamp(limit, MAX_SUBSCRIBED_CHANGESET_PAGE)`. The
  handler breaks on the first unavailable/pruned checkpoint and returns the
  contiguous prefix, identical to `changeset_page` (`mod.rs:248-275`).
- **Resume (per-cohort, not a global rewind).** The receiver partitions the
  subscribed ids into **cohorts** by their per-id resume point
  `resume(id) = cov.head(id).map(+1).unwrap_or(subscribed_at_seq)` (§5.3), and
  issues **one** `subscribed_changeset_page` per cohort with that cohort's shared
  `from_seq = resume` and the cohort's ids. Because the server is stateless,
  resume is just the next request per cohort. This is the load-bearing fix for
  per-id `from_seq` divergence: a single request over the whole id-set would have
  to rewind to `min over ids of resume(id)` — the **slowest** id's lag — and
  re-prove every already-current id from that floor, multiplying the per-checkpoint
  `O(K · log N)` by the laggard span and collapsing the §7 bound during catch-up.
  Cohorting bounds total catch-up work by `Σ_cohorts (|cohort| · cohort_span · log N)`,
  never `(K · slowest_span · log N)`. Ids whose `resume` already equals the
  relay's head form a single steady-state cohort that advances one checkpoint at a
  time; only genuinely-lagging ids ride a deeper-`from_seq` cohort. A lagging cohort's
  entries arrive **below** the index's global `contiguous_head` (the always-present
  roots/inners drove the shared head ahead while the laggard was catching up) and are
  classified `AlreadyFolded` by the position gate, **yet each still advances its cohort
  ids' per-id `coverage.head`** — per-id coverage advancement is decoupled from the
  global head (§5.2, §8 step 6), so a laggard catches its own coverage up to
  `coverage.head(id)` over the same entries the global head already crossed. Cohorting
  is thus purely a bandwidth/CPU optimisation (it bounds re-proof work), **not** a
  correctness gate on whether a sub-head id can advance. A practical
  partition buckets ids by `resume` (exact, or coarsened into a small number of
  range buckets to cap the request fan-out), then **further splits any bucket
  whose size exceeds `MAX_SUBSCRIPTION_IDS` into `⌈|bucket| / MAX_SUBSCRIPTION_IDS⌉`
  pages**, each clamped to `MAX_SUBSCRIPTION_IDS = 256`. So for a registry of `N`
  ids the cohort/page count is **at least `⌈N / MAX_SUBSCRIPTION_IDS⌉`** (one page
  can carry at most 256 ids): the cap **partitions** the registry into pages, it
  does **not** bound the registry. In-flight pages are then throttled by
  `INFLIGHT_SUBSCRIBED_CHANGESET_PAGE` — a *concurrency* limit, **not** a cap on
  the total page count: a registry of `N` ids drains over `⌈N / MAX_SUBSCRIPTION_IDS⌉`
  pages issued at most `INFLIGHT_SUBSCRIBED_CHANGESET_PAGE` at a time, **never
  dropped for want of cap headroom.** A working set above 256 is paged, not
  truncated and not refused enrollment.
- **Backpressure / caps.** New constants in `mod.rs`, with defaults derived
  from the cost budget in §7.1 (which MUST be re-pinned against the Phase 0
  measurement before production):
  - `MAX_SUBSCRIBED_CHANGESET_PAGE = 16` — analog of `MAX_CHANGESET_PAGE = 64`
    (`mod.rs:376`), set **4× lower** because per-id proof construction is
    `O(ids · log N)` server CPU vs the full-set path's single map clone, and
    because the worst-case page must build in well under the 30s
    `RELAY_REQUEST_TIMEOUT` (§7.1). The server clamps `limit` to this exactly as
    `changeset_page` clamps at `mod.rs:253`.
  - `MAX_SUBSCRIPTION_IDS = 256` — a **per-request (cohort) clamp on
    `ids.len()`, NOT a cap on the receiver's registry.** The server rejects a
    request whose `ids` exceeds it rather than truncating (a truncated reply would
    silently violate the §4.3 completeness contract). 256 bounds the
    per-checkpoint fan-out **of one page** and, with `MAX_SUBSCRIBED_CHANGESET_PAGE`,
    the whole page (§7.1). **The receiver's registry may hold `N > 256` ids** — the
    live dwallet working set is dynamic and, in principle, unbounded — and the
    cohort partition (§4.3 Resume) splits it into `⌈N / MAX_SUBSCRIPTION_IDS⌉`
    requests, each clamped to 256. The cap is therefore a property of a single wire
    request; the registry is bounded by a **different** mechanism — TTL/GC
    residency, `O(working set)` (§5.4 item 4) — never by 256. Were 256 ever treated
    as a *registry* cap, a working set above it would force enqueue-drops, the §5.4
    reconcile re-walk would re-enroll the dropped ids, and they would overflow again
    — a drop / re-walk / re-overflow loop. **There is no such loop precisely because
    the registry is uncapped-but-TTL-bounded and cohorting pages it:** re-walk
    enrolls into the registry, cohorts page the registry, and the only thing 256
    limits is how many ids ride one wire request.
  - `INFLIGHT_SUBSCRIBED_CHANGESET_PAGE = 4` — analog of
    `INFLIGHT_CHANGESET_PAGE = 16` (`mod.rs:372`), tuned **4× lower** for the
    same CPU-per-request reason, wired via `inflight_limit::InflightLimitLayer`
    with `WaitMode::ReturnError` in `make_server()` (`mod.rs:380-416`).
- **Per-peer / per-id rate limiting (beyond the inflight cap).** The single
  `INFLIGHT_*` gate bounds *concurrent* requests but not *arrival rate*: one
  peer can serialize a flood of max-fan-out pages (`256 ids × 16 checkpoints` of
  non-inclusion `get_proof` walks each) within the inflight=4 budget and pin a
  serving core, and the `try_peers` round-robin (`client.rs:104-189`) means an
  honest fleet would then demote that server on timeout (§7.1) — a reflected DoS
  on the relay set. We therefore add a token-bucket limiter, keyed by
  `(PeerId, request)`, in the `subscribed_changeset_page` handler:
  `MAX_SUBSCRIBED_PAGES_PER_PEER_PER_SEC = 8` (refill rate) with a burst of
  `INFLIGHT_SUBSCRIBED_CHANGESET_PAGE`, and a coarser global
  `MAX_SUBSCRIBED_IDS_PER_PEER_PER_SEC = 2048` (= `8 × MAX_SUBSCRIPTION_IDS`,
  bounding *amplification* — total proofs/sec a peer can demand — independent of
  how the ids are split across pages). Over-budget requests return
  `ResourceExhausted` (a non-`NotFound` status, so `try_peers` treats it as a
  transient peer failure and rotates, never folding it into the all-NotFound
  fallback, `client.rs:142-156`). These limits are advisory caps a serving node
  sets; they do not affect soundness, only the relay's own DoS surface.
- **Completeness contract (the omission defense).** The receiver requires
  `entry.proofs` to contain a `SubscribedIdProof` for **every** id in the request's
  `ids` and **no foreign ids**. A requested id missing from `proofs`, or a proof for
  an unrequested id, is a hard `ChangesetError` (treated as omission); the entry is
  rejected and the receiver fails over via `try_peers`. **Absence must be PROVEN
  (id-bound non-inclusion), never inferred from a gap.** This is the wire-level
  enforcement of the omission argument (§6).

  > **Position binding (not just signature binding).** A proof verifying against
  > *some* committee-signed summary is necessary but **not** sufficient. The carried
  > `summary` must also sit at the **expected stream position**: its
  > `sequence_number()` must equal the next contiguous seq this page is folding, and
  > it must forward-chain (`previous_digest`) from the prior entry. Otherwise a
  > genuine, correctly-signed proof for an *older* checkpoint (where the id truly was
  > absent) could be replayed in the slot of a *newer* checkpoint (where the id was
  > modified), masking the modification with a real-but-stale non-inclusion. This is
  > enforced in `absorb_subscribed` (§8): the carried `summary` is position-gated
  > against the global frontier (`head_seq + 1` / `previous_digest`, mirroring the
  > full-set `absorb`, `ocs_currency.rs:269-285`) for the *global* head, and — for
  > **sub-head** entries a catching-up id rides — each id's proof is additionally
  > chained against that id's own `coverage.head_digest(id)`, so a stale-but-signed
  > proof can advance neither the global head nor any per-id coverage out of position
  > (§5.2, §8 step 6).

### 4.4 Non-inclusion encoding — single-target, no new primitive

Per `(checkpoint C, subscribed id X)` the server emits one `SubscribedIdProof`:

- **Absent**: `OCSNonInclusionProof` against `C`'s `ModifiedObjectTree.tree_root`,
  targeting `get_dummy_object_ref(X) = (X, 0, ObjectDigest::MIN)`, produced by
  `ModifiedObjectTree::get_non_inclusion_proof` (`ocs.rs:156-177`). The client runs
  ALL THREE mandatory checks:
  1. **Artifacts binding**: `CheckpointArtifactsDigest::from_artifact_digests(
     vec![proof.tree_root]) == summary.checkpoint_artifacts_digest()`.
  2. **Raw Merkle ordering + membership**:
     `proof.non_inclusion_proof.verify_proof(Node::from(tree_root), dummy_ref)`
     (this carries the intrinsic tree-adjacency of §3.2).
  3. **Id-binding**: `non_inclusion_binds_id(&proof, X)`.
- **Modified**: `OCSInclusionProof` whose verified leaf is `(X, version, digest)`;
  the client checks the inclusion proof, **asserts the leaf id == X**, and binds
  `tree_root` to the summary identically. Then it folds `X -> (version, digest)`.

**There is no batched/multi-id non-inclusion primitive** in fastcrypto, so this is
`K` independent single-target proofs, `O(K · log N)` per checkpoint with no path
sharing. We explicitly do NOT hand-roll a flat-boundary batch (it is unsound, §1.2).
A future fastcrypto Merkle multiproof / sorted-tree batched non-inclusion could
collapse the `K` gaps with shared paths; that is an upstream change and out of scope
(§10).

### 4.5 Receiver-side trait seam

A new trait method abstracts the transport for unit-testing the receiver, mirroring
the existing `ChangesetSource`:

```rust
trait SubscribedChangesetSource {
    async fn subscribed_changeset_page(
        &self,
        from_seq: CheckpointSequenceNumber,
        limit: u32,
        ids: Vec<ObjectID>,
    ) -> Result<Vec<SubscribedChangesetEntry>, TransportError>;
}
```

implemented for `SuiMirrorTransport` via `self.peers.try_peers`.

---

## 5. Subscription lifecycle and per-id currency

### 5.1 The dynamic read set (grounded)

There are exactly three currency-gated read entry points, each calling
`check_currency(id, anchored_seq)`:

- single: `verified_object` → `check_currency(resp.object.id(), proof_seq)`
  (`verified_reader.rs:673`),
- batch: `verified_objects` per slot (`:274`) — no application consumer today,
- bag: `verified_dynamic_fields_page` per entry (`:483`).

Id kinds: **(1,2)** the System and Coordinator outer roots are **static-known** from
`IkaObjectsConfig` (`messages_dwallet_mpc.rs:813-820`). **(3,4)** the
`SystemInnerV1` / `DWalletCoordinatorInnerV1` children are **version-derived**:
`derive_versioned_child_id(root, outer.version)` (`transport.rs:48-52`), discovered
by reading the verified outer. **(5)** the bag/dwallet entries are
**fully dynamic**: `verified_dynamic_fields_page` discovers each entry id only *after* the relay
returns the page, runs the OCS inclusion proof (`verified_reader.rs:434`) and the
membership-Owner binding (`:457-470`) on it, and only then — on the bound id — both
**enqueues `add_id(entry.object.id())`** into the subscription registry (§5.4
SUBSCRIBE) and calls `check_currency(entry.object.id(), seq)` (`:483`) **in the same
call**. The two session-event bag container ids are themselves read from the verified
`DWalletCoordinatorInner` (`bag_event_pump.rs:104-122`). The crux: a bag/dwallet id
is discovered, *bound*, and enrolled at the exact moment currency is needed, with
**no prior subscription window** — and enrollment is wired to the bag walk, not to the
currency gate (see the admission invariant below).

> **Registry admission invariant (two enrollment sites: static-pin and bag-path).**
> The registry has **exactly two** enrollment sites, and a byzantine relay can drive
> neither into naming a foreign id:
>
> **(A) Static roots/inners pin (the always-present class-1–4 ids, §8 head driver).**
> The `SubscribedChangesetReceiver` **seeds** the registry at construction with the
> two statically-known roots — `ika_system_object_id` and
> `ika_dwallet_coordinator_object_id` from `IkaObjectsConfig`
> (`messages_dwallet_mpc.rs:813-818`) — and **pins** each version-derived inner
> (`derive_versioned_child_id(root, outer.version)`, `verified_reader.rs:592/622`,
> `transport.rs:48-52`) on the first verified read of it. These ids are **statically
> pinned (non-bag) enrollment**, exempt from the bag-only admission of site (B): they
> are statically known (the roots) or deterministically derived from a verified parent
> (the inners), **never relay-listed**, so they carry **no** foreign-id-injection risk
> — the relay supplies neither a static config id nor a child-derivation seed. This is
> the enrollment the head driver (§8) rests on: it keeps the pinned set in *every*
> steady-state cohort's `ids`, so the shared `contiguous_head` advances one checkpoint
> at a time, guaranteeing an entry exists at every height. The shared head advancing is
> what keeps the *index* able to answer (§5.3); it does **not** by itself advance any
> dynamic id's per-id coverage — a fresh id advances its own `coverage.head` on the
> entries that carry its proof, whether those land at the head or below it (§5.2, §8
> step 6).
>
> **(B) Bag-path binding-checked enqueue (the dynamic class-5 ids).** An `ObjectID`
> enters the subscription registry as a verified child of a pinned bag **only** when
> admitted **lexically inside `verified_dynamic_fields_page`** *after* both the OCS inclusion
> proof (`verified_reader.rs:434`) and the membership-Owner binding (`:457-470`)
> have passed — `Owner::ObjectOwner(addr)` of the proof-verified object must equal
> the pinned `bag_id` or derive to its `Field<Wrapper<K>, ID>` wrapper id. The
> enrollment site is the bag walk itself: on the bound id, between the binding
> success (`:470`) and the existing `check_currency` call (`:483`),
> `verified_dynamic_fields_page` enqueues `add_id(entry.object.id())` to the registry.
>
> Neither site routes through the shared currency helper. **`add_id` is NOT enqueued
> from `check_currency`.** `check_currency(id, anchored_seq)` is a
> single helper invoked from **three** sites — single `verified_object`
> (`:673`), batch `verified_objects` (`:274`), and bag `verified_dynamic_fields_page` (`:483`)
> — and it carries **no provenance**: its arguments are only `(id, anchored_seq)`,
> so it cannot tell a binding-checked bag child from a relay-chosen id that a
> single or batch read happened to verify-and-gate. Were enrollment placed there,
> a single/batch read of a foreign id — or the verified `list_dynamic_fields`
> surface (`verified_transport.rs:165`, which *is* `verified_dynamic_fields_page` but is also
> consumed raw via `pull_dwallet_mpc_uncompleted_events`,
> `sui_syncer.rs:269`) feeding an unbound id — could name an id into the registry.
> Pinning admission to the post-binding line of `verified_dynamic_fields_page` closes that:
> the single (`:673`) and batch (`:274`) read sites do **not** admit, and the
> relay's raw `list_dynamic_fields`/`list_dynamic_fields`-style listing
> (`fallback_transport.rs:102`) — which has no membership-Owner binding — **never**
> admits. The roots/inners (classes 1–4) are **statically pinned (non-bag)
> enrollment** (site (A) above) and are likewise not bag-admitted; the two
> bag-container ids that anchor the walk are read from the verified
> `DWalletCoordinatorInner` (`bag_event_pump.rs:104-122`). So every id the registry
> ever holds traces to either a committee-anchored membership-bound bag read (site
> (B)) or a statically-known / version-derived pin (site (A)); the relay supplies key
> bytes but cannot name a foreign id into the set. This is a
> load-bearing invariant, not an incidental property of today's wiring: without it
> a byzantine relay injects arbitrary ids, **chooses which ids the node demands
> proofs for** (server-CPU amplification, since each demanded id costs the server
> `O(log N)` proof construction — §7), and makes the "memory bounded by
> subscription size" claim (§7) attacker-chosen rather than read-set-chosen. The
> invariant is what bounds registry growth to the verified dynamic read set; the
> §4.3 / §7 `MAX_SUBSCRIPTION_IDS` cap is a backstop on that bound, **not** its
> source — registry admission must reject any id that arrived through neither the
> bag-path binding-checked enqueue (site (B)) nor the static roots/inners pin (site
> (A)), regardless of cap headroom, and there are **no other** enqueue sites than
> those two.

### 5.2 Per-id coverage interval — the core invariant (fixes fatal S4/S7)

`ChangesetIndex` is extended with explicit per-id coverage state:

```rust
// new fields on ChangesetIndex
coverage: HashMap<ObjectID, CoverageInterval>,

struct CoverageInterval {
    subscribed_at_seq: CheckpointSequenceNumber,   // the resume seq the fresh id is requested from = the global contiguous head when it joined the request set (for the construction-seeded roots, §5.1 site A, this is seed.seq, the TrustedSeed/bootstrap height, §8; a version-derived inner pinned mid-stream takes the contiguous head at its first verified read, exactly like a bag child). The id's catch-up entries from this seq onward carry its proof, even when they arrive BELOW the global head and are classified AlreadyFolded (§8 step 2) — per-id coverage advancement is decoupled from the global head, so floor can land at subscribed_at_seq itself, NOT strictly above it
    floor: Option<CheckpointSequenceNumber>,       // first per-id-chained seq that actually carries the id's proof; lands at subscribed_at_seq on a fresh id whose first proof-bearing entry chains onto the trusted seed/head_digest (no off-by-one)
    head: Option<CheckpointSequenceNumber>,        // per-id contiguous head
    head_digest: Option<CheckpointDigest>,         // the digest of the entry at `head` — the per-id forward-chain anchor that the NEXT entry's previous_digest must match; this is what gates sub-head/AlreadyFolded advancement, NOT the global contiguous_head
    // DIAGNOSTIC-ONLY (not read by any verdict path): the digest of the
    // locally-trusted predecessor the floor entry chained onto (the seed
    // digest at the very floor, the prior contiguous-head digest thereafter).
    // Soundness rests on the absorb_subscribed position gate (§8 step 2), which
    // verifies that chain BEFORE the fold; this field merely records, after the
    // fact, which trusted predecessor was used, for debugging/observability. It
    // MAY be dropped without affecting any verdict.
    floor_anchored_on: Option<CheckpointDigest>,
}
```

**Coverage-interval invariant.** An id `X` may receive a `Current`/`Stale`/`NotLive`
verdict for anchor `M` only if `X`'s own stream has folded a **contiguous** run of
checkpoints (each carrying a verified inclusion-or-id-bound-non-inclusion for `X`,
with summaries forward-chained by `previous_digest`) such that
`coverage.floor(X) <= M <= coverage.head(X)`. Otherwise the verdict is `Unknown`.

This is the per-id analog of `absorb`'s `+1`/`previous_digest` forward-chain
(`ocs_currency.rs:258-287`). It is what actually discharges omission for the
subscription path — **not** the global frontier. A server that omits the checkpoint
where `X` was re-modified cannot advance `coverage.head(X)` past the gap (it can't
forge a non-inclusion there — `non_inclusion_binds_id` rejects it — and won't ship
the real inclusion), so `coverage.head(X)` stalls below the hidden modification and
any anchor at/above the gap reads `Unknown`.

**The subscribe instant — per-id coverage advances on sub-head entries too, so
`floor` lands at `subscribed_at_seq` with no off-by-one.**
`subscribed_at_seq` is the resume seq the fresh id `X` is requested from — the index's
global contiguous head `H` at the moment `X` is enrolled (§5.4 SUBSCRIBE). Because the
always-present roots/inners cohort drove the shared `contiguous_head` forward while `X`
was being enrolled, the catch-up entries the receiver fetches for `X` from
`subscribed_at_seq` onward arrive **below** the global head and are classified
`AlreadyFolded` against it (§8 step 2). The earlier draft treated such sub-head entries
as advancing nothing, which left `X` permanently `Unknown`; that is the gap this design
closes. **Per-id coverage advancement is decoupled from the global head**: a sub-head
entry that carries a verified inclusion-or-id-bound-non-inclusion for `X` **and**
forward-chains onto the per-id chain anchor (the trusted seed at the floor, or
`coverage.head_digest(X)` thereafter — *not* the global `contiguous_head`) advances
`coverage.head(X)`, regardless of whether the global head already crossed that seq.
Consequently:

- **`floor(X)` lands at `subscribed_at_seq` — no off-by-one.** A fresh id's resume
  point is `resume(id) = cov.head(id).map(+1).unwrap_or(subscribed_at_seq)` (§5.3);
  since `cov.head` is `None` on a fresh id, the receiver requests from
  `subscribed_at_seq`. The entry at `subscribed_at_seq` is `AlreadyFolded` against the
  **global** head, but it is the **first** proof-bearing, per-id-chained entry for `X`
  (it carries `X`'s proof and its `previous_digest` chains onto the index's already-trusted
  summary at `subscribed_at_seq - 1` — for an empty-index root the trusted predecessor is
  the seed, §8 step 6), so it **does** advance `X`'s coverage: `floor(X)` is set to
  `subscribed_at_seq` itself and `head(X)` rises with it. There is no `+1`: the fresh
  id's floor lands at its resume seq, not at `resume + 1`.
- **An anchor at `M == subscribed_at_seq` sharpens once that entry folds.** A read of
  `X` version-anchored exactly at the subscription instant `M = subscribed_at_seq`
  reads `Unknown → fallback` (§5.3) only until `X`'s catch-up entry at
  `subscribed_at_seq` folds and sets `floor(X) == M`; once the per-id interval brackets
  `M`, the verdict sharpens to a definite `Current`/`Stale`/`NotLive` drawn from `X`'s
  own folded coverage. While still `Unknown` the read is sound, not a false reject: the
  per-read OCS inclusion + membership binding still gate it. The only anchors
  permanently `Unknown` from this index are those **below** the deepest checkpoint the
  node can fold at all — the seed (`M == seed.seq`, never folded, §8) — not the
  subscription instant of a mid-stream id.

**The per-id chain anchor — what plays `contiguous_head`'s role at the floor.**
A "contiguous run" is only meaningful relative to a *seed* the node already
trusts. The global `absorb` gets its seed from the bootstrap arm
(`ocs_currency.rs:258-268`): the first checkpoint becomes the base with **no**
predecessor check, and every later checkpoint is admitted only at `head + 1`
with a matching `previous_digest` (`270-287`). A per-id interval **must not**
self-bootstrap that way — if the floor entry were allowed to become its own
base, a byzantine relay could ship a self-consistent, internally
forward-chained run `[F, F+1, …]` of genuinely BLS-signed summaries whose seed
`F` the node never reached, and the per-id chain would look contiguous while
beginning inside a gap. BLS-per-summary (§3.3) proves each summary is
authentic; it does **not** prove `F` is contiguous with what this node already
folded.

Therefore the floor entry of every per-id interval **must forward-chain onto a
summary the node already trusts independently of this stream**, and every later
per-id entry **must forward-chain onto that id's own previously-admitted entry**.
The trusted predecessor at the floor is one of exactly two, depending only on whether
the index has folded anything yet; **thereafter the chain is per-id**:

- **At the floor (index empty).** The first checkpoint `absorb_subscribed` folds
  must chain onto a checkpoint the node trusts **without** the relay — the
  `TrustedSeed` `(seed.seq, seed.digest)` (§8), which is
  `oldest_sui_committee_summary()` (`authority_perpetual_tables.rs:383-388`), the
  deepest checkpoint the node can committee-verify. The fold is admitted **only**
  when `seq == seed.seq + 1 && previous_digest == Some(seed.digest)`. The
  no-predecessor bootstrap arm of `absorb` (`ocs_currency.rs:258-268`) is
  **FORBIDDEN** for `absorb_subscribed`: the floor entry may **never** become its
  own base. This is what defeats a self-consistent, internally forward-chained run
  `[F, F+1, …]` of genuinely BLS-signed but stale summaries — `F`'s `previous_digest`
  cannot equal `seed.digest` unless `F` genuinely is `seed.seq + 1`.
- **At the floor (index non-empty, mid-stream fresh id).** A dynamic id enrolled
  after the index has been folding takes its floor at `subscribed_at_seq` (the global
  contiguous head when it joined). Its floor entry — fetched on catch-up, at
  `seq == subscribed_at_seq` — chains onto the index's already-trusted summary at
  `subscribed_at_seq - 1` (the entry the global head folded just before, whose digest the
  index already holds, established from the seed by the static-set driver), so the floor
  is anchored on a height the global chain has already reached from the trusted base,
  never on a relay-chosen floating start. The entry is `AlreadyFolded` against the
  *global* head yet still admitted into the id's coverage, because its chain check is the
  **per-id** one below — not the global `+1` gate, which never examines a sub-head entry.
- **Thereafter (per-id forward-chain).** Every later entry for `X` chains onto `X`'s
  **own** `coverage.head_digest(X)` — the digest of `X`'s current per-id head —
  admitted exactly when `previous_digest == Some(coverage.head_digest(X))`, the per-id
  analog of `absorb`'s contiguity arm. This is what advances `coverage.head(X)` on a
  sub-head/`AlreadyFolded` entry the global `contiguous_head` already crossed: the
  per-id chain re-imposes position-binding on every entry that moves `X`'s coverage,
  independent of where the global head sits.

`coverage.floor(X)` is set to the first admitted seq for `X`. The trusted-predecessor
chain is enforced by the **position gate** (§8 step 2 + step 6's per-id chain check),
which verifies `previous_digest == Some(seed.digest)` at an empty-index floor, chains a
mid-stream floor onto the trusted summary at `subscribed_at_seq`, and verifies
`previous_digest == Some(coverage.head_digest(X))` for every later per-id entry
**before** it advances `X`'s coverage — that gate, not any stored field, is what
discharges the soundness of the floor and of every sub-head advance.
`coverage.floor_anchored_on(X)` merely **records** which trusted predecessor digest was
used (the seed digest at an empty-index floor, the prior per-id `head_digest` thereafter)
as a **diagnostic** breadcrumb; it is **write-only — no verdict path reads it**
(`currency_subscribed` consults only `floor`, `head`, and the index record, §5.3), and
it MAY be dropped without weakening any verdict. The static-set driver (the
always-present roots/inners stream) keeps the global frontier advancing
checkpoint-by-checkpoint *from the trusted base*, guaranteeing an entry exists at every
height for a per-id interval to ride; but whether that interval **advances** is governed
by the per-id chain, so a per-id interval can attach and advance over the same
forward-chained summaries the global head crossed — at the head or below it — never at a
relay-chosen floating start. Because the subscribed ids ride the **same entries** (one
`summary` per checkpoint shared across all `K` ids, §4.2), the per-id chains and the
global head advance over the *same* forward-chained summaries; there is no separate
per-id trust root to forge.

A relay that wants to bless a forged-start run must therefore either make the global
`contiguous_head` jump to its forged base — which the position gate rejects at an
empty-index floor because `previous_digest != Some(seed.digest)` (`BrokenChain`) and at
the head because `absorb`'s `+1` / `previous_digest` gate (`270-287`) rejects it — **or**
advance a fresh id's per-id coverage onto a forged sub-head base, which the per-id chain
check (§8 step 6) rejects because the forged entry's `previous_digest` cannot match
`coverage.head_digest(X)` (at an empty-index floor) or the trusted summary at
`subscribed_at_seq` (at a mid-stream floor). The single-writer-per-index invariant (§8)
keeps any second writer from racing the head. With no trusted seed reachable,
`coverage.floor(X)` is never set (`floor == None`) and every read of `X` returns
`Unknown → fallback`. This is the exact S4/S7 seam closed: it is not enough that the
global frontier *brackets* `M`; the id's own floor must be *anchored* on the same
locally-trusted chain — and every entry that advances its coverage, at the head or below
it, re-chained against the per-id anchor — before any `Current`/`Stale`/`NotLive`
verdict is issued.

### 5.3 `currency_subscribed(id, M)` — the gated verdict

```text
let cov = coverage.get(id);
if cov is None
   or cov.floor is None or cov.head is None
   or M < cov.floor or M > cov.head:
       return Unknown                      // per-read fallback, never a false reject
// per-id coverage brackets M; now consult the index record
match index.get(id):
    Some(r) if r.last_seq == M && r.status == Modified  => Current
    Some(r) if r.last_seq == M && r.status in {Deleted,Wrapped} => NotLive
    Some(r) if r.last_seq >  M                            => Stale
    _                                                    => Unknown
```

The verdict mapping is unchanged from `currency()` (`ocs_currency.rs:310-335`); the
ONLY addition is the **per-id** bracket replacing the global one for subscribed ids.
This is the load-bearing fix: the fatal S4/S7 counterexamples relied on the GLOBAL
`[oldest_folded, contiguous_head]` (owed to the static set) bracketing `M` while the
fresh id's own coverage never spanned `[M, head]`. With `currency_subscribed`, `M`
below `cov.floor` (anchor predates the id's subscription) or `M` above `cov.head`
(the id's stream stalled or was pruned) both yield `Unknown` → fallback, never a
false `Current` and never a false `Stale`.

> **The subscription-instant boundary.** Because per-id coverage advances on sub-head
> entries too (§5.2), a fresh id's `floor(X)` lands at `subscribed_at_seq` itself (its
> catch-up entry at `subscribed_at_seq` is `AlreadyFolded` against the *global* head but
> still advances `X`'s coverage). So a read anchored at `M == subscribed_at_seq` reads
> `Unknown → fallback` only until `X`'s catch-up entry at `subscribed_at_seq` folds and
> sets `floor(X) == M`; thereafter the per-id interval brackets `M` and the verdict
> sharpens to a definite `Current`/`Stale`/`NotLive`. There is no off-by-one at the
> subscription instant. The **only** anchor permanently `Unknown` from this index is one
> below the deepest foldable checkpoint — the seed (`M == seed.seq`, never folded, §8) —
> which is sound and served by per-read fallback, never a false verdict.

`currency()` (global) is retained unchanged for the full-set path; `check_currency`
dispatches to `currency_subscribed` for ids governed by a subscription index and to
`currency` for full-set ids (§8).

### 5.4 Lifecycle states

1. **SUBSCRIBE.** The registry has **two** enrollment sites (§5.1), never the shared
   currency helper:

   **(A) Static-pin (roots/inners).** The `SubscribedChangesetReceiver` seeds the
   registry at construction with the two statically-known roots
   (`ika_system_object_id`, `ika_dwallet_coordinator_object_id` from
   `IkaObjectsConfig`, `messages_dwallet_mpc.rs:813-818`), recording each with
   `subscribed_at_seq = seed.seq` — the `TrustedSeed`/bootstrap height (§8) — and
   `floor = None`, so a root's floor can begin at the very first folded checkpoint
   `seed.seq + 1`. The always-present static set drives the shared `contiguous_head`
   from the trusted base (§8); each subscribed id (root or dynamic) advances its own
   `coverage.head` on the entries carrying its proof, at the head or below it (§5.2,
   §8 step 6). Each version-derived inner
   (`derive_versioned_child_id(root, outer.version)`) is pinned on its first verified
   read, recorded with `subscribed_at_seq = current contiguous head` like any
   mid-stream id. The pinned roots/inners are **never GC'd** (§5.4 GC) and are in
   every steady-state cohort, which is exactly what makes the head advance every
   checkpoint (§8). They carry no foreign-id-injection risk (statically known /
   version-derived, not relay-listed, §5.1).

   **(B) Bag-path binding-checked enqueue (dynamic bag/dwallet children).** This
   enrollment is wired **lexically into `verified_dynamic_fields_page`**. Inside
   `verified_dynamic_fields_page`, once an entry has cleared
   the OCS inclusion proof (`verified_reader.rs:434`) and the membership-Owner
   binding (`:457-470`), the reader enqueues `add_id(entry.object.id())` to the
   subscription registry over a **bounded, non-blocking channel** (so a bag read
   never blocks on the receiver's write lock) — on the **bound** id, on the line(s)
   between the binding success (`:470`) and the existing
   `check_currency(entry.object.id(), seq)` call (`:483`). The receiver records
   `subscribed_at_seq = current contiguous head`, `floor = None` on admission, and
   dedups against the registry on drain (idempotent), so re-walking a hot id does not
   re-enroll it. Because the enqueue is reached only *after* the binding, the
   enqueued id is necessarily a verified child of a pinned bag — the registry
   admission invariant of §5.1. The id is not yet folded; the read proceeds under
   `Unknown → Ok` (the per-read OCS inclusion + bag-membership Owner binding still
   gate it). **`add_id` is NOT enqueued from `check_currency`.** `check_currency`
   stays a pure currency gate with no admission side effect, precisely because it is
   also called by the single (`:673`) and batch (`:274`) read paths, which carry no
   bag-membership provenance and must never admit. Registry admission **rejects** any
   candidate id that did not arrive through the bag-path binding-checked enqueue —
   there is no API by which a relay listing (the raw `list_dynamic_fields` of
   `fallback_transport.rs:102`), a single/batch read, or a future caller
   short-cutting `verified_dynamic_fields_page` adds an id directly.

   **Channel-full must never be a silent subscription loss (red-team fix).** An
   unbounded channel is forbidden (`clippy.toml`: *"use a bounded channel
   instead"*), so under a burst that overflows the bound — epoch boundary, a large
   session batch — `try_send` returns `Full` and we MUST NOT drop the enrollment on
   the floor. A dropped `add_id` leaves the id permanently `Unknown → Ok`
   (authenticity-only, §5.5) with **no** currency gate and **no** signal — exactly
   the invisible coverage hole this design exists to close. The bounded channel is
   therefore made loud and self-healing, not lossy:
   - **Count every drop.** A `Full` `try_send` increments a monotonic
     `ika_ocs_subscription_enqueue_dropped_total` counter — a new **plain,
     unlabeled `IntCounter`** on `OcsMetrics`, registered with
     `register_int_counter_with_registry!` like `high_water_violations_total`
     (`ocs_metrics.rs:46/131`). It carries **no** label set: a channel-full drop
     is a single global producer→receiver event (the dropped `add_id`'s id need
     not even be recoverable to record the drop) and the reconciliation that heals
     it (the §5.4 reconcile re-walk) is global, so there is no natural per-id or
     per-bag dimension to slice on. It is **not** an `IntCounterVec` — unlike
     `bag_omission_suspected_total`, which **is** an `IntCounterVec` labeled
     `[bag]` (`ocs_metrics.rs:58/150`) precisely because each bag walk is a
     distinct keyed event. Because the counter is monotonic, the health verdict
     reads its **rate** — drops per sliding window, not the absolute value (§9,
     *Dropped-enrollment visibility*) — so a single drop the next reconcile tick
     heals into an enrollment is a benign transient, logged but not paged.
   - **Coalesce, don't multiply.** The read path is the producer for an *unbounded*
     id population, so the channel carries `add_id(ObjectID)` (idempotent), and the
     receiver dedups against the registry on drain — a burst of the same hot id
     collapses to one enrollment and does not itself overflow the bound.
   - **Reconcile by re-walking the pinned bags (the actual repair).** Because the
     subscribed set is recoverable by re-walking the two session-event bag containers
     (§12, item 8), a dropped enrollment is **not** lost. The
     `SubscribedChangesetReceiver` re-derives the live id-set **itself** on its poll
     tick rather than reading any internal state of `BagEventPump` (whose listed id-set
     is a function-local — `current_ids`, `bag_event_pump.rs:130` — inside its private
     `advance()` and is never exposed; `BagEventPump::run` consumes `self` and exposes
     no accessor). The receiver already holds the two collaborators the walk needs and
     no others: the shared `reader: Arc<OcsVerifiedReader>` and a clone of the
     `coordinator_rx: watch::Receiver<Option<(DWalletCoordinator, DWalletCoordinatorInner)>>`
     that carries the verified inner. Reconciliation is therefore a thin re-walk, the
     **same** surface the read path uses:

     1. Read the two per-epoch container ids out of the current verified inner —
        `inner.sessions_manager.{user,system}_sessions_keeper.session_events.id` —
        from the receiver's own `coordinator_rx` borrow, exactly as
        `bag_event_pump.rs:104-122` does (these container ids are themselves
        version-derived children of the verified `DWalletCoordinatorInner`, §5.1, so
        the walk cannot be steered at a relay-named bag).
     2. For each container, page through `reader.verified_dynamic_fields_page(bag_id, page_size,
        page_token)` (`verified_reader.rs:360`, already `pub`) to exhaustion, taking
        `entry.object.id()` of each returned `VerifiedObject`.
     3. Enroll (`add_id`, idempotent) every walked id **not already in the
        registry**; touch nothing else.

     **Why this enforces the registry-admission invariant (§5.1).** Every id the
     re-walk yields has, inside `verified_dynamic_fields_page`, already cleared the OCS inclusion
     proof (`verified_reader.rs:434`), the membership-Owner binding (`:457-470` — its
     proof-verified `Owner::ObjectOwner` must equal the pinned `bag_id` or derive to
     its `Field<Wrapper<K>, ID>` wrapper id), and the currency gate (`:483`) before
     `verified_dynamic_fields_page` returns it as a `VerifiedObject`. So reconciliation **only
     adds binding-checked ids** — it is the identical admission path as a live read
     firing `add_id` (§5.4 SUBSCRIBE), never a raw relay listing. This is deliberately
     *not* the alternative of broadcasting `BagEventPump`'s listed set: that set is
     filtered only for event-decoding, **not** for the membership-Owner binding, so
     consuming it would admit ids without the binding the invariant requires;
     re-walking re-runs the binding fresh.

     **Trust-independent in the safe direction.** The re-walk only ever *adds* ids the
     verified walk lists; it never GC's on a relay-driven shrink (per the §5.4 GC
     trust-independence rule — a relay omitting a child must not evict it). A byzantine
     relay can therefore at worst **delay** an enrollment (denied liveness, surfaced by
     `ika_ocs_subscription_enqueue_dropped_total`), never forge one (every added id is
     binding-checked) and never suppress one beyond the next clean walk. This is the
     bounded retry — a dropped `add_id` re-enrolls on the next reconcile tick rather
     than waiting for a fresh read to re-fire `add_id`. (The walk is the same paged
     traversal `BagEventPump` already runs every tick, so it adds no new trust surface
     and no new transport, only a second consumer of the existing `verified_dynamic_fields_page`
     RPC; its cost is one bag walk per reconcile interval, which can run at a coarser
     cadence than the §5.4 enqueue path since it is repair, not the primary enrollment
     trigger.)
2. **CATCH-UP.** The receiver's poll tick **partitions** the subscribed ids into
   cohorts by per-id resume point
   `resume(id) = cov.head(id).map(+1).unwrap_or(subscribed_at_seq)` and issues one
   `subscribed_changeset_page` per cohort with `from_seq = resume` shared across that
   cohort's ids (§4.3 Resume). For a fresh id (`cov.head == None`) the resume point is
   `subscribed_at_seq`; the entry at `subscribed_at_seq` returns `AlreadyFolded` for the
   **global** head (the index already folded that seq), but per-id coverage is decoupled
   from the global head — that entry carries the fresh id's proof, so it **does** advance
   the id's coverage: `floor` is set to `subscribed_at_seq` (the first proof-bearing,
   per-id-chained entry for the id) and `head` rises with it (§5.2, §8 step 6). There is
   no off-by-one: the fresh id's `floor` lands at its resume seq, not at `resume + 1`.
   This replaces a single request at the global `min over ids of resume(id)`, which
   would re-prove every already-current id back to the slowest id's lag and forfeit the
   §7 `O(K · log N)`-per-checkpoint bound. As each cohort's entries fold (at the head,
   on drain, or below the head), every id's `floor` is set to the first per-id-chained
   seq that carries the id's proof, and `head` rises only with that id's own contiguous
   frontier — independent of whether the global `contiguous_head` had already crossed
   those seqs (§5.2, §8 step 6) — so an id graduates to a higher (closer-to-head)
   cohort on the next tick and is never re-proven below its own `cov.head`. New ids
   enqueued by SUBSCRIBE join whichever cohort matches their `subscribed_at_seq` resume
   point.
3. **CURRENT.** Once `floor.is_some()` and the interval brackets a read's anchor,
   `currency_subscribed` becomes authoritative for that id.
4. **EVICT / GC.** Eviction is local (the server holds no per-subscription
   state) and is driven by the id's **verdict** plus a **locally-driven TTL** — timed
   from the id's last successful currency upgrade (or last read), never from anything
   an untrusted relay reports — but `Deleted` and `Wrapped` are *not* the same
   terminal:
   - **`Deleted`** is terminal: the id can never return under the same `ObjectID`
     (`unwrapped_then_deleted` is a tombstone, §3.4). It may be dropped from the
     request set immediately; its `IdRecord` ages out by the existing `prune`
     retain-window sweep (`ocs_currency.rs:396-410`) and its `CoverageInterval`
     row is dropped in the **same** step that removes it from the registry (see
     *Coverage-map pruning* below) — the two maps are pruned together, never
     leaving an orphan coverage row for a no-longer-subscribed id.
   - **`Wrapped`** is **reversible** (§3.4) and MUST NOT be evicted as terminal. The
     subscription **keeps the id in the request set** and keeps folding its per-id
     coverage, so that if the object is later unwrapped and re-modified at `M'`, the
     stream folds the unwrap leaf and advances `coverage.head(id)` over `M'`,
     overwriting the stale `Wrapped` record. This mirrors what the full-set path gets
     for free: it re-folds **every** id **every** checkpoint (`fold`,
     `ocs_currency.rs:341-364`), so an unwrap leaf overwrites the prior `Wrapped`
     record with no special handling — the subscription has no such automatic
     re-fold and must subscribe explicitly to obtain it.
   - **TTL/unread.** An id unread for an eviction window may be dropped regardless of
     verdict; dropping it removes its registry row, its `CoverageInterval`, and lets
     its `IdRecord` age out by `prune` — **all three**, so no map outlives the
     subscription (see *Coverage-map pruning*). A later read re-subscribes the id,
     which starts again at `coverage = None` and gets `Unknown → fallback` until it
     re-folds — **always sound** (§5.5), since the per-read OCS inclusion +
     bag-membership Owner binding still gate it and a fresh subscription can never
     inherit a stale `Current`.
     **If a re-discovered id's last known verdict was `Wrapped`** (or any record
     at/below the re-discovery anchor), re-subscription MUST **force the id to
     `Unknown` and clear/re-establish its `CoverageInterval`** (drop any residual
     row to `None`, then let it re-fold) rather than trusting the aged record, so
     currency rests on a freshly-folded coverage interval bracketing the new anchor
     and never on a pre-wrap record. The hazard this
     closes: because `prune` is amortized (it sweeps only once the floor has risen by
     a stride, over-retaining by `< stride`, `ocs_currency.rs:401-407`) and the
     retain window is large (`432_000` in production, §2), a stale `Wrapped` record
     can outlive the unwrap and — if eviction had stopped folding the id —
     `currency_subscribed` would read the reborn object's anchor `M'` against the
     stale `last_seq < M'` and return `Stale → Err NotCurrent`, **permanently
     stale-rejecting a legitimately-current object**. Keeping `Wrapped` ids watched
     (and force-`Unknown` on re-discovery) removes that path entirely.
   - **Registry residency is `O(working set)`, bounded by TTL — not by
     `MAX_SUBSCRIPTION_IDS`.** The §5.4 SUBSCRIBE reconcile re-walk enrolls **every**
     binding-checked walked id into the registry, so the registry tracks the **live
     dynamic read set**, which can exceed `MAX_SUBSCRIPTION_IDS = 256` (that cap is
     per-wire-request, §4.3, and cohorting splits a registry of `N` ids into
     `⌈N / MAX_SUBSCRIPTION_IDS⌉` pages). The registry itself carries **no 256
     ceiling**; it is bounded instead by the locally-driven TTL above — residency =
     `O(live working set)`, evicted by the **last-read TTL** (timed from the id's last
     successful currency upgrade or last read, never from anything a relay reports).
     This is what removes the apparent deadlock: the re-walk enrolls into the
     **uncapped-but-TTL-bounded** registry and the cohort pager (§4.3) drains it
     `⌈N / 256⌉` pages at a time, so there is no enqueue-drop driven by cap headroom
     and therefore no drop / re-walk / re-overflow loop.
     **If even the live working set is unbounded**, the last-read TTL is the backstop:
     should registry residency exceed a soft high-water bound, the **coldest-by-last-read**
     non-pinned, non-`Wrapped` ids are evicted **first** (an LRU keyed on last read,
     the same trust-independent clock the TTL uses) — each such id is re-derivable on
     its next read (`Unknown → fallback`, always sound, §5.5) and re-enrollable by the
     next reconcile re-walk. Eviction here is **one-directional toward `Unknown`**,
     identical to the GC trust-independence rule (§5.4 *GC trust independence*): an
     over-eager evict costs at most a re-subscription round trip, never a false
     `Current`. Roots and version-derived inners are **pinned** and exempt from this
     LRU pressure; `Wrapped` ids are kept (item 4) and exempt from terminal eviction.

> **Coverage-map pruning — the second map `prune` does not yet sweep.** The
> per-id `coverage: HashMap<ObjectID, CoverageInterval>` (§5.2) lives **alongside**
> `ChangesetIndex::index`, but the existing `prune` (`ocs_currency.rs:396-410`)
> only ever runs `self.index.retain(|_id, record| record.last_seq >= floor)` and
> raises `oldest_folded` — it **never touches a second map**. Left as-is, the
> `coverage` map would grow monotonically with every id ever subscribed and never
> shrink under `prune`, defeating the §7 memory bound. The subscription path
> therefore bounds the coverage map at **exactly three** points, and at no other:
>
> 1. **`prune` retain-floor (extended).** When `prune` raises `oldest_folded` to
>    `floor = head - retain_window`, the subscribed-index `prune` ALSO walks
>    `coverage` and, per entry, either (a) **drops** the row when its whole interval
>    has aged out — `cov.head.is_some_and(|h| h < floor)` — exactly mirroring the
>    `index.retain(last_seq >= floor)` test on the matching `IdRecord`, or (b)
>    **clamps** a straddling interval up to the new floor — `cov.floor =
>    max(cov.floor, floor)` — so no `CoverageInterval` ever brackets an anchor below
>    `oldest_folded` (which the index can no longer answer). Because the sweep is
>    amortized to the same stride gate as the index sweep (`401-407`), it adds a
>    second `retain` over an `O(K)` map, no new asymptotic cost.
> 2. **TTL eviction / GC (item 4).** Dropping an id from the subscription removes
>    its **registry row, its `CoverageInterval`, and (by aging) its `IdRecord`** in
>    one step — the coverage row is bounded by registry residency, not by the
>    retain-window, so an evicted id's coverage cannot outlive its subscription.
>    `Deleted` ids drop immediately (item 4); TTL-unread ids drop on the
>    locally-driven timer (GC trust-independence note below). Roots/inners are
>    pinned and their coverage rows are never GC'd.
> 3. **Re-subscription clear.** A re-added id `clear`s any residual
>    `CoverageInterval` to the fresh-subscribe state (`floor = None`,
>    `subscribed_at_seq = current contiguous head`) **before** the first fold, so it
>    can never inherit a stale `floor`/`head` from a prior subscription cycle (the
>    force-`Unknown`-on-Wrapped path in item 4 is the security-critical instance of
>    this; the general re-subscribe path uses the same clear).
>
> All three are one-directional toward `Unknown`: dropping or clamping a coverage
> entry can only *withdraw* a `Current`/`Stale`/`NotLive` verdict (the `M < floor`
> / `cov None` arms of §5.3 then return `Unknown → fallback`), never fabricate a
> `Current`. So the coverage map's lifecycle is sound by the same argument that
> makes `prune` sound for `index` (`ocs_currency.rs:389-395`): raising the floor
> only ever loses currency claims, never adds a false one. With these three points,
> `|coverage| = |registry| = O(K)` at all times — the dual bound §7 claims.

> **GC trust independence (red-team fix).** GC MUST NOT drop an id because an
> untrusted relay's bag page stopped listing it — otherwise a relay that omits a
> child could evict a live id; the worst that costs is a re-subscription round trip
> (sound: `Unknown → fallback`), but making GC *driven* by relay listings would let
> the relay control index residency. GC MUST also NOT treat a `Wrapped` verdict as a
> terminal trigger (only `Deleted` is terminal; see item 4). GC therefore fires
> **only on a locally-driven TTL** measured from the id's last successful currency
> upgrade (or last read), independent of any bag listing. Re-subscription after GC is
> always sound: a re-added id reads `Unknown → fallback` until it re-folds (§5.5), so
> a wrongful eviction is at worst a liveness/coverage blip, never a false `Current`.
> Roots and version-derived inners are **pinned** (never GC'd). An id oscillating
> subscribe/GC repeatedly raises a churn alarm.
>
> The verified `Bag.size`-vs-listed cross-check (`bag_event_pump.rs:208-220`) is a
> **best-effort omission alarm only, not a GC gate**: it is non-blocking ("we don't
> fail the tick"), it fires only on **under-listing** (`listed < expected_size`, so
> it can flag a parent claiming more children than were listed but **cannot observe
> a child that is genuinely gone** — a removal merely shortens the walk and trips
> nothing), and it is gated OFF on sui-state-direct (`detect_omission =
> bag_source_is_untrusted() = !cache_first`, `bag_event_pump.rs:76`,
> `verified_reader.rs:523-525`). It raises `bag_omission_suspected_total` for
> operator attention; it neither blocks a GC nor proves a child's absence, and GC
> never consults it.
>
> **Epoch-boundary re-pin.** The pinned set (roots + version-derived inners) is
> re-evaluated on each verified inner read: a reconfiguration that bumps the inner
> version pins the *new* inner id and lets the old one age out by retain-window. The
> per-epoch bag-container ids (§5.6(d)) are re-read each `BagEventPump` tick; a
> changed container id is a fresh subscription, and the old container is **retired**.
> Retirement does **not** synchronously force-drop the old container's children (that
> would be a relay-driven shrink). Instead every registry row is **tagged with the
> verified container generation** (`inner.current_epoch`, `bag_event_pump.rs:115`) it
> was enrolled under, and a retired container's still-tagged children are force-dropped
> at a fixed **`RECONFIG_GC_LAG`-epoch lag past retirement** — a *locally-counted,
> read-independent* drop measured from a verified retirement, not from a relay listing,
> so it neither lets a relay evict a live id nor lets stale-container children
> accumulate without bound. This caps the resident container generations at
> `RECONFIG_GC_LAG + 1` **independent of the reconfiguration count**, so
> `|registry| ≤ (RECONFIG_GC_LAG + 1) · O(per-generation working set)` across
> arbitrarily many reconfigurations — the lag drop bounds the generation *multiplier*,
> not the per-generation child count, which stays the TTL-bounded working set of §5.4
> item 4 (the 256 cap is per-wire-request, not a registry ceiling) (§5.6(d)). Like every
> coverage drop it is one-directional toward `Unknown` (sound): it can only withdraw a
> currency verdict, never fabricate one, and a still-live child is re-tagged to the
> current generation by the reconcile re-walk before the lag elapses.

### 5.5 The growth gap and its safe fallback

For a freshly-subscribed bag/dwallet id, currency is `Unknown` until its stream
folds a contiguous interval bracketing the anchor. `Unknown` maps to `Ok`
(`verified_reader.rs:709`) — never a false reject — so the read is gated by the
per-read OCS inclusion + membership-binding defenses that were already mandatory.
This is the explicit, accepted growth-gap semantics: a window of authenticity-only
(no currency) for newly discovered ids. It is sound but is a **liveness/coverage
degradation**, addressed by the observability requirements in §9.

### 5.6 Epoch boundaries and committee rotation

The currency machinery is anchored on `CommitteeStore::verify_summary`, which is
**epoch-keyed**: it BLS-verifies a summary against `committee(summary.epoch())`
(`committee_store.rs:250-264`), and `committee[E+1]` is *derived* from the
end-of-epoch summary of `E` (`end_of_epoch_data.next_epoch_committee`,
`committee_store.rs:140-159`, the "committees are derived from summaries" model).
The subscription path inherits this verbatim through `absorb_subscribed`'s
`verify_summary` step (§8), so each per-checkpoint summary in a coverage interval is
verified against *its own* epoch's committee — but two things change at a boundary
that the per-id machinery must handle explicitly.

**(a) A coverage interval may straddle a boundary; contiguity is digest-chained, not
epoch-chained.** The forward-chain that discharges omission is `previous_digest`, not
epoch (`absorb`/`drain_pending`, `ocs_currency.rs:258-287, 368-385`): the first
checkpoint of epoch `E+1` carries `previous_digest = digest(last checkpoint of E)`,
so the chain is **continuous across the boundary** even though the signing committee
switches. Therefore `coverage.floor(id) .. coverage.head(id)` MAY span an epoch
change with no special case in the contiguity logic — provided every summary in the
run verified, which means `committee[E+1]` was already installed when the first
checkpoint of `E+1` folded. **The hard gate is committee availability, not
contiguity** — and *availability is owned by a different subsystem than this stream.*

**The changeset fold does NOT install `committee[E+1]`.** `absorb` and
`absorb_subscribed` only *read* the committee table, via
`CommitteeStore::verify_summary` (`committee_store.rs:250-264`), which BLS-verifies a
summary against `committee[summary.epoch()]` and **never writes** it. The sole writer
of `committee[E+1]` is the separate **full-checkpoint committee ratchet**,
`OcsVerifyingClient::ratchet_to_current_epoch` → `CommitteeStore::install_next`
(`ocs_verifier.rs:141-245`, `committee_store.rs:276-289`): it fetches the *full*
end-of-epoch checkpoint of `E`, BLS-verifies it against `committee[E]`, extracts
`next_epoch_committee`, asserts `next.epoch == head + 1`, and installs it — advancing
`head_epoch` by exactly one real, committee-signed epoch per step. This loop runs on
its own 30s tick in the node (`ika-node/src/lib.rs:913-921`), wholly independent of
the changeset poll loop. So the first checkpoint of `E+1` cannot be folded by
**either** path until that ratchet has advanced `head_epoch()` to `E+1`; until then
`verify_summary` returns `SummaryVerifyError::MissingCommittee(E+1)`,
`absorb_subscribed` surfaces it as `ChangesetError::MissingCommittee(E+1)` (§8 step 1,
**not** flattened into `Unverified`), the entry does not fold, and `coverage.head(id)`
stalls at the last checkpoint of `E` for **every** subscribed id simultaneously.

**This is a cross-subsystem liveness dependency, and its failure is PERMANENT, not
transient.** A benign boundary stall (the ratchet simply hasn't reached `E+1` yet)
clears within one ratchet tick. But the ratchet itself can wedge: if the end-of-epoch
checkpoint of `E` has been **pruned upstream** and `allow_unverified_committee_fallback
= false` (the default — the unverified fallback re-roots trust on the endpoint's
word), `ratchet_to_current_epoch`'s `get_full_checkpoint(last_of_E)` returns
`NotFound` and the ratchet raises a hard `OcsError::ProofChainBroken { epoch: E }`
(`ocs_verifier.rs:166-178`). That error is **non-retryable** (`is_retryable()` returns
false for it, `ocs_verifier.rs:82-84`); the operator must re-anchor. Until they do,
`head_epoch()` never advances to `E+1`, so `committee[E+1]` never installs, so
**every** subscribed id's `coverage.head` is pinned at `E`'s last checkpoint
**indefinitely** and every read above that head falls back to `Unknown` — a total,
silent currency outage on the whole subscribed set that no amount of changeset polling
can heal. The full-set path exhibits the identical stall (it folds through the same
`verify_summary`), so this is not introduced by the subscription; what the
subscription adds is the requirement that the stall be **diagnosable**.

**Required boundary-stall health signal (gated on the ratchet head, not the changeset
head).** Because a boundary stall is sound (`Unknown → fallback`, never a false
`Current`) it must not page on sight — a node legitimately sits in it for one ratchet
tick at every epoch turn. The signal that distinguishes benign-transient from
wedged-permanent is the **ratchet head-epoch advancing**, which is already exported as
the `ika_ocs_committee_head_epoch` gauge (sampled every 10s from
`CommitteeStore::head_epoch()`, `ika-node/src/lib.rs:905-911`, `ocs_metrics.rs:22/69`)
alongside `ika_ocs_chain_latest_epoch` (the relay-claimed upstream epoch,
`ocs_metrics.rs:25/75`). The boundary-stall health gate is therefore:

> **Boundary-stall is benign iff `committee_head_epoch` is climbing toward
> `chain_latest_epoch`.** A coverage-head stall in which *all* subscribed ids are
> blocked on `ChangesetError::MissingCommittee(E+1)` is expected while
> `committee_head_epoch < E+1`. If `committee_head_epoch` stays frozen below
> `chain_latest_epoch` past a bounded window (the ratchet has wedged — typically
> `ProofChainBroken`), this is the **permanent** boundary stall and MUST page, not
> scroll past: it is a fleet-wide currency outage, not a per-epoch blip. This gate is
> distinct from the §9 per-id frontier-lag / tail-stall alarms, which fire on a
> *selective* stall (the global frontier advances while one hot id lags) — a boundary
> stall is the **opposite signature** (every id stalls at the same height while the
> ratchet head, not the changeset head, is what is stuck). Classifying a boundary
> stall as a selective-id stall would mis-route the operator to the relay set when the
> fix is to re-anchor the committee chain. See §9 ("Boundary-stall vs
> selective-id-stall").

The only new requirement on the contiguity logic itself is none: an interval is valid
iff **every** summary in it verified, which after this design means *the first
checkpoint of `E+1` folded only because the ratchet had already installed
`committee[E+1]`* — there is no way to advance `head` across a boundary on an
unverified successor, and the `MissingCommittee(E+1)` arm guarantees a not-yet-ratcheted
boundary fails closed (stall) rather than folding unverified.

**(b) Per-id chain re-anchor is automatic at the first checkpoint of `E+1`.** No
per-id re-anchor step is needed: the `previous_digest` of `E+1`'s first checkpoint
chains onto the id's own `coverage.head_digest(id)` (which at the boundary holds `E`'s
last summary digest — the per-id chain anchor of §5.2/§8 step 6, **not** the global
`contiguous_head`), so a subscribed id's `CoverageInterval` advances across the boundary
exactly as within an epoch — `coverage.head(id)` rises and `coverage.head_digest(id)` is
set from the new summary, with the BLS anchor having silently moved to `committee[E+1]`
inside `verify_summary`. The id's `IdRecord.last_seq` and its
`(version, digest)` leaf are epoch-agnostic (they live in `ModifiedObjectTree`,
which carries no epoch), so the per-id `previous_digest` chain crossing a boundary
needs no new field. The single invariant to preserve: an interval is only valid if
**every** summary in it verified, which after this design means *the boundary
summary's successor folded only because `committee[E+1]` was available* — there is no
way to advance `head` across a boundary on an unverified successor.

**(c) Currency is NOT force-reset to `Unknown` across the boundary.** A served
object's anchor `M` and its index record are committee-independent — `M` was
committee-signed at the epoch that produced it, and a later read at head in `E+1`
asks "was `id` re-modified in `(M, head]`?", which the (now boundary-straddling)
coverage interval answers directly. So `currency_subscribed` keeps answering across
the rotation with **no forced downgrade**, as long as the interval brackets `M`. The
*only* boundary-induced `Unknown` is the transient one from (a): while `head` is
stalled at the last checkpoint of `E` awaiting `committee[E+1]`, any read whose
anchor sits above that stalled head (or which is freshly subscribed and has no
`floor` yet) reads `Unknown → fallback`, by the unchanged §5.3 rule. We explicitly do
**not** add an epoch-equality check to `currency_subscribed`: forcing `Unknown` for
all ids on epoch change would be a gratuitous liveness regression and is unnecessary
for soundness (the BLS anchor already rotated correctly inside `verify_summary`).

**(d) Epoch-transition lifecycle for the bag/dwallet subscription set.** The two
session-event bag-container ids are **per-epoch**: they are read each tick out of the
verified `DWalletCoordinatorInner`
(`bag_event_pump.rs:104-122`, `sessions_manager.{user,system}_sessions_keeper.session_events.id`),
and `DWalletCoordinatorInner` is itself the version-derived child
`derive_versioned_child_id(coordinator_id, outer.version)` (§5.1,
`verified_reader.rs:592`). When the coordinator's inner version bumps at a
reconfiguration, the freshly-read inner can expose **different container ids**, so the
subscribed id-set must be rebuilt against them. The lifecycle is:

1. The roots (System, Coordinator) and the two version-derived inners are **pinned**
   (never GC'd, §5.4); on a version bump the *new* inner id is discovered by the
   normal verified-read path and pinned via the static-pin enrollment (§5.1 site A,
   §5.4 SUBSCRIBE (A)), and the old inner id ages out via the retain-window once no
   longer read. No subscription-set rebuild is needed for these — they ride the
   statically pinned (non-bag) enrollment (§5.1 site A) in every cohort, are folded
   through the single index by `absorb_subscribed` like every other subscribed id
   (§8), and are individually tiny.
2. The bag-**container** ids are re-read every `BagEventPump` tick from the current
   verified inner; when a tick observes a container id that differs from the prior
   tick's, the receiver treats the new container as a normal fresh subscription
   (§5.4 SUBSCRIBE): its children are discovered live and enter `Unknown → fallback`
   until their per-id streams fold a bracketing interval. The old container is
   **retired** at this tick. Retiring a container does **not** force-drop its
   children synchronously (that would be a relay-driven shrink, forbidden by the GC
   trust-independence rule, §5.4) — instead each child is **tagged with the container
   generation it was enrolled under**, and stale-container children are evicted at a
   **bounded epoch lag**, not at an open-ended read-driven TTL:
   - **Generation tag (trust-anchored, not relay-reported).** Every registry row
     records the generation it was enrolled under: the verified epoch
     `inner.current_epoch` read from the committee-verified `DWalletCoordinatorInner`
     **in the same borrow** that reads the two container ids
     (`bag_event_pump.rs:104-122`, `:115`). Because that epoch is a field of a
     BLS-anchored inner (§5.1) and the container ids are version-derived children of
     it, the tag cannot be steered by a byzantine relay — it is the same trust anchor
     the container-id discovery itself rides. A child that is still live under the
     **new** container is re-listed by the new container's verified walk and
     **re-tagged to the current generation** on the next reconcile re-walk (§5.4
     SUBSCRIBE reconcile) before any lag expires, so the tag tracks a child's *latest*
     live generation, not merely its first.
   - **Retirement-lag drop (bounded, read-independent, one-directional).** When the
     current verified epoch has advanced `RECONFIG_GC_LAG` epochs past a retired
     container's last-live generation, the receiver force-drops every registry row
     still tagged to that container — dropping its registry row **and** its
     `CoverageInterval`, and letting its `IdRecord` age out by `prune` (the three-map
     removal of §5.4 *Coverage-map pruning*), independent of whether any read recently
     touched it. This is the **only** force-drop the design permits, and it is **not**
     relay-driven: it fires on a locally-counted epoch lag measured from a *verified*
     retirement, so a relay can neither trigger it early (it cannot move the verified
     epoch) nor suppress it. It is one-directional toward `Unknown` exactly as every
     other coverage drop (§5.4 *Coverage-map pruning*): it can only **withdraw** a
     `Current`/`Stale`/`NotLive` verdict (the dropped id reverts to `Unknown →
     fallback`), never fabricate a `Current`. A child genuinely still live under the
     new container has been re-tagged to the current generation before the lag
     elapses, so the lag drop never evicts a still-reachable child; in the worst case
     a wrongful drop is re-enrolled by the next reconcile re-walk and reads
     `Unknown → fallback` in the interim — sound (§5.5).
   - The pre-lag interval (a retired container's children still inside the lag window)
     continues to age by the locally-driven TTL and is cross-checked against the
     verified `Bag.size` omission detector (`bag_event_pump.rs:208-220`) of the *old*
     container; the lag drop is the **hard ceiling** that guarantees eviction
     regardless of read activity, where the read-driven TTL alone gave none.

   **Resulting bound on `|registry|` across reconfigurations.** At most
   `RECONFIG_GC_LAG + 1` container generations can have resident children at any
   instant: the current generation plus the `RECONFIG_GC_LAG`-epoch lag window before
   a retired generation's children are force-dropped. A single generation's child set
   is **not** capped at `MAX_SUBSCRIPTION_IDS` — it **is** the live dwallet working set
   under that container, which is dynamic and uncapped (that cap is the per-wire-request
   cohort clamp of §4.3/§7, not a registry ceiling — §5.1, §5.4 item 4); each
   generation's residency is the **TTL-bounded `O(per-generation working set)`** of
   §5.4 item 4. So
   ```
   |registry|  ≤  (RECONFIG_GC_LAG + 1) · O(per-generation working set)
   ```
   for **arbitrarily many** reconfigurations. What the lag drop makes closed is the
   **generation multiplier**: it caps the number of resident generations at
   `RECONFIG_GC_LAG + 1` **independent of the reconfiguration count**, where before it
   could accumulate one stale-container generation per reconfiguration until read-driven
   TTL happened to evict each. Each resident generation is then bounded exactly as the
   single-generation steady state is (the locally-driven last-read TTL of §5.4 item 4),
   so the per-reconfiguration accumulation that the lag drop removes is the real leak,
   and the residual `O(per-generation working set)` factor is the same one the §7 `O(K)`
   memory claim already carries — the lag drop multiplies it by a fixed constant, it
   does not introduce a new unbounded factor. This keeps the §7 `O(K)` memory claim
   intact with `K ≤ (RECONFIG_GC_LAG + 1) · (per-generation working set)` (the pinned
   roots/inners of class 1–4 add a small constant on top, §5.4). `RECONFIG_GC_LAG` is a
   small fixed constant (e.g. 1–2 epochs) — large enough that a child momentarily absent
   from one verified walk is re-tagged before it is dropped, small enough that the
   resident-generation multiplier stays near 1. The pinned roots/inners (classes 1–4)
   carry no generation tag and are never lag-dropped (§5.4).
3. Because container-id discovery is gated on first folding the new
   `DWalletCoordinatorInner` (which is gated on `committee[E+1]`, per (a)), the
   subscription-set rebuild **cannot outrun** committee availability: the node never
   subscribes against a container id it has not verified at a checkpoint it can
   BLS-anchor.

> **Reconfiguration is cluster-suite territory.** Per the engineering guide, epoch
> boundaries / reconfiguration are the most fragile path and are validated on the
> cluster suite on CI (`CLAUDE.md`, "Epoch boundaries / reconfiguration /
> `sui_connector` → cluster suite"). The unit/property coverage below pins the
> committee-rotation logic in isolation; the end-to-end boundary behavior (container-id
> rebuild, stall-and-recover across a real reconfiguration) belongs in the cluster
> suite, not in `ocs_currency` unit tests.

---

## 6. Omission argument (per subscribed id, per checkpoint)

For every `(id X, checkpoint C)` in the requested contiguous range the server must
produce a proof verifying against `C`'s committee-signed
`checkpoint_artifacts_digest`, and that digest commits (two-level Blake2b256 over the
id-sorted `ObjectStates` Merkle tree) to the COMPLETE modified set — the server
cannot choose the root. Given that fixed root, exactly one of
`{inclusion at the true leaf, id-bound non-inclusion}` verifies:

- If `X` **was** modified: only an inclusion at the real `(X,v,d)` leaf passes Merkle
  membership; a dummy non-inclusion would need a neighbor with `id == X`, rejected by
  `non_inclusion_binds_id` (the Blocker-1 fix), and the intrinsic tree-adjacency
  (§3.2) forbids straddling the present leaf with non-adjacent honest neighbors.
- If `X` was **not** modified: no inclusion leaf exists; the id-bound non-inclusion's
  neighbors genuinely carry other ids.

**Boundary cases of id-bound non-inclusion are discharged.** The single-target
argument above must hold at the *ends* of the id-sorted leaf vector, not only for
an interior gap. The dummy target is `(X, 0, ObjectDigest::MIN)`
(`ocs.rs:61-63`); `compute_non_inclusion_proof` places it at
`position = leaves.partition_point(|leaf| leaf <= dummy)` (`merkle.rs:459`) and
sets `index = position`, `left = leaves[position-1]`, `right = leaves[position]`
(`merkle.rs:466-482`). The four boundary configurations resolve as follows.

- **X present, anywhere — the forcing argument (the case that must NOT be
  forgeable).** If `X` *was* modified, its real leaf `(X, v>0, d)` is in the tree.
  Because `ObjectRef` Ord is lexicographic and `v > 0` — a real object starts at
  `OBJECT_START_VERSION = SequenceNumber::from_u64(1)` (`object.rs:50`) and versions
  only increment, so `v >= 1` always holds and no genuine leaf carries `v == 0` —
  that leaf is **strictly
  greater** than the dummy `(X, 0, MIN)`, so `partition_point(<= dummy)` does **not**
  count it: `position` lands at-or-before the real leaf's slot, forcing
  `right = leaves[position]` to be **X's own real leaf** (it is the first leaf
  `> dummy`, and id-sort keeps all of X's representation contiguous — at most one
  per id, `ocs.rs:91-101`). That right neighbor carries id `X`, so
  `non_inclusion_binds_id` rejects (`ocs_currency.rs:51-62`; this is exactly the
  standing forgery test `a_forged_non_inclusion_for_a_present_id_is_rejected`,
  `ocs_currency.rs:455-494`). A byzantine server cannot escape this by **forging
  the `index`**: `verify_proof` re-verifies `right` at slot `index` and `left` at
  slot `index-1` against the committee-committed root (`merkle.rs:262-282`), and a
  Merkle path binds a leaf to its position — the real X leaf cannot be made to
  validate at any slot but its own, nor relocated out of the neighbor pair while
  the proof still verifies. The dummy's sort position is deterministic, so the
  server cannot choose a different `position` for it.
- **X sorts above all real leaves** (`right_leaf = None`, only the left neighbor
  checked). `verify_proof` requires the present left leaf to be the rightmost
  (`is_right_most`, `merkle.rs:289-292`). If `X` were in fact present and last, its
  real leaf would itself be that rightmost left neighbor and carry id `X` →
  `non_inclusion_binds_id` rejects. If `X` is genuinely absent and sorts past the
  end, the rightmost real leaf carries some other id and the proof is sound.
- **X sorts below all real leaves** (`left_leaf = None` at `index == 0`, only the
  right neighbor checked). `verify_proof` requires `right_leaf.is_some()` with
  `index == 0` (`merkle.rs:275-278`). If `X` were present it would be that slot-0
  right neighbor (every X leaf is `> dummy`), carrying id `X` →
  `non_inclusion_binds_id` rejects. If genuinely absent, slot 0 carries a different
  id and the proof is sound.
- **Empty tree** (zero modifications at that checkpoint). `verify_proof` returns
  `Ok` unconditionally (`merkle.rs:258-260`), and both neighbors are `None` so
  `non_inclusion_binds_id` is vacuously true. This is sound precisely because the
  artifacts-digest binding (§3.3) pins *which* checkpoint's root is being proven:
  an empty `ModifiedObjectTree` is a committee-committed claim that **nothing** was
  modified that checkpoint, so `X` is genuinely absent. A server cannot present a
  non-empty checkpoint's modifications as "empty" — that would change the root and
  break the artifacts binding.
- **Single-leaf tree.** The lone leaf is simultaneously the leftmost and rightmost,
  so the dummy falls into either the *sorts-below-all* branch (lone leaf is the
  slot-0 right neighbor) or the *sorts-above-all* branch (lone leaf is the rightmost
  left neighbor). Both are covered above; if that lone leaf is `X`'s own real leaf,
  `non_inclusion_binds_id` rejects in whichever branch it lands.

In every boundary configuration the proof either fails `verify_proof` (wrong
neighbor slot, non-rightmost left, or missing slot-0 right) or is caught by
`non_inclusion_binds_id` (a present-X neighbor) — so an `Absent` verdict for a
modified `X` is unreachable at the ends of the id range exactly as it is in the
interior.

Therefore the server cannot **(a)** drop a modification, **(b)** fabricate one (no
leaf exists in the committed root), or **(c)** silently skip an id — a missing
`SubscribedIdProof` for a requested id is a hard error (§4.3), so the checkpoint does
not fold for that id and `coverage.head(X)` does not advance, keeping `X` `Unknown`
→ fallback, **never** silently `Current`.

The **checkpoint-skip** axis (a whole `C` omitted from the sequence) **and the
stale-replay axis** (a genuine proof for an *older* checkpoint served in `C`'s
slot) are both caught by binding every entry to its **stream position**, not
merely to *a* signed summary. The full-set `absorb` already does this: it folds
only at `head_seq + 1` and only if `incoming.previous_digest == Some(head_digest)`
(`ocs_currency.rs:269-285`), so a summary presented out of position is
`AlreadyFolded`/`Queued`/`BrokenChain`, never folded as the head. `absorb_subscribed`
inherits the identical gate (§8). Two distinct forgeries this closes:

- **Skip.** A successor summary that does not forward-chain — onto the **global**
  frontier (the entry is `BrokenChain`/queued/dropped, `absorb` `258-287`,
  `drain_pending` `379-382`) **or**, for an id catching up below the head, onto that
  id's own `coverage.head_digest(X)` — cannot advance `coverage.head(X)` over the gap,
  so any anchor at/above the gap reads `Unknown` → fallback. The per-id chain check
  (§5.2, §8 step 6) is what discharges skip for a sub-head catch-up entry, since such
  an entry is `AlreadyFolded` against the global head and the global `+1` gate never
  examines it.
- **Stale replay.** A genuine `Absent(OCSNonInclusionProof)` for `C-100` (where `X`
  really was not modified) carries `C-100`'s correctly-BLS-signed summary, whose
  artifacts digest genuinely commits `C-100`'s tree, and `verify_proof`
  (`merkle.rs:256-299`) verifies it against that root with **no notion of which
  checkpoint the root belongs to**. Steps 1–4 of the naive check therefore all pass.
  The position gate rejects it: replaying it in `C`'s slot fails the
  `sequence_number() == expected_next_seq` check, and chaining `C-100`'s summary onto
  the head fails `previous_digest`. So `X`'s real modification at `C` cannot be masked
  by a valid-but-stale absence — `coverage.head(X)` cannot cross `C` without the proof
  that actually verifies at `C`'s root (which, since `X` was modified there, can only be
  an inclusion at the real `(X,v,d)` leaf), and that holds whether `C` is folded at the
  global head or crossed by `X` below the head on catch-up: the per-id forward-chain on
  `coverage.head_digest(X)` (§5.2, §8 step 6) re-imposes position-binding on every entry
  that advances `X`'s coverage, not only on the entry at the global frontier.

> **The decisive correction over the unsound framings:** omission is discharged by
> the **per-id coverage-interval invariant + completeness contract**, NOT by the
> global frontier and NOT by global contiguity alone — and, because per-id coverage
> advances on sub-head catch-up entries too, the invariant binds **every** entry that
> moves `coverage.head(X)`, including those the global `+1` gate classifies
> `AlreadyFolded` (§5.2, §8 step 6). The fatal refutations all exploited
> the assumption that "global frontier brackets `M`" implies "X was checked over
> `[M,head]`." It does not, and `currency_subscribed` no longer makes that
> inference.

---

## 7. Bandwidth / memory regime, and when to prefer each path

**Bandwidth per page** = Σ over checkpoints in `[from_seq, from_seq+limit)` of Σ over
subscribed ids of one proof. An inclusion proof is one Merkle path `~log2(N)`
hashes; a non-inclusion proof is `~2×` (two neighbor leaves, each a full root-path).
So a `K`-id page over span `S` is `O(K · S · log N)` with **no path sharing**
(fastcrypto has no multiproof). The summary is shipped once per checkpoint and shared
across all `K` ids in the entry, so its BLS verify is amortized across `K`.

**Index memory** = one `IdRecord` in `index` + one `CoverageInterval` in
`coverage`, **per subscribed id** = `O(K)` where `K` is the **registry residency**
(the live working set under the §5.4 TTL/GC, which **may exceed
`MAX_SUBSCRIPTION_IDS = 256`** — that cap bounds a single wire page, §4.3, not the
index/coverage maps; a registry of `K > 256` ids is served by `⌈K / 256⌉` pages,
never by truncating the index) — and **independent of `N`** (the per-checkpoint
modified-set size), the dual bound the full-set path lacks (under `filter=None`
the full-set `index` grows with chain activity). The two maps are bounded by
*different* mechanisms and `prune` (`ocs_currency.rs:396-410`) only directly
governs one of them:

- `index` (`IdRecord`s) is bounded **both** by registry residency **and**
  *downward* by `prune`'s retain-window: an idle subscribed id's record ages out
  once its `last_seq` falls below `head - retain_window`, even while the id stays
  registered (it simply reverts to `Unknown → fallback` until re-folded).
- `coverage` (`CoverageInterval`s) is bounded by the **registry** — one row per
  subscribed id, dropped at GC/EVICT and re-subscription (§5.4 *Coverage-map
  pruning*). `prune` does not retain it on the retain-window; the extended
  subscribed-index `prune` only **clamps/drops** coverage rows that have aged
  entirely below the raised `oldest_folded` floor, which is a soundness clamp (no
  interval brackets an anchor the index can't answer), **not** the primary bound.

So `|index| ≤ |registry|` and `|coverage| = |registry|`, both `O(K)`. The earlier
draft's claim that coverage is "bounded by `prune`'s retain-window" was wrong:
`prune` sweeps `self.index` only; the coverage map's bound is registry residency,
which is why GC/EVICT/re-subscribe (not the retain-window) are its load-bearing
removal points.

**Crossover.** The subscription wins iff `K · log N << N`, i.e. the node reads far
fewer ids than the chain modifies per checkpoint — the production OCS regime (2
static roots + 2 version-derived inners + a retain-window-bounded live dwallet
working set vs a busy Sui modified set). The full-set path wins when `K` approaches
`N` (a huge live dwallet population), where its proof-free `O(N)` beats `O(N log N)`.

> **No in-tree benchmark exists**; the bounds are structural, not measured. Concrete
> proof-size and server-CPU measurements are required before tuning the caps (§9, §10).

**Server CPU is the cost to watch.** Producing `K` non-inclusion proofs per
checkpoint is a `partition_point` neighbor lookup + up to two `get_proof` calls
EACH, vs the full-set path's single `object_states` clone. Hence
`INFLIGHT_SUBSCRIBED_CHANGESET_PAGE` and `MAX_SUBSCRIPTION_IDS` are set conservatively
and tuned empirically.

### 7.1 DoS / amplification cost budget

The subscription's cost is dominated by **server CPU to construct proofs**, not
by index memory (which is `O(K)`, §7). This subsection pins that cost to the
caps so a max-fan-out page cannot (a) exceed the 30s `RELAY_REQUEST_TIMEOUT`
(`client.rs:62`) — which would get the honest server demoted by every peer in
the fleet — or (b) amplify a small request into an unbounded proof workload.

**Per-non-inclusion unit cost (grounded).** Producing one `Absent` proof is, in
fastcrypto terms: one `partition_point` over the id-sorted leaf slice
(`compute_non_inclusion_proof`, `merkle.rs:459`, `O(log N)` comparisons) + up to
**two** `get_proof` tree walks (left neighbor at `position-1`, right at
`position`, `merkle.rs:466-476`), each walk collecting `⌈log2 N⌉+1` sibling
`Node`s (`get_proof`, `merkle.rs:426-445`) — i.e. up to `2·(⌈log2 N⌉+1)`
32-byte Blake2b digests copied into the proof — then BCS + snappy of those two
root-paths into the `OCSNonInclusionProof`. An `Modified` (inclusion) proof is
the cheaper half: one `get_proof`, one root-path. Write `c_ni ≈ 2·(log2 N + 1)`
and `c_inc ≈ log2 N + 1` hash-copies; the non-inclusion case is the budgeted
worst case (a long-idle subscribed id costs one non-inclusion per checkpoint,
§12.1).

**Per-page CPU (closed form).** A page over span `S = limit` checkpoints with
`K = ids.len()` subscribed ids costs

```
work_page  =  Σ_{c in [from_seq, from_seq+S)}  Σ_{x in ids}  proof_cost(c, x)
           ≤  K · S · c_ni
           =  O(K · S · log N)        // no path sharing — fastcrypto has no multiproof (§1.2, §4.4)
```

plus one `ModifiedObjectTree` materialization per distinct checkpoint touched
(amortized by the server-side `ProofCache` — see §7.2 for the cap it MUST be
raised to before this path ships) and one summary BLS-verify per
checkpoint **on the client**, amortized across all `K` ids in the entry (§7).
With the §4.3 defaults `K ≤ MAX_SUBSCRIPTION_IDS = 256` and
`S ≤ MAX_SUBSCRIBED_CHANGESET_PAGE = 16`, a single worst-case page performs at
most `256 · 16 = 4096` non-inclusion constructions =
`≤ 4096 · 2·(log2 N + 1)` `get_proof` sibling-collections plus `4096`
`partition_point`s.

**Per-page bandwidth (closed form).**

```
bytes_page  ≈  S · |summary|                                  // one CertifiedCheckpointSummary per checkpoint, shared across K ids
            +  K · S · (proof_bytes · snappy_ratio)           // one proof per (id, checkpoint)
proof_bytes(Absent)    ≈ 2·(log2 N + 1)·32  + 2·|ObjectRef|   // two neighbor root-paths + two neighbor leaves
proof_bytes(Modified)  ≈   (log2 N + 1)·32  +   |ObjectRef|
```

The `K·S` proof term has **no path sharing**, so bandwidth is linear in the
page's id-checkpoint product. At `N ≈ 2^20` (log2 N = 20), an `Absent` proof is
`≈ 2·21·32 = 1344` bytes of path before snappy; a max page is therefore on the
order of `256 · 16 · ~1.3 KiB ≈ 5 MiB` pre-compression, `S · |summary|` on top.
This is the amplification ceiling a single request can demand and is why
`MAX_SUBSCRIPTION_IDS · MAX_SUBSCRIBED_CHANGESET_PAGE` (not either alone) is the
quantity to bound.

**Latency invariant (load-bearing).** `try_peers` wraps each `op` in
`tokio::time::timeout(RELAY_REQUEST_TIMEOUT, …)` (`client.rs:139`); on elapse it
**demotes the peer** (`client.rs:157-173`) and the all-NotFound fallback is
explicitly *not* taken (`all_not_found = false`, `client.rs:161`). Therefore:

> **Invariant (max-page latency).** Worst-case page assembly —
> `MAX_SUBSCRIPTION_IDS × MAX_SUBSCRIBED_CHANGESET_PAGE` proof constructions on
> a cold `ProofCache`, plus BCS+snappy — MUST complete in **strictly less than
> `RELAY_REQUEST_TIMEOUT = 30s`**, with comfortable margin (target ≤ 5s p99, a
> 6× headroom for queueing, GC pauses, and a partially-cold cache), or honest
> serving peers are demoted on timeout and the fleet converges on the cheapest
> (possibly byzantine-withholding) peer. The caps above are chosen so the
> `4096`-proof worst case sits inside this margin on the measured per-proof
> cost; **they are placeholders until the Phase 0 measurement (§10) pins the
> real per-proof CPU**, after which `MAX_SUBSCRIBED_CHANGESET_PAGE` and
> `MAX_SUBSCRIPTION_IDS` are set so `4096 · (measured c_ni) · (cold-cache
> materialization factor) ≪ 5s`.

**Why these defaults.** `INFLIGHT_SUBSCRIBED_CHANGESET_PAGE = 4` caps concurrent
serving cores at the worst-case page; `4 · 4096 = 16384` in-flight proof
constructions is the steady-state ceiling a single peer's inflight budget
admits. The token bucket (§4.3) then bounds *arrival rate* on top of
concurrency, so a peer cannot churn max-fan-out pages faster than
`MAX_SUBSCRIBED_PAGES_PER_PEER_PER_SEC = 8`, capping per-peer demanded proofs at
`8 · 4096 ≈ 32k/sec` (the `MAX_SUBSCRIBED_IDS_PER_PEER_PER_SEC = 2048` bucket
bounds the same quantity when the attacker spreads ids thin across many small
pages). All four numbers are **conservative placeholders justified by the
structural budget, not measured** (§7's no-in-tree-benchmark caveat applies);
Phase 0 re-pins them, and the budget — assembly p99, demand rate per peer, and
amplification ratio (`bytes_out / bytes_in`) — is itself a §9 health metric so a
mis-tuned cap surfaces as timeout-demotions rather than silent currency loss.

### 7.2 `ProofCache` sizing — a hard constraint, not a tuning knob

The latency invariant of §7.1 assumes each distinct checkpoint a page touches is
materialized **at most once** (the `ModifiedObjectTree` build is the `O(N)`-hash
cost the cache exists to amortize across the `K` ids that share a checkpoint).
That assumption holds **only if the cache can hold every checkpoint that is
concurrently in flight at once.** Today's default `ProofCache` is sized for
the single-object inclusion-proof workload — `tree_capacity = 32`, `tree_ttl =
300s` (`ProofCacheConfig::default`, `proof_provider.rs:351-358`) — and that cap
is **too small for the subscription path**:

- The cache is a single per-`LocalProofProvider` instance shared across all
  concurrent requests (`LocalProofProvider { cache: ProofCache, .. }`,
  `proof_provider.rs:392-409`), keyed by `CheckpointSequenceNumber`
  (`ProofCache { trees: Cache<CheckpointSequenceNumber, _>, .. }`,
  `proof_provider.rs:364-371`; populated by `cached_checkpoint`,
  `proof_provider.rs:411-431`).
- `INFLIGHT_SUBSCRIBED_CHANGESET_PAGE = 4` pages may be served concurrently, and
  each page spans up to `MAX_SUBSCRIBED_CHANGESET_PAGE = 16` **distinct**
  checkpoints. When those four pages cover disjoint checkpoint ranges — the worst
  case, and exactly what cohorted resume (§4.3) produces, since different cohorts
  resume at different `from_seq` — the live working set is
  `INFLIGHT_SUBSCRIBED_CHANGESET_PAGE × MAX_SUBSCRIBED_CHANGESET_PAGE = 4 × 16 =
  64` distinct trees demanded **simultaneously**, against a cap of 32. The cache
  then evicts trees that a still-in-flight page will touch again, and every such
  page re-materializes (`get_full_checkpoint` + `ModifiedObjectTree::new`,
  `proof_provider.rs:420-424`) the tree it just lost — the per-checkpoint `O(N)`
  build the §7.1 closed form charges **once** is now paid repeatedly, and the
  worst-case page can blow the 30s `RELAY_REQUEST_TIMEOUT`, demoting the honest
  server (§7.1) and converging the fleet onto the cheapest — possibly
  byzantine-withholding — peer. This thrash defeats the §7.1 worst-case-page-`<30s`
  / p99-≤5s invariant.

> **Note: the full-set path never exposed this.** `changeset_page` does **not**
> use `ProofCache` at all — it calls `get_full_checkpoint` directly and ships the
> raw `object_states` with no proof construction (`mod.rs:248-275`), so its
> `INFLIGHT_CHANGESET_PAGE × MAX_CHANGESET_PAGE = 16 × 64 = 1024` product never
> pressured the 32-tree cap. The subscription is the **first** consumer whose
> in-flight × per-page checkpoint product is a live demand on the cache, which is
> why the cap must be revisited *now*, with this path, and not before.

> **Invariant (cache covers the in-flight working set).**
> ```
> tree_capacity  ≥  INFLIGHT_SUBSCRIBED_CHANGESET_PAGE × MAX_SUBSCRIBED_CHANGESET_PAGE
> ```
> i.e. the `ProofCache` MUST hold at least one tree for every checkpoint that the
> maximum concurrent set of pages can have in flight at once. Below this bound the
> §7.1 "materialized at most once per distinct checkpoint" amortization is
> unsound and the latency invariant cannot be claimed.

**Reconciled values (with the §4.3 locked caps).** The subscription path
constructs a dedicated `ProofCacheConfig` (it MUST NOT inherit the
single-object `default()`):

```
tree_capacity  = INFLIGHT_SUBSCRIBED_CHANGESET_PAGE × MAX_SUBSCRIBED_CHANGESET_PAGE
               = 4 × 16
               = 64            // raised from the default 32
tree_ttl       = 300s          // unchanged; bounds residency
```

64 is the **minimal** value satisfying the invariant at the current caps; round
up to the next page-multiple headroom (e.g. 96 = `1.5 ×`) if a single provider
ever serves both the subscription and the legacy single-object inclusion path
concurrently, so the two workloads do not evict each other. The memory cost
stays bounded: each tree is a checkpoint summary plus a `ModifiedObjectTree`
(object refs + hashes, tens of KB for a busy checkpoint — `ProofCacheConfig`
doc, `proof_provider.rs:336-341`), so 64 trees is single-digit MB worst-case,
and `tree_ttl` still bounds residency. If a moka `weigher` is wanted to bound by
bytes rather than count, that is the upgrade the existing doc comment already
anticipates (`proof_provider.rs:340-341`).

**The constraint is symmetric — lowering the caps satisfies it too.** Because
the Phase 0 measurement (§10) may force `MAX_SUBSCRIBED_CHANGESET_PAGE` or
`INFLIGHT_SUBSCRIBED_CHANGESET_PAGE` *down* to meet the §7.1 latency budget, the
constraint MUST be re-checked whenever any of the three numbers move: lowering
`MAX_SUBSCRIBED_CHANGESET_PAGE` to 8 would let `tree_capacity = 4 × 8 = 32`
suffice (the default), eliminating the change entirely. The implementation MUST
assert the invariant at construction (`debug_assert!(tree_capacity >=
INFLIGHT_SUBSCRIBED_CHANGESET_PAGE * MAX_SUBSCRIBED_CHANGESET_PAGE)`) so a future
cap edit cannot silently re-open the thrash.

---

## 8. Coexistence with the full-set path — single index, single writer

There is **exactly one `ChangesetIndex`** and **exactly one writer** for it. The
node subscribes to **all** currency-relevant ids *per-id* — the static roots/inners
(classes 1–4 of §5.1) **and** the dynamic bag/dwallet children (class 5) — and folds
them through one index via `absorb_subscribed`. There is **no** second index, no
per-id ownership routing, no overlap window, and no cross-index reconciliation. The
two-index split that earlier drafts carried is retired in full (see *Removed* at the
end of this section); it was load-bearing only while two writers could touch one
frontier, and the single-writer model removes that race by construction rather than
by reconciling around it.

**The full-set path is retained verbatim, but coexistence is node-level EITHER/OR.**
The full-set `changeset_page` / `absorb`-with-artifacts-digest path
(`ocs_currency.rs:231-288`) is kept unchanged for `filter=None` nodes (production
today). A node runs **one driver**: the full-set `ChangesetReceiver` folding via
`absorb`, **or** the `SubscribedChangesetReceiver` folding via `absorb_subscribed` —
**never both against the same index, and never a per-id overlap between them.** This
is already enforced structurally and we keep that enforcement:

- `ChangesetIndex` is **tagged at construction** with its fold mode (`FullSet` or
  `Subscribed`) via a typestate or a stored mode + runtime assertion.
- `absorb`/`absorb_verified` (full-set) and `absorb_subscribed` (per-id) are
  **mutually exclusive** on one instance — calling the wrong one panics/asserts.

Because the modes are exclusive and there is only one writer, `check_currency` never
combines verdicts from two indices. For a `Subscribed`-mode index it dispatches every
id to `currency_subscribed` (§5.3); for a `FullSet`-mode index it dispatches to
`currency` (§3). No id is ever governed by two indices, so there is no lagging-index
veto to reconcile, no two-lock read, and no snapshot-consistency hazard — those were
artifacts of the two-index design and are gone with it.

**Why one shared frontier suffices for every subscribed id.** The decisive property
is that the static roots/inners subscription is **always present and pinned** (§5.4
GC: roots and version-derived inners are never GC'd). They are in the registry not by
a bag walk but by the **statically pinned (non-bag) enrollment** (§5.1 site A): the
`SubscribedChangesetReceiver` seeds the two roots
(`ika_system_object_id` / `ika_dwallet_coordinator_object_id` from `IkaObjectsConfig`)
into the registry **at construction** (with `subscribed_at_seq = seed.seq`, so their
floor can begin at the very first folded checkpoint `seed.seq + 1`, §5.2/§5.4
SUBSCRIBE (A)) and pins each version-derived inner
(`derive_versioned_child_id(root, version)`) on first verified read. Because they are
in the registry, the cohort partition (§4.3 Resume) puts them in **every** steady-state
cohort's `ids`, and the §4.3 completeness contract then forces **every** returned
entry to carry their proofs. So **every checkpoint produces an entry** and the index's
single global
`contiguous_head` advances **one checkpoint at a time** over the per-checkpoint
committee-signed summaries — the same forward-chained `previous_digest` head that
`absorb` maintains (`ocs_currency.rs:269-285`). The summary is shipped **once per
checkpoint and shared across all `K` ids** in the entry (§4.2), so the global head
and every per-id `CoverageInterval` advance over the *same* chained summaries; there
is no separate per-id trust root and no separate per-id chain to forge. A
freshly-subscribed id's interval can only *attach* at a height the shared head has
already reached from its trusted base (§5.2) — the global head bounds the *reachable*
attach height — but the id's `coverage.head(id)` then rises with that id's **own**
per-id-chained frontier over the entries that carry its proof, **whether those entries
land at the global head or below it** (a catch-up entry is `AlreadyFolded` against the
global head yet still advances the id's coverage, §8 step 6). The shared head advancing
is what guarantees an entry exists at every height for the id to ride; it is not itself
the thing that advances the id's coverage. The "memory bounded by `K`" claim (§7)
is unchanged: one index, `O(K)` `IdRecord`s + `O(K)` `CoverageInterval`s.

> **A static-set proof is not optional padding — it is the head driver.** If a page
> ever returned entries that omitted the pinned roots/inners ids, that page would
> fail the §4.3 completeness contract (`proofs` keyset ≠ requested `ids`) and be
> rejected. So the receiver always requests the pinned set in *every* cohort whose
> `from_seq` is the steady-state head (§5.4 CATCH-UP), guaranteeing the shared
> `contiguous_head` never stalls for lack of an entry while honest checkpoints exist —
> which in turn guarantees an entry exists at every height for a sub-head id to ride and
> advance its own `coverage.head` over (§8 step 6). A genuine stall
> (e.g. an awaited `committee[E+1]`, §5.6(a)) stalls **all** ids together and is
> surfaced as a boundary stall, not a selective-id stall (§9).

### `absorb_subscribed` (the single writer)

`ChangesetIndex::absorb_subscribed(&CommitteeStore, seed: TrustedSeed, &summary,
proofs: BTreeMap<ObjectID, SubscribedIdProof>, requested_ids: &HashSet<ObjectID>)`,
where

```rust
/// A checkpoint the node trusts WITHOUT this stream — the only legitimate
/// predecessor the contiguous frontier may be bootstrapped onto.
#[derive(Clone, Copy)]
pub struct TrustedSeed {
    pub seq: CheckpointSequenceNumber,
    pub digest: CheckpointDigest,
}
```

The steps:

1. **BLS-verify the summary, preserving the committee-availability vs bad-signature
   distinction (do NOT flatten).** Call `CommitteeStore::verify_summary`
   (`committee_store.rs:250-264`) — the `absorb_verified` pattern — but **thread its
   structured error through**, not the single `ChangesetError::Unverified(String)` that
   the full-set `absorb_verified` collapses it into (`ocs_currency.rs:303-304`).
   `SummaryVerifyError` already splits the two cases (`committee_store.rs:61-67`), and
   they have opposite meanings here:
   - `SummaryVerifyError::MissingCommittee(epoch)` → a new
     `ChangesetError::MissingCommittee(epoch)` arm. This is the **benign all-ids
     boundary stall** (§5.6(a)): the committee ratchet (`ratchet_to_current_epoch` →
     `install_next`, a different subsystem) has not yet reached this summary's epoch, so
     the entry simply does not fold yet. It feeds the boundary-stall metric (§9) and
     does **not** trigger relay failover (the relay is not at fault) — the stall clears
     when the ratchet installs the committee.
   - `SummaryVerifyError::BadSignature { epoch, error }` → `ChangesetError::Unverified`
     (unchanged). This is a **byzantine** summary; the entry is rejected and the
     receiver fails over via `try_peers`.

   This typing is load-bearing for observability: it is the **only** thing that lets a
   node tell "the whole subscribed set is stalled because we are mid-epoch-boundary and
   the committee isn't ratcheted yet" (transient, ratchet-gated) apart from "a peer is
   serving forged summaries" (byzantine, failover-gated). Flattening both into
   `Unverified(String)` makes a benign boundary stall indistinguishable from an attack,
   which would either mask a real attack (operator dismisses it as "just a boundary") or
   cry wolf every epoch turn. Note this proves the summary is *a* genuine
   committee-signed checkpoint for *its* epoch — **not** that it is *this position's*
   checkpoint (the position gate, step 2, closes that), and **not** that its position is
   one the node ever reached.

   > **`ChangesetError` gains one arm.** Add `MissingCommittee(u64)` to the enum
   > (`ocs_currency.rs:124-136`) alongside the existing `ArtifactsMismatch` /
   > `BrokenChain` / `Unverified` / `Internal`. The `u64` is an **epoch**, not a
   > `CheckpointSequenceNumber`: it is forwarded verbatim from
   > `SummaryVerifyError::MissingCommittee(u64)` (`committee_store.rs:61-67`, which
   > carries the epoch with no committee), and the §9 boundary-stall gate keys on it
   > by epoch (`committee_head_epoch` vs `chain_latest_epoch`). This is the **only**
   > arm that carries an epoch — its siblings (`ArtifactsMismatch`, `BrokenChain`)
   > carry a `CheckpointSequenceNumber`, because they describe a per-checkpoint
   > position fault, whereas a missing committee is a per-epoch availability fact that
   > clears only when the ratchet installs that epoch's committee. The full-set
   > `absorb_verified` MAY adopt the same split (it has the identical boundary stall),
   > but that is an optional, behavior-preserving refinement; the subscription path
   > MUST split it.
2. **Position gate (anti-replay + trusted-seed bootstrap).** Let `seq =
   summary.sequence_number()`. The classification mirrors `absorb`'s `269-285`
   **except the bootstrap arm is replaced by a trusted-seed forward-chain** — the
   no-predecessor bootstrap arm (`ocs_currency.rs:258-268`) is **forbidden** for this
   path:
   - **Index empty** (`contiguous_head == None`): admit the entry as the floor of the
     frontier **only if** `seq == seed.seq + 1` **and** `summary.previous_digest ==
     Some(seed.digest)`. Otherwise reject `BrokenChain { seq }`. This is the
     load-bearing change: the first folded checkpoint must **forward-chain onto the
     locally-trusted seed**, never become its own base. A relay-chosen floating start
     `F` (even a genuinely-BLS-signed run `[F, F+1, …]` of *real but stale*
     checkpoints) fails here because `F`'s `previous_digest` cannot equal
     `seed.digest` unless `F` is genuinely `seed.seq + 1`.
   - **Index non-empty**: classify exactly as `absorb` for the *global* head —
     `AlreadyFolded` at/below head, the contiguity arm at `head + 1` requiring
     `previous_digest == Some(head_digest)`, `Queued` for a forward gap. **`AlreadyFolded`
     governs the global `contiguous_head` and the index fold only; it does NOT discard
     the entry for per-id coverage.** A sub-head entry (`seq <= contiguous_head`) carries
     a fresh, lagging id's catch-up proof — the always-present roots/inners cohort drove
     the global head ahead while that id was being enrolled — and step 6 advances the
     id's per-id coverage from it via the per-id chain check, gated against the summary's
     committee signature (step 1) and artifacts binding (step 4) at the **same gated
     `seq`**. The position gate verifies the summary sits at *its own* checkpoint position
     (its `sequence_number()` and `previous_digest` are the summary's real ones); a
     sub-head entry whose `summary` is genuine and at its real position is therefore a
     legitimate per-id catch-up entry, not a replay.
   A stale-but-valid summary for an *older* checkpoint fails the position gate **for the
   head** (wrong `seq` and/or non-chaining `previous_digest`) and is never folded into
   the index — closing the replay where a genuine non-inclusion for `C-100` is served in
   `C`'s slot **of the head stream**. A sub-head per-id catch-up entry is a different
   thing: its `summary` genuinely sits at `seq` and the entry advances *only* the per-id
   coverage of the lagging id whose chain anchor it matches (step 6), never the global
   head and never any other id's coverage out of position.
3. **Completeness**: error if `proofs` keyset ≠ `requested_ids` (§4.3).
4. **Per-id proof verification** against **this position-gated** summary's artifacts
   digest:
   - `Modified`: inclusion verify + leaf-id == id + `tree_root` bound to summary.
   - `Absent`: raw non-inclusion verify + `non_inclusion_binds_id` + `tree_root`
     bound.
5. Build the per-id delta `BTreeMap<ObjectID,(SequenceNumber,ObjectDigest)>` from the
   `Modified` entries and fold it through the **existing** `fold`/contiguity/
   `drain_pending` machinery (no change to `fold`), reusing `prune` **extended** to
   also bound the `coverage` map (§5.4 *Coverage-map pruning*) — `prune` is the one
   piece of that machinery that is not byte-identical for the subscribed index,
   because the full-set `prune` sweeps only `self.index`. The `fold` step writes an
   id's `IdRecord` under last-write-wins by `seq`, so a **sub-head** `Modified` delta a
   lagging id rides (at `seq <= contiguous_head`) updates that id's record only when it
   is the id's latest known modification and never clobbers a later record — the index
   record and the per-id coverage (step 6) advance over the *same* sub-head entries. The
   full-set `from_object_states` artifacts-digest check (`241-249`) is **replaced** for
   this path by the per-id binding (step 4) **plus** the position gate (step 2) — the
   former proves *what* is in the committed root, the latter proves *which* checkpoint's
   root it is.
6. **Advance per-id coverage on every verified entry — head, drain, OR
   sub-head/`AlreadyFolded` — each gated by a per-id forward-chain, decoupled from the
   global `contiguous_head`.** The entry's **full requested-id keyset** (the `Modified`
   ids ∪ the `Absent` ids = `requested_ids`, by step 3) is the set whose
   `coverage.head` this checkpoint may advance — an `Absent` id writes nothing to
   `index` but its coverage **still** advances (the id's prior record stays its latest,
   which is exactly what `Current` depends on). For **each** id `X` in that keyset,
   coverage advances **iff** the entry forward-chains onto `X`'s own per-id anchor at
   the gated `seq`:

   - **Per-id chain check (the soundness boundary for sub-head advancement).** Let `seq
     = summary.sequence_number()` (the position-gated seq of step 2). `X`'s coverage
     advances to `seq` only if `seq == coverage.head(X) + 1 && summary.previous_digest
     == Some(coverage.head_digest(X))` — `X`'s **own** per-id head, not the global
     `contiguous_head`. On `X`'s **first** entry (`coverage.head(X) == None`) the anchor
     is the trusted predecessor of §5.2: at an empty-index floor, `seq == seed.seq + 1
     && previous_digest == Some(seed.digest)`; at a mid-stream floor, the floor entry sits
     at `seq == subscribed_at_seq` and chains onto the index's **already-trusted summary
     at `subscribed_at_seq - 1`** (the entry the global head folded just before, whose
     digest the index already holds), i.e. `previous_digest ==
     Some(digest(subscribed_at_seq - 1))`. (Equivalently: `subscribed_at_seq` is itself
     at-or-below the global `contiguous_head`, so its predecessor digest is already a
     trusted index record — the floor never chains onto a relay-supplied base.) On success
     `coverage.head(X) = seq`, `coverage.head_digest(X) = summary.digest()`, and on the
     first such advance `coverage.floor(X) = seq` (which, for a mid-stream fresh id, is
     `subscribed_at_seq` itself — **no off-by-one**, §5.2). An entry that does **not** chain onto `X`'s
     anchor (a gap or a forged sub-head base) advances neither `coverage.head(X)` nor
     `floor(X)` — it is a per-id `BrokenChain`, leaving `X` `Unknown` over the gap. This
     per-id chain — **not** the global `+1` gate of step 2, which never examines a
     sub-head entry — is what re-imposes position-binding on every entry that moves
     `X`'s coverage, so a stale-but-signed sub-head proof can mask no omission below the
     head.
   - **Head path (`seq == contiguous_head + 1`).** The entry also advances the global
     `contiguous_head` and folds its `Modified` deltas into `index` (step 5). Every id
     in `requested_ids` whose per-id chain matches (which, at the head, is every id that
     has been continuously covered) advances in lockstep.
   - **Sub-head path (`seq <= contiguous_head`, `AlreadyFolded` for the head).** The
     global head and `index` are untouched (the seq was already folded), but the per-id
     chain check still runs for each id in `requested_ids` and advances the coverage of
     any lagging id whose anchor it matches. This is what lets a freshly-subscribed
     dynamic id whose catch-up entries arrive below the head advance its own coverage
     and leave `Unknown` — the gap this design closes.
   - **Drain path.** A `Queued` entry advances nothing yet — not the index, not coverage
     — until the gap before it drains. When `drain_pending` pulls it, the same per-id
     chain check runs against each covered id's anchor, so an out-of-order entry advances
     coverage for every id it covered **at drain time**, identically to one folded
     directly (see *Drain* below).

   `floor_anchored_on(X)` is updated alongside `floor`/`head` as a **diagnostic-only**
   breadcrumb of the trusted predecessor digest the advance chained onto — it is never
   read by `currency_subscribed` (§5.3) and may be dropped without affecting any verdict.
   Because every advance — head, sub-head, or drain — is gated on a forward-chain onto a
   position-gated, committee-signed `seq`, no id's coverage can be advanced past a
   checkpoint by a proof drawn from a different checkpoint.

**Where the seed comes from, and how the seed checkpoint itself is treated.**
`TrustedSeed` is the node's own bootstrap/ratchet trust anchor, read out-of-band from
`CommitteeStore`-backed perpetual state, never from the relay page. It is a checkpoint
the node already **trusts independently of the changeset stream** — a committee-verified
end-of-epoch summary — so it is the chain *anchor*, **not** a relay-supplied changeset
to re-fold.

- The `SubscribedChangesetReceiver` derives it from
  `perpetual.oldest_sui_committee_summary()`
  (`authority_perpetual_tables.rs:383-388`), the deepest checkpoint the node can
  committee-verify — the operator-pinned end-of-epoch anchor (digest-verified at
  bootstrap, `committee_store.rs:140-163`) or a ratchet-verified end-of-epoch summary
  persisted in `sui_committee_summaries`. That accessor returns
  `IkaResult<Option<SuiCertifiedCheckpointSummary>>`, so the derivation is
  `Option<TrustedSeed>`, not `TrustedSeed`: when a summary is present its
  `(*summary.sequence_number(), summary.digest())` **is** the `TrustedSeed` (the
  `None` case is handled in the next bullet). On an empty index the receiver requests
  `from_seq = seed.seq + 1` — **the seed checkpoint itself is never requested and never
  folded by this path.** The first entry it folds is `seed.seq + 1`, admitted by the
  position gate **only if** it forward-chains onto the seed (`seq == seed.seq + 1 &&
  previous_digest == Some(seed.digest)`, §8 step 2).

  > **Relationship to the full-set `bootstrap_from` — the from_seq is the same, the
  > bootstrap *arm* is not.** The full-set receiver also requests `from_seq = seed.seq
  > + 1` on an empty index: its `bootstrap_from` is
  > `oldest_sui_committee_summary().sequence_number().saturating_add(1)` (`setup.rs:350`)
  > and `pump_changesets` resumes at `highest_contiguous_seq().map(+1).unwrap_or(
  > bootstrap_from)` (`changeset_receiver.rs:70-74`), so on an empty index it too starts
  > at `seed.seq + 1` and **never folds the seed checkpoint.** Where the two paths
  > genuinely diverge is the **bootstrap arm of the first fold**, not the `from_seq`:
  > the full-set `absorb` admits its first returned entry (at `seed.seq + 1`) through the
  > **no-predecessor** arm (`ocs_currency.rs:258-268`) — it makes that entry its own base
  > with **no** check that it chains onto the seed. `absorb_subscribed` **forbids** that
  > arm and instead position-gates the first fold against `seed.digest` (§8 step 2), so
  > the subscription path is *strictly stricter* at bootstrap: it additionally proves the
  > first folded checkpoint forward-chains onto the locally-trusted seed. (This is a
  > soundness *tightening*, not a regression: the full-set path's looser bootstrap is
  > acceptable there only because its full-set artifacts-digest binding re-derives the
  > complete modified set per checkpoint; the per-id path has no such full-set binding
  > and needs the seed forward-chain to refuse a relay-chosen floating start, §5.2.)
- **No seed yet — empty `sui_committee_summaries`: the subscribed receiver does not
  start.** `oldest_sui_committee_summary()` is `None` exactly when
  `sui_committee_summaries` is empty — a node booted from a direct-install committee
  with **no** backing end-of-epoch summary (the `CommitteeBootstrap::UnsafeGenesis`
  bootstrap arm, `committee_store.rs:161-162`, installs the committee but writes nothing
  to `sui_committee_summaries`; only an end-of-epoch bootstrap, `:158-159`, or a
  ratchet-recorded transition, `record_sui_committee_transition`, populates it). With
  no summary there is **no trusted predecessor digest** to forward-chain the floor entry
  onto, so the position gate (§8 step 2) has no defined `seed.digest` and a
  `TrustedSeed` cannot be constructed. The subscription path therefore **requires a
  non-empty trusted seed**: on `None` the `SubscribedChangesetReceiver` is **not
  started** (no subscribed receiver runs, no `absorb_subscribed` is ever called) and the
  node stays **entirely in `Unknown` → per-read fallback** (§5.3) — every currency
  verdict falls back to the per-read OCS inclusion + membership binding, which is sound.
  The receiver re-derives the seed on a later tick; as soon as the committee ratchet has
  persisted at least one end-of-epoch summary (`record_sui_committee_transition`, a
  different subsystem), `oldest_sui_committee_summary()` becomes `Some`, the seed exists,
  and the receiver starts with a well-defined `(seq, digest)` anchor and requests
  `from_seq = seed.seq + 1`.

  This is **sound by construction, and the deliberate departure from the full-set
  path.** The full-set receiver tolerates the same `None` by `.unwrap_or(0)`
  (`setup.rs:347-351`), bootstrapping from seq `0` and admitting its first returned
  entry through the **no-predecessor** arm (`ocs_currency.rs:258-268`) — it self-anchors
  on whatever the relay returns first, which is acceptable there **only** because the
  full-set artifacts-digest binding re-derives the complete modified set per checkpoint.
  The subscription path has no such full-set binding and **forbids** that arm (§8 step
  2), so it deliberately does **not** mirror `unwrap_or(0)`: doing so would either
  manufacture a `seed.seq = 0`/`seed.digest = <none>` anchor with nothing to chain onto
  (every floor entry rejected `BrokenChain`, the receiver permanently stalled) or
  reintroduce the relay-self-bootstrap the path was designed to refuse. "No seed → do
  not start" is the only seed-less behavior consistent with *never self-bootstrap*: it
  reaches neither the forbidden no-predecessor arm nor a panic (the `None` branch is an
  explicit non-start, **not** an `.unwrap()`), and it costs nothing in soundness because
  per-read fallback already covers every read until the seed materializes.
- Thereafter the seed is **irrelevant**: once `contiguous_head` is set, every entry is
  gated against the index's own forward-chained head, and the receiver resumes at
  `highest_contiguous_seq() + 1`. The seed is consulted **only** to anchor the very
  first fold.

**Consequence: an object last-modified exactly at `seed.seq` reads `Unknown`.** Because
the seed checkpoint is never folded, no id's `floor` can be `<= seed.seq`: the first
foldable checkpoint is `seed.seq + 1`, so `floor >= seed.seq + 1 > seed.seq` for every
id. An object whose last modification was at `M == seed.seq` with **no** later
modification therefore has `M < cov.floor`, and `currency_subscribed` returns `Unknown
→ per-read fallback` (§5.3) — it is **not** a false verdict. This is the **only**
permanently-`Unknown` anchor from this index (§5.2/§5.3): the seed checkpoint is never
folded at all, so no id's coverage can ever bracket it — unlike a mid-stream fresh id's
subscription instant, whose catch-up entry at `subscribed_at_seq` *does* fold and set
`floor == subscribed_at_seq` (the decoupled, no-off-by-one model, §5.2/§8 step 6). A
checkpoint that was never folded cannot anchor a currency verdict, so the read falls
back to the per-read OCS inclusion + membership binding, which is sound. The full-set
path exhibits the identical behavior at its own
`oldest_folded` floor — an anchor at `seed.seq` is below `oldest_folded` (which the
full-set `absorb` also sets to its first fold at `seed.seq + 1`) and `currency` returns
`Unknown` there too — so this is not a property the subscription introduces.

This makes the **trusted base** the anchor of every interval (§5.2): the always-present
pinned roots/inners stream keeps the shared `contiguous_head` advancing
checkpoint-by-checkpoint *from that base*, guaranteeing an entry exists at every height,
so a per-id interval can only attach at a height the global chain has already reached
from the base — never at a relay-chosen floating start. Whether the interval then
*advances* is governed by the per-id chain (`coverage.head_digest(id)`, seeded by the
trusted base, §8 step 6), so it advances over the same forward-chained summaries the
global head crossed — at the head or below it — never out of position.

**Drain (coverage advances on out-of-order entries).** `drain_pending`
(`ocs_currency.rs:368-385`) currently folds a queued entry's `object_states` into the
index but cannot advance coverage, because the queued `PendingChangeset` carried only
`object_states` (the `Modified` deltas) and no record of which **requested** ids the
entry covered (an all-`Absent` entry has empty `object_states` yet still must advance
those ids' `coverage.head`). `PendingChangeset` is therefore extended to carry the
entry's covered-id set:

```rust
struct PendingChangeset {
    digest: CheckpointDigest,
    previous_digest: Option<CheckpointDigest>,
    object_states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)>,
    // NEW (subscription path only): the entry's full requested-id keyset
    // (Modified ids ∪ Absent ids). Every id here has a verified
    // inclusion-or-id-bound-non-inclusion at this checkpoint, so draining
    // the entry advances coverage.head for all of them — not just the
    // Modified ones folded into `index`. Empty for the full-set path.
    covered_ids: HashSet<ObjectID>,
}
```

`drain_pending` (and the head-path fold) advance `coverage.head(id)` (and set `floor`
on the first contiguous fold, plus the diagnostic-only `floor_anchored_on` recording
the digest the drained entry chained onto) for **every** `id` in the drained entry's
`covered_ids`, keyed off the now-contiguous `seq`. The full-set `absorb` records an **empty**
`covered_ids` (it has no per-id coverage notion), so its drain behaviour is
unchanged. The bug this fixes: previously an out-of-order entry that queued and later
drained folded the index but left `coverage.head(id)` below the drained seq forever,
so that id read `Unknown` permanently even after its modification had been
verifiably folded; now the drain advances coverage in lockstep with the index.

**Coverage pruning.** `coverage` is pruned in the same sweep as `index`
(`prune`, `ocs_currency.rs:396-410`): when the retain-window floor rises, drop the
`CoverageInterval` of any **non-pinned** id whose `head` fell below the new floor
(pinned roots/inners are never pruned), so the `O(K)` coverage map is bounded by the
same retain window as the index and the §7 memory claim holds. The exact removal /
clamp points are specified in §5.4 *Coverage-map pruning*.

---

**Removed (obsolete two-index machinery — delete verbatim from the prior §8):** the
`owner(id) -> Index` ownership-classification function and its `FullSet`/`Subscribed`
routing; the *Ownership-routed dispatch (no cross-index veto)* bullet; the
*Overlap window — Current-wins* rule (the 4-step `v_full`/`v_sub` reconciliation and
its soundness paragraph); the *Snapshot consistency model* two-lock paragraph; the
*Transition invariant* paragraph; and the *Recommended deployment* paragraph that
prescribed the two-index split for mixed nodes. The single-writer typestate tag and
the `absorb`/`absorb_subscribed` mutual-exclusion assertion are **kept** (they now
enforce the node-level EITHER/OR mode).

---

## 9. Observability and health (red-team liveness fixes)

Soundness is preserved against every attack (no false `Current`), but multiple
red-team attacks are real **liveness/coverage** denials that leave the node looking
healthy while the currency gate is silently absent for targeted ids. These MUST be
surfaced, not logged-and-forgotten:

- **Per-id frontier lag.** Track, per subscribed id, `subscribed_at_seq` →
  `coverage.head` lag and the gap between `coverage.head(id)` and the relay's
  claimed upstream head. **Alarm** (and demote/rotate the peer via `try_peers`) when
  an id stays `Unknown`-due-to-lag beyond an SLA **while the global frontier
  advances** — this catches *selective-id stall* (server answers everyone but one
  hot id) which the global stall detector cannot see.
- **Tail-stall detection.** A frozen frontier (valid chained prefix to `H`, then
  nothing) is indistinguishable from honest catch-up unless an independent head
  signal exists. `currency` never consults `observed_upstream_head`. **Alarm** when
  `highest_contiguous_seq()` has not advanced within `N` polls while
  `highest_seen_seq()` / the relay's `claimed_latest_checkpoint_seq` keeps rising.
- **Boundary-stall vs selective-id-stall (cross-subsystem liveness).** A coverage-head
  stall where **every** subscribed id is blocked on
  `ChangesetError::MissingCommittee(E+1)` is an *epoch-boundary* stall, not a relay
  fault: `committee[E+1]` is installed only by the separate committee ratchet
  (`ratchet_to_current_epoch` → `install_next`, `ocs_verifier.rs:141-245`), never by
  the changeset fold (§5.6(a)). Emit a boundary-stall metric keyed on the
  `MissingCommittee` arm (a sibling of `bag_omission_suspected_total`,
  `ocs_metrics.rs:58/150`), and **gate its health verdict on the ratchet head, not the
  changeset head**: it is benign while `ika_ocs_committee_head_epoch`
  (`ocs_metrics.rs:22/69`, sampled at `ika-node/src/lib.rs:905-911`) is climbing toward
  `ika_ocs_chain_latest_epoch`, and **fails health (pages)** once
  `committee_head_epoch` stays frozen below `chain_latest_epoch` past a bounded window —
  the wedged-ratchet pathology (typically `OcsError::ProofChainBroken`,
  `ocs_verifier.rs:166-178`, which is non-retryable, `:82-84`), under which every
  subscribed id's currency is denied **permanently** until an operator re-anchors. This
  is deliberately **distinct from** the per-id frontier-lag and tail-stall alarms above:
  those fire on a *selective* stall (global frontier advancing while one id lags); a
  boundary stall is the inverse — all ids stall at the same height while the *ratchet*
  head is what is stuck — and mis-classifying it as selective would point the operator
  at the relay set instead of the committee chain.
- **Fallback-rate health gate.** Health-gate on (a) frontier advance rate,
  (b) count of ids stuck not-caught-up, (c) `Unknown`-fallback read rate. **Fail
  health (not warn)** when fallback dominates the dynamic read set — otherwise a
  timing adversary keeps every dwallet id permanently in fallback and the node
  delivers zero currency for its unbounded read set while looking healthy.
- **Distinguish benign vs suspicious `Unknown`.** Fresh-subscribe `Unknown` (no
  coverage yet) is benign; stalled-frontier `Unknown` (anchor above a frozen head
  with a real gap) is suspicious. For security-critical reads (the roots/inners
  class), an anchor still `Unknown` after a bounded catch-up window SHOULD escalate
  to a soft reject or forced multi-peer cross-check, not silent `Ok`.
- **`freshness_bound`.** Make it **mandatory and small** for the roots/inners path in
  subscription mode (today `None` in production — a no-op), so a tail-stall cannot
  serve a far-behind anchor unchecked. Persist the read-path high-water across
  restarts (or re-bootstrap currency before serving), since it is in-memory today.
- **Partial-pruning signal.** When the serving node has pruned below a subscribed
  id's anchor, surface a distinct "permanently Unknown for this anchor (server
  retention)" signal rather than silent indefinite fallback. Mitigate by anchoring
  bag-entry reads at recent checkpoints (entries are read live) rather than deep
  history.
- **Dropped-enrollment visibility.** The §9 lag/stall/fallback machinery only sees
  ids that are *already in the registry* (each owns a `CoverageInterval` to
  lag-track); an id whose `add_id` was dropped on a full channel (§5.4) owns **no**
  row and is invisible to all of it. Surface it directly:
  `ika_ocs_subscription_enqueue_dropped_total` is a first-class health input.
  Because the counter is **monotonic** — it never decreases, so its absolute value
  alone can never show that reconciliation has caught up — the health verdict is a
  **rate, not a level**: the **delta over a sliding window**
  `W = drop_health_window` (a small fixed multiple of the §5.4 reconcile interval,
  long enough that at least one reconcile re-walk completes inside it — e.g. `W = 3
  × reconcile_interval`). Compute `drops_in_window = counter(now) −
  counter(now − W)` and **fail health (not warn)** only when `drops_in_window`
  exceeds a small threshold `DROP_RATE_HEALTH_THRESHOLD` (drops per `W`) — i.e.
  drops are **still arriving faster than reconciliation clears them**. A one-off
  drop, or a burst that the next reconcile tick re-walks back into the registry,
  leaves `drops_in_window` flat after that window elapses (the counter stops
  advancing) and **does not fail health** — it is the benign self-healed transient
  §5.4 describes, logged but not paged. A *sustained* non-zero `drops_in_window`
  across consecutive windows means the read set is outrunning the channel and a
  slice of the dynamic id-set is silently running authenticity-only; that is a
  coverage denial, not a benign transient, and must page rather than scroll past.

---

## 10. Phased implementation plan

Each phase is independently reviewable and lands behind the existing
`changeset_index: Option<...>` no-op gate, so partial landing never regresses
direct/pre-catchup nodes.

**Phase 0 — preconditions / confirmations (no code).**
- Confirm whether `effects.written()` can emit an `OBJECT_DIGEST_CANCELLED`
  (`[77;32]`) leaf into `ObjectStates`. If yes, add `IdStatus::Cancelled →
  NotLive` to `from_digest` on BOTH paths with a test; if never, document the
  invariant. Blocks reliance on currency for any class.
- Measure real inclusion / non-inclusion proof sizes and server CPU per id per
  checkpoint to tune the §4.3 caps. No in-tree benchmark exists.

**Phase 1 — wire types + RPC (no behavior change).**
- Add `SubscribedChangesetPageRequest/Response/Entry`, `SubscribedIdProof` to
  `sui_state_mirror/mod.rs`.
- Declare `subscribed_changeset_page` `Method` in `build.rs`; add
  `MAX_SUBSCRIBED_CHANGESET_PAGE`, `MAX_SUBSCRIPTION_IDS`,
  `INFLIGHT_SUBSCRIBED_CHANGESET_PAGE` + `InflightLimitLayer` in `make_server()`.
- Implement `Server::subscribed_changeset_page`: per checkpoint via the cached
  `ModifiedObjectTree` (`LocalProofProvider` `ProofCache`,
  `proof_provider.rs:411-431`) sized per the §7.2 invariant
  (`tree_capacity ≥ INFLIGHT_SUBSCRIBED_CHANGESET_PAGE × MAX_SUBSCRIBED_CHANGESET_PAGE`
  = 64 at the §4.3 caps, raised from the default 32; construct a dedicated
  `ProofCacheConfig`, do **not** inherit `default()`), emit inclusion
  (`is_object_in_checkpoint` →
  `get_inclusion_proof`) or non-inclusion (`get_non_inclusion_proof(
  get_dummy_object_ref(id))`) per requested id; break on first unavailable
  checkpoint.
- Client method `SuiMirrorTransport::subscribed_changeset_page` via `try_peers`.

**Phase 2 — client-side proof verification (pure functions, heavily tested).**
- Add `verify_subscribed_id_proof(summary, id, &SubscribedIdProof) -> Result<...>`
  next to `non_inclusion_binds_id` in `ocs_currency.rs`: artifacts-digest binding +
  inclusion-or-(raw-non-inclusion + `non_inclusion_binds_id`) + leaf-id == id.

**Phase 3 — index extension: coverage intervals + `absorb_subscribed`.**
- Add `coverage: HashMap<ObjectID, CoverageInterval>` and `currency_subscribed`.
- Add `ChangesetError::MissingCommittee` and thread `verify_summary`'s structured
  error through `absorb_subscribed` (§8 step 1; do not flatten to `Unverified`).
- Add `absorb_subscribed` (§8) taking a `TrustedSeed`, with the completeness check,
  the trusted-seed bootstrap gate (the no-predecessor arm forbidden), and per-id
  coverage advance. Reuse `fold`/contiguity unchanged, but **extend** `drain_pending`
  (and `PendingChangeset` with `covered_ids`) and `prune` (coverage sweep, §5.4
  *Coverage-map pruning*) — those two are NOT byte-identical to the full-set path.
- Add `subscribe_id`/`unsubscribe_id` mutators (today `with_fold_filter` is
  set-once with no mutator).
- Tag the index with its fold mode; make `absorb`/`absorb_subscribed` mutually
  exclusive (typestate or assertion).

**Phase 4 — subscription receiver + registry.**
- `SubscribedChangesetReceiver` (sibling of `ChangesetReceiver`), sole writer of its
  `SharedChangesetIndex`, owning a `SubscriptionRegistry`. **At construction it seeds
  the registry with the two static roots** (`ika_system_object_id`,
  `ika_dwallet_coordinator_object_id` from `IkaObjectsConfig`,
  `messages_dwallet_mpc.rs:813-818`), each recorded with `subscribed_at_seq = seed.seq`
  and `floor = None` (§5.1 site A, §5.4 SUBSCRIBE (A)) — the static-pin enrollment that
  drives the shared head (§8); version-derived inners are pinned on first verified read.
  `pump` calls `subscribed_changeset_page` and folds via `absorb_subscribed`, passing
  the `TrustedSeed` derived from `perpetual.oldest_sui_committee_summary()` (§8) and
  requesting `from_seq = seed.seq + 1` on an empty index; poll-loop on
  `tokio::interval`. Because `oldest_sui_committee_summary()` returns
  `IkaResult<Option<...>>`, the seed is derived as `Option<TrustedSeed>` and **the
  receiver requires a non-empty seed to run** (§8 *Where the seed comes from*): on `None`
  (empty `sui_committee_summaries` — a direct-install committee with no backing
  end-of-epoch summary) it does **not** start the subscribed pump and the node stays in
  `Unknown` → per-read fallback; it re-derives the seed on a later tick and starts once
  the ratchet has persisted an end-of-epoch summary. The constructor does **not** mirror
  the full-set path's `.unwrap_or(0)` (`setup.rs:347-351`) — that would reintroduce the
  forbidden no-predecessor self-bootstrap (§8 step 2). Bounded `add_id` channel fed by
  the read path. The receiver holds `Arc<OcsVerifiedReader>` + a clone of
  `coordinator_rx` so its reconcile tick can re-walk the pinned bag containers via
  `reader.verified_dynamic_fields_page` (§5.4 SUBSCRIBE reconcile), with no new accessor on
  `BagEventPump`.

**Phase 5 — read-path wiring (subscription growth).**
- In `verified_reader.rs::verified_dynamic_fields_page`, **after** the membership-Owner
  binding passes (`:457-470`) and **before/at** the existing
  `check_currency(entry.object.id(), seq)` (`:483`), enqueue
  `add_id(entry.object.id())` non-blocking on the bound id. This is the **sole**
  admission site for the **dynamic** bag/dwallet ids (§5.1 site B); the static
  roots/inners are enrolled by the construction-time pin of Phase 4 (§5.1 site A), not
  here. Do **not** enqueue from `check_currency` (it is also
  reached from the single `:673` and batch `:274` read paths, which have no
  membership binding); leave `check_currency` a pure gate that continues to map
  `Unknown => Ok`. Dispatch `check_currency` to `currency_subscribed` for a
  `Subscribed`-mode index and `currency` for a `FullSet`-mode index — a node runs
  one or the other (node-level EITHER/OR, §8), never a per-id two-index split.

**Phase 6 — observability/health.**
- Per-id frontier-lag metric, tail-stall watchdog, fallback-rate health gate,
  benign-vs-suspicious-`Unknown` classification, mandatory small `freshness_bound`
  for roots/inners, partial-pruning signal, boundary-stall-vs-selective-id-stall
  signal gated on the ratchet head (§9). GC trust-independence and churn alarm (§5.4).

**Phase 7 — coexistence config.**
- Config to select the node's fold-mode driver — the full-set `absorb` path **or**
  the subscription `absorb_subscribed` path — and assert the construction-time
  mutual-exclusion (§8). No two-index migration machinery: coexistence is node-level
  EITHER/OR over a single index.

---

## 11. Test plan

### 11.1 Unit / property

- `currency_subscribed` bracket: `Unknown` for `M < floor`, `M > head`, `floor None`,
  `head None`, untracked id; `Current`/`Stale`/`NotLive` only inside `[floor, head]`.
  Include the **subscription-instant boundary**: a fresh id subscribed at
  `subscribed_at_seq` whose catch-up entry at `subscribed_at_seq` (`AlreadyFolded`
  against the global head) folds sets `floor == subscribed_at_seq`, so an anchor at
  `M == subscribed_at_seq` reads `Unknown` only until that entry folds and then sharpens
  to a definite verdict once `head >= M` — there is **no** off-by-one at the
  subscription instant (§5.2, §8 step 6).
- `floor` lands at the resume seq (no off-by-one): for a fresh id, the first
  proof-bearing, per-id-chained entry sets `floor(id) == subscribed_at_seq` (its resume
  seq), not `subscribed_at_seq + 1` — assert this for both the head/sub-head and the
  out-of-order drain path. The only floor that cannot descend to a given seq is one
  below the seed (`floor > seed.seq`, §8), never the subscription instant.
- `absorb_subscribed` folds a per-id delta identically to the full-set `fold` for the
  same ids (last-write-wins in contiguous seq order).
- Coverage `floor`/`head` advance only on an X-proven entry that forward-chains onto
  `X`'s own per-id anchor (`coverage.head_digest(X)`, or the trusted seed/the trusted
  summary at `subscribed_at_seq` at the floor) — at the head, on drain, OR below the
  head (`AlreadyFolded` against the global head), decoupled from the global
  `contiguous_head` (§5.2, §8 step 6).
- Tombstone: a `Modified` entry carrying `[99;32]`/`[88;32]` → `Deleted`/`Wrapped`
  → `NotLive`.

### 11.2 Byzantine-server regression tests (MUST exist)

1. **Forged-version present-leaf rejection (Blocker-1, generalized).** An `Absent`
   proof for an id that WAS modified, with the real present leaf passed as the dummy's
   right neighbor: raw verify accepts, `non_inclusion_binds_id` rejects, the entry is
   rejected, coverage does not advance. (Extends `ocs_currency.rs:455-494`.)
2. **Non-adjacent-honest-neighbor straddle (the SCS fatal counterexample, must FAIL
   to forge).** Two genuine non-tree-adjacent leaves bracketing an omitted modified
   leaf. The single-target `verify_proof` MUST reject because the right neighbor
   cannot validate at the claimed adjacent index. This is the regression that
   justifies rejecting the batched gap-cover; it must be a standing test.
3. **Omission / missing-proof detection.** An entry whose `proofs` keyset omits a
   requested id (or includes a foreign id) is a hard `ChangesetError`; the entry does
   not fold and the receiver fails over. No code path folds an entry with an
   unaccounted requested id.
4. **False-tombstone / mask-a-delete.** A server ships `Absent` for a checkpoint that
   deleted/wrapped the id → rejected (the marker leaf carries the id;
   `non_inclusion_binds_id` rejects). A deleted id is never read `Current`.
4a. **Wrap → unwrap → re-modify currency (the Wrapped-eviction regression).** Id `X`
    is wrapped at `M` (`[88;32]` leaf → `Wrapped → NotLive`), then unwrapped and
    re-modified at `M' > M` (a genuine `(X, v', d')` leaf via `WriteKind::Unwrap`).
    With `X` kept in the request set, the receiver folds `M'` and
    `currency_subscribed(X, M')` MUST return `Current` (not `Stale`/`NotLive`). The
    test MUST also assert the failure mode it guards: if folding of `X` had stopped
    at the wrap, the stale `Wrapped` record makes `currency_subscribed(X, M')` read
    `Stale` — a false reject. Companion case: an id `Deleted` at `M` and never
    re-folded stays `NotLive` and is legitimately evictable (contrast with `Wrapped`).
5. **Premature-Current via global-frontier confusion (fatal S4 regression).**
   Construct it on the SINGLE index in `Subscribed` mode. Seed the index from a
   `TrustedSeed` at the genesis anchor; advance the shared head to `5000` by folding the
   always-present pinned roots/inners every checkpoint; subscribe fresh id `X` at head
   `5000` (so `subscribed_at_seq(X) == 5000`) with a genuine inclusion anchored at
   `M = 4000` but never fold `X`'s coverage over `[4000, 5000]`. Assert
   `currency_subscribed(X, 4000)` returns `Unknown` (`cov.floor(X)` is `None`, or
   `> 4000` once `X` catches up from `5000`), never `Current`/`Stale`. This proves the
   single shared head does not bless `X`'s anchor — the global frontier brackets `4000`
   yet `X`'s own floor never does (`4000 < subscribed_at_seq(X)`, below where `X` could
   ever begin folding). This arm tests fail-closed soundness and is unchanged by the
   decoupled advancement model: an anchor below the id's own folded coverage reads
   `Unknown`.
5b. **Sub-head catch-up advances a fresh id's coverage (the closed-gap regression).**
   Continue the same fixture (shared head already at `5000`, `X` fresh with
   `subscribed_at_seq(X) == 5000`). Feed `X`'s catch-up entries for `[5000, ...]` that
   land **below** the global `contiguous_head` (classified `AlreadyFolded` for the
   global head), each carrying `X`'s `Modified`/`Absent` proof and forward-chaining onto
   `X`'s per-id anchor (the trusted summary at `subscribed_at_seq`, then
   `coverage.head_digest(X)`). Assert these sub-head entries **do** advance
   `coverage.floor(X)` and `coverage.head(X)` — decoupled advancement, §5.2/§8 step 6 —
   so `X` is **not** stuck `Unknown` below the head. Assert `coverage.floor(X) == 5000`
   (its resume seq, **no** off-by-one, **not** `5001`), and that once `coverage.head(X)`
   rises past an anchor `M` (e.g. a genuine inclusion `X` carries at some `M' >= 5000`)
   `currency_subscribed(X, M')` sharpens from `Unknown` to a definite verdict. This is
   the direct regression for the gap a fresh dynamic id whose catch-up entries arrive
   below the head must still advance its own coverage.
6. **Stalled-stream-looks-healthy (fatal S7 regression).** Outer id healthy to head
   `200`; inner id frozen at `coverage.head = 160` while really modified at `175`.
   `currency_subscribed(inner, 155)` is inside `[floor, 160]` only if `160 >= 155`;
   the test asserts that the *frozen head below the hidden modification* keeps any
   anchor at/above `175` `Unknown`, and that the frontier-lag/tail-stall alarm fires
   for the inner id while the outer advances.
7. **Growth-gap currency.** A just-discovered bag id reads `Unknown → Ok` at
   discovery; after the receiver folds a contiguous interval bracketing the anchor,
   the verdict sharpens to `Current`/`Stale`/`NotLive`; before that it never
   false-rejects or false-accepts.
8. **Wrong-summary `tree_root`.** A proof whose `tree_root` does not reconstruct to
   the BLS-signed summary's artifacts digest → rejected before fold.
9. **Single-writer / fold-mode mutual-exclusion guard.** Calling `absorb` on a
   `Subscribed`-tagged index (or `absorb_subscribed` on a `FullSet`-tagged index)
   asserts/panics — the construction-time fold-mode tag plus the mutual-exclusion
   assertion (§8) make a node-level EITHER/OR mode unbypassable. There is no
   two-index reconciliation to test (retired): assert that a `Subscribed`-mode index
   dispatches **every** id (roots/inners and bag/dwallet alike) through
   `currency_subscribed` and never consults a second index, and that a `FullSet`-mode
   index dispatches through `currency`; assert no code path reads two indices for one
   id.
10. **Checkpoint-skip / broken-chain.** A non-chaining successor stalls the per-id
    head; anchors above the gap read `Unknown`.
11. **Stale-summary replay at the wrong sequence position (distinct from #8).** A
    *genuine, correctly-BLS-signed* summary for an older checkpoint `C-100` — at which
    the id `X` truly was **not** modified — carrying its real `Absent` non-inclusion
    that verifies cleanly against `C-100`'s `tree_root` (so #8's wrong-`tree_root`
    rejection does **not** apply: here the root *does* reconstruct to a signed
    summary's artifacts digest). The byzantine server presents this entry in the slot
    for checkpoint `C` (where `X` **was** modified) to mask the modification.
    `absorb_subscribed` MUST reject it at the position gate: `summary.sequence_number()
    != expected_next_seq` and/or `summary.previous_digest != Some(head_digest)`. Assert
    that the entry does not fold, `coverage.head(X)` does not advance over `C`, and
    `X`'s modification at `C` is never masked (a later genuine read at/above `C` is not
    served `Current` off the pre-`C` version). Contrast with #8: #8 forges the root;
    this test uses a *real* root at the *wrong position*.
12. **Boundary non-inclusion: target sorts above all (left-only neighbor).** Build a
    tree whose largest id is `Y < X`; request an id-bound non-inclusion for absent
    `X` with the dummy `(X, 0, MIN)`. Assert `verify_proof` accepts via the
    `right_leaf = None` / `is_right_most(left_leaf_index)` branch
    (`merkle.rs:289-292`) and `non_inclusion_binds_id(_, X)` holds. Then forge a
    left neighbor that is **not** the rightmost leaf and assert `verify_proof`
    rejects at `291`. Finally, place a real `(X, v>0, d)` leaf as the (rightmost)
    left neighbor and assert `non_inclusion_binds_id` rejects (X present-and-last
    cannot be served `Absent`).
13. **Boundary non-inclusion: target sorts below all (right-only neighbor at index
    0).** Build a tree whose smallest id is `Z > X`; request non-inclusion for
    absent `X`. Assert `verify_proof` accepts via the `index == 0` / `right_leaf`
    present branch (`merkle.rs:275-288`) and the id binds. Then forge `index != 0`
    with no left neighbor and assert `verify_proof` rejects at `275`. Finally, pass
    a real `(X, v>0, d)` leaf as the slot-0 right neighbor and assert
    `non_inclusion_binds_id` rejects.
14. **Boundary non-inclusion: empty tree.** Build an empty `ModifiedObjectTree`
    (a checkpoint that modified nothing) and a summary whose artifacts digest
    commits to it. Assert `verify_proof` accepts unconditionally
    (`merkle.rs:258-260`) and `non_inclusion_binds_id` is vacuously true (both
    neighbors `None`), so any `X` reads `Absent` soundly. Assert that a server
    cannot pass off a **non-empty** checkpoint as empty: swapping in a non-empty
    root fails the artifacts-digest binding (§3.3) and the entry is rejected before
    fold.
15. **Boundary non-inclusion: single-leaf tree.** Build a one-leaf tree `[(Y, v, d)]`
    with `Y != X`. For `X < Y` assert the proof takes the *below-all* branch and
    binds; for `X > Y` assert it takes the *above-all* / `is_right_most` branch and
    binds. Then set the lone leaf to `(X, v>0, d)` and assert `non_inclusion_binds_id`
    rejects in whichever branch the dummy lands (the lone leaf is X's own).
16. **Boundary-straddling coverage interval.** A coverage interval whose contiguous
    run spans the last checkpoint of epoch `E` and the first of `E+1` (the latter's
    `previous_digest` chaining onto the former, signed by `committee[E+1]`, which the
    test installs into the `CommitteeStore` up front to model a ratchet that has already
    advanced): assert the interval advances `head` across the boundary, that
    `currency_subscribed` answers `Current`/`Stale` for an anchor on *either* side
    without a forced `Unknown`, and that a successor signed by the **wrong** (e.g.
    still-`E`) committee fails `verify_summary` with
    `SummaryVerifyError::BadSignature` → `ChangesetError::Unverified` (not
    `MissingCommittee`) and does not advance `head`.
17. **Boundary stall on missing next committee, and that the CHANGESET fold cannot
    clear it.** With `committee[E+1]` deliberately **not** installed in the
    `CommitteeStore` (modelling a ratchet that has not yet reached `E+1`), offer the
    first checkpoint of `E+1` to `absorb_subscribed`. Assert it returns the **typed**
    `ChangesetError::MissingCommittee(E+1)` — *not* `Unverified` — so the benign
    boundary stall is distinguishable from a byzantine bad signature; assert
    `coverage.head(id)` stalls at `E`'s last checkpoint for **all** subscribed ids
    simultaneously (not a single id), and reads above the stalled head fall back to
    `Unknown`. Assert the **boundary-stall** signal fires (keyed on the
    `MissingCommittee` arm) and the **selective-id frontier-lag/tail-stall** alarm does
    **not** (this is the all-ids signature, not a selective one). Then assert the stall
    is cleared **only by the ratchet, not by folding more changeset entries**: feeding
    additional `E+1` entries while `committee[E+1]` is still absent keeps returning
    `MissingCommittee(E+1)` and never advances `head`; after the test installs
    `committee[E+1]` (modelling `install_next`), the next `absorb_subscribed` of the
    same first-`E+1` checkpoint folds and `coverage.head` resumes advancing. Companion
    assertion on the wedged-ratchet case: a node whose `committee_head_epoch` stays
    below `chain_latest_epoch` past the bounded window fails the §9 boundary-stall
    health gate (the permanent-stall path; the ratchet-wedge itself — `ProofChainBroken`
    on a pruned end-of-epoch checkpoint — is exercised in the ratchet's own tests and
    the cluster suite, not here).
17a. **`ChangesetError` typing.** `absorb_subscribed` maps
    `SummaryVerifyError::MissingCommittee` → `ChangesetError::MissingCommittee` and
    `SummaryVerifyError::BadSignature` → `ChangesetError::Unverified`, so a benign
    boundary stall is type-distinguishable from a byzantine bad signature (mirrors
    `absorb_verified_rejects_a_foreign_committee_signature`, `ocs_currency.rs:817-828`).
18. **Trusted-seed bootstrap rejects a relay-chosen floating start.** Build a
    genuinely-BLS-signed run of REAL-but-STALE checkpoints `[F, F+1, F+2]` whose
    internal `previous_digest` chain is self-consistent, with `F != seed.seq + 1` (or
    `F == seed.seq + 1` but `previous_digest != seed.digest`). Call `absorb_subscribed`
    on the **empty** index with `TrustedSeed { seq, digest }` from
    `oldest_sui_committee_summary()`. Assert the first entry is rejected
    `BrokenChain { seq: F }`, `contiguous_head` stays `None`, every id's
    `coverage.floor` stays `None`, and every read returns `Unknown → fallback`. Then
    feed the genuine `seed.seq + 1` entry whose `previous_digest == seed.digest` and
    assert it folds and seeds the frontier.
19. **Trusted-seed bootstrap forbids the no-predecessor arm.** Assert that calling
    `absorb_subscribed` on an empty index with an entry whose `seq == seed.seq + 1` but
    `previous_digest == None` (or any digest `!= seed.digest`) is `BrokenChain`,
    proving the `absorb` bootstrap arm (`258-268`) is unreachable on this path.
20. **Drain advances coverage for an out-of-order-then-drained entry.** Seed the index,
    fold the head to seq `H`. Queue entry `H+2` first (it `Queued`s — gap at `H+1`),
    covering ids `{A (Modified), B (Absent)}`; assert `coverage.head(A)` and
    `coverage.head(B)` are still `<= H` (not advanced). Then fold `H+1` (also covering
    `{A,B}`); `drain_pending` pulls `H+2`. Assert
    `coverage.head(A) == coverage.head(B) == H+2`, that `B` (all-`Absent` at both
    checkpoints) advanced its coverage despite never writing to `index`, and that
    `currency_subscribed` now brackets an anchor at `H+2` for both. This is the
    regression for the old `PendingChangeset`-lacks-coverage bug.
21. **Drain sets `floor` on first contiguous fold via the drain path; floor is strictly
    above the seed.** With an empty index seeded by `TrustedSeed`, queue `seed.seq+2`
    (covering id `X`) before `seed.seq+1`; assert `X`'s `floor` stays `None` while
    queued; fold `seed.seq+1` (covering `X`) so drain pulls `seed.seq+2`; assert
    `coverage.floor(X) == seed.seq+1` and `coverage.head(X) == seed.seq+2`. Assert the
    strict-inequality consequence: `coverage.floor(X) > seed.seq` (the seed checkpoint
    is never folded, §8 *Where the seed comes from*), so an anchor at `M == seed.seq`
    reads `Unknown` from this index. The `floor_anchored_on` field is **diagnostic-only**
    (no verdict path reads it, §5.2/§5.3); a test MAY assert
    `coverage.floor_anchored_on(X) == seed.digest` to pin the bookkeeping, but this is
    **not** a soundness assertion — soundness is discharged by the `absorb_subscribed`
    position gate (§8 step 2), which is the subject of tests #18 and #19, not by this
    recorded digest. (An implementation that drops `floor_anchored_on` entirely drops
    only this diagnostic line, not any verdict.)
22. **Single-index static-set drives the shared head every checkpoint.** Subscribe
    only the pinned roots/inners plus one dynamic id that is `Absent` every checkpoint;
    fold a contiguous run and assert `highest_contiguous_seq()` advances by 1 per entry
    (the static-set proofs alone advance the **global** head) and the dynamic id's
    `coverage.head` tracks it **because each entry carries the dynamic id's `Absent`
    proof** — i.e. the dynamic id advances on its own per-id-chained proofs, not because
    the global head moved. Companion arm: subscribe a **second** dynamic id mid-run, at
    a height where the global head is already ahead, and feed it catch-up entries that
    land **below** `contiguous_head` (classified `AlreadyFolded` for the global head);
    assert those sub-head entries still advance the second id's `coverage.floor`/`head`
    (decoupled advancement, §5.2/§8 step 6), so a freshly-subscribed id below the head
    is not stuck `Unknown`.
22a. **Receiver seeds the static roots at construction; head advances on a root-only
    modification.** Construct a `SubscribedChangesetReceiver` and assert that, **before
    any page is folded**, its registry already holds the two static roots
    (`ika_system_object_id`, `ika_dwallet_coordinator_object_id` from `IkaObjectsConfig`)
    via the static-pin enrollment (§5.1 site A, §5.4 SUBSCRIBE (A)), each with
    `subscribed_at_seq = seed.seq` and `floor = None`, with **no** bag walk having run
    (no `add_id` from `verified_dynamic_fields_page`). Then fold a single checkpoint at `seed.seq+1`
    that modifies **only** a root (a `Modified` proof for that root id, the cohort's
    other pinned ids `Absent`): assert `highest_contiguous_seq()` advances from the seed
    to `seed.seq+1` driven by the root's own proof alone — i.e. the static-pin enrollment
    is what keeps a root in the cohort `ids` so a root-only checkpoint still produces an
    entry that advances the shared head — and that the modified root's `coverage.floor`
    is set to `seed.seq+1` (`> seed.seq`, §5.2). Assert the roots are exempt from the
    bag-only admission invariant: they entered the registry with no `verified_dynamic_fields_page`
    binding and are never GC'd (§5.4).
23. **Coverage prune drops aged non-pinned ids but keeps pinned roots/inners.** Fold
    past the retain window; assert a dynamic id whose `head` fell below the floor has
    its `CoverageInterval` removed (and reads `Unknown`), while a pinned inner id keeps
    its interval (never pruned).
24. **Coverage prune clamps a straddling interval's floor.** `cov(X) = [floor=f,
    head=h]` with `f < new_floor < h` after `prune`; assert `cov.floor` is clamped up
    to `new_floor`, that `currency_subscribed(X, M)` for `f <= M < new_floor` returns
    `Unknown` (below the raised index floor), and for `new_floor <= M <= h` still
    answers `Current`/`Stale`/`NotLive` from the index.
25. **Coverage GC drops the row with the registry.** TTL-evict a subscribed (non-
    `Deleted`, non-`Wrapped`) id; assert its registry row AND coverage row are both
    gone in the same eviction, no orphan `CoverageInterval` left behind.
26. **Coverage re-subscribe clears a stale interval.** Subscribe `X`, fold to
    `cov(X)=[f,h]`, evict, then re-subscribe `X` at a higher head; assert the new
    `CoverageInterval` has `floor=None` and `subscribed_at_seq=current head` (no
    inherited `f/h`), and `X` reads `Unknown` until it re-folds — extends the `Wrapped`
    force-`Unknown` regression (test 4a) to the general re-subscribe case.
27. **Coverage map bounded by registry.** Subscribe and evict many ids over many
    checkpoints (more than retain-window/stride cycles); assert `coverage.len()` never
    exceeds `registry.len()` at any tick — the map does not grow monotonically the way
    it would if `prune` ignored it. (Guards against a verbatim-copy of `prune` that
    sweeps only `self.index`.)
28. **Registry admission only from `verified_dynamic_fields_page`.** Drive a single
    `verified_object` read (`:673`) and a batch `verified_objects` read (`:274`) of an
    id that is NOT a bag child; assert the subscription registry remains empty
    afterward (no `add_id` fired) — enrollment never happens off the single/batch paths.
29. **Registry admission after binding only.** In `verified_dynamic_fields_page`, feed an entry
    whose membership-Owner binding FAILS (owner `!= bag_id` and not the derived wrapper
    id) so the call returns `DynamicFieldMembership`; assert no `add_id` was enqueued for that
    entry's id (admission is strictly downstream of the binding, never on a rejected
    entry).
30. **Registry admission on a bound bag child.** Feed a `verified_dynamic_fields_page` entry that
    passes inclusion + membership-Owner binding; assert exactly one idempotent
    `add_id(entry.object.id())` enqueue for the bound id, recorded with
    `subscribed_at_seq = contiguous head` and `floor = None`, and that re-walking the
    same id does not double-enroll (drain-side dedup).
31. **`list_dynamic_fields` relay listing does not admit.** Route a relay-chosen
    foreign id through the raw `list_dynamic_fields`/`pull_dwallet_mpc_uncompleted_events`
    path that does not carry the membership-Owner binding; assert the registry does not
    admit it (only the binding-checked `verified_dynamic_fields_page` admits).
32. **Reconciliation re-walk admits only binding-checked ids.** Stand up a
    `SubscribedChangesetReceiver` whose registry is missing an id that the verified bag
    walk lists; assert the reconcile tick enrolls exactly that id, and that an id the
    relay tries to inject WITHOUT a passing membership-Owner binding (a
    `verified_dynamic_fields_page` entry that fails `:457-470`) never reaches the registry —
    `verified_dynamic_fields_page` errors it out before `entry.object.id()` is taken.
33. **Reconciliation never GC's on a relay-driven shrink.** A bag page that omits a
    previously-enrolled child does NOT remove it from the registry (trust-independent
    direction), it only adds; assert registry membership is monotone under
    reconciliation alone.
34. **`ProofCache` sizing assertion.** Construct the subscription
    `LocalProofProvider`'s `ProofCacheConfig` and assert `tree_capacity >=
    INFLIGHT_SUBSCRIBED_CHANGESET_PAGE * MAX_SUBSCRIBED_CHANGESET_PAGE` (the
    construction-time `debug_assert`). Regression: a cap edit lowering `tree_capacity`
    below the product trips the assertion, so a future tuning change cannot silently
    re-open the thrash.
35. **Server-side cache residency.** Drive `INFLIGHT_SUBSCRIBED_CHANGESET_PAGE`
    concurrent `subscribed_changeset_page` requests over disjoint
    `MAX_SUBSCRIBED_CHANGESET_PAGE`-wide checkpoint ranges and assert each distinct
    checkpoint's `ModifiedObjectTree` is materialized at most once
    (`proof_tree_cache_misses_total` increments at most once per distinct checkpoint,
    no second miss for a checkpoint already built within the in-flight window) — i.e.
    no eviction-and-rebuild while pages are still in flight.
36. **Cohort partition pages an over-cap registry without dropping ids.** Stand up a
    `SubscribedChangesetReceiver` whose registry holds
    `N = 2·MAX_SUBSCRIPTION_IDS + 1 = 513` ids all at the same resume point; assert the
    receiver issues exactly `⌈513/256⌉ = 3` `subscribed_changeset_page` requests (each
    with `ids.len() <= 256`), that the union of the three requests' ids equals the full
    registry with no id omitted and no id duplicated across pages, and that no id is
    dropped from the registry for want of cap headroom.
37. **Reconcile re-walk enrolls beyond the 256 wire cap.** Drive a reconcile tick over
    a verified bag walk that lists `N = 300 > MAX_SUBSCRIPTION_IDS` binding-checked
    children; assert all 300 are admitted into the registry (`registry.len() == 300`,
    no 256 ceiling applied at enrollment) and that the next CATCH-UP tick partitions
    them into `⌈300/256⌉ = 2` cohort pages rather than refusing or truncating
    enrollment.
38. **No drop / re-walk / re-overflow loop above the cap.** With a registry held at
    `N > MAX_SUBSCRIPTION_IDS` across several reconcile + CATCH-UP ticks, assert
    `ika_ocs_subscription_enqueue_dropped_total` does **not** increment (enrollment is
    not gated on the 256 cap), the registry size stays stable (monotone under reconcile
    per the trust-independence rule), and every id is covered by exactly one cohort page
    per tick.
39. **Last-read LRU backstop evicts coldest ids only, toward `Unknown`.** Fill the
    registry past a soft high-water bound with non-pinned, non-`Wrapped` ids of varying
    last-read timestamps; advance the local TTL clock; assert the coldest-by-last-read
    ids are evicted **first** (their registry + `CoverageInterval` rows dropped
    together), pinned roots/inners and `Wrapped` ids are never evicted by this pressure,
    a subsequent read of an evicted id returns `Unknown → fallback` (never a false
    `Current`), and the next reconcile re-walk re-enrolls it.
40. **Stale-container retirement-lag drop is bounded and read-independent.** Drive a
    sequence of reconfigurations that each move the session-event container ids (bump
    `inner.current_epoch` and the version-derived container ids), with a per-generation
    child set **exceeding** `MAX_SUBSCRIPTION_IDS` (so the bound under test cannot be the
    256 cohort clamp). After more than `RECONFIG_GC_LAG + 1` reconfigurations, assert the
    **resident-generation multiplier is bounded** — the number of *distinct live
    generation tags* present in the registry is `≤ RECONFIG_GC_LAG + 1` at every tick,
    regardless of reconfiguration count **and** regardless of per-generation child count
    (NOT that each generation, or `registry.len()`, is `≤ MAX_SUBSCRIPTION_IDS`) — that
    children of a container retired more than `RECONFIG_GC_LAG` epochs ago are dropped
    **without any read touching them** (read-independent), and that their
    `CoverageInterval` rows are dropped in the same step (no orphan coverage row).
41. **Lag drop never evicts a still-live re-tagged child.** A child present under both
    the old and the new container (same `ObjectID` listed by both verified walks) is
    re-tagged to the current generation by the reconcile re-walk before the lag elapses;
    assert it is **not** lag-dropped at the retired generation's expiry and keeps its
    `CoverageInterval`.
42. **Lag drop is one-directional toward `Unknown` (sound).** Drive a child to
    `Current` under a container, retire that container, advance `RECONFIG_GC_LAG`
    epochs; assert the lag drop withdraws the verdict to `Unknown → fallback` (never a
    false `Current`/`Stale`), and that re-discovery under the new container
    re-subscribes it at `coverage = None` (extends the re-subscribe-clears-stale-interval
    test #26).
43. **Generation tag is trust-anchored, not relay-steerable.** Assert the registry
    generation tag is taken from the committee-verified `inner.current_epoch`
    (`bag_event_pump.rs:115`) and that a relay-supplied bag listing cannot change a
    resident row's generation tag (only a verified re-walk re-tags); a relay that omits
    a child does **not** advance or reset its generation tag (trust-independent,
    monotone-add under reconciliation).
44. **Empty `sui_committee_summaries` → receiver does not start.** Construct the
    `SubscribedChangesetReceiver` (or its seed-derivation helper) against a
    `CommitteeStore` whose perpetual `sui_committee_summaries` is empty (modelling a
    `CommitteeBootstrap::UnsafeGenesis` direct-install bootstrap,
    `committee_store.rs:161-162`). Assert `oldest_sui_committee_summary()` returns
    `Ok(None)`, the derived seed is `None`, the subscribed pump is **not** started (no
    `absorb_subscribed` is ever invoked), and a `check_currency` on any id routes to
    `Unknown => Ok` per-read fallback (§5.3). Assert no panic and no `BrokenChain` stall
    loop. (§8 *Where the seed comes from*, §10 Phase 4.)
45. **Seed materializes after a ratchet transition → receiver starts.** Starting from
    empty `sui_committee_summaries` (seed `None`, receiver not started), record one
    end-of-epoch summary via `record_sui_committee_transition`. Assert the next seed
    re-derivation yields `Some(TrustedSeed { seq, digest })` with
    `(seq, digest) == (*summary.sequence_number(), summary.digest())`, the receiver
    starts, and it requests `from_seq = seed.seq + 1` on the empty index (the seed
    checkpoint itself is never folded, §8).
46. **No `unwrap_or(0)` regression.** Assert (e.g. by a targeted unit/inspection test on
    the seed-derivation path) that the `None` branch does **not** fall through to a
    seq-0 / no-predecessor self-bootstrap: with seed `None` the index's
    `contiguous_head` stays `None` and no entry is admitted as a floor, distinguishing
    the subscription path from the full-set `setup.rs:347-351` `.unwrap_or(0)` behavior.
47. **Per-id forward-chain guards a sub-head entry (per-id `BrokenChain`).** Subscribe
    id `X`; advance the global `contiguous_head` ahead via the static cohort so any of
    `X`'s catch-up entries land below the head (`AlreadyFolded` for the global head).
    Feed `X` a sub-head `Absent` entry whose `summary.previous_digest` does **not** match
    `coverage.head_digest(X)`. Assert the entry advances neither `coverage.head(X)` nor
    `coverage.floor(X)` nor any verdict (a per-id `BrokenChain`), proving the **per-id**
    chain check (§5.2/§8 step 6) — not the global `+1` gate of step 2 — guards sub-head
    advancement, and that a stale-but-signed sub-head proof cannot mask an omission below
    the head. Then feed the genuine chaining entry (`previous_digest ==
    coverage.head_digest(X)`) and assert it advances `X`'s coverage.
48. **Fresh-id floor bootstraps at the resume seq (no off-by-one).** Two cases.
    (a) *Empty-index root:* with an empty index seeded by `TrustedSeed`, subscribe a
    construction-seeded root with `subscribed_at_seq == seed.seq`; feed the first
    proof-bearing entry at `seed.seq + 1` whose `previous_digest == seed.digest`; assert
    `coverage.floor(root) == seed.seq + 1` (the first foldable checkpoint, `> seed.seq`)
    and that the head bootstraps from the empty index. (b) *Mid-stream dynamic id:* with
    the global head already at `H`, subscribe a fresh id `X` with `subscribed_at_seq == H`;
    feed `X`'s first proof-bearing catch-up entry at `H` (`AlreadyFolded` against the
    global head, its `previous_digest` chaining onto the index's already-trusted summary
    at `H - 1`); assert `coverage.floor(X) == H` (its resume seq, the entry that an
    earlier draft would have discarded as `AlreadyFolded`), **not** `H + 1`. This is the regression for the
    bootstrap off-by-one called out in the (now-resolved) header gap block.

### 11.3 Liveness / observability tests

- Selective-id stall raises the per-id frontier-lag alarm while the global frontier
  advances.
- Tail-stall (valid prefix then silence) raises the watchdog when
  `highest_seen_seq()` rises but `highest_contiguous_seq()` does not.
- Relay-driven GC churn (bag page omits an id) does NOT GC the id (trust-independent
  GC) and raises the churn alarm.
- Burst `add_id` overflow increments
  `ika_ocs_subscription_enqueue_dropped_total`, and the next receiver tick re-walks
  the pinned bag containers via `reader.verified_dynamic_fields_page` and enrolls the dropped id
  (the burst is not a permanent subscription loss); a drop that never reconciles fails
  the health gate.

---

## 12. Open questions / known limitations

1. **Idle-run compression is impossible under today's commitments (accepted).**
   "X unchanged in `[A,B]`" cannot be a single range assertion: each checkpoint has
   an independent `ModifiedObjectTree` with no cross-checkpoint linkage of an id's
   last-modified seq, and fastcrypto has no range/multiproof. A long-idle subscribed
   id costs **one non-inclusion proof per checkpoint**. Compressing this requires a
   NEW commitment (a per-id last-modified accumulator / sparse history tree committed
   in the summary) — a `messages_checkpoint.rs` / `sui-light-client` change that
   breaks the no-fastcrypto-change premise of Blocker-1. Out of scope; documented as
   the dominant cost driver on slow-churn ids.

2. **No batched non-inclusion primitive (accepted; cost not measured).** `O(K · log
   N)` per checkpoint with no path sharing. A future fastcrypto sorted-tree batched
   non-inclusion / Merkle multiproof would cut both bandwidth and server CPU for large
   subscriptions, but the hand-rolled flat-boundary batch is **unsound** (§1.2) and
   the safe batch would need committed leaf counts + per-gap consecutive-index checks.
   Whether the upstream change is justified depends on measured proof sizes, which do
   not exist in-tree.

3. **`OBJECT_DIGEST_CANCELLED` classification (unverified, blocking Phase 0).** If
   `effects.written()` can emit a `[77;32]` leaf, `from_digest` mis-buckets it as
   `Modified → Current` on BOTH paths. Must be confirmed before relying on currency;
   fix is `IdStatus::Cancelled → NotLive`.

4. **Forward-compat: single-artifact assumption.** `from_artifact_digests(vec![
   single_root])` assumes exactly one `CheckpointArtifact` variant. A future variant
   breaks the per-proof `tree_root` binding here and `OCSProof::verify`. The wire
   format should eventually carry the artifact index/variant tag rather than
   hardcoding `vec![root]`.

5. **Partial pruning → permanent fallback (accepted, mitigated).** A subscribed id
   whose anchor precedes the serving node's retention can never get a contiguous fold
   over the anchor → permanent `Unknown` for that read. Sound (fallback, never false
   `Current`) but a coverage hole. Mitigate by anchoring bag reads at recent
   checkpoints; surface a distinct retention-Unknown signal.

6. **Selective-id / tail-stall liveness (mitigated, not eliminated).** A byzantine
   relay can keep a targeted id (or the whole frontier) permanently in `Unknown`
   fallback without producing a false read — under the decoupled advancement model this
   is now a withheld-per-id-proof stall (the id's `coverage.head` cannot cross a
   checkpoint whose proof is withheld), the same fail-closed behavior as a withheld head
   entry, surfaced by the §9 per-id frontier-lag alarm. Soundness holds; the defense is
   observability + failover + health-gating (§9), not a cryptographic guarantee. A
   timing adversary that controls all reachable peers can deny currency indefinitely
   — this is a liveness limit of any untrusted-relay design, not specific to the
   subscription.

7. **Coexistence index model (resolved — single index, node-level EITHER/OR).** A
   node runs **one** `ChangesetIndex` with one writer: it subscribes **all**
   currency-relevant ids per-id (static roots/inners **and** dynamic bag/dwallet
   children) and folds them through `absorb_subscribed`, **or** it runs the full-set
   `absorb` path — never a per-id two-index overlap (§8). The two-index split
   (ownership routing, overlap-window Current-wins, transition invariant) is retired.
   Residual: a deployment that genuinely needs the full-set path for the
   roots/inners **and** the subscription for the dynamic set *simultaneously* on one
   node is no longer expressible; by design, and must be re-opened deliberately if
   ever required.

8. **Subscription persistence across restarts.** The subscribed id-set is
   reconstructable by re-walking bags, but cold start means every bag id is `Unknown`
   until re-caught-up. Whether a persisted registry is warranted (vs re-walk) is open.

9. **Transitive dwallet discovery.** Whether the dynamic id set grows transitively
   from decoded session-event contents beyond the bag-entry `Field` object was not
   traced (`decode_session_event`, `bag_event_pump.rs:228-247`, does not appear to
   issue further verified reads, but downstream MPC consumers were not inspected). If
   it does, those ids also need subscribing.

10. **`verified_objects` (batch) has no application consumer today** (only relay
    plumbing + tests). If a future caller (e.g. the validator-set read) uses it, that
    adds another static-known id class to the subscription; confirm intent.

11. **Server-side `ProofCache` sizing under subscription load (resolved — §7.2).**
    The default cap (`tree_capacity = 32`, `proof_provider.rs:351-358`) was sized
    for the single-object inclusion-proof workload and is too small here: up to
    `INFLIGHT_SUBSCRIBED_CHANGESET_PAGE × MAX_SUBSCRIBED_CHANGESET_PAGE = 4 × 16 =
    64` distinct checkpoints can be in flight at once, so a 32-tree cache thrashes
    and re-derives `ModifiedObjectTree`s, defeating the §7.1 latency invariant.
    This is **not** left to load analysis: §7.2 fixes it with the hard constraint
    `tree_capacity ≥ INFLIGHT_SUBSCRIBED_CHANGESET_PAGE × MAX_SUBSCRIBED_CHANGESET_PAGE`
    (reconciled to `tree_capacity = 64` at the §4.3 caps), re-checked (and the caps
    possibly lowered instead) whenever the Phase 0 measurement moves any of the
    three numbers. The remaining *measurement* question — the absolute per-proof CPU
    that sets whether the caps go up or down — lives in Phase 0 (§10), not here.

12. **Container-id churn at reconfiguration (mitigated, cluster-validated).** A
    reconfiguration that changes the session-event bag-container ids (via an inner
    version bump, §5.6(d)) restarts those containers' children at `Unknown → fallback`
    until their per-id streams re-fold a bracketing interval — a per-boundary
    coverage dip on the dynamic dwallet set, analogous to the cold-start gap (open
    question 8). It is sound (never a false `Current`) and is mitigated by anchoring
    bag-entry reads at recent checkpoints, but the end-to-end behavior across a real
    reconfiguration is fragile enough to require cluster-suite validation, not unit
    coverage. Whether the container-id-stable case (version bump that does *not* move
    the container ids) can skip even the transient dip is unverified and not relied on.
