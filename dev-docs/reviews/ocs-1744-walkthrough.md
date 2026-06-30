# OCS PR #1744 — guided walkthrough remarks

> Working review file. Each topic below is walked in small sections; the
> reviewer's remarks are recorded under it verbatim (with the section context).
> PR: `feat/ocs-grpc-migration` → `dev` (+23,473 / −1,224, 85 files).
>
> **Status: PR #1744 is MERGED to `dev`** (commit `05d66e6024`). This is therefore a
> post-merge review; the concerns below (C1–C7, Findings 1–3) describe live `dev` code,
> not pre-merge blockers. All `file:line` references and `feat/ocs-grpc-migration` mentions
> now resolve on `dev`.

## Session 2 summary — pusher (`IkaCheckpointPusher`) deep dive

Function-by-function walk of the sui-state-direct **pusher** (`push_worker.rs`) and the
committee-chain code it calls. Coverage:

- **`new`** — relevance-set captured once from `IkaPackageConfig` (stale if a new Ika package
  id appears at runtime → its objects silently not folded); cursor resume vs **first-boot
  tip-start** (→ C6); tripwire seeding via `note_processed`. First-boot has the only network
  call (→ C7).
- **`run`** — 2s interval (hard-coded, not config); infinite loop, **no shutdown branch**
  (unlike sibling loops); errors swallowed (`warn!`) — the catch-all for `advance`'s few hard-`?`
  paths.
- **`advance`** — stall gauge (100) vs fast-forward (1000) bands; per-seq crash-consistent
  ordering (absorb persists, then cursor persisted last → re-fold on restart is idempotent);
  fetch-failure skips a seq *including its committee capture*; `note_processed` marks
  fetch-skipped checkpoints "processed" so the reader sees "current" for objects that were never
  folded (stale-until-evicted); `build_entries`'s hard `?` can wedge progress on a single
  bad checkpoint.
- **`capture_committees_through`** — best-effort committee salvage before a fast-forward jump.
  Failure analysis: 4 of 5 exits are **silent `break`s**; only the pruned-full-checkpoint path
  logs. The `_ => break` arm silences `BadSignature`/`Extract`/`EpochMismatch` — exactly the
  trusted-uplink-corruption signals — and stops the walk short on a benign concurrent-install
  race. Pruned boundary mid-jump **strands the committee head behind the cursor** with no
  in-band recovery → handed to the ratchet → `ProofChainBroken` → re-anchor (finding-17 surface).
- **The ratchet** (`ocs_verifier.rs::ratchet_to_current_epoch`) — clarified as the loud,
  error-surfacing **catch-up backstop** (periodic 30s, all OCS nodes) that every "let the ratchet
  handle it" break defers to. Same audited `install_next_from_checkpoint` core as the pusher's
  eager capture, opposite failure posture: it returns terminal `ProofChainBroken` /
  `BadCheckpointSig` / `NotEndOfEpoch` errors at `error!` level where the pusher silently breaks.
  Three drivers turn the committee ratchet: pusher eager capture (full checkpoints), committee
  follower (summary-only stream, prune-immune), background ratchet (authoritative backstop).
- **`head_epoch`** — clarified: the committee-chain frontier (highest Sui epoch with a verified
  committee), distinct from the pusher cursor (checkpoint seq), the chain's current Sui epoch,
  and the Ika epoch.

New concerns raised this session: **C5** (retain-window prune defeated by bootstrap-floor clamp
= `ocs-cache-committee-1`), **C6** (pusher first-boot tip-start mis-aligned with advertised
mirror-bootstrap floor), **C7** (pusher first-boot network failure silently disables the pusher
for the process lifetime — no retry, no fail-fast, no backstop; verified to be the *only* such
spawn site). Two observations left unrecorded pending reviewer call: the `run` missing-shutdown
branch, and `capture_committees_through`'s silent-`Err` observability gap (failure point 5).

## Topic list

### A. OCS verified-reads subsystem
1. Trust chain overview — the 3-link proof (committee BLS → artifacts-digest binding → Merkle inclusion) + "reader owns the target"
2. Verifier chokepoint code — `verify_response` / `verify_proof_inner` / `verify_summary` / `verify_ocs_inclusion`
3. Committee ratchet — `ratchet_to_current_epoch`, +1 stepping, next-committee-from-verified-summary, pruning fallback
4. Bootstrap & trust anchor — `sui_trusted_anchor`, `has_anchor` 4-way OR, perpetual-state-wins, re-anchoring
5. Node roles & transport selection — `NodeMode::detect_from_config`, the config-shape gate, `SuiDataSource` variants, `rename_all_fields`
6. Freshness & rollback — monotone `observed_upstream_head`, version high-water, dormant `freshness_bound`, eclipse residual
7. Bag walks & event pump — `BagEventPump`, bag-page parent binding (`ObjectOwner == bag_id`), dynamic-field id derivation
8. Relay protocol — `SuiStateMirror` server, `try_peers`, 30s per-peer timeout, peer demotion/failover
9. Cache fast path & DB persistence — `verified_state_cache`, perpetual tables, the persisted-format-fragility HIGH finding
10. Currency / changeset stream — `check_currency`, `changeset_index`, `CurrencyVerdict`
11. Transport layer — `ika-sui-client` gRPC backend, `SuiTransport`
12. `ika-network` relay — `sui_state_mirror`, `proof_provider`

### B. Epoch-close fix (#1736)
13. `decide_v4_epoch_close` coupled to `handoff_signatures_meet_quorum` + liveness backstop + tests

### C. Upgrade-test harness + CI memory
14. Harness — runner matrix, `v118_churn` scenario, `[flow N/total]` logging, genesis-committee anchor
15. CI memory — jemalloc `background_threads`, `max_mpc_computation_cores`, rayon bound (#1770), `cross_binary` 96 GiB OOM

### D. Cross-cutting
16. Sui version bump (1.73.2) + version-bump convention
17. Contracts (`ika_common`) + spec/skills/docs

---

## Coverage log
- Topics 5 + 8 — how non-uplink validators read: verified p2p relay; mirrored vs peer-only; peer untrusted, 3-link proof.
- Direct vs old path: old = legacy JSON-RPC (`sui-rpc-url`, kept as-is); direct = new gRPC+OCS-with-uplink + serves mirror.
- Topic 9/1 — direct cache fold + self-verification: direct does NOT BLS-verify its own fold (Finding 1).
- Far-behind fast-forward + committee install logic (Finding 2; downgraded — threshold is checkpoints, sub-epoch).
- Cache mechanics (Topic 9): object-memo `ObjectID→VerifiedSnapshot`; fold_head vs processed_head; absorb_entries
  (pusher, persisted) vs absorb_shadow_entries (reader, in-mem); cache-first (direct) vs cache_first=false (mirrored,
  write-only shadow today); staleness tripwire; anchor-through-tripwire exception; DB persistence/restore.
- What's cached: only Ika-relevant objects via `object_touches_ika` (type-tag test); not whole checkpoints.
- Relevance filter mechanics: type address ∈ ika_packages OR recursive generic type-arg ∈ ika_packages; type tag is
  self-contained (no RPC for generics); single read gives type+owner+contents+version, NOT history/children.
- Currency model (Finding 3) — verified read = existence-at-checkpoint, not latest; best-effort defenses.
- Pusher full call-tree walkthrough: `new` (cursor resume / tip-start), `run`, `advance`, `capture_committees_through`,
  `capture_committee`→`install_next_from_checkpoint`→`install_next_from_verified_summary` (BLS+contents verify,
  `epoch==head+1` assert, `install_next` monotonic `fetch_max`), `persist_end_of_epoch`, `build_entries`
  (`object_touches_ika`, `ModifiedObjectTree::new` once, per-object `get_inclusion_proof`), `absorb_entries`→
  `insert_inner` (monotonic-by-version under lock) / `advance_head` (CAS) / `persist` (in-order `source_seq`, not
  `head_seq`) / `maybe_prune` (Concern C5 = `ocs-cache-committee-1` floor clamp). (Concerns C6, C7 raised — see below.)
- Function-by-function deep dive started. `new`: relevance-set capture (stale if a new Ika package appears at runtime),
  cursor resume vs first-boot tip-start (C6), tripwire seeding; first-boot network-failure handling (C7).

## Remarks

### Finding 3 — Currency model is best-effort, not absolute (reviewer: "very worried about all of it")
A verified OCS read authenticates **existence of `X@V` at checkpoint N** (its last-modifying
checkpoint) under committee BLS — it does NOT prove `V` is the latest version, and even a true-latest
read is only current as-of-read (a modification the next instant makes it stale; TOCTOU). OCS gives
*unforgeable*, not *fresh*.

Currency defenses and why each is non-absolute:
- **version high-water** — anti-rollback only (rejects a *lower* version); a stale-but-not-lower read passes.
- **monotone `observed_upstream_head`** — relative freshness only; starts empty (eclipse residual on cold boot).
- **`freshness_bound`** — the only absolute checkpoint-distance bound — is **dormant** (`None`) in production.
- **`check_currency` / changeset index** — optional; returns `Unknown` (never rejects) outside the folded range.
- **mirrored "latest"** is the relay's unproven *claim* (proof attests existence, not latest).

Sub-findings folded in:
- **(3a) skip-staleness (direct cache).** Fast-forward (`FAR_BEHIND_THRESHOLD`) and per-checkpoint
  fetch-failures drop modified sets; the fold is **incremental** (modified-set per checkpoint, never a
  full re-scan), so a dropped set's version updates are **permanently missed** until the object is
  modified again. Uncaught by high-water/tripwire; changeset returns `Unknown` for the skipped range.
  Hot objects (anchors) self-heal; cold objects can stay stale.
- **(3b) relevance filter non-exhaustive** (`object_touches_ika`) — heuristic on the unstated invariant
  "all Ika state is Ika-typed (own type or generic arg)". Blind spots: object-table index entries
  (`Field<Wrapper<K>, ID>`), concrete Ika field in a foreign struct, opaque-byte (`vector<u8>`) storage.
  Safe today because relevance is deterministic-per-immutable-type → a missed object is never cached →
  always read live. NOT a staleness source on its own; noted for completeness.

**(3c) OPEN — the crux, needs consumer-side (MPC) review.** Cross-validator read consistency: if two
validators read Sui at different moments / different versions, do their MPC inputs diverge? The
verified-read layer provides NO cross-validator consistency. Resolution hinges on whether a higher Ika
layer anchors all validators to an *agreed* Sui checkpoint/state (→ best-effort currency is fine) or the
MPC consumer relies on currency OCS doesn't provide (→ unsafe). This determines whether the whole
best-effort currency model is acceptable. **Not yet traced** — review the MPC consumer's use of these reads.

The spec acknowledges much of this (eclipse residual, dormant `freshness_bound`, "monotone defenses are
relative, not absolute"). Known, not hidden — but (3c) is the unresolved safety question.

**Status:** OPEN — (3c) is the gating question; (3a) real (direct cache); (3b) benign-but-noted.

---


### Finding 1 — direct-node folds are NOT committee-BLS-verified (potential gap)
**Reviewer:** potential gap; wants it verified if feasible. Asked: any reason not to verify? is it easy?

**Observation.** `IkaCheckpointPusher` (`push_worker.rs:168-191`, `build_entries`) folds every
checkpoint from the node's **own** `get_full_checkpoint` uplink into the verified-state cache,
building inclusion proofs from the checkpoint `ModifiedObjectTree`, but **never calls
`verify_summary`** (no committee BLS check anywhere in `push_worker.rs`). Direct cache-first reads
then return those entries and may skip re-running the proof. So a direct node trusts its own
fullnode; OCS verification only protects the relay (mirrored/peer-only) path. The proofs it builds
exist so the peers it serves can verify.

**Contradicts spec invariant #8** ("Cached state is committee-verified before it enters the cache;
the cache never holds unverified state") — the summary is committee-*signed* but never
committee-*checked* locally before `absorb_entries`.

**Feasibility.** The check is ~2 lines (`committees.verify_summary(summary)` already exists). Reasons
not to / complications: (a) per-checkpoint BLS cost on a lag-sensitive hot loop; (b) committee
availability on the fast-forward/catchup span (`FAR_BEHIND_THRESHOLD`, `capture_committees_through`
best-effort) → `MissingCommittee`, needs a skip-vs-block policy; (c) "own fullnode" trust rationale
is weak vs OCS premise. **Lean:** verify on the contiguous fold, log-and-skip on fast-forward spans,
fix invariant-#8 wording regardless.

**Reviewer follow-up:** wary of BOTH the "far-behind → skip verify" escape hatch AND the
per-epoch committee-storing logic the verify would depend on.

**Reframed conclusion.** Direct folds from the node's OWN fullnode; OCS's threat model is
untrusted *relays*, not own infra. So fold-verify is defense-in-depth against a compromised
*local* fullnode — outside the stated threat model — and only buys it by introducing the two things
the reviewer fears. Therefore: **downgrade to a spec-wording bug.** Fix invariant #8 to state the
real trust boundary (direct-fold = trusted-from-own-uplink, proofs built for serving, not
re-verified; committee BLS verify is the consumer/relay-side guarantee). Fold-verify stays an
OPTIONAL future hardening, not a now-fix.

**Action:** (1) fix invariant #8 wording; (2) optional residual: defense-in-depth fold-verify if the
threat model ever expands to untrusted local fullnode.
**Status:** OPEN — agreed direction: spec-wording fix, no code change. Verify with author.

> Note: the security-critical committee population is the **ratchet** (mirrored/peer-only build their
> store via BLS-verified +1 stepping), NOT the pusher's `capture_committee` (direct-node self-trust).
> Scrutinize the ratchet + gap handling next (Topic 3).

**Reviewer decision (supersedes the downgrade above): VERIFY the direct fold anyway** — defense-in-depth
against a compromised/buggy local fullnode is wanted, and it makes invariant #8 true. So fold-verify is
a real action item, not optional. Status of Finding 1 → **OPEN, will add fold-verify** (and the
far-behind path must support it — see Finding 2).

### Finding 2 — far-behind fast-forward decouples the object cursor from the verified committee head
**Reviewer:** the far-behind path "feels broke."

**Correction first:** the committee *install* logic is sound — `install_next_from_verified_summary`
(committee_store.rs) BLS-verifies (`verify_with_contents`), enforces strictly +1, and guards
`next.epoch == head+1`. Both capture paths use it. So committees in the store are verified; this is
NOT about wrong installs.

**The problem.** Fast-forward block (`push_worker.rs:153-167`):
1. `capture_committees_through(new_cursor)` walks the committee chain forward (BLS-verified each step)
   but is **best-effort — breaks at the first pruned/unavailable end-of-epoch** (the accepted gap).
2. The object cursor then jumps to `latest-100` **unconditionally**, regardless of whether (1) caught up.

Far-behind ⇒ the skipped span is exactly where Sui has pruned end-of-epoch checkpoints ⇒ (1) often
can't complete ⇒ committee store stuck epochs behind while the object fold jumps to the current epoch.
The node folds (and a direct node serves) current-epoch objects its committee store can't verify;
the ratchet hits the same prune → `ProofChainBroken` → re-anchor. Masked today only because the
object fold doesn't verify (Finding 1) — so adding fold-verify breaks here with `MissingCommittee`
precisely in the far-behind-pruned case. Object head and verified-committee head are decoupled.

**Fix direction.** Gate the object cursor on the **verified committee head**: never fold past the
highest BLS-verified committee. On a pruned chain the node stops at the gap and surfaces a loud
"stuck → re-anchor" instead of jumping ahead and folding unverifiable state. Makes fold-verify
(Finding 1) always have its committee, and far-behind degrades cleanly.

**Reviewer correction (DOWNGRADES this finding).** `FAR_BEHIND_THRESHOLD` is **1000 checkpoints**, and a
Sui epoch is tens of thousands of checkpoints — so far-behind is minutes (sub-epoch), at most one
recent/unpruned boundary. A functioning node (on the latest Ika epoch) is current on Sui to within
~an epoch by definition; it cannot be many Sui epochs behind. The multi-epoch / pruned-chain case
only arises during **long-downtime boot recovery** (node not participating), where
`ProofChainBroken → re-anchor` is the documented operational limitation, not a bug.

**Status:** DOWNGRADED → minor recovery-path robustness nit (optionally: fail-loud / gate cursor on
verified committee head during recovery, so a recovering node never folds unverifiable state). NOT a
functioning-node concern. Implication: **fold-verify (Finding 1) is simple** — committee is always
present in steady state; `MissingCommittee` only during far-behind recovery, where not-folding is
the desired behavior.

---

## Decisions (reviewer)
- **D1 — never skip verify, in any case.** Always BLS-verify before folding *or* serving. If verification
  is impossible (committee missing in far-behind recovery / pruned chain), **refuse** (halt → surface
  re-anchor); never fold/serve unverified. Scope to confirm with author: applies to the direct **fold**
  AND the direct **cache-miss read fallthrough** (a direct node should not blindly trust its own fullnode
  anywhere). Note: not-folding a span (cache gap → later live read) is allowed; folding-unverified is not.

## Open concerns (reviewer-raised, to weigh)
- **C1 — write-only cache on mirrored/peer-only.** `verify_response` does a per-read bcs clone +
  `absorb_shadow_entries` into a cache the read path never serves from ("Step 2 only writes"). Pure
  per-read overhead + memory (bounded by `retain_window`) for zero current benefit, notable given this
  PR's memory pressure. Question: carry it now (staging/readiness) vs add population when the read path
  actually lands. Reviewer skeptical it's worth it now.
- **C2 — mirrored can/should cache like the pusher.** Reviewer's point: the difference is *currency*, not
  caching — the pusher gets currency from contiguous in-order folding; a mirrored node would get the same
  by folding the **changeset stream** in order instead of pulling on demand. So the write-only shadow is a
  half-measure; the real path is the in-order changeset fold (the `changeset-stream-mirror-currency` plan).
  Caveat: even that inherits the skip/incremental limits (Finding 3a).
- **C3 — throughput/scaling.** Reviewer worried the relevance scan is too expensive at Sui prod scale
  (thousands tx/s). Locating it: the **type-walk is cheap** (in-memory tag, no RPC, O(1) lookups). The real
  cost is **fetching + bcs-decoding every full checkpoint** (`get_full_checkpoint` per seq) — that's why the
  pusher lags under load. Open: does this keep up at mainnet scale once Sui ≥ v122 (mainnet is on v121 today,
  so OCS isn't running there yet)? A checkpoint subscription / changeset stream would cut the per-checkpoint
  full fetch. Watch the fetch/decode throughput, not the relevance check.
- **C4 — full-checkpoint object-body fetch scales with TOTAL Sui activity, not Ika.** `SuiTransport` exposes
  only `get_full_checkpoint → CheckpointData` (full bodies of every modified object) — no refs/effects-only
  option. The pusher calls it for **every checkpoint, unconditionally**, *before* knowing relevance (it must
  scan `output_objects`). So full bodies of ALL modified objects (tens of thousands → tens of MBs/checkpoint
  at mainnet scale) are fetched + bcs-decoded + held transiently **per checkpoint, even when no Ika object is
  touched**. Only the Ika subset is kept; the rest exists solely to build the tree — which conceptually needs
  only refs (`id/version/digest`), not bodies. Cost ∝ total Sui throughput, on a memory-pressured node.
  Mitigation (none wired today): a lighter Sui checkpoint representation (refs/effects-only + batch-fetch Ika
  bodies) if gRPC offers it, or the changeset stream. **Action:** confirm Sui gRPC capabilities; measure
  checkpoint payload sizes at target scale. Reviewer: "might be too much."
- **C5 — retain-window prune defeated by the bootstrap-floor clamp** (= the multi-agent review's
  `ocs-cache-committee-1`, open). `prune_floor` = `head - window` then `.min(oldest_sui_committee_summary().seq)`.
  That oldest summary is the never-pruned bootstrap anchor, so once the chain passes `anchor + window` the `.min`
  pins the floor at the anchor forever → `prune` never drops anything → the retain window is a no-op. Slow-onset
  growth (keyed by distinct Ika object-id, not checkpoint count) on long-running direct validators. Fix: use a
  moving floor for general pruning, keep the anchor floor only for the mirrored-bootstrap retention path.
- **C6 — pusher first-boot starts at the tip, mis-aligned with the mirror-bootstrap floor it advertises.**
  `IkaCheckpointPusher::new` initializes a fresh cursor at `get_latest_checkpoint()` (the tip), so a fresh direct
  node folds object state + retains end-of-epoch checkpoints only from tip-forward. But the committee chain is
  anchored at a configured (possibly much older) anchor, and `prune_floor` clamps the object cache down to that
  anchor "because a mirrored peer bootstrapping from there still needs those objects" — history the tip-starting
  pusher never folded. So the node advertises a bootstrap floor (back to the anchor) it cannot actually serve from
  its own DB. Reviewer's point: the pusher start point should track the **configured** bootstrap/retention floor,
  not default to tip — same as we configure for mirrors. Honest counterweights: (1) not a hard break today — the
  committee ratchet (`RetainedFullnodeTransport`) and the changeset-stream server both fall back to the *fullnode*,
  so pre-tip history is serveable while the fullnode still retains it; the gap is exactly the
  self-sufficiency plan's "accepted residual" (degrade to `Unknown`, never stall) once the fullnode prunes below it.
  (2) Backfilling from the anchor on first boot pays the C4 full-checkpoint-fetch cost over the entire anchor→tip
  span — a real first-boot cost, not a free win. Net: align pusher start with the configured floor, bounded by
  fullnode retention either way. **Action:** decide the first-boot start policy (tip vs configured floor vs a
  bounded backfill depth) and make it the same knob that sets the mirror-bootstrap depth.

- **C7 — pusher first-boot network failure silently disables the pusher for the process lifetime; no retry, no
  fail-fast.** The only network call in `IkaCheckpointPusher::new` is the first-boot `get_latest_checkpoint().await?`
  (resume path has no network call — it reads the persisted cursor). On `Err` the spawn site
  (`ika-node/src/lib.rs:972`) does `Err(e) => warn!("checkpoint folder failed to start")` and the task **exits** —
  fire-and-forget `tokio::spawn`, never awaited, so node boot continues and reports healthy. Consequence: the pusher
  never runs until a manual restart → cache never populates (every direct read is a permanent miss → network-verified
  fallback), no eager committee capture (chain leans on ratchet+follower only), no end-of-epoch retention for mirrored
  peers. Observable only as one `warn!` — no metric, no readiness gate. Contrast: once `run()` is up, `advance` is
  resilient (latest-checkpoint failure → warn+retry next tick; full-checkpoint failure → skip seq + continue). The
  fragile spot is the single hard `?` on first boot. Reviewer's ask: **either retry `new` with backoff** (mirror
  `advance`'s own resilience) **or, more importantly, make critical-service start-failure fail the whole node** rather
  than letting one service die while the rest limps on degraded — i.e. audit that all spawned critical services
  propagate a start failure to process exit, not just this one.
  **Sweep done (the reviewer's "check all processes exit" ask):** the pusher is the *only* offender. Every other
  spawned OCS service is covered: `build_sui_connector_stack` (which constructs the changeset receiver, follower,
  ratchet, reader, cache) is built under a fail-fast `?` at `lib.rs:556/882` — if it can't construct, node boot
  aborts; the mirrored initial-ratchet `Err→warn` (`lib.rs:889`) is deliberately backstopped by the periodic ratchet
  retry (`lib.rs:913`, warn+retry/30s); the changeset receiver (569/886) and `CommitteeFollower` (943) only spawn
  `.run()` (construction already gated by the stack-build `?`), so they can't fail-to-construct in the spawn. The
  pusher alone (`lib.rs:971`) has a *fallible* `new()` (the first-boot network call) inside a fire-and-forget spawn
  with a swallowed `Err` and no retry and no backstop. And its committee-capture half *is* backstopped (follower +
  ratchet also capture), but the **cache-folding + EoE-retention halves have no other task on a direct node** — so a
  dead pusher means no cache folding until restart. **Action:** retry the pusher `new` with backoff, or hoist its
  construction into the fail-fast stack build so a start failure aborts boot like every sibling service.

## Verification result V1 — Sui-API usage is correct (calls, params, values)
Checked the trust-critical call sites against the Sui APIs. **Sound.** All read paths
(`verify_proof_inner` single, `verified_objects` batch, `verified_bag_page`) and the ratchet
(`install_next_from_verified_summary`) satisfy:
1. **Right committee** — `verify_summary` looks up by `summary.epoch()`, BLS via `try_into_verified(&committee)`;
   relay can't claim a different epoch without that epoch's signature.
2. **Inclusion only against a BLS-verified summary** — single: `Proof::verify(&committee)` does BLS+inclusion
   against `committee(summary.epoch())`; batch/bag: `verify_summary` → `verify_ocs_inclusion` against the
   resulting `VerifiedCheckpoint`. Never an unverified summary.
3. **Reader owns the target** — `ProofTarget::new_ocs_inclusion(object.compute_object_reference())` built from
   the HELD object everywhere; + request↔response id binding.
4. **Committee extraction guarded** — verify against `committee[head]`, require `end_of_epoch_data`, assert
   `next.epoch == head+1`.
5. **Bag membership** — proof-attested owner == `bag_id` (inline) or locally-derived
   `derive_object_field_wrapper_id(...)` (object-table); relay key can't derive a foreign owner.

Artifacts-digest binding is internal to Sui's `verify`; Ika correctly passes the BLS-verified summary.
**Only verification bypass:** the direct-node cache fold (Finding 1). Every network read path verifies.

## Architecture (verified model — what's Sui vs Ika)
**Sui (upstream `sui-light-client` @ mainnet-v1.73.2 + the v122+ chain feature) provides:**
- end-of-epoch checkpoints carrying `committee[E+1]`, signed by `committee[E]`;
- the code to verify a checkpoint summary against a committee (BLS);
- the committee-signed `checkpoint_artifacts_digest`;
- the code to construct + verify object-inclusion proofs against the modified-objects Merkle tree.

**Ika writes only the state machine / wiring (no Merkle/BLS/digest crypto, no proof parsing):**
- anchor bootstrap (pinned end-of-epoch *digest* → install `committee[A+1]`);
- the committee ratchet (+1, install-from-verified-summary, gap → re-anchor);
- per-read: pick the right epoch committee, build `ProofTarget` from the *held* object, run Sui's verify;
- relevance filter (`object_touches_ika`), relay/transport, cache/fold, freshness/currency.

**Digest-vs-root (point 1):** the committee signs `checkpoint_artifacts_digest`. Since
`from_artifact_digests(vec![tree_root])` — a SINGLE element — reproduces it, the artifacts list
**currently contains exactly one element: the modified-objects Merkle root.** So today the digest is just
the root wrapped in a domain-separated "digest-of-list" envelope — functionally ~= signing the root, in
an extensible shape (Sui could add artifacts later; callers would then pass them too). NOT currently a
hash over multiple artifacts (an earlier note of mine overstated that). Unverified: whether
`from_artifact_digests` internally folds in any fixed artifacts — would need Sui's source.

**Caveat:** "just the state machine" understates the risk — Sui's crypto removes one bug class, but trust
can still break entirely in Ika's state machine (wrong committee, unbound proof target, the freshness/
currency holes in Findings 3/3a/3c, the relevance filter). The review surface is exactly that state machine.

## Clarifications (model facts established; some correcting earlier reviewer-flagged inaccuracies of mine)
- Committee changes **once per epoch** (at the end-of-epoch checkpoint), NOT per checkpoint. `capture_committee`
  runs every checkpoint but `install_next_from_verified_summary` no-ops unless `end_of_epoch_data.is_some()`
  and `epoch == head`. Per-checkpoint work is only the *summary signature* (each checkpoint independently signed).
- "Far behind" = `FAR_BEHIND_THRESHOLD` of **1000 checkpoints** (sub-epoch), not epochs.
- Relevance is type-only (no owner-chain walk, no RPC for generics); single read gives type+owner+state, not
  history/children. Filter is non-exhaustive but deterministic-per-type → misses are always-live reads, not
  stale (Finding 3b).
