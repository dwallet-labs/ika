# OCS verified-Sui-reads — branch audit review

**Reviewed:** the `feat/ocs-grpc-migration` branch (OCS verified-Sui-reads
subsystem: gRPC transport, `SuiStateMirror` relay, peer-only validators,
the push/cache fast path, the committee ratchet).
**At commit:** reconciled against `59f6a61d13` (branch `origin/dev..HEAD`,
31 commits).
**Dates:** multi-agent review 2026-06-13; reconciled against HEAD
2026-06-14.
**Verdict:** sound-with-concerns. At the 2026-06-14 reconcile, of 16
enumerated findings: 9 fixed, 3 partial, 3 open, 1 obsolete. All three
independent design judges rated the branch sound-with-concerns.
**Status (updated):** **15 resolved** (the 9 fixed + 10/11/12/13/14/15), **1 obsolete**
(16) — see each finding's RESOLUTION and the remaining-work list. The
directly-exploitable proof-binding and boot-liveness concerns are resolved.
The separate earlier-confirmed **K1–K9** set (recovered below) is now also
fully closed: K1–K5 fixed, K6/K7 documented, K8/K9 accept-and-documented (the
eclipse/currency residuals whose real fix is the future changeset-stream
design). Nothing from the audit remains open.

> Point-in-time record (per `reviews/` convention) — not maintained as a
> source of current truth. Current behavior lives in
> [`../specs/ocs-verified-sui-reads.md`](../specs/ocs-verified-sui-reads.md).

## Method

Multi-agent review (large fan-out, each finding adversarially verified by
independent agents), followed by a reconciliation pass that re-checked every
finding against the actual code at HEAD rather than trusting commit messages
(several "fixed by" claims were confirmed false or incomplete and corrected
below). Severities: **high** = security/liveness reachable in a supported
config; **medium** = DoS / silent-misconfig / test-integrity; **low** =
hygiene / observability / docs.

## Findings

Each finding: severity, anchor, and a RESOLUTION filled as addressed.

### Fixed

1. **[high] Bag-page entries not bound to the requested collection.**
   `verified_reader.rs::verified_dynamic_fields_page` proved each entry on-chain but did
   not bind it to `bag_id`, so a malicious relay could inject validly-proven
   dynamic fields of a *different* collection (e.g. replayed session events,
   or a foreign network-encryption-key). Anchor:
   `crates/ika-core/src/sui_connector/verified_reader.rs` (bag-membership
   check). RESOLUTION: bound each entry by its committee-proven owner —
   `ObjectOwner(bag_id)` for a plain Bag/Table, or the derived
   `Field<Wrapper<K>, ID>` id for an ObjectTable/ObjectBag. Fixed in
   `c5ec7211fe`; corrected for the dynamic-object-field `Wrapper` in
   `0721efa9df`. CI-verified (peer-only cluster test).

2. **[high] Relay reads had no per-request timeout.** The anemo outbound
   default is no timeout and QUIC keep-alives keep an idle-but-hung peer
   "connected", so one peer that accepted a stream and never replied would
   wedge every verified read (incl. peer-only boot) with no failover.
   Anchor: `crates/ika-network/src/sui_state_mirror/client.rs` (`try_peers`).
   RESOLUTION: 30s `tokio::time::timeout` per peer dispatch → demote +
   failover. Fixed in `1249e3c820`.

3. **[high] `SuiDataSource` struct-variant fields silently snake_case.**
   `rename_all = "kebab-case"` on the enum does not cascade to struct-variant
   fields in serde 1.0.228 (verified empirically), so `fallback-grpc-url` was
   silently dropped → a mirrored validator silently degraded to peer-only.
   Anchor: `crates/ika-config/src/node.rs` (`SuiDataSource`). RESOLUTION:
   `rename_all_fields = "kebab-case"`. Fixed in `ecda23667b`.

4. **[high] Default validator config had no trust anchor.** A new-style
   config with no anchor is boot-gate-rejected, breaking `ika start` /
   ts-integration; test-cluster passed only because it seeded the anchor.
   Anchor: `crates/ika-swarm-config/.../node_config_builder.rs`. RESOLUTION:
   seed the epoch-0 committee in `network_config_builder` (the production
   `ika start` → `Swarm::build()` path), not just test-cluster. Fixed in
   `59137c5591` (+ `51e85513e1`, `3a50b2084d`). Fullnodes correctly exempt.

5. **[medium] simtest tokio patch broken by the msim bump.** `tokio
   =1.52.1` + the msim bump left the cargo-simtest tokio/futures-timer patch
   mismatched → simtest determinism silently lost. RESOLUTION: bump the patch
   rev to match. Fixed in `497b8d11b3`.

6. **[high] Peer-only boot ratchet retried permanent errors forever.** On a
   determinate ratchet failure (pruned/broken proof chain, BLS-failed or
   not-end-of-epoch checkpoint, wrong-epoch fallback, missing committee) the
   boot loop retried every ≤10s forever, warn-only — a silent boot hang with
   no operator-actionable abort. Anchor:
   `crates/ika-node/src/lib.rs` (peer-only boot) +
   `crates/ika-core/src/sui_connector/ocs_verifier.rs` (`OcsError`).
   RESOLUTION: `OcsError::is_retryable()` (only `Transport` retryable); boot
   fails fast with an actionable error on a non-retryable result; transient
   errors still back off. Unit-tested. Fixed in `2ff9153c96`.

7. **[high→verified] consensus_manager 1.72.3 rewiring unreviewed.** The
   `own_index` drop / `protocol_keypair→Some` / `enable_v3=false` adaptation
   was a hot-path change that hadn't been reviewed. RESOLUTION: verified
   correct against the pinned Sui source — all three match Sui's own
   production `consensus_manager` defaults at this tag; safe because ika
   consensus nodes are always committee validators. In `e153f096b1`. No
   change required.

8. **[low→done] No spec for the OCS subsystem (CLAUDE.md violation).**
   RESOLUTION: added
   [`../specs/ocs-verified-sui-reads.md`](../specs/ocs-verified-sui-reads.md)
   (`3aa742be23`, extended `df066184c8`).

9. **[low] Operator/maintainer-facing doc lies.** A nonexistent `PeerMirror`
   config mode and a nonexistent `ika validator anchor-last-eoe-checkpoint`
   command (`node.rs`), plus a false "`execute_transaction` cannot be
   relayed" claim repeated across the mirror client module doc,
   `fallback_transport.rs`, the `setup.rs` diagram, and the spec (which
   contradicted itself). RESOLUTION: corrected every instance to match the
   code (`execute_transaction` *does* relay — `SubmittedTransaction` is
   `Deserialize`; only `get_transaction`'s `ExecutedTransaction` return is
   genuinely un-relayable). Fixed in `59f6a61d13`.

### Partial

10. **[medium→low] Push handler absorbs first-sight stale peer state.** On a
    direct node that also serves a mirror, an untrusted peer push of a
    proof-valid-but-rolled-back object the cache hasn't yet folded is
    absorbed (version-monotonicity is vacuous on first sight) and served
    cache-first with no recency check. Bounded only by the trusted local
    pusher winning the race. Anchors:
    `crates/ika-core/src/sui_connector/push_handler.rs`,
    `verified_state_cache.rs` (`insert_inner`), `verified_reader.rs`
    (`try_cache_hit`). Re-severity: the local pusher already holds
    authoritative state, so the peer-push ingest is *redundant* and the
    attack vector — this is a "remove a needless untrusted write path", not a
    critical hole. RESOLUTION: removed the push-objects gossip entirely
    (`b9be273a74`) — the direct pusher keeps its authoritative local fold, so
    no untrusted peer state ever enters the served cache. Committee-attested
    cache-first currency for mirrored nodes is specced separately in
    [`../plans/ocs-changeset-stream-mirror-currency.md`](../plans/ocs-changeset-stream-mirror-currency.md)
    (a future feature, gated on a non-inclusion id-binding fix).

11. **[low] Checkpoint pusher fanout is sequential.** One slow/hung peer
    serially delays the cursor advance up to P×30s, widening replication lag
    (the cache itself is written before fanout, so it's safe). Anchor:
    `crates/ika-core/src/sui_connector/push_worker.rs::fanout`. RESOLUTION:
    moot — the fanout was removed with the rest of the push-objects gossip
    (`b9be273a74`).

12. **[low] Failure-observability gaps on batch/bag verify paths.** Only
    inclusion-proof and batch id-mismatch failures increment
    `proof_verify_failures_total`; DynamicFieldMembership, BLS-summary, freshness, and
    decode failures on the batch/bag paths leave no metric trail. Anchor:
    `crates/ika-core/src/sui_connector/verified_reader.rs`,
    `ocs_metrics.rs`. RESOLUTION (`384dce3f18`): added a `record_fail` helper
    and routed every bypassing failure point (summary BLS verify,
    missing-summary decode, freshness, high-water, bag-membership) through it,
    so all batch/bag verify failures now increment
    `proof_verify_failures_total` (and the high-water gauge). A metric-assert
    test is deferred to the H2 negative-tests work.

### Open

13. **[medium] Security-critical paths have zero negative/adversarial tests.**
    Proof rejection, high-water rollback, the DynamicFieldMembership binding, and the
    legacy-JSON-RPC vs new-style gate truth-table are exercised only by
    happy-path cluster tests — nothing asserts they *reject* forged, stale, or
    foreign-owned input, so a future weakening of any proof or gate check
    would still pass CI. Anchor: the OCS read + transport-gate paths in
    `crates/ika-core/src/sui_connector/`. RESOLUTION: resolved. The negative
    tests now cover every proof/binding gate. Fixture-free local gates:
    - **high-water rollback** — `verified_reader::tests::high_water_rejects_a_version_rollback`:
      a lower version after a higher one yields `StaleVersion`, the rejected
      rollback does *not* lower the mark, and ids are independent.
    - **freshness bound** — `freshness_rejects_a_checkpoint_too_far_behind_the_head`
      (exact `gap`/`bound` on `StaleCheckpoint`) and
      `freshness_is_disabled_when_no_bound_is_set`.
    - **DynamicFieldMembership binding derivation** — `transport::tests` assert
      `derive_object_field_wrapper_id` re-wraps `K` into `Wrapper<K>` (≠ bare
      `K`) and matches the canonical on-chain `dynamic_object_field` id.

    End-to-end crypto-fixture tests (`verified_reader::tests`) build a
    self-consistent fixture — a `new_simple_test_committee` signs a
    `CheckpointSummary` whose `CheckpointArtifactsDigest` commits to a
    synthesized `ModifiedObjectTree`, plus the matching `OCSInclusionProof` —
    driven through the reader's real BLS + Merkle path via a staged
    `ProofProvider`:
    - **valid proof accepted** (`a_valid_inclusion_proof_is_accepted`) — proves
      the fixture is sound, so the rejections aren't vacuous.
    - **id substitution** (`an_object_id_substitution_is_rejected`, finding K1):
      a valid proof for X answering `get(Y)` → `InvalidProof`.
    - **foreign-committee signature** (`a_summary_signed_by_a_foreign_committee_is_rejected`):
      BLS gate rejects an untrusted signer → `InvalidProof`.
    - **substituted object state** (`a_substituted_object_state_is_rejected`):
      same id at a different version than the proven ref → Merkle gate rejects.
    - **bag membership** — accepts an entry owned by the bag UID
      (`…owned_by_the_bag…`) and one owned via the derived
      `Field<Wrapper<K>,ID>` (`…owned_via_the_object_field_wrapper…`); rejects a
      foreign `ObjectOwner` (`…owned_by_a_foreign_object…`) and an `AddressOwner`
      (`…owned_by_an_address…`) → `DynamicFieldMembership`.
    Each rejection also asserts the `proof_verify_failures_total{kind,reason}`
    counter increments (finding 12's deferred metric-assert). Finding 6's fix
    added the ratchet error-classification negative test.

    The legacy-JSON-RPC vs new-style transport gate (the last sliver) was
    extracted from `ika-node`'s boot path into a pure
    `ika_config::node::select_sui_transport(data_source, sui_rpc_url_present,
    has_anchor, is_validator) -> Result<SuiTransportPlan, String>` and given an
    exhaustive truth-table test (`node::tests`) over all 4 data-source shapes ×
    rpc × anchor × role — the three reject combinations (no endpoint;
    anchor-without-data-source; new-style-validator-without-anchor) and the
    three plans (LegacyJsonRpc / PeerOnlyRelay / Grpc). The extraction was
    independently verified behavior-preserving across all 32 input rows.

14. **[medium] Serving side has no caps.** No limits on batch ids / bag
    page_size / `GetVerifiedSnapshot` (which deep-clones the whole cache
    under the objects read lock); no inflight/rate-limit on the mirror anemo
    service. A peer can request unbounded server work. Anchors:
    `crates/ika-network/src/sui_state_mirror/`, `proof_provider.rs`.
    RESOLUTION (`efeba7726b`): cap `BatchVerifiedObjects` ids (4096, > the
    validator set), clamp `VerifiedBagPage` page_size (1000), and add
    per-method anemo inflight limits on the heavy RPCs (verified_object 256,
    batch 64, bag_page 64, full_checkpoint 32, `WaitMode::ReturnError`). The
    `GetVerifiedSnapshot` deep-clone was already removed with the push gossip
    (`b9be273a74`).

15. **[low] OCS committee trust tables grow unbounded.** `sui_committees` /
    `sui_committee_summaries` DBMaps + the in-memory `BTreeMap` mirror grow
    one entry per Sui epoch forever, with no pruner (the only pruner is on
    the checkpoint cache). Slow but perpetual RocksDB/RAM growth on
    long-lived nodes. Anchor:
    `crates/ika-core/src/sui_connector/committee_store.rs`. RESOLUTION
    (`cc62581c5e`): the per-epoch committee store was redundant — an
    end-of-epoch summary carries the next committee, so persist only the
    verified summaries and derive committees on demand (a DB read + decode).
    `sui_committees` is now sparse (no-summary cases only), and the in-memory
    map is a fixed-cap cache instead of an all-epochs mirror, bounding RAM.
    The summaries themselves are kept (needed to verify old-anchored proofs);
    serving them to peers ratcheting from an old anchor is a separate future
    feature.

17. **[high] OCS verified-read path depends on live Sui-fullnode history and
    hard-fails when it is pruned (surfaced as a TS-integration localnet hang).**
    The pruner here is the **separate Sui fullnode** the ika node talks to
    (`127.0.0.1:9000`, launched independently as `sui start --force-regenesis`),
    not ika — ika's own `DEFAULT_AUTHORITY_DB_RETENTION_EPOCHS=2` prunes ika's
    RocksDB, a red herring. "The direct validator caches everything" is true only
    for Ika object *state* (`IkaCheckpointPusher` folds Ika-modified objects into
    an in-memory `state_cache`, served cache-first), and that does **not** make
    the node self-sufficient against fullnode pruning, for three reasons — both
    observed errors fall through exactly these gaps:
    - **The committee ratchet is never cached.** To advance epoch E→E+1 it
      fetches the end-of-epoch checkpoint *live* from the fullnode
      (`ocs_verifier.rs:163-164`, routed to the primary transport, never the
      state cache — `fallback_transport.rs:71-88`). It tracks *new* epochs ahead
      of any cache, so the object cache is structurally irrelevant. With
      `allow_unverified_committee_fallback=false` (default), a pruned checkpoint
      is a hard `OcsError::ProofChainBroken` (`ocs_verifier.rs:166-176`).
    - **The cache is keyed by `ObjectID`, and the inner child's id changes at the
      epoch boundary.** The System/Coordinator inner is a versioned child,
      `derive_versioned_child_id(parent, version)` (`verified_reader.rs:592,622`).
      At the boundary a *new* child id appears, created in the same end-of-epoch
      checkpoint the fullnode just pruned — so the pusher can't fold it (building
      its proof needs that checkpoint) and the executor's cache-first read misses
      and falls through to `verified_object` → `tx_checkpoint(previous_transaction)`
      → `get_transaction` on a pruned tx → `Transport(NotFound("Transaction …"))`.
      The cache can only contain what the node could *build a proof for*, and
      proof-building has the same live fullnode dependency.
    - **No degrade path.** On a pruned anchor the executor retries forever
      (`push_worker.rs:106-114`, executor `must_get_*` loops) — no serve-stale /
      skip / return-`Unknown`. A transient or permanent gap becomes a hard stall.

    Evidence (run
    [`27552227493`](https://github.com/dwallet-labs/ika/actions/runs/27552227493),
    commit `6b5900ef90`, all validators `SuiStateDirect`): healthy through
    ~15:16 (8 test files pass, dwallet checkpoints climbing to seq 209), then at
    15:16:58 `ocs_verifier: ratchet … head=59 target=60 last_seq=17561
    reason="Checkpoint 17561 not found"`, at 15:17:09 `verified_system_inner
    failed … NotFound("Transaction 2mGWRd9… not found")` (12k+ retries, never
    recovers), no dwallet checkpoint after seq 209, and every subsequent
    `all-combinations-future-sign` test times out on its 1200s wait, hanging the
    run for ~1h until cancelled. The TS-integration localnet also runs ~60s
    epochs (epoch ~60 in ~58 min) vs production's 24h, so the boundary checkpoint
    is pruned within a minute while the 30s-poll ratchet is still reaching for
    it. This is **not** the changeset-stream / currency work: that runs only on
    `SuiStateMirrored`/peer-only nodes, and this localnet is all-`SuiStateDirect`
    (`changeset_index = None`, the `ChangesetReceiver` is never spawned,
    `check_currency` is an inert `Unknown`→fallback no-op — zero changeset-receiver
    activity in the logs); a Sui-side `NotFound` is not something the currency
    gate can produce. The cluster suite (`test-cluster.yaml`) passes 18/18 on
    sibling commits because its topology/retention doesn't hit the prune. Anchors:
    `crates/ika-core/src/sui_connector/ocs_verifier.rs` (ratchet,
    `allow_unverified_committee_fallback`), `…/sui_executor.rs`
    (`verified_system_inner`), `…/proof_provider.rs`, `…/verified_state_cache.rs`
    (in-memory only — `RwLock<HashMap>`, no DB), `…/push_worker.rs`.

    RESOLUTION: **resolved for direct nodes** (the all-`SuiStateDirect` topology
    where finding 17 was observed) via the direct-validator self-sufficiency plan
    [`../plans/ocs-direct-validator-self-sufficiency.md`](../plans/ocs-direct-validator-self-sufficiency.md),
    Slices 1/2/4/5 — cluster-validated green. (a) Eager end-of-epoch committee
    capture from the pusher stream, (b) the verified state cache persisted to DB
    with a config-driven retention pruner (restart resumes from DB, not a pruned
    fullnode), (c) graceful degrade — the per-read currency gate already returns
    `Unknown`/fallback, and the mandatory inner reads back off + escalate one clear
    retention-gap diagnostic (they can't degrade — the MPC pipeline needs them),
    and (d) a deterministic mock-transport regression guard (eager-capture + skip;
    the real-Sui-pruning cluster test was infeasible — the in-process harness
    doesn't expose Sui-fullnode retention). Slice 3 (serving a *mirrored* peer's
    committee ratchet from the direct node's retained store) is now also done via
    Option A — a `RetainedFullnodeTransport` decorator that serves the end-of-epoch
    `get_full_checkpoint` / `last_checkpoint_of_epoch` from persisted
    `sui_end_of_epoch_checkpoints` before the fullnode (no cross-crate trait /
    anemo RPC / ratchet change; Option B was abandoned because `ika-network` can't
    depend on `ika-core`). Below is the original plan summary.
    The end-of-epoch checkpoint
    *carries the next committee* (`EndOfEpochData::next_epoch_committee`,
    `messages_checkpoint.rs:304-314`) and ika already extracts and **DB-persists**
    the committee chain (`committee_store` → `sui_committee_summaries`), so the
    committee is durable *once captured* — the only failure is capturing it late.
    Plan: (a) **capture each end-of-epoch checkpoint eagerly from the pusher's
    checkpoint stream** (the pusher already fetches every full checkpoint as it
    passes) and install the next committee then, instead of a separate 30s
    reach-back loop that can race the prune; (b) **persist the verified state cache
    (objects + proofs) to DB**, not just memory, so a restart resumes from the DB
    instead of re-syncing from a possibly-pruned fullnode, and so mirrored peers
    get everything from the direct validator's retained store; (c) **graceful
    degrade safety net** for the unavoidable residual (a fresh node, or one that
    fell behind past the fullnode's retention, cannot capture already-pruned
    history): on a pruned/uncaptured anchor return per-read `Unknown`/fallback and
    re-anchor the ratchet to the servable floor rather than hard-stall — *you
    cannot cache what is already pruned*, so degrade keeps those reads non-fatal;
    (d) **regression-test it by shortening the localnet Sui-fullnode retention** so
    CI exercises the pruned-history path — asserting the validators keep advancing
    (committee from captured EoE, in-window reads/currency) and degrade gracefully
    (no hard-stall) out-of-window; size retention above ika's worst-case
    catch-up lag (or assert degrade, not always-success) to avoid runner-speed
    flake. Quick CI unblock while (a)–(d) land: set
    `allow_unverified_committee_fallback=true` on localnet, and/or lengthen
    localnet epochs / raise the fullnode retention.

### Obsolete

16. **[was: scoring inert] `reputation_score` returns `None`.** This made
    ika's submission-side low-scoring-authorities reordering inert. OBSOLETE:
    pinned Sui 1.72.3 removed `reputation_scores_desc` from `CommittedSubDag`
    and moved scoring into `consensus_core`'s leader schedule; ika's
    hardcoded `None` matches upstream's posture (Sui's own sui-core deleted
    the submission-reordering path at this tag). Only dead-code cleanup
    remains (ika still carries the removed `update_low_scoring_authorities`
    machinery, now always operating on an empty map) — a hygiene item, not a
    correctness defect.

### K-findings — earlier-confirmed set (recovered 2026-06-14)

A separate **"K1–K9"** set predates the ultrareview; the ultrareview
confirmed all nine still-present at HEAD. They are distinct from findings
1–16. Recovered from the original review run and re-checked against current
HEAD below — all still open unless noted. **K1 is the standout** (a real
single-object substitution gap, comparable in class to finding 1).

- **K1 [high — security] Single-object reads don't verify the returned
  object is the one requested.** `verified_reader.rs::verify_response` checked
  the inclusion proof, freshness, and high-water but never asserted
  `resp.object.id() == requested id` — it wasn't even *passed* the id. A
  malicious relay asked for object X could return any validly-proven object Y
  and the reader accepted it (substitution). The **batch** path guarded this;
  the single-object path did not. RESOLUTION (`e04b516490`): pass the
  requested id into `verify_response` and reject a mismatch with `InvalidProof`
  before absorbing anything; the cache-hit path was already safe (keyed by the
  object's own id).
- **K2 [low] `compiled_in_trusted_anchor` ORs into `has_anchor` regardless of
  `sui_data_source`.** When release tooling fills it, old-style configs on
  that chain gain an anchor and trip the anchor-without-data-source boot
  guard. Anchor: `ika-node/src/lib.rs`. RESOLUTION (`a6c3cda627`): gate the
  compiled-in term on `sui_data_source.is_some()` so the binary default only
  applies to migrated (gRPC) nodes; explicit anchors still force OCS.
- **K3 [low] No guard rejects a notifier/fullnode configured peer-only**
  (`SuiStateMirrored{fallback:None}`) — fails late with an unclear error.
  Anchor: `ika-node/src/lib.rs`. RESOLUTION (`c58d8df1e6`): `select_sui_transport`
  now rejects a *notifier* + peer-only (its relayed submission returns
  unverified effects — the design assumed notifiers never run peer-only).
  Narrowed from the finding: fullnodes/validators never submit, so their
  peer-only path stays valid. Gate now takes `NodeMode` (distinguishes
  Notifier from Fullnode); truth-table covers all three roles.
- **K4 [low — defense-in-depth] The BLS-verified ratchet path lacks the
  `next.epoch == head+1` assert** the unverified fallback has;
  `ocs_verifier.rs` installs `extract_new_committee_info` output without the
  explicit check. RESOLUTION (`932d5c3bbd`): added the assert (new
  `RatchetEpochMismatch`, distinct from the fallback's `FallbackEpochMismatch`),
  making the two ratchet paths symmetric.
- **K5 [low — dead code] The `sui_checkpoint_cache` table + pruner are dead.**
  `get_sui_checkpoint`/`put_sui_checkpoint` (+ inline pruning) had zero
  callers; `CheckpointCache` was never even a real type (referenced only in a
  `transport.rs` doc comment). RESOLUTION (`31d8c71120`): removed the column
  (auto-deregistered by the `DBMapUtils` derive; new/undeployed table, no
  migration), the accessors, and the doc-lie.
- **K6 [low] Stale old-style config templates** — `validator.template.yaml`,
  `fullnode.template.yaml`, `shared.sh`,
  `skills/ika-operator/references/configuration.md` still use the deprecated
  `sui-rpc-url`-only shape. RESOLUTION (`f103fcc4ea`): the operator skill docs
  (SKILL.md, configuration.md) now show new-style `sui-data-source` +
  `sui-trusted-anchor` (grounded in the real serde keys) with `sui-rpc-url`
  marked deprecated. The TS system-test fixtures stay on the legacy path on
  purpose (no localnet anchor is provisioned) but carry a note pointing at the
  new-style guidance.
- **K7 [low — docs] `SuiTransport::batch_get_objects` same-order contract is
  undocumented** while callers zip results positionally with inputs. Anchor:
  `ika-sui-client/src/transport.rs`. RESOLUTION (`acc6599758`): documented the
  contract on the trait method — same-order, same-length, **all-or-nothing**
  (the gRPC client collects into a `Result`, so any missing id fails the whole
  call rather than yielding a short/reordered vec; a success is always one
  object per id in input order). An initial diagnosis suspected a length bug,
  but the all-or-nothing collect upholds the contract, so this was docs-only.
- **K8 [residual] Eclipse** — a peer-only node talking to a single malicious
  relay can be served a self-consistent stale world (freshness head seeded by
  the relay). The currency limitation addressed by the changeset-stream
  design (`../plans/`); open by design. RESOLUTION (`c969b95dc5`):
  accept-and-document — an in-code comment at `check_freshness` now states the
  residual, points to the spec, and lists the mitigations (enabled
  `freshness_bound` and/or multiple independent relays). The real fix remains
  the future changeset-stream design.
- **K9 [residual] `get_current_epoch` is a relay-claimed/unverified
  passthrough** used as the ratchet target; with the fallback flag off it only
  stalls, with it on the head can be walked one real epoch per call. Accepted
  degradation; open by design. RESOLUTION (`c969b95dc5`): accept-and-document —
  a comment at the use site explains why it's safe: the relay-claimed epoch
  only sets the loop target; each step BLS-verifies the checkpoint and asserts
  `next.epoch == head+1`, so a lie causes at worst a stall, never a forged
  advance.

## Remaining work (risk-ordered)

DONE: all 16 enumerated audit findings are resolved or obsolete, and the
recovered **K1–K9** are all closed — K1–K5 fixed, K6/K7 documented, K8/K9
accept-and-documented (their real fix is the future redesign below). The one
post-audit runtime finding (**17**, discovered 2026-06-15) is **resolved for
direct nodes**.

1. **[resolved — direct nodes] Sui-retention hard-fail (finding 17)** — the
   verified-read path hard-failed (ratchet `ProofChainBroken` +
   `verified_system_inner` `NotFound`) once a long-running localnet pruned the
   history it needs. Fixed for the all-`SuiStateDirect` topology by Slices 1/2/4/5
   of [`../plans/ocs-direct-validator-self-sufficiency.md`](../plans/ocs-direct-validator-self-sufficiency.md)
   (eager EoE committee capture, DB-persisted cache + retention pruner, executor
   backoff/diagnose, mock-transport regression guard) — cluster-validated. Slice 3
   (serve a mirrored peer's ratchet from the retained store, via a
   `RetainedFullnodeTransport` decorator — Option A) is also done.
2. **Mirrored-node currency redesign** (future feature, not an audit finding) —
   [`../plans/ocs-changeset-stream-mirror-currency.md`](../plans/ocs-changeset-stream-mirror-currency.md)
   and its bandwidth-bounding successor
   [`../plans/ocs-subscription-changeset-stream.md`](../plans/ocs-subscription-changeset-stream.md);
   the real fix for the K8/K9 eclipse/currency residuals, gated on a fastcrypto
   non-inclusion id-binding fix.

## Distilled pitfalls

Recurring failure classes from this review worth promoting to
`../learnings/pitfalls.md`:

- serde `rename_all` does **not** cascade to struct-variant fields — test
  serde round-trips, don't assume (finding 3).
- Inclusion/authenticity proofs are **not** currency proofs — a validly
  signed old checkpoint proves an old version forever (findings 10, and the
  currency design in plans/).
- Commit messages overstate fixes: this review found "fixed-by" claims that
  were false (finding 10's credited commit), incomplete (finding 9), or
  orthogonal — always reconcile against the code.
