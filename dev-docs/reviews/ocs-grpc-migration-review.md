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
(16) — see each finding's RESOLUTION
and the remaining-work list. The directly-exploitable
proof-binding and boot-liveness concerns are resolved. A separate
earlier-confirmed **K1–K9** set (recovered below) is mostly still open; its
standout **K1** (single-object relay-substitution gap) is now fixed
(`e04b516490`).

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
   `verified_reader.rs::verified_bag_page` proved each entry on-chain but did
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
    `proof_verify_failures_total`; BagMembership, BLS-summary, freshness, and
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
    Proof rejection, high-water rollback, the BagMembership binding, and the
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
    - **BagMembership binding derivation** — `transport::tests` assert
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
      (`…owned_by_an_address…`) → `BagMembership`.
    Each rejection also asserts the `proof_verify_failures_total{kind,reason}`
    counter increments (finding 12's deferred metric-assert). Finding 6's fix
    added the ratchet error-classification negative test.

    Not covered (out of this finding's proof-path scope): the legacy-JSON-RPC
    vs new-style transport gate is computed inline in `ika-node`'s boot path
    (`config.sui_data_source.is_none() && mode.is_validator()`), not a pure
    function, so a truth-table unit test would need a boot-logic refactor; left
    as a separate follow-up.

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
  guard. (Also a spec residual.) Anchor: `ika-node/src/lib.rs`.
- **K3 [low] No guard rejects a notifier/fullnode configured peer-only**
  (`SuiStateMirrored{fallback:None}`) — fails late with an unclear error.
  Anchor: `ika-node/src/lib.rs`.
- **K4 [low — defense-in-depth] The BLS-verified ratchet path lacks the
  `next.epoch == head+1` assert** the unverified fallback has;
  `ocs_verifier.rs` installs `extract_new_committee_info` output without the
  explicit check. (Also a spec residual.)
- **K5 [low — dead code] The `sui_checkpoint_cache` table + pruner are dead.**
  `get_sui_checkpoint`/`put_sui_checkpoint` (+ inline pruning) had zero
  callers; `CheckpointCache` was never even a real type (referenced only in a
  `transport.rs` doc comment). RESOLUTION (`31d8c71120`): removed the column
  (auto-deregistered by the `DBMapUtils` derive; new/undeployed table, no
  migration), the accessors, and the doc-lie.
- **K6 [low] Stale old-style config templates** — `validator.template.yaml`,
  `fullnode.template.yaml`, `shared.sh`,
  `skills/ika-operator/references/configuration.md` still use the deprecated
  `sui-rpc-url`-only shape.
- **K7 [low — docs] `SuiTransport::batch_get_objects` same-order contract is
  undocumented** while callers zip results positionally with inputs. Anchor:
  `ika-sui-client/src/transport.rs`.
- **K8 [residual] Eclipse** — a peer-only node talking to a single malicious
  relay can be served a self-consistent stale world (freshness head seeded by
  the relay). The currency limitation addressed by the changeset-stream
  design (`../plans/`); open by design.
- **K9 [residual] `get_current_epoch` is a relay-claimed/unverified
  passthrough** used as the ratchet target; with the fallback flag off it only
  stalls, with it on the head can be walked one real epoch per call. Accepted
  degradation; open by design.

## Remaining work (risk-ordered)

DONE since the audit: findings 6 (S1), 9 (H3), 12 (H4), 13 (H2), 14 (S2),
15 (S4) fixed + K1, K5; 10/11 closed by removing the push/cache gossip
subsystem (`b9be273a74`). All 16 enumerated findings are now resolved or
obsolete. Remaining items below are residuals, not enumerated findings.

1. **JSON-RPC-vs-new-style gate truth-table** (the one sliver of finding 13
   left uncovered) — the gate is inline boot logic in `ika-node`, not a pure
   function; a unit test needs a small boot-logic extraction. Low risk.
2. **K2–K4, K6–K9** — lower-severity config / docs / defense-in-depth
   residuals (K8/K9 are the eclipse/currency residuals the changeset-stream
   design addresses; K5 dead-code removal done in `31d8c71120`).
3. **Mirrored-node currency redesign** (future feature, not a finding) —
   [`../plans/ocs-changeset-stream-mirror-currency.md`](../plans/ocs-changeset-stream-mirror-currency.md);
   gated on a non-inclusion id-binding fix.

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
