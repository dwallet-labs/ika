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
**Status (updated):** **13 resolved** (the 9 fixed + 10/11/12/15), **2 open**
(13 adversarial tests, 14 serving caps), **1 obsolete** (16) — see each
finding's RESOLUTION and the remaining-work list. The directly-exploitable
proof-binding and boot-liveness concerns are resolved.

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
    `crates/ika-core/src/sui_connector/`. RESOLUTION: open. Finding 6's fix
    added the first negative unit test (ratchet error classification), and
    finding 12 deferred its metric-assert test here; the four adversarial
    paths still need coverage.

14. **[medium] Serving side has no caps.** No limits on batch ids / bag
    page_size / `GetVerifiedSnapshot` (which deep-clones the whole cache
    under the objects read lock); no inflight/rate-limit on the mirror anemo
    service. A peer can request unbounded server work. Anchors:
    `crates/ika-network/src/sui_state_mirror/`,
    `crates/ika-core/src/sui_connector/verified_state_cache.rs::take_snapshot`.
    RESOLUTION: open — add caps + an inflight/rate-limit layer (note:
    `GetVerifiedSnapshot` is being removed with the push gossip, finding 10).

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

### Not enumerated (gap)

The working notes also reference an earlier-confirmed **"K1–K9"** set
(predating this ultrareview) as *"still present at HEAD"*, but those nine
were never broken out into individual findings — neither here nor in the
notes. They are **not** covered by findings 1–16 above and would need to be
recovered from the original ultrareview run to be re-checked. Flagged so the
"16 findings" count is not mistaken for the full set of known issues.

## Remaining work (risk-ordered)

DONE since the audit: findings 6 (S1), 9 (H3), 12 (H4), 15 (S4) fixed; 10/11
closed by removing the push/cache gossip subsystem (`b9be273a74`) — which also
took out the sequential fanout (11) and the unbounded `GetVerifiedSnapshot`
clone (part of 14) in one removal. Open items below.

1. **Finding 14** (remaining caps) — batch/bag page_size limits + mirror
   service rate-limit.
2. **Finding 13** (adversarial tests) — negative tests for proof-rejection,
   high-water rollback, BagMembership binding, and the JSON-RPC gate
   truth-table. Finding 6's fix added the first (ratchet error
   classification); build out the rest.
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
