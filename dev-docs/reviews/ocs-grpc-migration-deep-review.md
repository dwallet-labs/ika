# OCS verified-Sui-reads — deep review (2026-06-19)

**Reviewed:** the full `feat/ocs-grpc-migration` PR — OCS verified Sui reads:
gRPC transport, `SuiStateMirror` relay + peer-only validators, the push/cache
fast path + DB persistence, the committee ratchet + follower, the
currency/changeset stream, and the notifier write-back.
**At commit:** `b68e413c06` (range `origin/dev...HEAD`, merge-base `d1fc914d68`;
96 commits, 65 files, ~17K insertions).
**Date:** 2026-06-19.
**Method:** multi-agent. 12 review units (9 per-subsystem + 3 cross-cutting
lenses — trust model, concurrency/lifecycle, fail-closed error handling). Every
finding was handed to an independent skeptic prompted to *refute* it against the
code (default-refute if unconfirmable). A completeness critic then named the
review's own blind spots, and a targeted second pass deep-read the files the
units under-covered (`grpc_backend.rs`, `authority_perpetual_tables.rs`,
`anchor.rs`, `mod.rs`/`sui_syncer.rs`). 74 agents total.
**Verdict:** **sound.** 59 raw findings, **53 refuted** on verification — many
were reviewers affirming correct code as a "finding"; the alarming-looking ones
were control-flow misreads. The cache-through-tripwire anchor fix (`aa519ee28e`)
was independently confirmed safe. No surviving critical/high *code* defect from
the structured pass; the one HIGH and the actionable mediums all came from the
second pass over under-reviewed files. The bulk of the actionable output is
**test coverage**: the trust gates are correct today but several are untested and
one refactor from a silent regression.

> Point-in-time record (per `reviews/` convention) — not maintained as a source
> of current truth. Current behavior lives in
> [`../specs/ocs-verified-sui-reads.md`](../specs/ocs-verified-sui-reads.md). The
> 2026-06-13 audit of an earlier state is
> [`ocs-grpc-migration-review.md`](ocs-grpc-migration-review.md).

## Findings

Each carries a RESOLUTION field; fill it in (with the fixing commit) as addressed.

1. **[HIGH] Persisted-format fragility halts boot on a Sui version bump.**
   `authority_perpetual_tables.rs` (new columns), `verified_state_cache.rs:49-55`,
   `committee_store.rs:134-144`. The new perpetual columns persist **upstream**
   sui_types (`Object`, `OCSInclusionProof`, `CertifiedCheckpointSummary`, full
   `CheckpointData`, `Committee`) via plain BCS with **no schema-version tag and
   no migration/eviction path**. A Sui version bump (pinned ~90 places, bumped on
   a schedule — see [`../conventions/sui-version-bump.md`]) that changes any of
   these BCS layouts makes the `safe_iter` deserialize `Err` propagate `?` through
   `VerifiedStateCache::open` / `CommitteeStore::open` → `ika-node` boot fails →
   the validator halts on upgrade. The committee columns are the worse half (no
   rebuild escape hatch — the node can't bootstrap its committee head). **Fix:**
   treat a `SerializationError` from these caches as cold-cache → drop+recreate
   the column family / re-anchor, never propagate. (The related upgrade concern —
   new CFs on an existing DB — is already handled: `populate_missing_cfs` +
   `create_missing_column_families` auto-create them.) RESOLUTION: fixed in
   `cdf8ede388` — cache opens empty + re-folds on a `SerializationError`; the
   committee chain surfaces an actionable error (default) or auto-re-anchors from
   the pinned anchor behind the new `auto_reanchor_on_format_change` flag.
   Residual: this typed_store build's range deletes are no-ops and corrupt-value
   keys can't be enumerated, so the `verified_object_cache` value entries can't be
   physically wiped — they're left and not loaded, so cache *persistence* stays
   degraded (re-fold from the fullnode each boot) until the operator clears the
   cache. The boot-halt itself is gone. A per-value schema-version envelope would
   close the residual cleanly if wanted.

2. **[MEDIUM] Persisted `verified_object_cache_head` can be written ahead of its
   objects under concurrent absorb.** `verified_state_cache.rs:199-218,311-326`.
   `absorb_entries` does in-memory `advance_head` then `persist`, and `persist`
   re-reads the **shared** `head_seq()`. The pusher fold and the reader's per-read
   folds (`verified_reader.rs:348,578,770`) both call `absorb_entries` with no
   lock over the advance→persist pair, so a higher-seq absorb on another thread
   bumps the head between thread A's advance and A's persist; A then persists a
   head above its own (lower-seq) objects. On crash the persisted head overstates
   the persisted objects, defeating the rehydration anti-staleness guarantee the
   head exists for. **Fix:** persist `min(source_seq, head_seq())` from the seq
   actually being folded, not the shared atomic. RESOLUTION: fixed in `65756c0ffa`
   — `persist` takes the caller's own in-order `source_seq`, and reader shadow-writes
   use a new non-persisting `absorb_shadow_entries`, so only the single-threaded
   pusher persists (contiguous, never overstates). Regression test added.

3. **[MEDIUM — needs author confirmation of reachability] Sender-fork silent drop
   → MPC starvation.** `mod.rs:147,193`, `sui_syncer.rs`. `run_legacy_event_ingestion
   = reader.is_none()`. A node with `reader.is_some() && !mode.is_validator()`
   (a Fullnode/Notifier configured **with** an OCS anchor) routes both non-Clone
   event senders into `pump_senders`, but the pump is gated on `mode.is_validator()`
   and never spawned → both senders dropped silently. If that node is/becomes a
   committee member (`state.is_validator()` — the supported "promote fullnode to
   validator" path), `DWalletMPCService` consumes a Closed receiver → MPC stalls
   with **no panic and no log**. The `.expect()` in `sui_syncer.rs` is itself
   unreachable (same boolean gates sender-presence and the expect). **Fix:** gate
   the pump on `state.is_validator` (the consumer predicate), or assert
   `reader.is_some() ⇒ mode.is_validator()`, or at minimum log the dropped-sender
   branch. RESOLUTION: fixed in `006317652b` — added a loud `warn!` on the
   `reader.is_some() && mode != Validator` branch (the senders are still dropped,
   but no longer silently; a clear misconfiguration signal). Not a panic, since a
   fullnode/notifier with an anchor that runs no MPC is a legitimate config.

4. **[LOW] `persist_end_of_epoch` is not atomic across its two columns.**
   `push_worker.rs:290-295`. The epoch→seq index and the retained `CheckpointData`
   are written in two separate `DBBatch`es; a crash between them leaves a dangling
   mapping. Low impact — both serve a mirrored peer's ratchet and degrade to the
   fullnode / re-anchor. **Fix:** one method writing both in a single batch.
   RESOLUTION: open.

5. **[LOW] `get_uncompleted_events` skips bag-membership binding (latent footgun,
   currently dead).** `grpc_backend.rs:236`. It walks an untrusted
   `list_dynamic_fields` and reads each entry via inclusion-only `verified_object`,
   **not** `verified_bag_page` — so spec Invariant 5 (collection-ownership
   binding) is omitted. Confirmed **unreachable** on every untrusted-relay config:
   the only caller is spawned when `reader.is_none()`, which dispatches the
   JSON-RPC backend, not this gRPC one; OCS nodes use the `BagEventPump`
   (`verified_bag_page`, binding enforced). **Fix:** make it return `Err(...)`
   like the `query_events` stub, so an accidental future re-wiring fails loudly
   instead of accepting unbound entries. RESOLUTION: open.

6. **[LOW] `ChangesetIndex.pending` has no size cap.** `ocs_currency.rs:159`.
   `absorb` queues gap-creating changesets unbounded; `prune`/`retain_window`
   touch only `self.index`, not `pending`. Gated in practice (every queued entry
   is committee-BLS- and artifacts-digest-verified, so the relay can't fabricate
   or inflate; `pump_changesets` advances one page per tick), and growth also
   requires the relay to simultaneously stall currency (a visible liveness
   symptom; reads fall back to `Unknown` — no safety break). **Fix:** cap
   `pending` (e.g. 256) + drop-oldest-or-alert, validate the returned seq window,
   add a depth metric. RESOLUTION: open.

7. **[TEST — 5 confirmed coverage gaps, guards present & correct, untested].**
   - `committee-002`: the unverified-fallback epoch-mismatch guard
     (`ocs_verifier.rs:196-201`, `FallbackEpochMismatch`) — no test.
   - `committee-003`: the bootstrap anchor digest gate + end-of-epoch gate
     (`setup.rs:295-304`, `AnchorDigestMismatch`/`AnchorNotEndOfEpoch`) — no test
     (`setup.rs` has no `mod tests`).
   - `committee-004`: perpetual-state-overrides-reconfigured-anchor on restart
     (`resolve_bootstrap_plan`, `setup.rs:150-171`, `BootstrapPlan::Hydrated`) —
     no test (Invariant 3).
   - `committee-005` [MEDIUM]: committee derivation from stored summaries on a
     cache miss (`committee_store.rs:222-233`, `resolve_committee`) — no test
     (`committee_store.rs` has no `mod tests`).
   - `committee-006`: follower capture-failure is benign and the ratchet recovers
     (`committee_follower.rs:87-107`) — the `capture()` `Err` arm is untested.
   RESOLUTION: open — covered by the P0 unit tests below.

   **INFO (not a defect):** the leaf structs `DWalletCoordinatorInnerV1` /
   `DWalletNetworkEncryptionKey` are non-tagged, so a *same-version* Move
   field-add silently mis-decodes while passing every OCS proof gate. Pre-existing
   and identical to the legacy JSON-RPC path; `VersionedMPCData` *is* a tagged
   enum, so a new variant fails closed. Worth a note to the author; not a blocker.

## Refuted on verification — recorded so they are not re-raised

- **`relay-005`** "peer-only submit returns unverified effects" — **structurally
  unreachable.** `VerifiedSuiTransport::execute_transaction` returns
  `unreachable(...)`; the bare `SuiMirrorTransport` is never wired as a SuiClient.
  (Finding 5's `Err()` hardening covers the same class of footgun.)
- **`executor must_get_*_inner` retry-forever** — intended and pre-existing; a
  *mandatory* read must not fall back to unverified state.
- **`cache_fallback` high-water "wedge"** — `.ok()?` swallows the `StaleVersion`
  error to `None`, making the fallback purely additive. **The anchor fix cannot
  wedge an anchor read.**
- **Anchor digest gate, `rename_all_fields` kebab-case, peer-only boot order,
  NotFound-vs-Network classification** — all correct code raised as findings.
- **`current_head_seq` per-read RPC** — real but one small amortized RPC per
  request; low priority. (Matches the deferred follow-up noted on the anchor fix.)
- **`anchor.rs` producer epoch-boundary race** — fails closed (returns `NotFound`,
  not a stale digest); the consumer re-validates the pinned digest byte-exact.

## Test plan

50 unit/integration + 12 cluster/e2e, **deduplicated against existing tests**
(the trust-chain, bag-binding, currency, high-water, freshness, and the
`anchor_reads_serve_cache_through_a_tripped_tripwire` cases already present were
not re-proposed).

### Unit / integration — P0 (15; the trust-chain & fail-closed boundary)

> **Status: all 15 landed** (`407faa49e5`, `fefa972d26`). The relay-failover
> verdict was made unit-testable by a behavior-preserving extraction of
> `classify_failed_pass` from `try_peers`; the anemo round-trip / demotion
> plumbing and the cluster-only scenarios below remain for the cluster suite.

- `ocs_verifier::unverified_fallback_rejects_epoch_mismatch` — guards committee-002.
- `ocs_verifier::ratchet_does_not_fall_back_on_network_error` — fallback keys
  strictly on `NotFound`, never `Network`.
- `ocs_verifier::ratchet_advances_epoch_by_one_per_step` — Invariant 2, no skip.
- `setup::anchor_digest_mismatch_is_rejected` / `anchor_not_end_of_epoch_is_rejected`
  — committee-003, the trust root.
- `setup::perpetual_state_overrides_reconfigured_anchor` — committee-004 /
  Invariant 3.
- `verified_reader::freshness_boundary_conditions` (bounds 0/1/100) — off-by-one.
- `verified_reader::observed_upstream_head_is_monotonic_and_pins_freshness` —
  relay can't under-report head (Invariant 4 / eclipse residual).
- `verified_reader::high_water_rejects_network_rollback_after_cache_hit` — both
  paths consult the same mark.
- `verified_reader::anchor_fallback_rejects_a_cached_version_below_high_water` —
  the anchor fix's rollback-safety case (tripwire bypassed, high-water is not).
- `push_worker::fast_forward_captures_all_boundaries_then_stops_at_a_pruned_one` —
  Invariant 2, fast-forward must not skip an uncaptured boundary.
- `changeset_receiver::forged_object_states_are_rejected_and_not_folded` —
  `ArtifactsMismatch` terminal.
- `verified_transport::unreachable_methods_error_with_descriptive_message` —
  Invariant 6, fail-closed.
- `grpc::rpc_status_err_maps_not_found_distinctly_from_network` — the source
  classification all decorators must preserve.
- `sui_state_mirror::try_peers_classification` (anemo-loopback integration) —
  all-NotFound vs mixed vs 30s-timeout→Network vs no-peers; feeds the ratchet
  fallback decision (Invariant 6).

### Unit / integration — P1 (25) and P2 (10) — summary

P1: committee derivation after cache eviction; follower capture recovery;
`pending`-queue bound (finding 6); prune-floor never below oldest summary;
version-monotonic cache insert; restart staleness-on-boot
(`processed_head == fold_head`); fetch-failure advances processed-head;
`FallbackTransport` routing split; serde kebab-case for `SuiDataSource`;
peer-only read-stack integration; follower/ratchet no-double-install;
broken-chain / partial-page-BLS contiguity in the receiver; batch
partial-failure & missing-summary semantics; bag-binding malformed key type;
uninstalled-future-committee rejection in the fold. P2: proof-clone codec/identity;
`forget_high_water` semantics (**flagged: defined but never called — confirm
intentional vs dead code**); retained-transport DB-error fallthrough; drain
pass; `deny_unknown_fields` on `SuiDataSource` so a snake_case key errors instead
of silently flipping a node peer-only.

### Cluster / e2e — P0 (6) and P1 (5)

P0: `ocs_peer_only_survives_three_epoch_boundaries`;
`ocs_mirrored_fallback_routes_unrelayable_reads_to_grpc` (metrics-assert the
relay/gRPC split); `ocs_direct_pusher_ratchet_follower_five_epochs`;
`ocs_validator_restart_resumes_from_persisted_cache` (also the home for findings
1 & 2); `all_combinations_*_throughput_against_ocs_anchored_localnet`
(ts-integration — the anchor-fix regression guard, the dense `session_events`
bag; validated by run 27812142652);
`ocs_ratchet_pruned_eoe_degrades_per_fallback_flag` (finding-17, driven at the
`MockTransport` seam). P1: relay failover on killed peer; hung-peer 30s-timeout
(needs a fault-injection wrapper, else rely on the unit test + kill-peer);
committee handoff with churn; sustained load across an epoch switch; peer-only
bootstrap waits-for-relay.

### Constraints & harness levers

- Sui `TestClusterBuilder` exposes **no pruning config** → real fullnode pruning
  cannot be forced in-cluster; drive prune-degrade at the `push_worker`
  `MockTransport` seam (as `pusher_skips_pruned_checkpoint_without_stalling`
  already does). Real-prune coverage belongs on a manual/`#[ignore]` localnet test.
- Hung-peer injection has no first-class hook; the 30s-timeout-classified-as-Network
  property is cheapest pinned by a `try_peers` unit test with a delayed mock op.
- Relay topologies need ≥45–60s epochs (the class-groups propagation flake under
  load). Use `#[tokio::test(flavor = "multi_thread")]` — none of these target
  scheduling nondeterminism, so `#[sim_test]` is not warranted.
- Levers: `with_ocs_genesis_anchor`, `with_sui_state_direct_count`,
  `with_peer_only_mirrored`, `with_epoch_duration_ms`; `Node::stop()/start()` +
  `spawn_new_node` for restart/churn; `relay_peer_failover_total` + the
  staleness/cache metrics for assertions.

## Residuals — open seams worth a follow-up look

- **Retained-checkpoint retention floor vs a far-behind peer-only bootstrap:** the
  only direct node can prune the end-of-epoch checkpoint a peer's ratchet still
  needs → the peer wedges `ProofChainBroken`. A three-file liveness seam
  (`retained_transport` ↔ cache retention floor ↔ remote ratchet).
- **Persisted eclipse:** the spec's eclipse-residual analysis assumes empty
  `observed_upstream_head`/high-water at cold start, but the node now rehydrates
  these (and the committee head) from disk. A relay that controlled a node before
  a crash could leave a persisted-but-stale floor that suppresses post-restart
  freshness detection.
- **Children-index ObjectBag wrapper-parent consistency:** the persisted-cache
  rebuild derives parent from `Owner::ObjectOwner(addr)`, but ObjectBag/ObjectTable
  children are owned by the `Field` wrapper id — confirm the rebuilt children
  index and the bag-binding logic agree on parent identity for that case.
