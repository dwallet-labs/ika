# OCS #1744 pre-merge cleanup (plan)

**Status:** landed — pre-merge cleanup (items 1–5) + `ocs-binding-1` landed
2026-06-26 (commits `857ffdd645`..`41ff40f586`, each with a test where meaningful);
all review items (incl. the bag-pump hygiene) are closed.
**Branch:** feat/ocs-grpc-migration (#1744).

The actionable checklist derived from the pre-merge review
([`../reviews/ocs-1744-pre-merge-review.md`](../reviews/ocs-1744-pre-merge-review.md)) —
that doc *records* the findings and their mechanisms; this one *tracks* the work to
close them. The lone MUST-FIX (`mpc-consensus-1`) is already done, so merge is
technically unblocked; the cheap cluster below is worth landing first.

## Pre-merge cleanup (~half a day; all trivial/small, each closes a real gap)

- [x] **`ocs-verifier-core-1`** — `verified_objects` zip-truncates a relay-short results
      vec and returns a partial set as `Ok`. Fix: before the loop, reject if
      `resp.results.len() != ids.len()` (`verified_reader.rs:284`). One line, all callers.
- [x] **`spec-conformance-1`** — the currency gate ships live but was documented as future.
      Spec updated (`specs/ocs-verified-sui-reads.md`: live in *Freshness*, invariant #9,
      `ChangesetPage` in *Relay protocol*, eclipse/cache notes corrected) AND the stale
      `ocs_currency.rs` module doc fixed.
- [x] **`authority-epoch-1`** — correct the provably-false inline comment at
      `authority_per_epoch_store.rs:4185-4188` ("a deterministic function of the
      consensus-sequenced handoff_signatures table"): the table's write *order* is
      consensus-ordered, but *whether* a row exists depends on off-consensus
      attestation/provider install; close-determinism rests on buffered-quorum adoption +
      the `grace×4` backstop. (Gate rework itself = a design-review item, not this PR.)
- [x] **`node-config-2`** — `IKA_ENABLE_SMALL_PRESIGN_POOLS` mutates process-global config
      on the real validator path for ANY defined value, and the "Validator binaries never
      call it" comment is false (`node_runner.rs:93-95`). Fix: require an explicit sentinel
      (e.g. `=1`) and/or gate behind a non-production chain id, emit a startup `warn!`, fix
      the comment.
- [x] **`ocs-transport-1`** — make the dormant hazard fail-closed: `SuiMirrorTransport::execute_transaction`
      (`sui_state_mirror/client.rs:533-536`) should return an `unreachable`/unsupported error
      instead of silently returning relay-supplied (unverified) effects, so a future mis-wire
      fails loudly. 1 line.

## Fast-follow (own PR, not merge-blocking)

- [x] **`ocs-binding-1`** — bound the `pending_active_set` ExtendedField read (the only
      unbound object-graph hop). Shipped a shared `transport::dynamic_field_child_owned_by`
      (extracted from `verified_dynamic_fields_page`, which now calls it) and bound the ExtendedField
      child in the gRPC backend's `get_extended_field_value_bcs`. **Layer correction vs the
      design:** the bind lives at the gRPC backend, NOT the verified-reader layer — `get_object`
      already returns the proof-bound `Owner` there on a peer-only node, so no new reader
      method or caller routing was needed. LOW impact (discovery-only). Helper unit-tested;
      the 30 `verified_reader` tests pass through the refactored binding.
- [x] **`network-mirror-1`** — DONE (`550db6ba2f`). **Scope sharpened during review:**
      `submit_transaction` had no live caller (writes are notifier-gated → direct uplink;
      `SuiMirrorTransport::execute_transaction` already fail-closes), so rather than cap it we
      **removed it entirely** — dropped the `.method()` from `build.rs` and deleted the handler +
      `SubmitTransaction{Request,Response}` types. Then capped *every* served read: the five that
      already had an `InflightLimitLayer` plus the seven that didn't
      (`last_checkpoint_of_epoch`, `get_transaction_checkpoint`,
      `get_checkpoint_summary_by_digest`, `get_latest_checkpoint`, `get_current_epoch`,
      `get_reference_gas_price`, `get_chain_identifier`), via a `macro_rules! inflight`
      (each `add_layer_for_*` is generic over its own request type, so a closure won't type-check).
      Per-peer rate-limit / admitted-peer firewall deferred (the inflight ceilings bound the DoS).
- [x] **`network-mirror-2`** — DONE. Consumer-side response-length bounds against a
      byzantine *server* that ignores its own clamp: `verified_dynamic_fields_page` now
      rejects `resp.entries.len()` over `min(page_size, MAX_VERIFIED_PAGE_ENTRIES=1024)`
      *before* the `Vec::with_capacity` + O(entries) verify loop (`ReaderError::OverlongPage`),
      and `pump_changesets` rejects `page.len() > page_limit` before the per-entry BLS verify.
      The batch path was already bounded by the `results.len() != ids.len()` check
      (`ocs-verifier-core-1`). Fault-injected unit test
      (`an_overlong_dynamic_fields_page_is_rejected`): with the bound removed the 3-entry
      page is accepted, with it the page is rejected.
- [x] **`ocs-cache-committee-1`** — DONE. The object-cache `prune_floor()` is now just
      `head - window` (the anchor clamp removed) — verified the cache is the direct node's
      *own* cache-first read path (a pruned snapshot just re-fetches; mirrored peers are
      served fresh by `LocalProofProvider`, which never reads it), so clamping was both
      harmful (pinned the floor → leaked one entry per object id) and unnecessary. The anchor
      clamp moved to a new `eop_retention_floor()` used ONLY for the served end-of-epoch
      checkpoints (which a mirrored peer's ratchet can't re-derive). Fixed the module /
      `with_retain_window` ("Mirrors ChangesetIndex") / field docs, and rewrote the leak-
      encoding test to `object_window_prunes_past_the_anchor_while_eop_retention_keeps_it`
      (fault-injected: re-clamping the object prune lets the below-window snapshot survive).

## Eventually (defense-in-depth / hygiene)

- [x] **`ocs-ingest-2` + `ocs-wiring-1`** (same `BagEventPump` loop) — DONE. The run loop now
      applies exponential backoff (`next_pump_backoff`: poll-interval → 5s cap — short, since the pump is a live event feeder, cf.
      `verified_read_retry_backoff`) and escalates `advance()` failure logging warn→error after
      5 consecutive failures (then the grown backoff throttles to ~1/30s). Omission escalates
      across ticks (`omission_escalation` / `note_bag_omission`): one warn on the first suspected
      tick, one error once *sustained* (~100 ticks ≈ 5s — rotate-relay hint), info on recovery,
      quiet in between (the per-tick metric still ticks). Both decision helpers unit-tested.

## Done

- [x] **`mpc-consensus-1`** — `compute()` wrapped in `catch_unwind` + always-send-completion;
      core slot always reclaimed (`ff3feba0f6`, two unit tests).
