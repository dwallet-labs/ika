# OCS #1744 pre-merge cleanup (plan)

**Status:** active. **Date:** 2026-06-26. **Branch:** feat/ocs-grpc-migration (#1744).

The actionable checklist derived from the pre-merge review
([`../reviews/ocs-1744-pre-merge-review.md`](../reviews/ocs-1744-pre-merge-review.md)) —
that doc *records* the findings and their mechanisms; this one *tracks* the work to
close them. The lone MUST-FIX (`mpc-consensus-1`) is already done, so merge is
technically unblocked; the cheap cluster below is worth landing first.

## Pre-merge cleanup (~half a day; all trivial/small, each closes a real gap)

- [ ] **`ocs-verifier-core-1`** — `verified_objects` zip-truncates a relay-short results
      vec and returns a partial set as `Ok`. Fix: before the loop, reject if
      `resp.results.len() != ids.len()` (`verified_reader.rs:284`). One line, all callers.
- [~] **`spec-conformance-1`** — the currency gate ships live but was documented as future.
      Spec **DONE** this session (`specs/ocs-verified-sui-reads.md`: live in *Freshness*,
      invariant #9, `ChangesetPage` in *Relay protocol*, eclipse/cache notes corrected).
      **Remaining:** fix the stale `ocs_currency.rs:16-18` module doc.
- [ ] **`authority-epoch-1`** — correct the provably-false inline comment at
      `authority_per_epoch_store.rs:4185-4188` ("a deterministic function of the
      consensus-sequenced handoff_signatures table"): the table's write *order* is
      consensus-ordered, but *whether* a row exists depends on off-consensus
      attestation/provider install; close-determinism rests on buffered-quorum adoption +
      the `grace×4` backstop. (Gate rework itself = a design-review item, not this PR.)
- [ ] **`node-config-2`** — `IKA_ENABLE_SMALL_PRESIGN_POOLS` mutates process-global config
      on the real validator path for ANY defined value, and the "Validator binaries never
      call it" comment is false (`node_runner.rs:93-95`). Fix: require an explicit sentinel
      (e.g. `=1`) and/or gate behind a non-production chain id, emit a startup `warn!`, fix
      the comment.
- [ ] **`ocs-transport-1`** — make the dormant hazard fail-closed: `SuiMirrorTransport::execute_transaction`
      (`sui_state_mirror/client.rs:533-536`) should return an `unreachable`/unsupported error
      instead of silently returning relay-supplied (unverified) effects, so a future mis-wire
      fails loudly. 1 line.

## Fast-follow (own PR, not merge-blocking)

- [ ] **`ocs-binding-1`** — bind the `pending_active_set` ExtendedField read (the only
      unbound object-graph hop). Generic fix per
      [`ocs-read-binding-and-verification.md`](ocs-read-binding-and-verification.md):
      extract `verify_dynamic_field_entry_binding` from `verified_bag_page`, add
      `OcsVerifiedReader::verified_extended_field_value`, route the read through it (the
      proof-bound `Owner` only exists at the verified-reader layer). LOW impact (discovery-only).
- [ ] **`network-mirror-1`** — add `InflightLimitLayer` (+ per-peer rate limit) to the three
      uncapped serving RPCs: `submit_transaction`, `last_checkpoint_of_epoch`,
      `get_transaction_checkpoint` (`sui_state_mirror/mod.rs` `make_server`).
- [ ] **`network-mirror-2`** — consumer-side: reject responses where
      `resp.entries.len()` / `results.len()` exceeds the requested `page_size`/`limit`
      before allocating (`verified_reader.rs:477`). Server-side caps already exist.
- [ ] **`ocs-cache-committee-1`** — decouple `prune_floor` from the immutable bootstrap-anchor
      clamp so the retain window actually prunes once `head - window > bootstrap_seq`
      (`verified_state_cache.rs:279-288`); keep the anchor floor only for the mirrored-bootstrap
      path; fix the misleading "Mirrors ChangesetIndex" doc and the unit test that encodes the leak.

## Eventually (defense-in-depth / hygiene)

- [ ] **`ocs-ingest-2` + `ocs-wiring-1`** (same `BagEventPump` loop) — add exponential backoff +
      log-severity escalation on `advance()` failure (mirror `verified_read_retry_backoff`), and
      escalate on *sustained* bag omission (rotate relay / fatal alert) instead of warning at
      ~20 Hz forever. One combined change (`bag_event_pump.rs:96-99`, `183-222`).

## Done

- [x] **`mpc-consensus-1`** — `compute()` wrapped in `catch_unwind` + always-send-completion;
      core slot always reclaimed (`ff3feba0f6`, two unit tests).
