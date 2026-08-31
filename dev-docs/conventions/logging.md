# Log levels — the `tracing` discipline

## The rule

Pick the level by **how often the line fires** and **who has to read it**:

- `error!` — a genuine failure: an operation that should have succeeded
  didn't, and an operator must look. (Failed to persist a blob, failed to
  ingest off-chain keys, a `send` on a live channel returned `Err`.)
- `warn!` — a recoverable or expected-but-notable anomaly the node
  handles itself: a rejected peer message, a dropped stale announcement,
  a transient that will retry. Not a failure of *this* node. Example: a
  validator whose on-chain metadata will not parse fails the whole
  re-keying of the committee to consensus-basis names
  (`rekey_committee_to_consensus_names` returns `InvalidCommittee`); the
  caller logs `warn!` and `continue`s to the next sync tick
  (`sui_connector/sui_syncer.rs`). Logging that at `error!` — on a path
  that re-runs every poll tick — is exactly the noise this rule exists to
  prevent.
- `info!` — a low-frequency lifecycle milestone: roughly **once per
  epoch / session / reconfiguration**. Rule of thumb: if a healthy node
  can emit it more than a handful of times per epoch, it is not `info!`.
- `debug!` — anything on a **hot path**: per-cryptographic-computation,
  per-MPC-round, per-consensus-message, per-session-tick. These dominate
  log volume under load and bury the `info!`/`warn!` lines an operator
  actually needs.
- `trace!` — verbose inner-loop detail, off in every normal run.

## Why it matters here

A validator runs the entire MPC pipeline **in one process**. An `info!`
on a per-computation path — which `CryptographicComputationsOrchestrator`
(`dwallet_mpc/crytographic_computation/orchestrator.rs`) drives once per
round per session — makes the log unreadable exactly when something is
wrong. The spam-reduction pass that set this discipline demoted the
orchestrator's per-computation *completion*, *no-available-cores*, and
*starting-computation* lines from `info!` to `debug!` (PR #1721); a
later `Merge dev into fast-schnorr (keep ours)` silently reverted the
three flips and they were re-asserted in PR #1766. When in doubt about a
line on the compute path, it is `debug!`.

## Hot paths in this codebase → `debug!` (or lower)

- `dwallet_mpc/crytographic_computation/orchestrator.rs` — per-computation
  start / completion / no-available-cores lines (the recurring per-round work).
- per-round / per-message / per-tick handlers in
  `dwallet_mpc/mpc_manager.rs` and `dwallet_mpc/dwallet_mpc_service.rs`.

## Events that ARE `info!` (verify the once-per-epoch guard)

- Off-chain validator-MPC-key **ingestion** (`mpc_manager.rs`) and
  **delivery** (`sui_connector/sui_syncer.rs`) of the agreed frozen set
  — each guarded so it fires once per epoch (e.g. `sui_syncer` only enters
  the delivery block while `current_keys_sent_for_epoch != Some(current_epoch)`,
  and stamps it on success). An `info!` here is only
  correct *because* of that guard; the same log without a guard would be
  spam and belongs at `debug!`.
- Epoch open/close, reconfiguration start/finish, committee changes.
- Recovery from a previously warned bounded degradation. Recovery is a state
  transition, not a success line for every retry.

## Aggregate hot asynchronous races

Do not warn once per consensus-delivered item when the item can legitimately
race a local state transition. Count every item with bounded labels, retain
only fixed-size aggregation state, and log:

- per-item detail at `debug!`, without payloads;
- the first sustained-degradation transition at `warn!`, with aggregate
  counts and a fixed reason code;
- reminders no more than once per documented interval;
- one `info!` transition after a warned period recovers.

Messages arriving after an MPC session reaches `Completed` are the canonical
example. `Failed` remains a separate metric/log status; rejection,
conflicting-output, quorum-failure, and malicious-self paths keep their
immediate anomaly diagnostics.

## Test-subscriber trap

`tracing_subscriber::fmt().init()`-style setup in tests **caps at INFO
and ignores `RUST_LOG`**, so `debug!` evidence vanishes and a "green"
run proves nothing about a demoted line. Use the
`try_from_default_env().…try_init()` form — see
[`../learnings/pitfalls.md`](../learnings/pitfalls.md).

## See also

- [`../playbooks/mpc-anomaly-diagnostics.md`](../playbooks/mpc-anomaly-diagnostics.md)
  — bounded per-session debug metadata that is flushed at `WARN`/`ERROR` only
  when an MPC anomaly occurs.
- [`metrics.md`](metrics.md) — for a signal a **test or alert** must
  assert on, prefer a scrapable metric over grepping a log string.
