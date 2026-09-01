# MPC stall post-mortem

Use this when the network stops making MPC progress: epochs stop
advancing, user sessions time out ("Object ... does not exist" from the
SDK), or quorum events go silent. The checks are ORDERED — each one
either identifies the stall class or eliminates it; the order reflects
how often each class was the answer in real investigations and how cheap
the check is. Run them against the localnet/validator log (debug-level
`ika_core::dwallet_mpc=debug` gives the full picture; info-level still
answers most of them).

See also: if the stall is one you *induced* on purpose to confirm a guard
fires (fault injection / validating a test) rather than an unexpected one
to diagnose, you want [`test-testing.md`](test-testing.md) instead — same
log-grepping, opposite goal.

## 0. Get the timeline anchors first

```bash
L=<log file>
grep -o "run_epoch epoch=[0-9]*" $L | sort -u | tail -3          # highest epoch entered
grep -E "Successfully locked last session|handoff-cert quorum reached" $L | awk '{print $1, $NF}' | tail -6
grep "MPC output reached quorum" $L | tail -1 | awk '{print $1}' # last quorum = stall onset
```

The minute quorums stopped is the anchor for every later check.

## 1. Malicious conviction (check FIRST — it masquerades as everything else)

```bash
grep -c "recognized itself as malicious" $L
grep "malicious actors identified" $L | head -3
```

A convicted validator's messages are silently ignored from conviction
onward — the committee runs at reduced redundancy and the EVENTUAL stall
(often much later) looks like an unrelated message-flow bug. If this
fires: the divergence source is almost always a network-key parameter
mismatch on the convicted validator (see the adoption guards in
`../specs/handoff.md`), not actual byzantine behavior.

## 2. Started-vs-completed computation balance (orchestrator health)

```bash
grep -c "Starting cryptographic computation" $L
grep -c "Cryptographic computation completed successfully" $L
```

A persistent delta = computations stranded (leaked orchestrator slots /
results sent into a dead handle). Per-validator attribution: re-run with
`| grep "name=k#<id>"`. Zero CPU (cgroup sampler ~idle) while sessions
sit Active means computations are not SPAWNING — different class than
hanging.

## 3. Epoch-entry wedge — "locked but can't close" (issue #1736)

The epoch committed to closing (the last user session is locked) but
never advances. Start at the end-of-publish gate, which names the
blocker directly:

```bash
grep "end-of-publish gate STUCK" $L | tail -3              # post-lock stall, re-warned every 60s
grep "end-of-publish gate not yet satisfied" $L | tail -1  # same per-condition breakdown at debug
```

The gate prints every advance condition as a bool; the `false` one is
the wedge. (The warn fires only *after* the session lock — pre-lock the
gate is legitimately unsatisfied for most of the epoch, so it isn't
counted.) The roots seen for #1736, keyed by which field is false (all
four fixed; kept for the diagnostic shapes):

- **`next_epoch_committee_exists=false` — stale System committee anchor.**
  The notifier writes `next_epoch_committee` on-chain mid-epoch, but each
  validator reads the `System` inner through the always-cache anchor
  path, which historically had no staleness bound and served the
  pre-write snapshot forever, so the new committee was never observed and
  reconfiguration never started. Fixed by bounding the anchor cache: it
  forces a verified network re-read on a miss *and* at most once per
  `ANCHOR_REFRESH_INTERVAL` (2 s) — see `verified_anchor_object` in
  `sui_connector/verified_reader.rs` and the cache-fast-path section of
  `../specs/ocs-verified-sui-reads.md`. Confirm by reading the on-chain
  `next_epoch_committee` (it is set) while the gate still reports it
  absent.
- **`all_network_encryption_keys_reconfiguration_completed=false` —
  reconfiguration MPC stalled.** The network-key reconfiguration never
  finishes. One cause was a synchronous VSS-cache derive
  (`derive_vss_shamir_cache_for_key`) running inline on the async runtime
  and starving every other task on that thread; it is now offloaded to
  rayon (`network_dkg.rs`). When this field is false, trace the
  reconfiguration session (check 6) and watch CPU (check 2) — a frozen
  single thread reads as "Active but zero CPU".
- **network-key adoption gap (the original stale-mpc_data variant).**
  ```bash
  grep "Adopted network key epoch does not match" $L | sed -E 's/^([^ ]+).*name=(k#[a-f0-9]{8}).*/\1 \2/'
  grep "Updating network key" $L | sed -E 's/^([^ ]+).*name=(k#[a-f0-9]{8}).*/\1 \2/' | tail -8
  ```
  Exactly ONE rejection warn per epoch boundary is routine — that
  validator's presign sessions may be silently dead all epoch (invisible
  at 3-of-4 quorum). TWO at one boundary = quorum death for internal
  presigns = pool starvation = the wedge. Check whether sessions created
  during a validator's key gap ever compute afterwards.
- **mid-epoch-restart strand (issue #1852): sessions parked, zero
  instantiation attempts.** Signature (per wedged validator):
  `ika_dwallet_mpc_requests_pending_for_network_key` climbing while
  `ika_dwallet_mpc_network_key_instantiations_in_flight` stays 0,
  `ika_dwallet_mpc_network_key_instantiation_failures_total` shows no
  increase (never attempted, not failing), and
  `ika_dwallet_mpc_network_key_loaded_epoch` cut off exactly at process
  restart. Mechanism: the validator restarted after
  this epoch's reconfiguration completed; the overlay served only the
  just-produced next-committee output, which adoption skips
  (`adoption skipping network key` log with
  `already_instantiated=false` — that field value IS the strand).
  Fixed by stranded-key recovery (adoption flags the key; the syncer
  chain-reads the current-epoch output for flagged keys — see the third
  adoption guard in `../specs/handoff.md`); if the shape recurs, check
  for the "network key stranded after a mid-epoch restart" log and that
  read path first.
- **`all_epoch_sessions_finished=false` with `checkpoint_writer_lag > 0`
  — the checkpoint WRITER is the blocker, not MPC (issue #1892; both
  2026-07 testnet epoch-close outages).** Sessions completed and were
  certified into local dwallet checkpoints, but the notifier never landed
  them on Sui, so the on-chain `completed_sessions_count` can never reach
  the lock target. Check the gate warn's `checkpoint_writer_lag` field
  (also the `ika_sui_connector_chain_dwallet_checkpoint_writer_lag`
  gauge and the `checkpoint_writer_lag` blocked-reason label) — positive
  and growing means go look at the notifier, not the MPC pipeline. On
  the notifier itself, grep for `checkpoint sync is STALLED` (the
  known−synced self-report; `ika_dwallet_checkpoint_sync_stall_seconds`
  > 0) — a sync-side stall gives the writer *nothing to submit*, so the
  submission-failure log never fires. Recovery is operational (restart /
  fix the notifier — the network has exactly one writer by design; see
  `../specs/checkpoint-writer-observability.md`).
- **`all_epoch_sessions_finished=false` — a locked user session that is
  never re-pulled (WAS the open core of #1736; root-caused and fixed in
  PR #1809).** All other gate conditions read true; the epoch locked its
  last user session and simply waits for a session that never computes.
  The re-pull "does not fire" because the validators literally never see
  the session's `session_events` bag entry again: the OCS checkpoint
  pusher permanently skipped checkpoints it could not fetch before the
  fullnode's pruning watermark passed them (fixed: 250ms poll +
  pending-gap repair in `push_worker.rs`), and the dynamic-fields walk
  permanently dropped live-listed bag children whose defining checkpoint
  was pruned (fixed: the provider reports the skipped ids and the reader
  resolves them from the committee-verified cache). Issue #2018 showed
  both recovery paths can still lose the race when pruning outruns them
  (a throttled CI runner, `num_epochs_to_retain=0`): one lost DKG-request
  entry inside the locked close set wedged the epoch. The pusher now has
  a third layer — pending gaps the fullnode keeps refusing are fetched
  from the checkpoint archive (public store on mainnet/testnet; the Sui
  fullnode's data-ingestion dir on a localnet via `ika start
  --sui-checkpoint-archive-url`) and folded through the same committee
  verification. Diagnosis, if the shape recurs:
  ```bash
  grep -E "holding .*re-pulled next epoch" $L | tail -3   # the held session + its seq
  # then confirm that seq never returns (no completion, no re-pull):
  grep "session_sequence_number=<SEQ>" $L
  # pusher losing checkpoints? (only fires when the ARCHIVE also failed —
  # check ika_ocs_pusher_gap_dropped_total / _gap_archive_repairs_total)
  grep -E "never materialized within the gap retry deadline" $L
  grep -E "recovered from the archive and folded" $L
  # walk dropping children the cache can't serve either?
  grep -E "could not be resolved from the verified cache" $L
  # a session admitted but never computing (the issue #2018 open shape —
  # warned once a minute per validator while it persists):
  grep -E "active without a local output past the stall" $L
  ```
  The end-to-end guards are `sim_user_flows_across_boundaries` and the
  presign-traffic sim tests (deterministic reproducers of the original
  wedge).
  A second, correlated signature at every epoch entry: VSS-algorithm
  internal-presign refill sessions created inside the epoch-entry key gap
  (network key installed, off-chain validator key set not yet ingested).
  Historically this appeared as a `FailedToAdvanceMPC(InvalidParameters)`
  round-1 burst, later as `should_never_happen=true
  error=NetworkDecryptionKeyNotReady` with terminally-Failed sessions
  starving the VSS pools. Both are fixed: those requests now PARK
  ("network key data not ready for internal presign session; parking it
  for retry") and activate once the key data lands ("network key data
  arrived; activating parked internal presign session"). The wedge
  signature today is a park line with NO later activation line for the
  same session, or a sustained non-zero
  `ika_dwallet_mpc_internal_presign_requests_pending_for_network_key_data`
  gauge — that means the off-chain key set never arrived (back to the
  announcement/freeze checks). Residual #1736 evidence (the
  parked-sessions-never-compute CI link) is tracked on that issue; the
  captured instrumented run is CI run 28577745311.

## 4. Chain counters — the over/undershoot discriminator

Read the coordinator inner object (dynamic field of the coordinator id;
get the REAL id from the run's own publish logs, never from a possibly
stale `~/.ika/ika_config/network.yaml`):

- `locked_...` + `last_user_initiated_session_to_complete_in_current_epoch`
  (the frozen target) vs `user_sessions_keeper.completed_sessions_count`.
- `completed > target` → **overshoot**: permanently unhealable (the close
  predicate is a strict equality); a completion path bypassed the lock
  gate — see `../specs/epoch-close-session-lock.md`.
- `completed < target` → **undershoot**: a locked-set session can't
  complete; find WHY it can't (pool starvation? messages missing? — back
  to checks 1-3).
- System keeper: `started == completed` required for close as well.

## 5. What still flows vs what doesn't

Narrow the dead layer by checking each pipeline stage independently:

```bash
grep -c "Presign request reached majority vote" $L   # consensus + votes alive? (debug-level)
grep -c "Adding a new MPC session" $L                # admission alive?
grep -c "popped presign from internal pool" $L       # serving alive?
grep -c "broadcasting new requests" $L               # event sync alive? (debug-level)
```

The combination "votes flow + sessions added + zero quorums + zero
serving" pinpoints computation/messaging; "nothing flows" pinpoints
consensus or the service loop. The event-sync backlog itself is a gauge
rather than a log line: `ika_sui_connector_uncompleted_events_backlog`
is how many sessions the chain still shows uncompleted from this
validator's view, so a climbing value with the pump still ticking is a
consumption problem, not a delivery one.

## 6. Trace ONE session end-to-end

Pick a stuck session id and pull every line mentioning it, per
validator: who added it, who computed each round ("Advancing session" /
"Starting cryptographic computation"), how many round messages each
validator received, who submitted outputs. The validator whose round-N
message never appears IS the lead. Verify session ids are byte-identical
across validators (internal-presign ids are deterministic by
construction; divergence = determinism bug).

## Hard-won interpretation rules

- **Silence is a finding.** "No errors" + dead pipeline usually means a
  silent skip (`.ok()?`-style swallows) or a result delivered into a
  dropped channel — not the absence of a problem.
- **Distinguish slow from never.** Budgets/timeouts that were calibrated
  standalone WILL fire under 4-way CI contention; the failure mode worth
  hunting is "never", not "slow". Before tightening, check whether the
  thing eventually happened after the budget expired.
- **A validator that trails consensus is draining or dead, and the
  difference is whether the gap falls.** A restart refolds the epoch from
  its first commit and feeds every round to the drain again, and the gauge
  that shows it is `ika_dwallet_mpc_catchup_gap_rounds`, never
  `ika_mpc_consensus_round_lag`: the fold blocks on the bounded round
  channel, so the raw lag stays within a channel's worth (1,024) of the
  drain even mid-replay — an unremarkable reading there is not evidence the
  backlog is small. The MPC service announces the drain itself (`MPC
  service entered catch-up mode`), and the catch-up gap falls fast while
  it runs — with computation suppressed the drain manages ~1-2k rounds/s
  against a ~19.5 rounds/s tip, so a backlog closes at fifty to a hundred
  times the rate it grows. What to act on is
  `ika_mpc_stopped_contributing_condition_active == 1` (nothing is
  draining and MPC has stopped: `MPC subsystem has stopped keeping up
  with consensus`) or `ika_mpc_catch_up_stuck_condition_active == 1`
  (draining, but the gap stopped falling). Restarting a validator that
  is mid-drain only discards its progress and makes it refold the epoch.
- **A drain that stopped consuming does NOT trip the commit-liveness
  watchdog, by design.** The consensus fold hands rounds to the drain over a
  bounded channel and waits when it is full; the watchdog holds its clock
  while the fold waits, because a node holding a commit it received is not
  isolated. So a wedged drain produces no exit and no silence alarm. Its
  signature is `ika_consensus_fold_blocked_seconds_total` climbing while
  `ika_last_process_mpc_consensus_round` is flat and
  `ika_consensus_round_channel_depth` sits at capacity. Check that pair
  before concluding the node is healthy because nothing alarmed.
  `ika_consensus_fold_blocked_sends_total` tells a wedge from a merely
  slow drain: flat while the seconds climb is ONE park that never ended;
  climbing alongside them is many short parks, i.e. a drain that is
  behind but alive (the reading table is in
  [`production-alerts.md`](production-alerts.md)). The seconds gauge
  counts the park still in progress, so a permanently parked fold keeps
  moving it — a flat reading is evidence, not a gap in the metric.
- **The log's absence of a line is only meaningful at the right
  RUST_LOG.** Several load-bearing lines are debug-level; at info, do
  not conclude "X never happened" for a debug-level X.
- **Multi-line struct dumps break line-based grep.** Anchor greps on the
  timestamp prefix (`^2026-`) or use single-line fields
  (`session_sequence_number=`), and prefer python for multiset diffs.
- **A "healthy" checkpoint folder that folds nothing is a specific
  failure, not a contradiction — and the cursor's SIDE tells you
  which.** On a sui-state-direct node, `ika_ocs_pusher_pushed_total`
  flat with dwallet sessions stalling has two opposite causes, so
  always compare `ika_ocs_pusher_cursor_seq` against the chain's real
  latest checkpoint (any fullnode's `GetServiceInfo.checkpoint_height`)
  before acting:
  - **Cursor AHEAD of the chain head → poisoned cursor.**
    `ika_ocs_pusher_stalled` reads 0 (a cursor past the head has no lag
    to report) and the staleness tripwire is blind too — it measures the
    observed head against the folder's own processed head, and poisoning
    both leaves the difference at zero forever. Recovery: stop the node
    and clear the `sui_pusher_last_seq` row in the perpetual tables so
    the folder re-initializes from the watermark.
    Then check `rate(ika_ocs_pusher_gap_dropped_total[5m])`: climbing
    steadily at roughly the chain's checkpoint rate (~4/s) means the
    upstream is *ramping* the watermark — feeding a consistent
    slightly-too-fast head that the rate bound admits — so clearing the
    cursor only buys time until the endpoint is replaced. A flat drop
    counter means a one-shot jump instead. See the residuals in
    [`../specs/ocs-verified-sui-reads.md`](../specs/ocs-verified-sui-reads.md).
  - **Cursor BEHIND the chain head with
    `ika_ocs_watermark_implausible_total{consumer="folder"}` climbing →
    the rate bound is refusing the upstream's samples.** Either the
    endpoint really is reporting an unexplainable head (check it), or
    the process was paused/suspended for longer than the bound's burst
    covers (~an hour of production) — the bound uses monotonic time,
    which does not advance while a host is suspended. It heals on its
    own at a few checkpoints per second, and a **restart clears it
    outright** (the bound is in-process state, re-seeded at start). Do
    NOT clear the cursor row here; the cursor is fine.

  Mechanism, both bounds, and the full recovery note:
  [`../specs/ocs-verified-sui-reads.md`](../specs/ocs-verified-sui-reads.md)
  ("Reading the head").
- **Verify the chain you query is the chain the network used.** Stale
  config files (object ids from a previous run) and multiple listeners
  on one port have both produced hours of false "the object doesn't
  exist" leads. Get ids from the run's own publish output.
