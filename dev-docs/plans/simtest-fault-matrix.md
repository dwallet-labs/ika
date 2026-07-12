# Simtest fault matrix — deterministic edge-case coverage under the crypto mock

Status: landed (2026-07-11, PR #1808) — suite green in CI (Simtest run
29145489698: 6/6 passing on the enabled suite; 3 seeded reproducers of
open findings marked #[ignore], evidence below).

## Motivation

msim's price was always that every simulated validator shares one OS
thread, which made real class-groups MPC prohibitively slow — so simtest
stayed a single smoke test. The `dwallet-mpc-unsafe-mock` feature removes
exactly that cost (constant keys, no threshold crypto, memoized setup),
and `ika-test-cluster`'s dev-dependency self-reference already builds the
crate's tests with the mock. Under msim, time is also virtual — it jumps
when all tasks idle — so epoch churn is nearly free.

What simtest uniquely adds over the crate's `#[tokio::test]` suite:

- **Deterministic seeds** — a failure replays exactly
  (`MSIM_TEST_SEED=<n>`).
- **Seed sweeps** — each seed is a different task/message interleaving;
  one test × N seeds = N distinct schedules.
- **Surgical fault injection** — kill/restart/partition/delay at precise
  moments relative to protocol events.

This stays inside the repo convention: `#[sim_test]` targets
scheduling/ordering nondeterminism. Every test below exists because a
real ordering-dependent failure of that shape has occurred (or is one
fault away from one we have seen).

## Explicit non-goals (mock limits)

Mock outputs are constant, so simtest CANNOT cover: crypto correctness,
output byte-divergence, or malicious-conviction flows (all outputs are
identical under the mock). Those stay in the real-crypto
`dwallet_mpc::integration_tests` harness and the crypto crates' unit
tests. Simtest covers coordination, timing, and liveness only.

## Phase 0 — Calibration

- Measure the existing smoke test under `cargo simtest` with the mock
  (wall time per epoch; confirm virtual time compresses idle waits).
- Confirm via the sim build that the mock feature actually unifies into
  the test binaries (dev-dep self-reference path).
- Pick sim-test epoch-duration constants from the measurement.
- Record numbers in this doc.

Calibration result (2026-07-10, M-series laptop, seed 1):
`sim_swarm_reaches_epoch_2` (4 validators, 10s ika epochs) PASSES under
msim in ~205s wall — boot (genesis + publish + network DKG under mock)
dominates; epoch crossings themselves are cheap. The historical
OCS-state-sync-under-madsim failure did not manifest. Budget
implication: ~3.5 min per boot-fresh sim test; nextest runs test
binaries in parallel, so a ~15-test suite fits the ~25-minute target
with per-file parallelism; prefer several scenarios per booted cluster
where independence allows.

## Phase 1 — Harness fault toolkit (`ika-test-cluster`)

Primitives on `IkaTestCluster`, `cfg(msim)`-gated where msim-specific:

- `kill_node(idx)` / `restart_node(idx)` — already partially present via
  the swarm (restart_mid_grace test); promote to first-class helpers with
  an "at event" form (epoch boundary observed, session lock observed).
- `partition(node_set, duration)` / `heal()` — sui-simulator network
  APIs.
- Per-link latency injection.
- Delayed-start (laggard) validator — one node's components start
  seconds after the rest at an epoch boundary. This is the epoch-entry
  key-gap shape (issue #1736) as a reusable primitive.
- Flow drivers the lib currently lacks (only dwallet DKG + network-key
  DKG exist today): presign (pooled global + dedicated), sign,
  future-sign, imported-key, transfer, make-user-share-public. All
  driveable in Rust because `dwallet-mpc-centralized-party` forwards the
  mock, so both 2PC halves agree.
- Invariant probes: chain reads for the end-of-publish gate conditions,
  session-lock target vs completed counts, internal presign pool sizes —
  tests must assert the specific property, not just "epoch advanced".

## Phase 2 — Flow × fault matrix

Order of implementation: Group B first (each test guards a known real
bug), then A, then C.

### Group B — named races with a real failure behind each

| Test | Fault | Property asserted |
| --- | --- | --- |
| laggard_entry_window | one validator's start delayed at epoch entry | VSS refills fail ONLY as not-ready (never InvalidParameters), pools heal after ingestion, no wedge |
| stale_batch_expiry_refire | partition isolates a refill batch's messages past the expiry | batch presumed dead exactly once, counters reconciled, refire completes after heal |
| held_vote_repull_across_epoch | user presign lands inside the close-lock window | held vote is re-pulled and completes in the NEXT epoch (the "re-pulled next epoch otherwise" promise) |
| close_lock_undershoot | kill a validator that holds in-target work at the lock | epoch still closes (no strict-equality wedge), completed==target |
| handoff_barrier_restart | restart a validator mid-handoff-fetch | it blocks on the prepare barrier, enters late, no stale-share signing |
| two_laggards_one_epoch | two delayed validators in one entry window | quorum survives via retries; epoch closes (the historical quorum-death shape) |

### Group A — every user flow across epoch churn

Each flow (dkg, presign pooled+dedicated, sign, future-sign,
imported-key, transfer, make-public) spanning at least two
reconfigurations, seed-swept. Asserts flow completion AND
pool-refill-every-epoch (permanent regression net for the presign
starvation fix).

### Group C — generic churn sweeps

- f=1 kill during each of {network DKG, reconfiguration, lock window,
  end-of-publish}; restart before the next boundary.
- Partition-then-heal straddling an epoch boundary.
- Joiner arriving at adversarial timings relative to the freeze.
- Protocol-version transition with a mid-transition restart.

## Phase 3 — CI shape

- Dispatch: 1 seed (fast gate). Nightly: seed sweep (10–25 seeds),
  printing each seed so any failure is a one-line local replay.
- Budget target: full sim suite under ~25 minutes.
- The simtest workflow keeps `--no-tests=pass` (harmless once targets
  exist) and gains a seed-count input.

## Phase 4 — Prove the tests bite

Per `dev-docs/playbooks/test-testing.md`: every Group B test gets a
fault injection expected to trip it (e.g., locally reverting the
stale-batch expiry must fail `stale_batch_expiry_refire`), the expected
log evidence is confirmed, then the injection is reverted. Update
`dev-docs/conventions/simtest.md` ("slow by design" is no longer true
under the mock) and CLAUDE.md's simtest pointer when the suite lands.

## Progress log

- [x] Phase 0 calibration numbers (sim smoke passes: 205s, seed-deterministic)
- [x] Phase 1 stop/start/handle/poll_until primitives (flow drivers pending)
- [x] Group B: laggard_entry_window, two_mpc_degraded, dkg_inside_degradation (vacuity-guarded), degradation_across_close
- [x] Group A: dkg flow under fault; presign traffic (pure form is reproducer #3 — open close-race)
- [x] Group C: restart_during_reconfiguration (further churn sweeps = follow-on work)
- [x] CI wiring: sim_ default filter, seed sweep via test_num, rust_log input (info default), 3600s virtual cap
- [x] Test-testing evidence: vacuity guards embedded in the fault-leg tests, plus seven recorded instances of the suite failing on real misbehavior during development (swarm unwrap, syncer-guard hazard, presign close race) — the tests demonstrably bite. Docs updated (simtest.md, this plan).

## Phase 1 implementation notes (living)

- Restart primitive: promote restart_mid_grace's pattern — access via
  `cluster.swarm.node(name)` → `stop()` / `start()`; state probes via
  short-lived `get_node_handle()` (NEVER hold an `IkaNodeHandle` across
  a stop/start: it is a strong Arc keeping RocksDB open, and the respawn
  dies on the held store LOCK). `poll_until` (100ms tick, deadline) is
  the event-predicate driver for kill-at-event forms.
- Fail points: ika-core already compiles `sui_macros::fail_point_async`
  into `sui_connector/sui_executor.rs` and `consensus_handler.rs`;
  sim tests can `register_fail_point_async` to delay/abort at those
  hooks — the surgical mechanism where network faults are too blunt.
- Under the sim runner, plain `#[tokio::test]`s are listed but ignored
  (22 skipped) — `#[sim_test]` is the only runnable form; sui-macros is
  already a cfg(msim) dep of ika-test-cluster with the static-init
  wiring in place.

## Finding: simultaneous dual validator restart stalls the cluster (under investigation)

`sim_two_laggards_one_epoch` (stop 2 of 4 mid-epoch, restart both 5s
later) NEVER leaves epoch 1 within the 1000-virtual-second sim_test
budget (SUI_SIM_TEST_TIMEOUT_SECS default). Ruled out: RocksDB
lock-across-restart, node panics. Observed: no consensus rounds in the
log tail — consensus does not resume after the simultaneous dual
restart (2-of-4 halts Mysticeti as expected; the question is why the
two returners never re-form a quorum). Discriminators queued:
staggered restarts (one rejoins fully before the second stops being
needed) and a 3000s budget (slow-vs-never). Single-validator
stop/restart across a boundary (sim_laggard_entry_window) PASSES —
the stall is specific to the dual outage.

Update: staggered restart + 3000-virtual-second budget ALSO never
recovers — "never", not "slow". Scenario reclassified: stopping 2 of 4
halts CONSENSUS itself (sub-quorum for Mysticeti), which is NOT the
historical two-laggards shape (consensus alive, laggards MPC-degraded).
Node-stop test kept as an #[ignore]d reproducer of the open
full-halt-recovery question (msim-only vs real — undetermined). The
faithful Group B scenario will degrade the MPC computation path on two
nodes via sui_macros fail points (hook to be added in the computation
spawn path) while consensus keeps committing.


## Finding: post-degradation recovery tail is minutes long (open follow-up)

`sim_presign_traffic_with_degradation_window` (seed 1, CI): after the
two-validator MPC-degradation window heals, the epoch hosting the
backlog takes ~6 VIRTUAL MINUTES to complete its network-key
reconfiguration and close (healthy epochs: seconds). The first gate
run failed purely on budget — EndOfPublish markers appear at
02:14:25/02:14:35 with the 420s budget expiring at 02:15:13. Budgets
raised (test 900s, SUI_SIM_TEST_TIMEOUT_SECS 3600); WHY the skipped-
computation retry backlog drains that slowly is worth its own
investigation (retry cadence? per-round pacing of pending computations?).

Update: the slow tail is WORSE than first read — with a 900s budget and
the 3600s virtual cap the wide-window variant still fails (two more CI
runs), and the guard-scoping fix in the syncer (correct hardening,
kept) did not change it. No stuck-gate warn fires, so the close is
timer-paced through a backlog rather than pinned on one condition; the
prime suspect is the NOA-checkpoint/session backlog accumulated while
2-of-4 validators were MPC-dead, drained at full tick intervals per
item in virtual time. The PASSING test now uses a one-submission
window; the wide window is preserved as
sim_presign_long_degradation_reproducer (#[ignore]) pending the
backlog-drain investigation.

RESOLVED: the "slow post-degradation recovery" is the internal-presign
stale-batch expiry doing its job at a DIFFERENT wall-time scale: the
constant is 3000 consensus rounds (loaded-CI localnet ~20 rounds/s ->
~2.5 min), but msim's virtual round rate is ~4/s -> ~12.5 virtual
minutes of pool starvation before the expiry releases the dead refill
batch — beyond every budget tried, with the gate correctly reporting
all_epoch_sessions_finished=false (the in-window presign vote waiting
for a servable pool; serving retries correctly each round). Everything
self-heals; no liveness bug. Sim tests now override the expiry to 300
rounds via the protocol-config test setter, which ALSO makes the suite
exercise the full expiry->refire->serve->close recovery path in-budget
(Group B's stale-batch scenario realized inside the presign test).
FOLLOW-UP (production consideration): the expiry constant's wall-clock
meaning varies ~6x with consensus round rate across environments;
consider documenting the intended envelope on the config field.

REVISED — the presign-during-degradation stall is an OPEN BUG, the
suite's strongest find: with the expiry overridden to 300 rounds (~75
virtual seconds) the epoch STILL never closes (four schedule variants,
900s budgets), all_epoch_sessions_finished=false alone. The
expiry-scale explanation was necessary but not sufficient; a presign
vote agreed during a sub-quorum window leaves a locked-set session
that never completes after heal — same shape as the historical
"held vote never re-pulled" core. Enabled suite carries pure
presign-traffic-across-boundaries (passes); the degradation variants
are ignored reproducers. THIS IS THE TOP FOLLOW-UP: diagnose with the
gate-breakdown info logging (now default) + a single-test dispatch at
rust_log info on the reproducer.

FINAL for this PR — the presign scenario is msim-reproducible WITHOUT
any fault injection: pure traffic astride close-locks pins
all_epoch_sessions_finished=false (100 presigns served, zero holds,
one locked-set session never completes; 840+ stuck virtual seconds;
seven schedule variants). The tokio twin passes on real timing — a
narrow scheduling-sensitive race in the close/serve interplay, exactly
the class simtest exists to surface. All three presign variants are
now #[ignore]d reproducers with deterministic seeds; the enabled suite
is six passing scenarios. TOP FOLLOW-UPS, in order: (1) the presign
close race (this), (2) full-consensus-halt recovery (dual node stop),
(3) expiry round-rate envelope documentation.

## ROOT CAUSE FOUND + FIXED: the close-lock wedge was the checkpoint pusher skipping unfetchable checkpoints

Cornered via the `sim_user_flows` reproducer with full sui_connector
debug logging (deterministic seed): the OCS checkpoint pusher
(`push_worker.rs`) polled the certified head every tick and, on a
full-checkpoint fetch failure, **advanced its cursor past the
checkpoint forever** ("fetch failed; advancing past"). The newest 2–3
checkpoints of every poll window routinely 404 (contents materialize
after the summary certifies — msim's virtual-time cadence makes this
constant; the skips repeat every ~10s poll, in identical bursts on all
four validators). Every skip left a PERMANENT gap in the verified state
cache the bag event pump reads: a `session_events` bag entry whose
creating checkpoint was skipped never entered any validator's cache, so
the pump never delivered the request to the fresh epoch's manager, the
session never ran, and `all_epoch_sessions_finished=false` pinned the
epoch forever. The 4,443 "served the committee-verified cached snapshot
(pusher behind)" fallback warns during the wedge were the same rot from
the read side, and the stale coordinator reads explain the "quiet-epoch
close-target starvation" latency shape too (the manager's synced close
target came from a stale cached coordinator).

FIX: the pusher now STOPS the scan at a failed fetch and retries the
same checkpoint next tick (in-order folding preserved; contract unit
tests rewritten to assert retry-and-recover, including the recovery of
an end-of-epoch checkpoint on a previously failed seq). The
FAR_BEHIND_THRESHOLD fast-forward remains the explicit escape valve for
genuinely pruned history; STALL_THRESHOLD warns cover the stretch in
between. All four `#[ignore]`d reproducers are re-enabled to guard the
fix end-to-end.

## Finding (superseded by the root cause above): the close-lock wedge is reachable from a single user request (flow-coverage PR)

The happy-path flow suite (PR #1809, `sim_user_flows.rs` /
`sim_future_sign.rs`) hit the same close/serve wedge WITHOUT presign
traffic: the flow runs ~ten sequential user sessions against 20-second
epochs, so on most msim schedules one of them lands astride an epoch
close — and a user MPC session locked into the close target astride
the close left the next epoch permanently unable to advance
(`session_locked=true`, `all_epoch_sessions_finished=false`, pinned
9.5+ virtual minutes to test end). The visible victim varies by
schedule (the imported-key verification on one run, the imported-key
dwallet's dedicated presign on another — msim schedules shift with the
log configuration). `sim_user_flows_across_boundaries` is preserved as
an `#[ignore]`d reproducer of this — a much cheaper route into the bug
than the traffic reproducer (one request, no stream).

Two adjacent latency findings from the same investigation, real but
non-wedging:

- **Quiet-epoch close-target starvation**: a session excluded from the
  close target (correctly, for arriving astride the lock) is starved
  for the ENTIRE next epoch when that epoch is quiet — on-chain,
  `update_last_user_initiated_session_to_complete_in_current_epoch`
  only runs on session initiate/complete, so nothing recomputes the
  target between locks in an idle epoch. Off-chain the manager mirrors
  the stale value and holds votes/sessions against it. Cost: roughly a
  full epoch of latency per unlucky request (24h on mainnet).
  Deterministically reproduced (seed 1): an imported-key verification
  requested astride a close reached output quorum ~295 virtual seconds
  (≈ one 20s-epoch cycle plus closes) after the request.
- **Global presign astride a close**: same shape observed for the
  pool-served path — the serve vote is held all of the following quiet
  epoch and pops only at the next close's lock recomputation.

Ruled out (2026-07-12, deterministic A/B on the `sim_user_flows`
reproducer, single-test dispatches, default log config): the wedge is
NOT closed by main up to 496bc2fc55, nor by the internal-presign
entry-window fixes #1818 (park on not-ready instead of terminal
failure) + #1819 (sequence-counter uniformity under install lag) — with
both merged in, the run still pins the epoch (`session_locked=true`,
`all_epoch_sessions_finished=false`; the victim session shifted from
the imported-key verification to the dedicated presign, the usual
schedule sensitivity). Those PRs fix a different family (system-session
entry-window races); the user-session close-lock wedge and the
quiet-epoch close-target starvation remain open.

The flow suite also produced harness knowledge worth keeping: the
pinned Sui renders Move enum values in object JSON WITHOUT a variant
tag ({type, fields} only), so fieldless variants are unobservable —
completion waits must match output-field presence, retry the follow-up
transaction (abort = still pending), or read BCS state
(`wait_for_user_sessions_drained`). See the drivers in
`crates/ika-test-cluster/src/flows.rs`.
