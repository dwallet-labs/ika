# Simtest fault matrix — deterministic edge-case coverage under the crypto mock

Status: active (2026-07-10). Branch `test/simtest-fault-matrix`
(from `origin/main` at the internal-presign expiry fix).

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
- [ ] Group B tests (1/6: laggard_entry_window PASSES, 285s)
- [ ] Group A tests
- [ ] Group C tests
- [ ] CI wiring
- [ ] Test-testing evidence + doc updates

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
