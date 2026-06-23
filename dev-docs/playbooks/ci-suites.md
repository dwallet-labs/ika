# Running the heavy suites on CI instead of locally

The heavy suites have dispatchable workflows on the `ika-k8s-large`
self-hosted runners (80 vCPU; measured at full per-thread parity with an
M3 Max). Prefer these over hours-long local runs — they parallelize,
don't tie up a laptop, and upload logs as artifacts for post-mortem.

## Nightly orchestrator

`.github/workflows/scheduled-all-suites.yaml` runs every night at 03:00
UTC (and on `workflow_dispatch`). It fans out over `branch: [main, dev]`
× the four heavy suites below and dispatches each via `gh workflow run`
with that suite's default inputs. It only *dispatches* — each run reports
under its own workflow (Test Cluster / Integration Tests CI / TS
Integration Tests / Simtest) on the targeted branch, with its own logs.

Caveat: GitHub fires `schedule:` triggers only from the repository
DEFAULT branch (`main`). Until this orchestrator also lands on `main`,
the nightly cron does not run; `workflow_dispatch` works from any branch
it exists on.

## Dispatch commands

```bash
# Rust dwallet-MPC integration tests (~48 tests, ~35 min at 4 threads).
# Optional: test_filter (suffix after dwallet_mpc::integration_tests::),
# rust_log, scope=all for the whole workspace.
gh workflow run integration-tests-ci.yaml --ref <branch> \
  -f test_threads=4 [-f test_filter=network_dkg::test_network_dkg_full_flow]

# Cluster tests (in-process Sui+ika swarm tests via nextest,
# process-per-test, ~35-40 min at 4 threads; 8-way OOMs the 96Gi pod).
# test_filter is a nextest positional filter: it matches test FUNCTION
# names (test_validator_restart_...), NOT the test file stem — a
# file-stem filter silently runs 0 tests and the job fails with
# "no tests to run".
gh workflow run test-cluster.yaml --ref <branch> [-f test_filter=<fn-name>]

# Full TypeScript SDK integration suite against one Sui + ika localnet
# (9 files, ~60 min + ~10 min localnet readiness). For diagnosing
# localnet-side issues, pass debug logging — the artifact then carries
# a full MPC trace:
gh workflow run ts-integration-tests.yaml --ref <branch> \
  [-f test_filter=<file-stem>] \
  [-f localnet_rust_log="warn,ika=info,ika_node=info,ika_core=info,ika_core::dwallet_mpc=debug,ika_core::sui_connector::sui_executor=debug,ika_core::sui_connector::sui_syncer=debug"]

# Simtest (msim determinism; slow by design — see conventions/simtest.md).
gh workflow run simtest.yaml --ref <branch>

# Watch / fetch results
gh run watch <run-id>
gh run download <run-id> -n <artifact>   # localnet-logs / cluster-tests-log-<attempt> / rust-tests-log
```

## Upgrade test (run-when-needed, not in the nightly fan-out)

`.github/workflows/upgrade-test.yaml` runs the out-of-process cross-binary
upgrade harness (`crates/ika-upgrade-test/`) — real, separately-compiled
`ika-validator` child processes against an external `sui` localnet, swapped
across epochs. It is `workflow_dispatch`-only and deliberately NOT part of
`scheduled-all-suites.yaml`: it is a pre-mainnet-upgrade rehearsal and a
check for changes to versioning / serialization / the epoch boundary, not a
per-push gate. The contract it verifies is
[`../specs/cross-binary-upgrade.md`](../specs/cross-binary-upgrade.md).

```bash
# `test` selects scenarios: 'all' (the default) fans EVERY scenario out as its
# own matrix job on its own runner, in parallel (fail-fast off, so one
# scenario's failure/runner-death doesn't cancel the others). Pass a
# comma-separated subset to run several, or a single name to run one. Each
# scenario's artifacts/logs are suffixed with its name. smoke/workload need
# only the current build; cross_binary/v118_upgrade/v118_churn also build an OLD
# binary from `old_ref` in a worktree (own toolchain) and run --test-threads=1.
# NOTE: per-run overrides (old_ref/old_max_protocol_version) apply to EVERY
# selected scenario — leave them empty unless you scope `test` to one scenario.

# Everything in parallel (default), or a subset:
gh workflow run upgrade-test.yaml --ref <branch>                       # = test=all
gh workflow run upgrade-test.yaml --ref <branch> -f test=smoke,cross_binary,v118_churn

# Plumbing go/no-go (fastest): 4 same-binary processes reach epoch 2.
gh workflow run upgrade-test.yaml --ref <branch> -f test=smoke

# v3 -> v4 upgrade then a full user DKG -> Presign -> Sign on-chain.
gh workflow run upgrade-test.yaml --ref <branch> -f test=workload

# Rolling swap + committee churn between two wire-compatible builds (the
# default scenario). Defaults build the OLD binary from THIS branch with
# MAX_PROTOCOL_VERSION pinned to 3 — current toolchain, no dependency on an
# old tag still building.
gh workflow run upgrade-test.yaml --ref <branch> -f test=cross_binary
#   override the old side, e.g. a specific commit kept at v3:
#   -f old_ref=<sha-or-branch> -f old_max_protocol_version=3 -f old_bin_name=ika-validator

# Atomic mainnet rehearsal: boot the literal mainnet-v1.1.8 binary, swap all
# to the current build, confirm v4 and continued serving. Pick it explicitly
# before a mainnet upgrade (builds the tag at its own old toolchain).
gh workflow run upgrade-test.yaml --ref <branch> -f test=v118_upgrade
#   override the old tag:  -f old_ref=tag-or-sha  (defaults to mainnet-v1.1.8)

# Loaded runner slack: bump epochs for the upgrade scenarios.
#   -f epoch_duration_ms=600000

# Artifacts: upgrade-test-log-<test>-<attempt> (test stdout),
# upgrade-test-node-logs-<test>-<attempt> (per-validator *.log),
# resource-sampler-<test>-<attempt> (15s CPU+memory samples). Plus, on a
# runner death, the in-Run-step ::warning:: annotations (memory 90/95%,
# oom_kill) survive on the job page when artifacts do not.
```

### Scenario differences — `cross_binary` vs `v118_upgrade` (and the rest)

All four scenarios genesis at **protocol v3** (a v4 *genesis* DKG is rejected
forever — the network must upgrade *into* v4) with one notifier + a validator
committee. They differ in the OLD binary, how it is swapped, and what
continuity they prove:

| | `smoke` | `workload` | `cross_binary` | `v118_upgrade` |
|---|---|---|---|---|
| OLD binary | current build | current build | **this branch pinned to `MAX_PROTOCOL_VERSION=3`** (one-line patch, current toolchain) | **the literal `mainnet-v1.1.8` `ika-node`** from the tag (old toolchain, `--no-default-features`) |
| Binary swap | none | none | **rolling** — one at a time; mixed-binary committees exchange consensus + MPC mid-epoch | **atomic** — all validators at once |
| Committee churn | no | no | **yes** — 4 → 3 → 5 → 4 across epochs (remove, join 2 brand-new validators, remove); a real reshare to a different party set at every boundary | **no** — fixed 4 |
| `GlobalPresignConfig` | n/a | full | **empty** (harness arrangement → routes presign per-dWallet; exercises targeted-presign) | **populated** (mainnet-faithful → global presign; exercises the pre-activation fallback / upgrade-window deadlock guard) |
| Proves | 4 validators reach epoch 2 | one full DKG→Presign→Sign lifecycle | wire-compat + on-disk compat + reshare/churn **between two builds of the same branch** | the **real mainnet 1.1.8 → current upgrade**: local boots against RocksDB **written by 1.1.8**, reshares a key whose DKG bytes were **produced by 1.1.8's crypto**, 1.1.8 dWallets stay usable, global-presign pre-activation fallback (no deadlock) |

**Why the swap style differs:** `cross_binary`'s two binaries are the same
branch differing only in advertised protocol version, so they are
MPC-wire-compatible and a *rolling* swap with mixed committees is valid.
`v118_upgrade` can't do that — this branch single-pins `cryptography-private`,
so a mixed 1.1.8/local committee can't exchange MPC messages; it must swap
**atomically** (a coordinated full-network restart). A *rolling* `cross_binary`
from 1.1.8 is therefore invalid; to get churn from a real 1.1.8 origin you swap
atomically first, then churn — which is exactly **`v118_churn`** (`v118_upgrade`
+ one post-swap joiner: the v4 reshare of the 1.1.8-origin network key then
includes a party that never held it, with no mixed committee).

**Which to use:** `v118_upgrade` is the pre-mainnet-upgrade rehearsal (real
release, real on-disk + crypto continuity); `v118_churn` is the same plus one
joiner. The OCS joiner-anchor path (`add_joiner_validator`) is exercised by two
scenarios — `cross_binary` (synthetic, between two builds of this branch;
**heaviest**: 5-member peak + two MPC lifecycles + multiple joiners) and
`v118_churn` (a single join from a genuine 1.1.8 origin — lighter, and the more
faithful test). All churn scenarios peak at ≥5 validators, so they hit the
runner-resource ceiling below.

### CI runner resources & the `cross_binary` runner-death failure mode

`cross_binary` co-locates 5–6 `ika-validator` processes (4 → 5 with the joiner,
+ notifier), each doing class-groups DKG/presign, on one self-hosted pod — by
far the heaviest upgrade-test. On the current `ika-k8s-large` pods the
**runner "loses communication" and dies**: the job fails with **0 artifacts**
and `Run cross_binary` + all `if: always()` steps **blank** (distinct from a
real nextest failure, which leaves artifacts + exit 100). The *same* death
reproduces on a clean `dev` checkout, so it is the **pod, not any branch's
code**. The mechanism is not yet proven (see the forensic findings below).

What the surviving **"Runner resources"** step reports on these pods (it runs
*before* the test, so its log survives the death):

| | value |
|---|---|
| `nproc` (host cores) | **96** |
| `cgroup cpu.max` (CFS quota) | `8000000 100000` → **80 effective CPUs** |
| `cgroup memory.max` | **96 GiB** |
| swap | **0** |

**What a 2026-06 forensic pass (run 28048024508 + 12 prior `cross_binary`
jobs) actually established — read this before "fixing" it again. Several
earlier confident claims here were wrong:**

- **The death is a deterministic test phase, not an external timer.** Build /
  setup time varies between jobs, yet the death lands at a near-constant
  **~29 min into the *Run* step** (≈1760 s). One job with +108 s longer setup
  still died at the same *run-relative* time — i.e. +108 s later in pod
  wall-clock — so it tracks the scenario, not pod age. ~29 min is the
  peak-concurrency phase (final 5→4 reshare / second MPC lifecycle, 5 resident
  validators). This rules out a runner max-lifetime / kubelet-eviction timer.
- **CPU starvation is refuted.** The sampler shows the heavy scenarios peak at
  **~13 of the 80-CPU quota** with **zero in-window CFS throttling**
  (`nr_throttled` flat). The runner agent always had schedulable CPU;
  `rayon_threads_per_node` (#1770) already keeps threads well under quota.
- **Memory-OOM is the leading suspect but UNPROVEN.** Until 2026-06 *nothing
  measured memory* — the old sampler recorded CPU only, and a runner death
  404s the job log + drops all artifacts, so no dead `cross_binary` pod's
  memory was ever observed. 96 GiB / no swap across 5–6 class-groups
  validators makes OOM plausible, but it is inference, not data. Don't restate
  it as fact.
- **`max_mpc_computation_cores` is NOT a proven fix, and is a CPU lever, not a
  memory one.** It caps *concurrent* dwallet-MPC computations
  (`currently_running < available`, orchestrator.rs) — but each computation
  already fans out across the whole rayon pool (the `parallel` crypto
  feature), so the cap bounds concurrent pool-saturating fan-outs (CPU
  contention), not memory directly. Empirically it changes nothing observable:
  **`v118_upgrade` passes with the cap unset (run 27954982236) and set (run
  28048024508), and `cross_binary` dies either way.** Its earlier billing as
  "the memory axis, complementary to #1770's CPU axis" was wrong — both act on
  CPU. Keep it as a cheap knob; don't rely on it to fix the death.

**To actually diagnose the death:** the sampler is now memory-aware
(`resource-sampler.log`): every 15 s it records `mem=current/max pct=… swap=…
oom_kill=… top=[RSS by process]`, and — because it runs *inside* the Run step —
raises `::warning::` annotations at 90 %/95 % of `memory.max` and on any cgroup
`oom_kill`. Annotations reach the server as the run proceeds, so the last one
before death **survives the "lost communication"** that erases everything else.
Run `cross_binary` once and read the job's annotations: memory climbing to
~96 GiB → OOM; flat memory while CPU pegs → starvation (already unlikely); both
calm at the kill → external eviction. For a definitive answer, also have the
infra owner pull the pod's **kubelet eviction events** and **`dmesg`
OOM-killer** lines — those live on the node, not the (dead) pod.

**Meanwhile, to get `cross_binary` green:** raise epochs for slack
(`-f epoch_duration_ms=600000`); if memory is confirmed, use a bigger-memory
pod or a smaller committee. `v118_upgrade`/`v118_churn` (no / one churn) and
`smoke`/`workload` are lighter and pass. Note: artifacts **and** the live
test-step log are lost on runner death — only the pre-test steps ("Runner
resources", builds) and the in-Run-step `::warning::` annotations survive.

## Facts that save debugging time

- **Concurrency groups cancel in-flight runs**: re-dispatching a workflow
  on the same branch cancels the previous run of that workflow+ref. Don't
  re-dispatch while a run you care about is in flight.
- **Workflow definitions are pinned at dispatch**: a run uses the
  workflow file from the commit it was dispatched on; pushing fixes does
  not affect in-flight runs.
- **Artifacts upload on cancel but not on runner death**: `if: always()`
  steps run when a job is cancelled (so cancelling a doomed run still
  yields artifacts), but a runner-pod death ("The self-hosted runner lost
  communication with the server", log cut off, zero artifacts) skips
  everything — the live step log is lost too (the job-log blob 404s). The
  only channels that survive a death are pre-test step logs and
  **`::warning::` annotations emitted from inside the running step** (the
  upgrade-test resource sampler exploits this for memory). That is also
  why failure replays stay inline in the cluster workflow.
- **`exit code 100`** from the cluster job is nextest's tests-failed
  code (real failures, artifacts present) — distinct from runner death.
- **Cluster parallelism is memory-bound**: 4-way is the validated
  default; 8-way OOM-kills the 96Gi pod and presents as runner death.
- **TS suite known flake**: the pre-existing epoch-entry stale-mpc_data
  race (issue #1736) can wedge a localnet mid-suite. Before attributing
  a TS failure to your change, run the
  [MPC stall post-mortem](mpc-stall-postmortem.md) on the localnet-logs
  artifact.
- **`RUST_BACKTRACE=1` is safe** in workflow env since the
  cryptography-private lazy-error fix (#575, pin `de3cddd`+). If a future
  crypto bump reintroduces suite-wide ~5x CPU with huge sys-time, suspect
  eager `Backtrace::capture()` on hot paths before suspecting hardware
  (see learnings/pitfalls.md).
