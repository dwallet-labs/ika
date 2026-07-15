# Running the heavy suites on CI instead of locally

The heavy suites have dispatchable workflows on the `ika-k8s-large`
self-hosted runners (80 vCPU; measured at full per-thread parity with an
M3 Max). Prefer these over hours-long local runs — they parallelize,
don't tie up a laptop, and upload logs as artifacts for post-mortem.

See also: a green run is not proof on its own. Before trusting one on a
high-stakes, hard-to-trigger property (cross-binary state continuity,
malicious-party detection, epoch-boundary invariants), confirm the test
isn't passing vacuously — [`test-testing.md`](test-testing.md) (the exit
code is not the assertion; the log is).

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

## Upgrade test (release gate and focused PR check)

`.github/workflows/upgrade-test.yaml` runs the out-of-process cross-binary
upgrade harness (`crates/ika-upgrade-test/`) — real, separately-compiled
`ika-validator` child processes against an external `sui` localnet, swapped
across epochs. Manual dispatch remains available. Pull requests that touch
MPC, crypto dependencies, serialization, protocol configuration, the upgrade
harness, or `Cargo.lock` automatically run the focused literal-v1.1.8 mixed
rollout rather than the entire matrix. The release workflow calls the same
reusable workflow with the exact candidate SHA and blocks tag publication on
that scenario. It is not part of `scheduled-all-suites.yaml`. The contract it
verifies is
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

# Coordinated full-committee rehearsal: boot literal mainnet-v1.1.8, then
# sequentially swap all validators to current before the tested reshare.
# before a mainnet upgrade (builds the tag at its own old toolchain).
gh workflow run upgrade-test.yaml --ref <branch> -f test=v118_upgrade
#   override the old tag:  -f old_ref=tag-or-sha  (defaults to mainnet-v1.1.8)

# Release-blocking decentralized rollout: one current validator and three
# literal v1.1.8 validators remain mixed through two protocol-v3 network-key
# reconfigurations. Real crypto and production presign-pool sizing are forced;
# its >=8-minute epoch reserves the bounded restart before the midpoint.
gh workflow run upgrade-test.yaml --ref <branch> -f test=v118_mixed_rollout \
  -f candidate_sha=<exact-candidate-sha>

# Test-test the release gate with the repository's compiled-in, feature-gated
# one-validator reconfiguration-message fault. This run is expected to fail;
# its logs must show the exact zero-malicious or output-convergence assertion.
gh workflow run upgrade-test.yaml --ref <branch> -f test=v118_mixed_rollout \
  -f candidate_sha=<exact-candidate-sha> -f test_testing_fault=true

# Loaded runner slack: bump epochs for the upgrade scenarios.
#   -f epoch_duration_ms=600000

# Artifacts: upgrade-test-log-<test>-<attempt> (test stdout),
# upgrade-test-node-logs-<test>-<attempt> (per-validator *.log),
# resource-sampler-<test>-<attempt> (15s CPU+memory samples; recovered only on
# runs that FINISH — a runner death drops it like every other artifact).
```

### Scenario differences

All scenarios genesis at **protocol v3** (a v4 *genesis* DKG is rejected
forever — the network must upgrade *into* v4) with one notifier + a validator
committee. They differ in the OLD binary, how it is swapped, and what
continuity they prove:

| Scenario | Binary topology at tested reshare | Protocol transition | Primary invariant |
|---|---|---|---|
| `smoke` | current only | none | process harness reaches epoch 2 |
| `workload` | current only | v3 → v4 | user DKG → Presign → Sign survives activation |
| `cross_binary` | current source plus current source pinned to max v3 | v3 → v4 | current-source wire compatibility and multi-epoch churn |
| `v118_upgrade` | literal v1.1.8, then every validator sequentially restarted onto current before the tested reshare | v3 → v4 | historical RocksDB/key continuity and pre-activation global presign |
| `v118_churn` | current only by the tested churn reshare | v3 → v4 | v1.1.8-origin key reshared to a new post-upgrade validator |
| `v118_mixed_rollout` | **one current + three literal v1.1.8** for two reshares | held at v3 | exact production rollout topology, zero false-malicious results, no stranded validator/session, canonical 4-of-4 output convergence |
| `legacy_config` | current only | v3 → v4 | old JSON-RPC-only configuration remains accepted |

`stop_and_swap([0, 1, 2, 3])` is sequential: it restarts and health-checks
each process before moving to the next. Therefore `v118_upgrade` and
`v118_churn` are coordinated full-committee replacement tests, not atomic
restart tests, and they replace every validator before intentionally crossing
their tested reshare. `v118_mixed_rollout` closes that gap by swapping only
validator 0, explicitly witnessing the reconfiguration start after the swap,
and retaining the other three literal historical processes through completion.

On-chain epoch advancement is deliberately not a success criterion for the
mixed scenario. A 3-of-4 old-binary majority can continue while the upgraded
validator is divergent or self-convicted. The test additionally requires local
epoch and health on all four processes, exact protocol-v3 ceilings, zero
malicious reports and self-malicious logs, completed on-chain and local session
accounting, and the same canonical output digest from all four authorities.

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
code**. The mechanism is now proven — a cgroup OOM-kill at the pod's 96 GiB
memory limit (`OOMKilled`/137); see the findings and the fix below.

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
  setup time varies between jobs, yet the job is marked failed at a
  near-constant **~29 min into the *Run* step** (≈1760 s). One job with +108 s
  longer setup still died at the same *run-relative* time — so it tracks the
  scenario, not pod age. Refinement from `kubectl`: the **actual OOM is ~20 min
  into the Run step** (peak 5→4 reshare / second MPC lifecycle); GitHub's "lost
  communication" then **lags the real kill by ~9–10 min** (its heartbeat-loss
  timeout), which is the ~29 min figure. Rules out a max-lifetime/eviction timer.
- **CPU starvation is refuted.** The sampler shows the heavy scenarios peak at
  **~13 of the 80-CPU quota** with **zero in-window CFS throttling**
  (`nr_throttled` flat). The runner agent always had schedulable CPU;
  `rayon_threads_per_node` (#1770) already keeps threads well under quota.
- **Memory-OOM is CONFIRMED (2026-06, via `kubectl`).** The runner pod ends
  `State: Terminated, Reason: OOMKilled, Exit Code: 137` — the kernel OOM-killer
  fired at the pod's **own 96 GiB cgroup limit** (`limits.memory=96Gi` on the
  ARC runner). "Runner lost communication" is just the downstream symptom (the
  OOM killed the runner container). It is **not** node pressure: the node
  (`ika-worker-8`, 125 GiB) was at 17 %. `kubectl top` traced the climb to the
  kill (steady ~24–36 GiB through the churn, then 24→54→56→66 GiB in the final
  5 min). Note `top` reports `working_set`, which under-reads the cgroup
  `memory.current` that triggers OOM, so its ~64 GiB peak is low — the
  `OOMKilled`/137 status is ground truth that `memory.current` hit 96 GiB.
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

**How it was confirmed — `kubectl`, not on-pod (every on-pod channel is wiped by
the death):** the in-pod sampler measured **each `ika-validator` ≈ 7.5–8 GB RSS**
(idle, from a surviving `smoke` run), but the death itself can't be read on the
pod — a runner death **wipes the job's runner-emitted `::warning::` annotations**
(a surviving `smoke` shows the sampler's startup line; a dead `cross_binary` with
the identical line shows none — only GitHub's backend "lost communication"
annotation remains), and drops the artifacts + job log too. The off-pod read is
the one that works: with `kubectl` on the runners' cluster (`ika-prod-netbird` —
NetBird must be up),

```bash
# while the cross_binary job runs, find its ephemeral runner pod + node:
kubectl get pods -n github-actions -o wide | grep ika-k8s-large
# trace memory live (metrics-server; survives the pod death):
kubectl top pod -n github-actions <pod>       # poll every ~20s
# after death — the smoking gun:
kubectl describe pod -n github-actions <pod> | grep -A3 'Last State'
#   -> State: Terminated  Reason: OOMKilled  Exit Code: 137
```

`OOMKilled`/137 at the pod's **96 GiB cgroup limit** is the confirmed cause; the
node (125 GiB, 17 % used) had headroom, so it is the pod limit, not eviction.
`max_mpc_computation_cores=1` + 10 min epochs **still OOM'd** (run 28062374647) —
the pressure is the **baseline per-validator footprint × 5–6 validators**, not
MPC transient, so the cap can't fix it.

**The fix (infra — the ARC `ika-k8s-large` `AutoscalingRunnerSet` in
`github-actions`):** the runner template is `requests.memory=16Gi
limits.memory=96Gi`, no `nodeSelector`, max 8 runners. cross_binary's peak demand
is **> 96 GiB** (it died *at* the limit; true peak unmeasured). Because the
*request* is only 16 GiB the scheduler can pack several bursting runners onto one
125 GiB node, so **raising the limit alone risks a node-level OOM** — raise the
*request* too (so heavy runners don't co-schedule), or pin cross_binary to the
**377 GiB node `ika-worker-51`** (the rest are 125 GiB) via `nodeSelector` and a
~150 GiB limit (which also reveals the true peak). Until then, `v118_churn` (one
joiner from a real 1.1.8 origin) already passes and covers the OCS joiner-anchor
path, so only cross_binary's heavier synthetic coverage is blocked. Note: on a
runner death, artifacts, the live step log, **and** runner-emitted annotations
are all lost — only pre-test step logs survive, and the live `kubectl top` /
post-mortem `describe` above are the diagnostic channels.

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
  everything — the live step log is lost too (the job-log blob 404s), and
  even runner-emitted **`::warning::` annotations are wiped** (only GitHub's
  own backend "lost communication" annotation remains; proven by a surviving
  vs dead run emitting the identical startup warning). The **only** channels
  that survive a death are pre-test step logs and anything pushed OFF the pod
  before it dies (kubelet/dmesg on the node, or a token-push). That is also
  why failure replays stay inline in the cluster workflow.
- **`exit code 100`** from the cluster job is nextest's tests-failed
  code (real failures, artifacts present) — distinct from runner death.
- **Cluster parallelism is memory-bound**: 4-way is the validated
  default; 8-way OOM-kills the 96Gi pod and presents as runner death.
- **dwallet-MPC integration tests are CPU-bound — isolate them locally**:
  each `dwallet_mpc::integration_tests` case drives real class-groups MPC
  across an in-process committee, so run alongside the rest of a
  `cargo test -p ika-core` suite under default parallelism they fail
  spuriously (proven: 24 "failures" in a full-crate run, all green run
  isolated — likely CPU oversubscription starving the MPC round timers,
  NOT a `--features test-utils` issue). CI dodges this with the separate
  `test_threads=4` job above; locally, filter to the target test(s) or
  pass `--test-threads=N`, and never read a regression from a heavy-MPC
  failure inside a full-crate run.
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
