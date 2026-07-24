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
gh run download <run-id> -n <artifact>   # localnet-logs / cluster-tests-log-<attempt> / rust-tests-log-<attempt>
```

## Upgrade test (out-of-process harness; release validation is MANUAL)

`.github/workflows/upgrade-test.yaml` runs the out-of-process harness
(`crates/ika-upgrade-test/`) — real, separately-compiled `ika-validator`
child processes against an external `sui` localnet. Manual dispatch remains
available. Pull requests that touch MPC, crypto dependencies, serialization,
protocol configuration, the upgrade harness, or `Cargo.lock` automatically
run the `workload` scenario rather than the entire matrix.

> **The release workflow no longer runs any suite (changed 2026-07-23, PR
> #1891).** It previously called this workflow with the candidate SHA and
> blocked tag publication on `v118_mixed_rollout`; that job was removed, so
> a release tag now builds, uploads and drafts **unconditionally**.
> Validating a release candidate is a manual step: dispatch this workflow
> (all three current-build scenarios) plus the cluster and Rust-integration
> suites against the exact tagged SHA and record the runs in the draft's
> Validation section (the notes scaffold prompts for it). A release whose
> notes carry no such record is unvalidated. NOTE: with the rollout
> rehearsal scenarios retired (below), there is currently NO dispatchable
> literal-old-binary cross-binary evidence — a release that must
> interoperate with deployed binaries during a rolling swap needs that
> machinery rebuilt from git history first.

It is not part of `scheduled-all-suites.yaml`. The contract it verifies is
[`../specs/cross-binary-upgrade.md`](../specs/cross-binary-upgrade.md).

**Retired scenarios (protocol v3/v4 support removal):** the cross-binary /
literal-old-binary rollout rehearsals — `cross_binary`,
`malicious_cross_binary`, `v118_upgrade`, `v118_churn`, `v118_mixed_rollout`,
`v121_rollout` — were deleted when `MIN_PROTOCOL_VERSION` moved to 5: the
current binary shares no protocol version with those literal old binaries,
so their topologies cannot boot. They rehearsed the mainnet-v1.1.8→v4 and
testnet-v1.2.1→v5 rollouts, both long completed. When the next version
boundary (v6) needs a rolling-upgrade rehearsal, rebuild the OLD-binary
machinery from git history (this playbook and the workflow before this
change document it, including the `cross_binary` 96 GiB runner-OOM
forensics and its infra fix).

```bash
# `test` selects scenarios: 'all' (the default) fans EVERY scenario out as its
# own matrix job on its own runner, in parallel (fail-fast off). Pass a
# comma-separated subset to run several, or a single name to run one. All
# scenarios need only the current build and run --test-threads=1.

# Everything in parallel (default), or a subset:
gh workflow run upgrade-test.yaml --ref <branch>                       # = test=all
gh workflow run upgrade-test.yaml --ref <branch> -f test=smoke,workload

# Plumbing go/no-go (fastest): 4 same-binary processes reach epoch 2.
gh workflow run upgrade-test.yaml --ref <branch> -f test=smoke

# Full user DKG -> Presign -> Sign on-chain (genesis protocol v5).
gh workflow run upgrade-test.yaml --ref <branch> -f test=workload

# Old-style (1.1.8-shape, JSON-RPC-only) YAML configs for every role.
gh workflow run upgrade-test.yaml --ref <branch> -f test=legacy_config

# Loaded runner slack: bump epochs.
#   -f epoch_duration_ms=600000

# Artifacts: upgrade-test-log-<test>-<attempt> (test stdout),
# upgrade-test-node-logs-<test>-<attempt> (per-validator *.log),
# resource-sampler-<test>-<attempt> (15s CPU+memory samples; recovered only on
# runs that FINISH — a runner death drops it like every other artifact).
```

### Scenario differences

All scenarios genesis at `ProtocolVersion::MIN` (= MAX = 5) with one
notifier + a validator committee:

| Scenario | Binary topology | Primary invariant |
|---|---|---|
| `smoke` | current only | process harness reaches epoch 2 |
| `workload` | current only | user DKG → Presign → Sign completes on-chain |
| `legacy_config` | current only | old JSON-RPC-only configuration remains accepted for every role |

### CI runner resources

The self-hosted `ika-k8s-large` pods report 96 host cores, an 80-CPU CFS
quota, a **96 GiB pod memory limit**, and no swap. Each idle `ika-validator`
runs ≈7.5–8 GB RSS, so co-locating many validators approaches the pod limit —
the deleted `cross_binary` scenario (5–6 validators) reproducibly OOM-killed
the runner at that limit (`OOMKilled`/137; forensics in this playbook's
pre-#1751 history). The remaining 4-validator scenarios fit comfortably.

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
