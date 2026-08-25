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
available. Pull requests that touch `ika-core/src`, `ika-types`,
`ika-network`, the MPC or crypto crates, protocol configuration, the upgrade
harness, or `Cargo.lock` automatically run the `v140_rollout` deployed-release
gate rather than the entire matrix. Those are whole-crate globs on purpose:
the filter previously listed individual modules and silently stopped covering
code three separate times as modules were added or split out — if you are
adding a trigger for a module, widen to its crate instead. A change outside
those crates that could still affect cross-binary behaviour needs a manual
dispatch; the suite not appearing on a PR is not evidence that it passed.
There is currently **no protocol-version transition gate**: `MIN` and `MAX`
are both 7, so no boundary exists to cross. `v127_v7_upgrade` and the
in-process `protocol_version_transition` cluster test were retired with the
v6 support they exercised. Both must be RESURRECTED, retargeted at the new
boundary, by whichever change introduces protocol v8 — that is a release
blocker for it, not a follow-up. The pattern is on record twice now: the
v5 -> v6 flavor was retired at MIN = 6 and resurrected for v6 -> v7.

> **The release workflow no longer runs any suite (changed 2026-07-23, PR
> #1891).** It previously called this workflow with the candidate SHA and
> blocked tag publication on `v118_mixed_rollout`; that job was removed, so
> a release tag now builds, uploads and drafts **unconditionally**.
> Validating a release candidate is a manual step: dispatch `v140_rollout`
> (the deployed-release compatibility gate) plus the cluster and
> Rust-integration suites against the exact tagged SHA and record the runs
> in the draft's Validation section (the notes scaffold prompts for it). A
> release whose notes carry no such record is unvalidated.

It is not part of `scheduled-all-suites.yaml`. The contract it verifies is
[`../specs/cross-binary-upgrade.md`](../specs/cross-binary-upgrade.md).

**Retired scenarios.** Each `MIN_PROTOCOL_VERSION` bump retires the
rehearsals whose old binary no longer shares a protocol version with the
current one — their topologies cannot boot. Retired at MIN = 5: the
v3/v4-era `cross_binary`, `malicious_cross_binary`, `v118_upgrade`,
`v118_churn`, `v118_mixed_rollout`, `v121_rollout`. Retired at MIN = 6: the
v1.2.5-based `v125_rollout`, `v125_churn`, `malicious_v125`, and the two
version-transition gates, which were retargeted rather than dropped:
`v125_v6_upgrade` -> `v127_v7_upgrade`. Retired at MIN = 7: the v1.2.7-based
`v127_rollout`, `v127_churn`, `malicious_v127`, and BOTH transition gates
(`v127_v7_upgrade` and the `protocol_version_transition` cluster test) —
retired outright this time rather than retargeted, because MIN = MAX = 7
leaves no boundary; see the note above on resurrecting them at v8. Their
successors are `v140_rollout`/`v140_churn`/`malicious_v140`
(below), which play the same mixed-committee gate against the CURRENTLY
deployed release (v1.4.0, both networks, protocol v7) — a pure binary swap
with no protocol transition. (Historical `cross_binary` 96 GiB runner-OOM
forensics and its infra fix: this playbook's pre-#1751 history.)

**Retarget the `v1XY_*` family whenever the deployed release moves.** The
scenario names carry the OLD BINARY's release, not the protocol version,
so that this maintenance is visible rather than silent: the set was
`v125_*` against v1.2.5, then `v127_*`, then `v128_*`, then `v131_*`, and is
now `v140_*` with `old_ref=release/mainnet-v1.4.0`. A retarget renames all of
it in one change — the three test files, their `RUN_*` opt-in env gates,
the workflow's scenario names, `RUN_FLAG` mapping, `old_ref` defaults and
both guard lists below, plus this playbook and the spec. Leaving any of
them behind is the failure the convention exists to make visible.

There are no capability-pinned scenarios left, but the convention still
holds and is worth stating: when a scenario's OLD side is pinned to a
specific capability rather than to "whatever is deployed", say so at the pin
and leave it there — the family sweep must not carry it along.
`mid_epoch_rollback` was the one such scenario, and the v1.3.1 → v1.4.0
retarget is where that first mattered: its subject was an old binary
reopening an epoch store that an event-sourcing binary had been writing, so
it needed the last release from BEFORE #2074 (v1.3.1) and kept
`old_ref=release/mainnet-v1.3.1` while everything else moved. Renaming it
forward would have left it booting a post-#2074 binary that finds its own
fold's tables exactly where it expects them, with nothing to re-derive and
three assertions that pass for free. It was deleted once v1.4.0 shipped and
was validated in production (#2077, #2064).

Retargeting also costs the gate whatever the OLD side happened to bring
beyond its version. The v1.3.1-based gate straddled the event-sourcing
change by accident of timing; the v1.4.0-based one does not, because both
sides are post-#2074. That used to be covered by the separately-pinned
backward scenario; with that scenario retired, nothing covers it, and a
future storage-model boundary needs a purpose-built gate rather than an
inherited one.
Naming a gate after the protocol version instead is what
produced the incomplete rename this convention now guards against: a
scenario briefly called `v6_rollout` left the workflow's real-crypto and
production-pool-sizing guards pointing at a name that no longer existed,
so both silently stopped covering the PR-default gate. A name that stays
superficially correct while the thing it tests changes underneath is
worse than one that visibly goes stale.

**Which gates must refuse mocks.** Every gate whose evidence is
cross-binary agreement: `v140_rollout`, `v140_churn` and `malicious_v140` —
plus any transition gate, the moment one exists again. (The list and the
workflow both dropped `mid_epoch_rollback` when that scenario was deleted;
the workflow now guards exactly these three.) Mocked cryptography is deterministic, so two
binaries agree under it for reasons that say nothing about whether they
agree in production — a green run on mocks is not weaker evidence of the
same claim, it is evidence of a different one. Retarget this list with
the family: when the next `v1XY_*` set lands, so do its guard entries. Add a
gate here the moment it starts standing behind a rollout or a protocol
flip. `v127_v7_upgrade` was omitted when it was added and was, for that
window, the one run backing a version flip on a live network while still
accepting mocks.

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

# Full user DKG -> Presign -> Sign on-chain (genesis protocol v7).
gh workflow run upgrade-test.yaml --ref <branch> -f test=workload

# THE DEPLOYED-RELEASE GATE (also the PR default, and the scenario to run
# by hand on every release tag): boot the literal v1.4.0 release, upgrade
# one validator to current, converge two mixed aggregated reshares
# (per-authority byte-equality, zero malicious), then swap the rest.
gh workflow run upgrade-test.yaml --ref <branch> -f test=v140_rollout
#   override the old side:  -f old_ref=release/mainnet-v1.4.0 -f old_bin_name=ika-validator

# THE PROTOCOL-UPGRADE GATE: none exists right now. MIN = MAX = 7, so there
# is no boundary to cross, and both transition gates were retired with the v6
# support they exercised. Whichever change introduces protocol v8 must bring
# one back — an out-of-process rehearsal that boots the deployed release,
# swaps the committee to current, crosses the boundary, and asserts the
# upgrade activated, the reshare converged, the committee kept every member,
# and the cross-epoch handoff cert still verified. Treat that as a release
# blocker for v8, not a follow-up: the version boundary is the one thing a
# pure binary-swap gate cannot cover.

# Test-test the gate with the compiled-in, feature-gated one-validator
# reconfiguration-message fault. This run is expected to fail; its logs must
# show the exact zero-malicious or output-convergence assertion firing.
gh workflow run upgrade-test.yaml --ref <branch> -f test=v140_rollout -f test_testing_fault=true

# The standalone test-testing counterpart (green = detection works): honest
# v1.4.0 committee + one faulty current validator (built in-workflow with
# --features test-testing); honest validators must convict it and reshare
# without it (committee dips to 3).
gh workflow run upgrade-test.yaml --ref <branch> -f test=malicious_v140

# v140_rollout's churn counterpart: full swap, then a mirrored OCS joiner
# folds into the reshared v1.4.0-origin key (4→5) and a shrink reshare
# removes an original validator (5→4).
gh workflow run upgrade-test.yaml --ref <branch> -f test=v140_churn

# NOTE: there is no rollback gate any more, and no backward direction in the
# matrix. `mid_epoch_rollback` proved a v1.4.0 -> v1.3.1 mid-epoch rollback
# safe for the v1.4.0 release commit (#2077, #2064) and was deleted once
# v1.4.0 shipped and was validated in production. Its measurements are kept,
# marked historical, in ../specs/event-sourced-epoch.md ("Rolling back").

# Loaded runner slack: bump epochs.
#   -f epoch_duration_ms=600000

# Artifacts: upgrade-test-log-<test>-<attempt> (test stdout),
# upgrade-test-node-logs-<test>-<attempt> (per-validator *.log),
# resource-sampler-<test>-<attempt> (15s CPU+memory samples; recovered only on
# runs that FINISH — a runner death drops it like every other artifact).
```

### Scenario differences

All scenarios genesis at `ProtocolVersion::MIN` (= MAX = 7) with one
notifier + a validator committee:

| Scenario | Binary topology | Primary invariant |
|---|---|---|
| `smoke` | current only | process harness reaches epoch 2 |
| `workload` | current only | user DKG → Presign → Sign completes on-chain |
| `v140_rollout` | **one current + three literal v1.4.0**, then all swapped | mixed aggregated reshares converge byte-identically with zero malicious reports; the fully-swapped committee converges and keeps serving |
| `v140_churn` | all swapped, then a mirrored joiner (4→5) and a removal (5→4) | the v1.4.0-origin key reshares to a party that never held it (OCS joiner trust-anchor path) and back down |
| `malicious_v140` | three literal v1.4.0 + one FAULTY current (test-testing build) | honest committee convicts the faulty validator and reshares without it — detection is not vacuous |

### CI runner resources

The self-hosted `ika-k8s-large` pods report 96 host cores, an 80-CPU CFS
quota, a **96 GiB pod memory limit**, and no swap. Each idle `ika-validator`
runs ≈7.5–8 GB RSS, so co-locating many validators approaches the pod limit —
the deleted `cross_binary` scenario (5–6 validators) reproducibly OOM-killed
the runner at that limit (`OOMKilled`/137; forensics in this playbook's
pre-#1751 history). `v140_rollout` is 4-validator and fits comfortably;
`v140_churn` peaks at 5 validators during its joiner phase — the same peak
as the retired `v118_churn`, which passed on these runners (the OOM death
was specific to `cross_binary`'s heavier 5–6-validator multi-lifecycle
profile).

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
- **A targeted test run is not evidence for a change in a tested module —
  run the WHOLE module.** Two real cases: an ECDSA signing-message fix
  passed its own tests while leaving a sibling layout test asserting a
  contract the change had removed; a presign consensus-order fix passed all
  three of its targeted tests while orphaning `mark_presign_as_used`, which
  broke the module's consumption assertions. Both surfaced only on the
  full-module run. The trap is self-reinforcing: heavy MPC modules flake
  under parallelism, which is exactly what tempts a narrow filter — so run
  the module single-threaded rather than running less of it, and see the
  flake-provenance rule in
  [`../learnings/pitfalls.md`](../learnings/pitfalls.md) before triaging a
  module failure as yours.
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
