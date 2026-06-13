# Running the heavy suites on CI instead of locally

The heavy suites have dispatchable workflows on the `ika-k8s-large`
self-hosted runners (80 vCPU; measured at full per-thread parity with an
M3 Max). Prefer these over hours-long local runs — they parallelize,
don't tie up a laptop, and upload logs as artifacts for post-mortem.

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
  everything — the live step log is the only surviving evidence. That is
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
