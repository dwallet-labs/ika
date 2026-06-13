---
name: dispatch-suites
description: Dispatch the heavy CI test suites (Rust integration, cluster, TypeScript) on a branch and watch them to verdicts. Use when a branch needs full validation before merge.
user-invocable: true
---

Dispatch and watch the heavy suites for branch `$ARGUMENTS` (default:
the current branch). Reference: `dev-docs/playbooks/ci-suites.md`.

1. Check for in-flight runs first — re-dispatching a workflow on the
   same ref CANCELS its in-flight run (concurrency groups):
   `gh run list --branch <branch> --limit 5`
2. Dispatch:
   ```bash
   gh workflow run integration-tests-ci.yaml --ref <branch> -f test_threads=4
   gh workflow run test-cluster.yaml --ref <branch>
   gh workflow run ts-integration-tests.yaml --ref <branch>
   ```
3. Capture the three run IDs (`gh run list --workflow <wf> --branch <branch> --limit 1`)
   and arm a background watcher per run; report each conclusion as it
   lands rather than polling inline.
4. On a failure, download the artifact before triaging
   (`rust-tests-log` / `cluster-tests-log-<attempt>` / `localnet-logs`).
   Distinguish three failure shapes:
   - test failure (nextest exit 100 / vitest FAILED) → read the failing
     test's replay;
   - runner-pod death ("runner lost communication", no artifacts) →
     infra, re-dispatch once;
   - TS-suite wedge (cascading "Object does not exist" timeouts) → run
     `dev-docs/playbooks/mpc-stall-postmortem.md` on localnet-logs FIRST;
     the pre-existing epoch-entry race (issue #1736) must be ruled out
     before attributing the failure to the branch.
