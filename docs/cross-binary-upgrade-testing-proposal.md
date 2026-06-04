# Cross-Binary Upgrade Testing — Proposed Implementation

## Context

Ika is a decentralized MPC signing network built on Sui. Validators run
the `ika-node` / `ika-validator` Rust binary and coordinate dWallet
operations (DKG, Presign, Sign, Reshare) via Mysticeti consensus. The
network has a real on-chain protocol-version vote: each validator
announces its `supported_protocol_versions` in a
`CapabilityNotificationV1` consensus message; at `EndOfPublish` the
quorum picks the highest version supported by 2f+1 + a buffer-stake
margin; on `advance_epoch()` the new `protocol_version` takes effect
on-chain. Move contracts are upgraded via Sui package upgrades; the
coordinator state schema can change. Crypto protocol data
(class-groups params, network DKG output, presign layout) is versioned
implicitly via bcs-encoded `VersionedMPCData` / `VersionedNetworkDkgOutput`
/ `VersionedPresignOutput` / `VersionedSignOutput` enums.

Today, **zero test coverage exists for a network where validators run
different compiled binaries simultaneously**. The existing simtest
harness (`ika-test-cluster`, `IkaTestClusterBuilder`) runs all validators
in one process under msim — by construction it cannot link two different
compiled binaries. The only "upgrade-shaped" test
(`test_simulated_load_with_accumulator_v2_partial_upgrade`) toggles a
feature flag per validator but uses one binary. The protocol-vote
machinery, wire-format compatibility across versions, and on-disk
RocksDB compatibility have never been exercised end-to-end.

## Mission objective

Build infrastructure that runs an Ika cluster on **one machine** with
validators **actually executing different compiled binaries**, drives
them across epoch boundaries, swaps binaries on individual validators
mid-run, and asserts:

1. The protocol-version vote advances correctly when quorum supports
   the new version, and not before.
2. Mid-epoch reconfiguration MPC succeeds across the transition.
3. dWallet sessions (DKG/Presign/Sign) submitted during the heterogeneous
   window either complete on-chain or fail with a documented reason —
   no silent drops, no hangs.
4. v_new binaries correctly deserialize consensus + MPC wire messages
   produced by v_old peers, and vice versa.
5. A validator can stop on v_old, restart on v_new with the same
   RocksDB data dir, and resume — with a positive read-back signal,
   not merely "did not panic."

This must be a real out-of-process harness driving real binaries via
the existing admin RPC and gRPC surfaces. msim is explicitly out of
scope for this work — it cannot satisfy the constraint.

## Counter-proposal scope

This document is a counter-proposal to `cross-binary-upgrade-testing.md`.
Hard constraint: must actually test **different compiled binaries
talking on one PC**.

## Shape: a separate harness, not a swarm refactor

New crate `ika-upgrade-test` (binary + lib). Does **not** extend
`ika-swarm`. `ika-swarm` stays in-process for fast tests; the upgrade
harness is its own thing with its own opinions.

```
ika-upgrade-test/
  src/
    process.rs    # one ValidatorProcess = Command::spawn + admin RPC client
    cluster.rs    # ClusterOfProcesses: N ValidatorProcesses, shared Sui localnet
    config.rs     # reuses ika-swarm-config as a library to mint NodeConfigs
    workload.rs   # dWallet workload driver (talks gRPC + signs user-side 2PC)
    scenario.rs   # the DSL
    bin/upgrade-test.rs
```

Why a separate crate: every method on `IkaNodeHandle` that's
`Arc<IkaNode>`-flavored would need a `Remote` counterpart if we bolt onto
swarm — a lot of plumbing for nothing. The upgrade harness needs a small
surface (start / stop / swap_binary / wait_for_epoch / get_capabilities)
and exposes only that.

## ValidatorProcess

```rust
struct ValidatorProcess {
    binary: PathBuf,          // ika-validator binary, caller-supplied
    config_path: PathBuf,     // YAML; per-validator, on a persistent data dir
    data_dir: PathBuf,        // survives restarts so on-disk compat is real
    admin_addr: SocketAddr,
    grpc_addr: SocketAddr,
    child: Option<Child>,
    log: PathBuf,
}

impl ValidatorProcess {
    async fn start(&mut self) -> Result<()>;            // spawn + wait for /node-config 200
    async fn stop(&mut self) -> Result<()>;             // SIGTERM → wait → SIGKILL
    async fn swap_binary(&mut self, new: PathBuf);      // stop, replace, start (same data_dir)
    async fn capabilities(&self) -> Capabilities;       // GET /admin/capabilities
    async fn force_close_epoch(&self);                  // POST /admin/force-close-epoch
}
```

All control via the **existing** admin RPC (`crates/ika-node/src/admin.rs`).
No new IPC. stdout/stderr to per-validator log file (tail-able while
running).

## Driving epoch boundaries — settle this first

This is the gating risk. Plan:

1. **Try `/force-close-epoch` fanned to 2f+1 validators concurrently.** If
   consensus closes the epoch deterministically within a bounded
   wall-clock, done.
2. **If not**, fall back to **short `epoch_duration_ms` configured at
   genesis** (memory already uses `--epoch-duration-ms 600000` as workaround
   for epoch-13). Harness picks e.g. 30s epochs and uses wall-clock waits
   with a generous timeout. Less elegant, more robust.

Build #1, measure, fall back to #2 if flaky. Do **not** design the DSL
assuming #1 works until proven on a 4-validator cluster.

## DSL — keep it dumb, no time-travel

```rust
Scenario::new(num_validators = 4)
    .start_all_with(old_binary)
    .wait_for_epoch(1)
    .with_workload(|w| w.continuous_dwallet_traffic())   // background task
    .stop_and_swap(validators = [0, 1], to = new_binary)
    .wait_for_epoch(2)
    .stop_and_swap(validators = [2, 3], to = new_binary)
    .wait_for_epoch(3)
    .expect_protocol_version_at_least(4)
    .stop_workload_and_assert_no_silent_drops()
    .run().await
```

Imperative, sequential, one validator at a time. No
`epoch(2).replace(...)` declarative magic — that just hides the
orchestration headache.

## Workload driver — the actually-hard piece

Write it in Rust, **reuse `dwallet-mpc-centralized-party`** for the
user-side 2PC. Driver:

- Maintains `Vec<InFlightSession>` with
  `{ session_id, kind, started_epoch, expected_completion_epoch_or_reject }`.
- Submits one of `{DKG, Presign, Sign}` every N ms via gRPC.
- Polls Sui for each session's terminal state.
- **Three terminal buckets:** `Completed`,
  `RejectedWithDocumentedReason(epoch_mismatch | …)`,
  `OrphanedAfterTimeout`. The last one is the bug. Test fails if non-empty.

Don't try to reuse SDK TypeScript tests. They're integration-shaped; we
need a Rust-side long-running driver. The 2PC user-side is already
available as a Rust lib in this repo.

## Binaries: caller-supplied, no cache

```
upgrade-test \
  --validators 4 \
  --old-binary /path/to/ika-validator-vN \
  --new-binary /path/to/ika-validator-vN+1 \
  --sui-binary /path/to/sui \
  --scenario rolling_majority_then_minority
```

That's it. If devs ask for `git-sha → binary` later, layer it. Cache is
a productivity feature, not a correctness feature.

## Sui side

Reuse `scripts/run_sui.sh` style flow — one Sui localnet, four
ika-validator processes published against it. Harness `Command::spawn`s
`sui-test-validator` (or workspace-pinned equivalent) as a sibling child
process and tears it all down on Drop.

## Sequencing

1. **First — prove epoch boundary control (go/no-go gate).** Standalone
   proof: spawn 4 ika-validators from CLI manually, confirm
   `force-close-epoch ×3` actually advances the epoch on Sui. If not, lock
   in the short-epoch-genesis fallback. Nothing else proceeds until this is
   settled.
2. **Next:** `ValidatorProcess` + `ClusterOfProcesses` + scenarios
   doing same-binary restart. No upgrade yet — just prove the harness
   works.
3. **Then:** Workload driver. Land it as a standalone tool too;
   useful for stress testing in general, not just upgrades.
4. **Then:** Cross-binary scenarios. Wire MIN/MAX protocol versions
   wide enough that v_old and v_new really diverge — otherwise the test
   is checking nothing.
5. **Last:** Absorb the inevitable
   RocksDB-doesn't-reopen / config-format-drifted / admin-port-collides
   surprises.

No msim work on this critical path. msim heterogeneity (the original P3)
is fine to do separately, but by construction can't satisfy the "actually
test different binaries" constraint.

## What I'm explicitly cutting from the original doc

- The `Container::InProcess | Process` refactor. Out of scope.
- `IkaNodeHandle::Remote`. Out of scope.
- Binary cache, `xtask warm-cache`, `~/.cache/ika-test-binaries`. Defer.
- The declarative `Scenario::epoch(N).replace(...)` DSL. Use imperative.
- P3 (msim heterogeneity). Separate effort.

## Open question to resolve before coding

Should the harness drive **the same Sui localnet across binary swaps**,
or use a fresh Sui per scenario? Same Sui is realistic (mainnet upgrades
happen on a live chain). Fresh Sui is easier and avoids Sui-side state
contamination. Default to same Sui; fork only when a specific scenario
needs isolation.

## Invariants the harness must check

(Inherited from original doc §"Invariants" — restated here for self-
containment.)

1. **Vote arithmetic:** protocol version advances iff 2f+1 + buffer stake
   supports it.
2. **Reconfiguration succeeds:** mid-epoch reconfiguration MPC completes;
   next committee's encryption-key shares present.
3. **Session lifecycle:** sessions started in epoch N either complete in
   N or are rejected with documented reason; no silent drops, no hangs.
4. **Wire compat:** v_new processes consensus + MPC messages serialized
   by v_old, and vice versa.
5. **On-disk compat:** `AuthorityPerpetualTables` opened by v_new with a
   v_old-written RocksDB is readable. Positive signal needed beyond "no
   panic" — e.g. column-family enumeration matches expected post-upgrade
   schema, or a sentinel row written by v_old reads back correctly under
   v_new.
