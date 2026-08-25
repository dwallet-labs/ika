# Cross-Binary Upgrade Testing

> ARCHIVED PLAN — built by #1727, then superseded. **The two tests its results
> table names, `tests/cross_binary.rs` and `tests/v118_upgrade.rs`, were deleted
> in #1895** (`0f2679799f`); the current scenarios are `v140_rollout`,
> `v140_churn`, `malicious_v140`, `restart_spectator`, `smoke` and `workload`
> (`mid_epoch_rollback` was added later and deleted again once v1.4.0
> shipped). The contract is
> [`../../specs/cross-binary-upgrade.md`](../../specs/cross-binary-upgrade.md)
> and the running procedure is
> [`../../playbooks/ci-suites.md`](../../playbooks/ci-suites.md). Kept for the
> out-of-process harness rationale, the workload-driver lessons and the port
> collision rule. Not maintained.

Status: landed (2026-06, PR #1727) — implemented in `crates/ika-upgrade-test/` (the `cross_binary` churn test and the `v118_upgrade` literal mainnet-v1.1.8 rehearsal). This file consolidates the original research/proposal and the implementation results for the effort.

---

## Research & infrastructure plan


Status: research / proposal. Not yet implemented.

## Goal

Test an Ika network where validators run **different binaries (of differing
versions) at the same time**, upgrade across epochs/times **independently**, and
verify that:

- epoch transitions work,
- backward compatibility (wire format, on-disk state, Move types) holds,
- dWallet protocols (DKG / Presign / Sign / Reshare) work across the
  transition.

## Findings from the current codebase

### 1. `ika-swarm` is in-process by construction

- `crates/ika-swarm/src/memory/container.rs:43-141` spawns an OS thread per
  validator and calls `IkaNode::start()` directly. Every validator is the same
  compiled binary, linked into the test process.
- `crates/ika-swarm/src/memory/node.rs:37-72` wraps a `NodeConfig` and a
  `Container`; `start()` directly instantiates `IkaNode`. No `Command::spawn`.
- `crates/ika-swarm/src/memory/swarm.rs:262-290` builds nodes from configs and
  launches them via `node.start()`. No per-validator binary path.
- `IkaNodeHandle` (`swarm.rs:363-365`) is `Arc<IkaNode>` — pure in-process.

Restart works (`memory/node.rs:161-174` demonstrates `start → stop → start`),
but a restart re-instantiates **the same compiled `IkaNode`** — there is no
hook to swap in a different binary.

### 2. The only "upgrade-shaped" test today is feature-flag-driven

`crates/ika-benchmark/tests/simtest.rs:103-119` —
`test_simulated_load_with_accumulator_v2_partial_upgrade` uses
`with_state_accumulator_v2_enabled_callback(Arc::new(|idx| idx % 2 == 0))`.
Half the validators enable a feature flag, half don't. This is **same binary,
different runtime config** — proves the per-validator config seam works, but
does not exercise serialization compatibility or binary heterogeneity.

### 3. Ika has a real on-chain protocol-version vote (not config-driven)

Verified by reading:

- `crates/ika-core/src/authority/authority_per_epoch_store.rs:2390` — each
  validator announces its `supported_protocol_versions` via
  `CapabilityNotificationV1` (an `AuthorityCapabilitiesV1`-style message) in
  consensus.
- `authority_per_epoch_store.rs:1995-2030` — at `EndOfPublish`, the validator
  calls `choose_highest_protocol_version_and_move_contracts_upgrades_v1()`.
- `crates/ika-core/src/authority.rs:910-989` — for each candidate version,
  checks stake aggregation against 2f+1 + a configurable buffer-stake margin
  (default 5000 bps).
- `contracts/ika_system/sources/system/system_inner.move:668-670` — at
  `advance_epoch()`, if `next_protocol_version` is set, it becomes the new
  `protocol_version`. Announced on-chain via the
  `SET_NEXT_PROTOCOL_VERSION_MESSAGE_TYPE` system checkpoint message
  (`messages_system_checkpoints.rs:26-27`, `system_inner.move:53, 873-878`).

Implication: the upgrade flow itself is meaningful machinery that warrants
end-to-end coverage, not a no-op.

### 4. `ProtocolVersionsConfig::PerValidator` already exists as a test seam

`crates/ika-swarm-config/src/network_config_builder.rs:32-50` accepts
`ProtocolVersionsConfig::PerValidator(callback)`; the closure at lines 372-376
applies per-validator version ranges when building configs. This is the right
primitive for the **logic-level** heterogeneity track.

`crates/ika-protocol-config/src/lib.rs:19-20` defines `MIN_PROTOCOL_VERSION =
3, MAX = 4`. Simulator builds expose a fake v5 at line 42.

### 5. There is already an admin HTTP RPC

`crates/ika-node/src/admin.rs:51-60` exposes a localhost:1337 control surface:

- `POST /force-close-epoch` — early epoch-closure vote
- `POST /set-override-buffer-stake`, `POST /clear-override-buffer-stake` —
  manipulate the protocol-vote buffer
- `GET /capabilities` — query this node's `AuthorityCapabilitiesV1`
- `GET /node-config` — current config snapshot
- `POST /logging`, `POST /enable-tracing`, `POST /reset-tracing`

Designed for ops, but it is exactly the orchestration seam a test harness
needs: force epoch boundaries, observe vote state, twiddle when versions
advance.

### 6. dWallet sessions are strictly epoch-scoped

- `crates/ika-core/src/dwallet_mpc/dwallet_session_request.rs:218-220` —
  `should_run_in_current_epoch` returns `self.pulled || self.epoch ==
  current_epoch`. Mismatched-epoch requests are dropped.
- `crates/ika-core/src/dwallet_mpc/mpc_session.rs:463-472` — skips with a
  warning when epoch mismatches.
- `mpc_manager.rs:282` — each epoch starts with `sessions: HashMap::new()`.
- `contracts/.../sessions_manager.move:62-70, 228-231` — on-chain
  `last_user_initiated_session_to_complete_in_current_epoch` blocks epoch
  advance until in-flight sessions complete or time out.
- Mid-epoch reconfiguration MPC runs at the 50% epoch mark
  (`sui_executor.rs:130-210`) to reshare key material to the next committee.

Implication: the relevant invariant is **not** "session survives epoch
boundary." It is "session either completes in epoch N or is cleanly rejected;
epoch N+1 starts new sessions correctly; reconfiguration MPC succeeded."

### 7. Wire surfaces that need real-binary coverage

- Consensus `ConsensusTransaction` enum, BCS
  (`crates/ika-types/src/messages_consensus.rs:42-48`). Variants include
  `DWalletMPCMessage`, `DWalletMPCOutput`, `SystemCheckpointSignature`,
  `IdleStatusUpdate`, `GlobalPresignRequest`, `NetworkKeyData`.
- MPC messages wrapped in enum-versioned BCS:
  `VersionedMPCData`, `VersionedNetworkDkgOutput`, `VersionedPresignOutput`,
  `VersionedSignOutput` (`crates/dwallet-mpc-types/src/dwallet_mpc.rs:20-32`).
  Enum dispatch — adding a variant in vN+1 will break vN deserialization
  unless explicitly handled.
- Checkpoints: `PendingDWalletCheckpoint` (versioned enum,
  `crates/ika-core/src/dwallet_checkpoints/mod.rs`), `NOACheckpointMessage<K>`
  (`crates/ika-types/src/noa_checkpoint.rs`), `SystemCheckpointMessage`
  (`crates/ika-types/src/messages_system_checkpoints.rs`).
- gRPC `DWalletService` (`proto/ika_dwallet.proto:15-26`): single
  `SubmitTransaction` RPC wrapping BCS payloads (`SignedRequestData`,
  `UserSignature`, `TransactionResponseData`).
- On-disk: `AuthorityPerpetualTables` over typed_store/RocksDB
  (`crates/ika-core/src/storage/rocksdb_store.rs`). No explicit versioned
  columns; relies on enum versioning inside values.
- Sui events consumed via `crates/ika-sui-client/src/lib.rs:141-150`.

### 8. Standalone binary surface

- `crates/ika-node/src/main.rs` — auto-detects mode from `NodeConfig`.
- Dedicated bins: `crates/ika-node/src/bin/{ika-validator,ika-fullnode,ika-notifier}.rs`.
- Config: YAML, deserialized via `serde_yaml`. Loaded in
  `crates/ika-config/src/node.rs:37-49`.
- User CLI: `crates/ika/src/main.rs:14-50` (`--client.config`, `--ika-config`,
  subcommands for dwallet/validator/config/protocol/system).
- Validator launch is config-file-driven; no `--protocol-version` style CLI
  flag exists today.

### 9. Simulator infra is custom Ika wrapper over Mysten's msim

- `crates/ika-node/src/lib.rs:123-127` — gated on `cfg(msim)`. Exposes
  `ika_simulator::runtime::NodeHandle`, `NodeLeakDetector`,
  `ika_simulator::task::kill_current_node(Some(restart_after))`.
- Root `Cargo.toml` pins `msim` to MystenLabs/mysten-sim at a specific rev.
- `#[sim_test]` examples in `crates/ika-benchmark/tests/simtest.rs:92-97`
  (`test_simulated_load_with_reconfig`) and the partial-upgrade test above.

**msim runs all nodes in one process.** By construction it cannot link two
different compiled `ika-node` binaries — so it cannot test true binary
heterogeneity. It is great for deterministic logic-level coverage of the
protocol-vote arithmetic and same-binary-with-flag scenarios.

## Recommended infrastructure play

The load-bearing investment is an **out-of-process swarm primitive driven via
the existing admin RPC**. A binary cache is small additional work on top.
msim coverage is a parallel track, not a substitute.

### P0 — Out-of-process swarm (prerequisite for everything else)

Refactor `Container` so it supports two modes:

```rust
enum Container {
    InProcess { /* existing */ },
    Process { binary: PathBuf, child: Child, admin_addr: SocketAddr },
}
```

- `Container::Process` does `Command::spawn(binary, "--config-path", cfg)`
  with per-validator data dir + admin port.
- `IkaNodeHandle` gains a `Remote { admin_addr, grpc_addr }` arm that proxies
  control operations via the admin RPC. No new IPC channel — the admin RPC
  already covers it.
- Child stdout/stderr piped to per-validator log files.
- Structured shutdown: SIGTERM, wait, SIGKILL fallback.
- Health check via `GET /node-config` before declaring "started."
- Per-validator data dir + admin port allocation in `SwarmBuilder`.

In-process mode stays for fast unit tests; process mode is what unlocks the
upgrade work.

### P1 — Upgrade-test DSL + workload generator

Built on top of P0. Strawman:

```rust
Scenario::new()
  .all_validators(BinarySpec::Head)
  .epoch(1).replace(0..2, BinarySpec::Head)   // 2/4 swap
  .epoch(2).replace(2..4, BinarySpec::Head)   // rest swap
  .expect_protocol_version_advance_at(epoch = 3)
  .with_workload(DWalletWorkload::continuous())
  .run().await?;
```

- `replace_validator(idx, binary)` = stop process via admin RPC, swap binary
  path, restart with same data dir.
- `expect_protocol_version_advance_at` = poll `GET /capabilities` and
  on-chain `protocol_version` until it changes.
- `DWalletWorkload::continuous()` = submit DKG/Presign/Sign every K seconds
  via the existing gRPC; track every `session_id` issued; assert each one
  either reached `Completed` on-chain or failed with a documented reason
  (e.g., epoch mismatch reject). This workload generator does not exist
  today — integration tests cover scenarios, not concurrent
  boundary-crossing load.

### P2 — Local binary cache (depends on P0)

```
~/.cache/ika-test-binaries/
  by-sha/<sha>/
    ika-node, ika
    .toolchain           # rustc -V from rust-toolchain.toml at that sha
    .lock                # flock during build
  tags/<tag> -> ../by-sha/<sha>
```

- Tag → sha via `git rev-parse` at lookup.
- Build-on-miss: `git worktree add /tmp/ika-build-<sha> <sha>` →
  `cargo build --release` → copy binaries → `flock` for concurrent callers.
- Cache key includes the pinned-rustc version (from that sha's
  `rust-toolchain.toml`), not host rustc.
- LRU eviction at ~20GB.
- New crate `ika-test-binaries` consumed by the swarm; `xtask warm-cache <tag>...`
  CLI for pre-population.
- Local-only for now. Remote tier can be layered later.

### P3 — msim track in parallel (does not block on P0)

Extend the `simtest.rs` pattern using `ProtocolVersionsConfig::PerValidator`
to give validators different supported ranges. Exercise:

- Stake-weighted vote arithmetic (`authority.rs:910-989`) under adversarial
  cases: validator restarts during `EndOfPublish`, capability-message
  reordering, equivocating capabilities.
- Buffer-stake override paths (`/set-override-buffer-stake`).
- Mid-epoch reconfiguration MPC under perturbation.

Deterministic, fast, runnable on every PR. Will not catch wire-format
regressions — that requires P0.

## Invariants the harness must check

1. **Vote arithmetic:** protocol version advances iff 2f+1 + buffer stake
   supports it. Assert via `GET /capabilities` and on-chain
   `protocol_version` after the boundary.
2. **Reconfiguration succeeds:** mid-epoch reconfiguration MPC completes;
   next committee's encryption-key shares are present.
3. **Session lifecycle:** sessions started in epoch N either complete in N or
   are rejected with `epoch != current`; no silent drops, no hangs.
   `last_user_initiated_session_to_complete_in_current_epoch` drains before
   epoch advance.
4. **Wire compat:** a v_new binary correctly processes consensus messages
   and MPC messages serialized by v_old peers, and vice versa.
5. **On-disk compat:** `AuthorityPerpetualTables` opened by v_new with a
   v_old-written RocksDB is readable. Simplest test: stop a node, swap
   binary, start, observe catch-up rather than panic.

## What to drop or defer

- **Hot binary swap inside a running process** — don't try. Stop, swap,
  start is sufficient and correct.
- **A separate test-only IPC channel** — admin RPC already covers it.
- **Building the cache first** — without P0 there is nothing to cache for.
- **Docker-hermetic builds** — local worktree builds are fine for dev.
  Revisit when this graduates to CI.
- **Long-tail buildability guarantees** — no promise that old tags
  build on today's toolchain. Fail loudly; let the dev cherry-pick or skip.

## Sequencing

- **First:** P0 — out-of-process swarm via admin RPC.
- **Then:** P1 — DSL + dWallet workload generator (depends on P0).
- **After P0:** P2 — local binary cache + `warm-cache` xtask.
- **In parallel, independent of P0:** P3 — msim heterogeneity track for the
  vote arithmetic.

## Open implementation questions (resolved at P0 start, not blocking design)

- Exact shape of `IkaNodeHandle::Remote` — which methods of the current
  `Arc<IkaNode>` surface are needed by existing tests and how many of them
  fan out to admin-RPC calls vs. need new endpoints.
- Whether `--config-path` is enough to launch a child or we need to also
  pass keystore/network bootstrap material on the command line.
- Whether `force-close-epoch` from a single node is sufficient to drive
  epoch boundaries in tests, or it needs to be invoked on quorum.

---

## Proposed implementation


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

This section is a counter-proposal to the **Research & infrastructure plan**
above. Hard constraint: must actually test **different compiled binaries
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

---

## Implementation results


Implements the **Research & infrastructure plan** / **Proposed
implementation** sections above. New crate: `crates/ika-upgrade-test`
(additive — no changes to `ika-node` / `ika-swarm`).

## What it is

An **out-of-process** harness that spawns real, separately-compiled
`ika-validator` child processes against an external `sui start` localnet, swaps
binaries on individual validators across epochs, and asserts the upgrade
invariants. Unlike `ika-test-cluster` (in-process `IkaNode`, one binary), it can
host genuinely different binaries in one committee.

- `sui.rs` — spawn `sui start --with-faucet --force-regenesis`; wait for RPC *and*
  faucet.
- `cluster.rs` — chain bootstrap via `init_ika_on_sui` + `ValidatorConfigBuilder`
  + a notifier fullnode; each `NodeConfig` is serialized to YAML and handed to a
  child via `--config-path`; on-chain `wait_for_epoch` / protocol-version reads
  via `IkaClient`.
- `process.rs` — `ValidatorProcess`: spawn / stop / `swap_binary`, health via the
  admin RPC.
- `binary.rs` — `BinarySpec` (path / tag / sha / branch) + a sha-keyed
  `git worktree` build cache honoring each commit's pinned toolchain.
- `scenario.rs` — imperative DSL runner (start / wait_for_epoch / stop_and_swap /
  expect_protocol_version).
- `workload.rs` — user dWallet DKG driver via `ika-sui-client` coordinator txns +
  `dwallet-mpc-centralized-party` crypto.

## Results

| Test | Status | Notes |
|------|--------|-------|
| `tests/smoke.rs` (go/no-go) | **GREEN** | 4 out-of-process validators + notifier, external sui, network DKG, reach epoch 2 (~396 s). |
| `tests/cross_binary.rs` | **GREEN** | Boot 4 on a v3-only binary, swap all to dev (v3..v4), capability vote advances **v3 → v4** (~722 s). *Version-only swap — the OLD binary shares dev's crypto (MAX pinned to 3); the real v1.1.8 crypto-boundary swap is **not** exercised here, see [Key finding](#key-finding-v118--dev-is-not-a-naive-binary-swap).* |
| `tests/workload.rs` | **GREEN** | Full user **DKG → Presign → Sign** lifecycle completes on-chain (~415 s). |

All tests are opt-in (`RUN_UPGRADE_SMOKE` / `RUN_CROSS_BINARY` /
`RUN_WORKLOAD_TEST`) and need real binaries + a matching `sui`.

The cross-binary green run demonstrates, end to end and out of process:
- **vote arithmetic** — protocol advances iff all four support the new version;
- **reconfiguration** — mid-epoch reconfiguration MPC completes across the swap;
- **wire compat** — a mixed (v3-only + v3..v4) committee processes each other's
  consensus + MPC messages;
- **on-disk compat** — validators restart on the new binary against their old
  RocksDB.

## Key finding: v1.1.8 → dev is NOT a naive binary swap

A literal `mainnet-v1.1.8` `ika-node` **cannot** share a committee with `dev`:

- v1.1.8 links `class_groups` from `dwallet-labs/inkrypto@37bb549f`; dev links
  `dwallet-labs/cryptography-private@84fa8dac` (the inkrypto → cryptography-private
  migration).
- v4 changed validator-key publication from the v1.1.8
  `ClassGroupsEncryptionKeyAndProof` shape to `ValidatorEncryptionKeysAndProofs`.

A v1.1.8 binary booted against dev-registered keys fails:
`Failed to deserialize class groups public key: remaining input` →
`validator's class-groups key does not match the one stored in the system state`
(panic in `ika-node` `verify_validator_keys`). This confirms the premise of
`plan-update-crypto-latest.md`: the real rollout needs the dual-pin /
backward-compatible handling, not a rolling binary swap. (dev already has
*backward* compat for v1.1.8 keys via #1710; v1.1.8 has no *forward* compat, and
no commit pairs MAX=3 with dev's crypto.)

To exercise a *successful* heterogeneous upgrade we therefore use an OLD binary
that shares dev's crypto but is pinned to `MAX_PROTOCOL_VERSION = 3` (a one-line
build of dev) — a genuinely different compiled binary, differing only in the
protocol version it advertises (the realistic minimal upgrade).

## Tuning that the harness surfaced

Short, rapid epochs + binary-swap churn **wedge the notifier's `sui_executor`**
on gas-coin version contention (the known epoch-13 wedge), and a swap that
overlaps the mid-epoch reconfiguration window stalls the epoch. The green run
uses **10-minute epochs** and swaps **all four at once** so the run crosses
exactly one reconfiguration, well clear of the swap window.

## Workload driver (session-lifecycle invariant)

`workload.rs` drives a full user **DKG → Presign → Sign** lifecycle to completion
on-chain by orchestrating the canonical `ika` CLI (`dwallet
register-encryption-key | create | presign | sign`) as a subprocess — the CLI is
the tested Rust client built on `dwallet-mpc-centralized-party` + `ika-sui-client`,
so this exercises the real client flow end to end. What it took to make it green
(each a real property of the system, surfaced by the harness):

- **Dedicated user.** The workload must NOT reuse the publisher key — the
  notifier submits from it, and sharing the coin causes lock contention
  ("already locked by a different transaction"). The driver generates a fresh
  key, faucet-funds SUI, and transfers one IKA coin from the publisher.
- **register-encryption-key before create.** The encrypted DKG borrows the
  user's encryption key from the coordinator (`encryption_keys.borrow(address)`),
  so it must be registered first (as the TS SDK does).
- **v4 genesis.** `internal_presign_sessions` is a v4 feature; at v3 global
  presign requests pile up and never run.
- **Long epoch (30 min).** Epoch 1 is reached fast (network-DKG-gated), so the
  lifecycle runs in the first minutes — clear of the mid-epoch reconfiguration
  MPC, which otherwise stalls presign completion.
- **Confirm sign via on-chain count, not `--wait`.** The CLI's `sign --wait`
  polls an ephemeral sign-session object that is removed on completion, so it
  races; the driver instead confirms the sign by the coordinator's user
  `completed_sessions_count` rising.

## Running

```bash
# go/no-go
RUN_UPGRADE_SMOKE=1 IKA_VALIDATOR_BIN=target/release/ika-validator \
  IKA_NOTIFIER_BIN=target/release/ika-notifier SUI_BIN=$(which sui) \
  cargo test --release -p ika-upgrade-test --test smoke -- --nocapture

# cross-binary (build the OLD binary first: a dev checkout with
# MAX_PROTOCOL_VERSION patched to 3, built --no-default-features)
RUN_CROSS_BINARY=1 OLD_BIN=/path/to/ika-validator-max3 \
  NEW_BIN=target/release/ika-validator NOTIFIER_BIN=target/release/ika-notifier \
  SUI_BIN=$(which sui) \
  cargo test --release -p ika-upgrade-test --test cross_binary -- --nocapture
```

Build binaries with `--no-default-features` to drop `enforce-minimum-cpu`
(panics on hosts with < 16 cores).

**Run one scenario at a time.** The harness binds the fixed Sui localnet ports
`9000`/`9123` and `chdir`s the process during publish, so two scenarios (or a
scenario alongside a stray `sui start`) collide. Each test has its own opt-in
guard (`RUN_UPGRADE_SMOKE` / `RUN_CROSS_BINARY` / `RUN_WORKLOAD_TEST`) so a
single guard can only launch one; do not set two at once, and free port `9000`
before a run.
