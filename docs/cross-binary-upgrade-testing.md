# Cross-Binary Upgrade Testing — Research & Infrastructure Plan

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
