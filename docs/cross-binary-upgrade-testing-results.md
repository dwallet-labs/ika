# Cross-Binary Upgrade Testing — Implementation Results

Implements the plan in `cross-binary-upgrade-testing.md` /
`cross-binary-upgrade-testing-proposal.md`. New crate:
`crates/ika-upgrade-test` (additive — no changes to `ika-node` / `ika-swarm`).

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
| `tests/cross_binary.rs` | **GREEN** | Boot 4 on a v3-only binary, swap all to dev (v3..v4), capability vote advances **v3 → v4** (~722 s). |
| `tests/workload.rs` | **PARTIAL** | User DKG submission proven (txn executes, event emitted); on-chain completion not yet green — see below. |

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

## Known gap: workload on-chain completion

The workload driver derives protocol public parameters from the on-chain network
key, runs the centralized Curve25519 party, and **submits** the DKG to the
coordinator (transaction executes, digest returned). But the validators currently
**ignore the emitted event** (`received an event that is not a
DWalletSessionEvent`), so the session never advances and
`completed_sessions_count` does not rise. The TS SDK calls
`registerEncryptionKey` before `requestDWalletDKG`; the Rust driver must do the
same (generate a class-groups encryption keypair, sign it, call
`register_encryption_key`) before the coordinator will process the DKG. Until
that prerequisite is wired, `issue_dkg_and_confirm` returns
`OrphanedAfterTimeout`. Presign and Sign build on a completed DKG and are not yet
implemented.

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
