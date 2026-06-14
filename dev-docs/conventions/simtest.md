# Simtest (msim) — when to use it and how it works here

## Picking a test type

`IkaTestClusterBuilder` works under both `#[tokio::test]` and `#[sim_test]`
(msim-specific code is `cfg(msim)`-gated). Default to
`#[tokio::test(flavor = "multi_thread")]` — real parallel crypto, fast
wall time, no seed-reproducibility.

Reach for `#[sim_test]` only when the thing being tested *is*
scheduling/ordering nondeterminism: message reordering during DKG, network
partition mid-reconfig, a validator joining at a precise epoch boundary.
Use pre-baked or stubbed crypto fixtures where you can — don't recompute
class-groups DKG inside a simtest just because the framework allows it.

Crypto correctness belongs in unit tests inside the crypto crate, not in
network-level integration tests. Integration tests should assume the
crypto works and exercise coordination on top.

## Why simtest is slow

Under `cfg(msim)`, every simulated validator runs on the same single OS
thread — that's how msim achieves seed-reproducibility, by collapsing all
sources of scheduling nondeterminism onto a controlled scheduler. Real
OS-thread parallelism (rayon `par_iter` inside class-groups, mpc, proof,
tiresias) is incompatible with that model: rayon workers are real threads
msim doesn't control, and any tokio/tracing call from them hits
`NodeHandle::current().unwrap()` and `rayon-core` aborts the process
(bypasses `panic_handler`).

The workaround in this repo is to drop the cryptography-private `parallel`
feature under `cfg(msim)` via `[target.'cfg(not(msim))'.dependencies]` overrides in
`ika-core` and `dwallet-classgroups-types`. That reads backwards but is the
only direction Cargo accepts — feature unification is additive only, so to
turn a feature OFF under msim you list the base dep without it and re-add
it in a `cfg(not(msim))` block. For rayon-from-msim-node code there are two
patterns: the orchestrator runs computations INLINE under `cfg(msim)`
(preferred for new code — the capture-and-re-enter guard breaks when the
node is torn down mid-compute and rayon-core aborts the process), while
the remaining `rayon::spawn_fifo` sites in
`dwallet_mpc/crytographic_computation/mpc_computations/network_dkg.rs`
capture the caller's `sui_simulator::runtime::NodeHandle` and re-enter it
as the first line of the closure (acceptable only where the spawning node
provably outlives the computation).

Net effect: class-groups crypto runs sequentially under simtest. The
single-OS-thread + no-parallelism combination makes the smoke test slow
enough that simtest is more useful on-demand (the manual GitHub workflow)
than per-PR. That's the trade-off, not a bug — for tests where the
slowness would dominate, `#[tokio::test]` is the right tool.

## Running it

```bash
# Locally (manual; slow by design)
MSIM_DISABLE_WATCHDOG=1 cargo simtest --package ika-test-cluster -- test_swarm_reaches_epoch_2

# On CI
gh workflow run simtest.yaml --ref <branch>
```

Driver: `scripts/simtest/cargo-simtest`. Smoke entry point:
`crates/ika-test-cluster/` (`IkaTestCluster` + `IkaTestClusterBuilder`).

## Gotcha catalogue

- **Move build under msim** breaks the moment it touches sui-framework
  (move-package-alt git-fetches via `tokio::process`, which msim doesn't
  emulate). `IkaTestClusterBuilder` works around this by rewriting each
  `Move.toml` to use explicit local-path deps on Sui framework + Move stdlib
  (`ika_move_contracts::save_contracts_to_temp_dir_for_simtest`). The
  `SIMTEST_STATIC_INIT_MOVE` warm-up uses the no-dep stub at
  `crates/ika-test-cluster/move-stub/` for the same reason.
- **IP allocation:** ika-config allocates from `10.11.0.x` (sui-config uses
  `10.10.0.x` and they each have their own thread-local `SimAddressManager`).
- **`Pub.<env>.toml`** persists across runs and breaks the next publish if
  its absolute paths point at a deleted temp dir. `IkaTestClusterBuilder`
  chdirs into the contracts temp dir before publish so the pubfile dies with
  the `TempDir`.
- **mysten-sim pin:** the rev must ship the same tokio version as the
  workspace, or the `[patch.crates-io.tokio]` patch silently no-ops (see
  [`sui-version-bump.md`](sui-version-bump.md)).
- **`[profile.simulator]`** matches release (`opt-level = 3`,
  `debug-assertions = false`, `overflow-checks = false`) — class-groups
  crypto is unusable otherwise. `debug = 1` keeps line-table backtraces.
- **Stale msim rot:** if `cargo simtest build` hits an `unresolved import`
  under `--cfg msim`, suspect a Sui-fork `#[cfg(msim)]` block referencing
  ika-renamed-but-not-actually-aliased symbols (`ika_simulator::*`,
  `OIDCProvider`, `safe_mode`, etc.).
