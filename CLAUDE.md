# Ika Network (dWallet)

Decentralized MPC signing network built on Sui. dWallets provide zero-trust multi-chain signing via 2PC-MPC protocol.

## Collaboration Style

Act as a critical intellectual sparring partner, not a yes-man. Evaluate every idea on its merits—the user is a collaborator who can be wrong, not an authority to defer to. Question assumptions, point out flaws, logical errors, unstated premises, and potential bugs immediately and directly. Be skeptical by default; each claim must prove itself. No opening praise or "you're right" unless genuinely warranted after scrutiny. Prioritize truth over harmony. Be ruthless with constructive criticism.

## Build Commands

```bash
# Rust - always use release mode for crypto code (debug is far too slow)
cargo build --release
cargo test --release
cargo clippy --all-targets --all-features

# TypeScript SDK
cd sdk/typescript && pnpm install && pnpm build
pnpm test                    # Run tests
pnpm lint                    # Lint check

# Move contracts (requires sui CLI)
cd contracts/ika && sui move build
cd contracts/ika_system && sui move build
cd contracts/ika_dwallet_2pc_mpc && sui move build

# Full monorepo
pnpm install                 # Install all JS dependencies
pnpm lint                    # Lint entire monorepo
pnpm prettier:check          # Check formatting
```

## Architecture

```
crates/
├── ika-core/              # Core MPC logic, dwallet operations, Sui connector
├── ika-node/              # Validator node implementation
├── ika-network/           # P2P networking layer
├── ika-types/             # Shared type definitions
├── ika-protocol-config/   # Protocol configuration and versioning
├── dwallet-mpc-types/     # MPC protocol type definitions
├── dwallet-mpc-centralized-party/ # Centralized party (user side) of 2PC-MPC
├── ika-sui-client/        # Sui blockchain client
├── ika-swarm/             # Local test network orchestration
└── ika-proxy/             # Metrics proxy

contracts/                  # Move smart contracts (deployed on Sui)
├── ika/                   # IKA token contract
├── ika_system/            # System/staking contracts
├── ika_dwallet_2pc_mpc/   # dWallet MPC coordination contracts
└── ika_common/            # Shared Move modules

sdk/
├── typescript/            # TypeScript SDK (@ika.xyz/sdk)
├── ika-wasm/              # Rust-to-WASM crypto bindings
└── dwallet-mpc-wasm/      # MPC WASM bindings
```

## Key Files

- `crates/ika-core/src/dwallet_mpc/` - Main MPC implementation
- `crates/ika-core/src/sui_connector/` - Sui event handling
- `contracts/ika_dwallet_2pc_mpc/sources/coordinator.move` - On-chain MPC coordination
- `sdk/typescript/src/` - TypeScript SDK source

## Dependencies

- Use workspace-level dependencies exclusively
- Define dependencies in root `Cargo.toml`, reference with `{ workspace = true }` in crate `Cargo.toml`

## Code Style

### Rust

**DO:**

- Rust 1.93 toolchain (`rust-toolchain.toml`), rustfmt 2024 edition
- Prefer functional style; use iterators, `map`, `filter`, `fold` over loops
- Shadow variables when transforming and old value won't be used (keep naming simple)
- Put imports at file top (e.g., `use std::collections::HashSet;`)
- Use English words for numbers in names (`first_item`, `second_part`)
- Module structure: `xxx.rs` as module file with `mod tests` inside
- For all-public structs, prefer direct instantiation over `new()` for clarity
- Malicious parties: use `HashSet`, or if `Vec` call `deduplicate_and_sort()`
- Use `tracing::*` macros for logging
- When moving code between files, copy-paste identically (easier to review)

**DON'T:**

- **NEVER use `unsafe`** - no exceptions
- Don't use mutable variables unless absolutely necessary
- Don't use fully-qualified paths inline in code (use `HashSet` after importing, not `std::collections::HashSet`)
- Don't place imports or function definitions inside functions
- Don't use numbers in names (`x1` → `first_x`, `part2` → `second_part`, `item3` → `third_item`)
- Don't create separate `mod.rs` or `tests.rs` files
- Don't mix public and private data in a struct (unless return-only and immediately destructured)
- Don't use `log::*` macros (use `tracing::*`)
- Don't use unbounded channels (use bounded)
- Don't use `futures::executor::block_on` (use tokio runtime)
- Don't use `bincode::deserialize_from` (use `bincode::deserialize`)
- Don't exceed 20 function arguments (clippy enforced)
- Don't reference plan/phase names in comments (e.g., "Phase 4f of crypto bump", "(Phase 4a, option 1)"). Plan-phase nomenclature rots once the plan doc is archived; keep the comment's technical content and drop the phase tag.
- When initializing a struct with locals, name the local like the field (use struct-init shorthand or shadowing). `let dkg_output = ...; let dkg_output = bcs::to_bytes(&dkg_output)?; PerCurveDkgData { dkg_output, public_key }` — not `let out = ...; let raw_bytes = bcs::to_bytes(&out)?; PerCurveDkgData { dkg_output: raw_bytes, public_key }`.

### Move

- Use `sui move build` for compilation
- Format with `pnpm prettier:fix-move`

## Testing

```bash
# Rust tests - MUST use release mode for crypto
cargo test --release
cargo test --release -p ika-core           # Single crate
cargo test --release -- --test-threads=1   # Sequential execution

# Integration tests
cargo test --release -p ika-core dwallet_mpc::integration_tests

# TypeScript SDK tests
cd sdk/typescript && pnpm test
```

## Simtest

`cargo simtest` (driver `scripts/simtest/cargo-simtest`) runs deterministic
single-threaded tests via mysten-sim. Smoke entry point:
`crates/ika-test-cluster/` (`IkaTestCluster` + `IkaTestClusterBuilder`).

Gotchas worth knowing before touching simtest code:

- **Rayon panics under msim.** Rayon workers are real OS threads with no msim
  node context, so any tokio/tracing call from them hits
  `NodeHandle::current().unwrap()` and `rayon-core` aborts the process
  (bypasses `panic_handler`). The cryptography-private `parallel` feature is
  therefore disabled under `cfg(msim)` via
  `[target.'cfg(not(msim))'.dependencies]` overrides in `ika-core` and
  `dwallet-classgroups-types`. Direct `rayon::spawn_fifo` sites in
  `dwallet_mpc/crytographic_computation/{orchestrator,mpc_computations/network_dkg}.rs`
  also capture the caller's `sui_simulator::runtime::NodeHandle` and re-enter
  it as the first line of the closure. New rayon-from-msim-node code needs
  both patterns.
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
- **mysten-sim pin:** rev `213e543` (tokio 1.49.0) to match the workspace
  tokio. Older pins ship 1.38.1 and the `[patch.crates-io.tokio]` patch
  silently no-ops.
- **`[profile.simulator]`** uses `opt-level = 3` — class-groups crypto is
  unusable below that.
- **Stale msim rot:** if `cargo simtest build` hits an `unresolved import`
  under `--cfg msim`, suspect a Sui-fork `#[cfg(msim)]` block referencing
  ika-renamed-but-not-actually-aliased symbols (`ika_simulator::*`,
  `OIDCProvider`, `safe_mode`, etc.).
- **Open follow-up:** the smoke test exceeds the `< 5 min` wall budget on
  sequential crypto. The fix is the deferred `chore/simtest-crypto-mock`
  branch — feature-gated mocked class-groups (mirroring how `cargo-simtest`
  already mocks `blst`).

## Cryptography Notes

- 2PC-MPC: Two-party computation where one party is emulated by n-party MPC
- Uses class groups for threshold cryptography
- External crypto dependencies from `dwallet-labs/cryptography-private`
- Curves: secp256k1 (k256), P-256 (p256), ed25519

## When to Stop and Ask

**IMPORTANT:** When given a task with a specific approach, follow that approach. If you encounter issues:

1. **Don't pivot to a different solution** - Ask first
2. **Don't assume the requested approach won't work** - It likely can and should be done that way
3. **Don't waste time implementing an alternative** - You'll just have to redo it

**Stop and consult the user when:**

- The specified approach hits an unexpected obstacle
- You're tempted to "simplify" by doing something different
- You think there's a "better" way than what was requested
- You're about to make architectural changes not explicitly requested

**Trust the user's direction.** If you don't know how to do it the requested way - ASK, don't improvise.

## Git Workflow

**DO:**

- Run `cargo fmt --all` before any commit, and include all formatted files in the commit
- Always work on dedicated feature/fix branches
- Commit and push after each completed task
- Fix any hook issues before committing
- For PR fixes: checkout the PR branch, fix comments, push to that branch

**DON'T:**

- Don't push/commit to `main`, `master`, or `dev` branches
- Don't use `--no-verify` to skip git hooks

## Gotchas

- **Release mode required**: Crypto operations are extremely slow in debug mode
- **Forked from Sui**: Much code structure mirrors Sui Network patterns
- **Sui dependency pinned**: Uses `mainnet-v1.51.5` tag for all Sui dependencies
- **WASM excluded**: `sdk/ika-wasm` is excluded from workspace (separate build)
- **Mysticeti consensus**: Uses Sui's Mysticeti for MPC message routing
- **NOA checkpoints not live**: The NOA checkpoint system (`crates/ika-core/src/noa_checkpoints/`) is under active development and not yet deployed. No backward compatibility constraints on serialization formats or type names
