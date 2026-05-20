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
- **Sui dependency pinned**: Check `grep '^move-package' Cargo.toml` for the current tag (e.g., `mainnet-v1.70.2`). The system `sui` binary on PATH must match this tag, not just be "some recent sui."
- **WASM excluded**: `sdk/ika-wasm` is excluded from workspace (separate build). `dist/` is gitignored and has its own `Cargo.lock` — `cargo run` on the workspace will NOT rebuild it. Switching branches with different `cryptography-private` revs without rebuilding the WASM produces silent BCS mismatches.
- **Mysticeti consensus**: Uses Sui's Mysticeti for MPC message routing
- **NOA checkpoints not live**: The NOA checkpoint system (`crates/ika-core/src/noa_checkpoints/`) is under active development and not yet deployed. No backward compatibility constraints on serialization formats or type names

## Local network preflight (before `scripts/rerun_ika_*.sh`)

The `rerun_ika_*.sh` scripts only `rm -rf ~/.ika` and `cargo run`. That's not sufficient — each item below must be handled or the run breaks in a way that looks like a different problem. Do these checks in order BEFORE re-launching, not after a 30-minute failed boot:

1. **Disk location.** Validator RocksDB grows fast. Set `IKA_CONFIG_DIR=/mnt/nvme0n1p1/.ika/ika_config` (or whichever big-disk path is local to your machine) before `ika start`, and `rm -rf` that path instead of `~/.ika`. Default `~/.ika` can fill a small rootfs and panic mid-epoch with `No space left on device`.

2. **Clean the Move ephemeral publish file.** `rm -f Pub.localnet.toml` at the repo root. This file (gitignored, generated by Sui Move) pins published-at addresses to a chain-id; after `sui --force-regenesis` the chain-id changes and the file's contents become invalid. With it stale, ika boots, requests faucet funds, and silently exits after printing `[error] Ephemeral publication file ... has chain-id X; it cannot be used to publish to chain Y`.

3. **Match the `sui` CLI to the workspace tag.** `sui --version` must report the same tag as `grep '^move-package' Cargo.toml` (e.g., `mainnet-v1.70.2`). An older sui-node VM will accept the simple `ika` package publish but reject `ika_common` (which uses newer Move framework symbols like `bls12381::UncompressedG1`) with `VMVerificationOrDeserializationError in command 0`. Download the prebuilt tarball: `https://github.com/MystenLabs/sui/releases/download/mainnet-v<X.Y.Z>/sui-mainnet-v<X.Y.Z>-ubuntu-x86_64.tgz`.

4. **Match the WASM crypto rev to the workspace.** Compare `cryptography-private?rev=` in both `Cargo.lock` AND `sdk/ika-wasm/Cargo.lock` — they must agree. To diagnose a suspected mismatch, `head -c 800 sdk/ika-wasm/target/wasm32-unknown-unknown/release/deps/group-*.d` will show which rev the WASM was actually compiled against (path contains `cryptography-private-<hash>/<short-rev>/...`). To fix: `cd sdk/ika-wasm && rm -rf target dist && PROFILE=release pnpm build`. Symptom of mismatch: every SDK integration test fails inside `IkaClient.getProtocolPublicParameters` with `Error: unexpected end of input` from `dwallet_mpc_wasm::network_dkg_public_output_to_protocol_pp` — the BCS decoder of `<dkg::Party as mpc::Party>::PublicOutput` runs off the end of the buffer because validator and WASM disagree on field layouts.

Full launch sequence (`scripts/run_sui.sh` first, then ika):
```bash
# terminal 1
RUST_LOG="off,sui_node=info" sui start --with-faucet --force-regenesis --epoch-duration-ms 180000000000

# terminal 2 — after "SuiNode started!"
rm -f Pub.localnet.toml
rm -rf /mnt/nvme0n1p1/.ika
IKA_CONFIG_DIR=/mnt/nvme0n1p1/.ika/ika_config \
RUST_LOG=warn,ika=info,ika_node=info,ika_core=info \
RUST_MIN_STACK=67108864 \
  cargo run --release --no-default-features --bin ika -- start --epoch-duration-ms 60000 \
  2>&1 | tee debug_output.txt

# wait for "Added presigns to the internal presign pool" before running SDK tests
cp ika_config.json sdk/typescript/ika_config.json
cd sdk/typescript && bash scripts/run-integration-tests-sequential.sh --timeout 300
```
