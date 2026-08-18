# Ika Network (dWallet)

## Communication (highest priority)

Write for a competent engineer who has never read this repo, the earlier
conversation, or the writer's vocabulary. Every explanation walks a path
from what that reader already has to the new thing, one step at a time. A
skipped step reads as an unsupported claim, not an argument.

1. Introduce every concept the first time it appears in a message or a
   document, with one plain sentence — even terms that feel standard in
   this domain. A term the reader has not been given may not be used.
2. Plain words. Never use a metaphor as a technical term ("seam",
   "load-bearing", "surface", "lane", "gate", "shape", "wedge",
   "stranded", "hardening", "blast radius", "plumbing", "landed", ...).
   Say the literal thing: "the code that reads Ethereum events", "the
   check was missing", "delivery stops forever".
3. One idea per sentence. Subject first. Usually under twenty words. No
   nested parentheses, no em-dash chains, no lists inside a sentence, no
   noun piles.
4. Lead with the claim in ordinary words — who did what, and what
   follows. Code identifiers come after, once, in parentheses, only when
   needed to find the thing.
5. No private labels in prose: no finding IDs, no invented shorthand, no
   agent names.
6. Explanations are prose paths. Tables only for looking up items the
   reader already understands.
7. Convey the same information. Never drop content or steps to be
   shorter; the plain version is longer, and that is correct. Summarize
   only when asked.
8. Do not signal being steps ahead ("worth flagging", "textbook", ...).
   Walk the steps.
9. Plain must not become vague: a plain sentence must be exactly as true
   as the code it describes.
10. Before sending any message or document: replace the words in rule 2;
    find every term a stranger would not know and check it was
    introduced; split every sentence with two ideas; confirm the first
    sentence states the claim.

When the reader asks "what is X" or repeats a claim back in their own
words, a step was skipped: walk back to their words and rebuild from
there — do not restate.

Decentralized MPC signing network built on Sui. dWallets provide zero-trust multi-chain signing via 2PC-MPC protocol.

## Collaboration Style

Act as a critical intellectual sparring partner, not a yes-man. Evaluate every idea on its merits—the user is a collaborator who can be wrong, not an authority to defer to. Question assumptions, point out flaws, logical errors, unstated premises, and potential bugs immediately and directly. Be skeptical by default; each claim must prove itself. No opening praise or "you're right" unless genuinely warranted after scrutiny. Prioritize truth over harmony. Be ruthless with constructive criticism.

## Working Principles (Karpathy's four)

1. **Think before coding** — state assumptions explicitly; if a request
   is ambiguous, present the interpretations and ask rather than guess.
2. **Simplicity first** — the minimum code that solves the stated
   problem; no unrequested abstractions, features, or "flexibility".
3. **Surgical changes** — every changed line traces directly to the
   request; don't touch unrelated code, comments, or formatting.
4. **Goal-driven execution** — turn the task into verifiable success
   criteria (a test, a check, a command) before starting, then iterate
   until they pass.

## Build Commands

```bash
# Rust - always use release mode for crypto code (debug is far too slow)
cargo build --release
cargo clippy --all-targets --all-features
# Tests: see Testing section below

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

## Engineering docs & specs (`dev-docs/`)

`dev-docs/` is the engineering knowledge base — read on demand, indexed
in `dev-docs/README.md`: behavioral specs, debugging playbooks,
conventions, and pitfalls. (`docs/` is the public docs website.)

`dev-docs/specs/` holds behavioral specifications for ika subsystems
(the protocol-level contract: actors, messages, decision rules,
invariants). **Read the relevant spec before changing a subsystem it
covers, and update the spec in the same PR as any behavior change.**
New consensus messages, cross-epoch invariants, or decision rules get a
spec (extend an existing file or add one). When spec and code disagree,
one of them has a bug — determine which before changing either. The
same maintenance rule applies to the playbooks and conventions: docs
here are part of the change, not documentation debt.

**Write for a reader without the originating context.** Don't put
out-of-context references in documentation, dev-docs, code comments, or
PR descriptions — internal labels (ticket shorthands, test/property IDs
like "F4-1", plan/phase numbers) are meaningless to anyone outside the
moment they were coined and rot once that context is gone. Spell out the
mechanism in plain terms instead. (The Rust-comment instance of this is
under Code Style.)

## Dependencies

- Use workspace-level dependencies exclusively
- Define dependencies in root `Cargo.toml`, reference with `{ workspace = true }` in crate `Cargo.toml`

## Code Style

### Rust

Mechanically-enforceable rules live in `clippy.toml` (disallowed
methods/macros: unbounded channels, `block_on`,
`bincode::deserialize_from`, `log::*`, arg-count limit) and
`[workspace.lints]` (`unsafe_code = "deny"`) — add new ones THERE, not
here. The rules below are the ones lints can't check:

- **NEVER use `unsafe`** — no exceptions (also denied by workspace lint)
- Rust 1.97 toolchain (`rust-toolchain.toml`), rustfmt 2024 edition
- Prefer functional style; iterators (`map`/`filter`/`fold`) over loops;
  avoid mutable variables unless necessary
- Shadow variables when transforming and the old value won't be used
- Imports at file top; no fully-qualified paths inline (use `HashSet`
  after importing, not `std::collections::HashSet`); no imports or fn
  definitions inside functions
- English words for numbers in names (`first_item`, not `item1`)
- Module structure: `xxx.rs` as module file with `mod tests` inside —
  no separate `mod.rs` or `tests.rs` files
- For all-public structs, prefer direct instantiation over `new()`
- Don't mix public and private data in a struct (unless return-only and
  immediately destructured)
- Malicious parties: use `HashSet`, or if `Vec` call `deduplicate_and_sort()`
- When moving code between files, copy-paste identically (easier to review)
- Don't reference plan/phase names in comments (e.g., "Phase 4f of
  crypto bump") — plan nomenclature rots once the plan doc is archived;
  keep the technical content, drop the phase tag
- When initializing a struct with locals, name the local like the field
  (struct-init shorthand or shadowing): `let dkg_output = bcs::to_bytes(&dkg_output)?;
  PerCurveDkgData { dkg_output, .. }` — not `let raw_bytes = ...;
  PerCurveDkgData { dkg_output: raw_bytes, .. }`

### Move

- Use `sui move build` for compilation
- Format with `pnpm prettier:fix-move`

## Testing

```bash
# Rust tests - MUST use release mode for crypto
# WARNING: workspace scope (no -p) runs MOCKED crypto — ika-test-cluster's
# self-dev-dependency enables dwallet-mpc-unsafe-mock and cargo feature
# unification spreads it to ika-core's own tests in the same invocation
# (verify: cargo tree -f "{p} {f}" -p dwallet-mpc-types --workspace).
# Real-crypto evidence requires package scope, e.g. -p ika-core.
cargo test --release
cargo test --release -p ika-core           # Single crate (real crypto)
cargo test --release -- --test-threads=1   # Sequential execution

# Integration tests — CPU-bound (real class-groups MPC). Heavy MPC tests
# flake under default parallelism, so filter to your target and/or limit
# threads; never infer a regression from a failure inside a full -p ika-core
# run. CI runs them as a separate test_threads=4 job.
cargo test --release -p ika-core dwallet_mpc::integration_tests -- --test-threads=4

# Simtest (manual; see dev-docs/conventions/simtest.md for what this is)
MSIM_DISABLE_WATCHDOG=1 cargo simtest --package ika-test-cluster -- test_swarm_reaches_epoch_2

# TypeScript SDK tests
cd sdk/typescript && pnpm test
```

Default to `#[tokio::test(flavor = "multi_thread")]` for cluster tests;
reach for `#[sim_test]` only when the test target IS scheduling/ordering
nondeterminism — decision guide and msim gotcha catalogue:
`dev-docs/conventions/simtest.md`. Crypto correctness belongs in unit
tests inside the crypto crate; integration tests exercise coordination
on top.

Prefer running the heavy suites on CI over hours-long local runs —
dispatch commands, runtimes, and artifact recovery:
`dev-docs/playbooks/ci-suites.md`. Running a local Sui+ika localnet
(version traps, readiness gates): `dev-docs/playbooks/localnet.md`.
Debugging an MPC stall: `dev-docs/playbooks/mpc-stall-postmortem.md`.

Minimal verification by change type (run the narrowest check that
covers the change; escalate to the full suite before merge):

- `dwallet_mpc/**` → `cargo test --release -p ika-core <nearest integration filter>`
- Epoch boundaries / reconfiguration / `sui_connector` → cluster suite on CI
- `sdk/typescript/**` → `./scripts/run-integration-tests-sequential.sh --filter <file-stem>`
- `contracts/**` → `sui move build` per touched package
- `ika-protocol-config` → `cargo test -p ika-protocol-config` (snapshot tests)

**Test-test meaningful features.** When you add or rely on a test that
guards a hard-to-trigger, high-stakes property — serialized-MPC-data /
state continuity across an upgrade, cross-binary wire compat,
malicious-party detection, reconfiguration/epoch-boundary invariants — a
green run is not enough on its own: prove the test would actually react if
the property broke. Inject a minimal fault that should trip it, confirm the
*expected evidence appears in the logs* (the exit code is not the
assertion — the catch is often recoverable and the test still passes), then
revert. The methodology (outcome shapes, the loop, worked examples) is in
`dev-docs/playbooks/test-testing.md` — run the `/test-testing` skill or
follow the playbook; don't invent it ad hoc. Skip this only for
trivial/mechanical tests where vacuous-pass isn't a risk.

## Cryptography Notes

- 2PC-MPC: Two-party computation where one party is emulated by n-party MPC
- Uses class groups for threshold cryptography
- External crypto dependencies from `dwallet-labs/inkrypto`
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

(Both DON'Ts and the fmt-before-commit rule are enforced
deterministically by `.claude/hooks/git-guard.sh`.)

## Long sessions

When compacting, always preserve: the modified-file list, test commands
already validated, branch names, and in-flight CI run IDs/URLs.

## Gotchas

- **Release mode required**: Crypto operations are extremely slow in debug mode
- **Forked from Sui — read the upstream as a reference**: much code
  structure mirrors Sui Network patterns, so when a forked subsystem is
  unclear (and especially for consensus — Mysticeti is Sui's
  `consensus/core`), read the pinned Sui source. It's checked out locally
  under `~/.cargo/git/checkouts/sui-*/<rev>/` (the one with `consensus/`
  at its root) and browsable at github.com/MystenLabs/sui at the pinned
  tag. How to locate it + what to read for what:
  `dev-docs/reference/sui-upstream.md`.
- **Sui version is pinned in MULTIPLE places** (currently `mainnet-v1.77.2`;
  sometimes a `testnet-v*` tag): when bumping it, bump EVERYWHERE in one
  PR — root `Cargo.toml` (~90 tag pins), excluded wasm workspace locks,
  the sui-binary downloads in the TS CI workflows, this file, and every
  developer's local `sui` binary (a mismatched localnet binary completes
  DKG but silently stalls reconfiguration). Checklist:
  `dev-docs/conventions/sui-version-bump.md`; enforced in CI by
  `scripts/check-sui-version-consistency.sh`.
- **WASM excluded**: `sdk/ika-wasm` is excluded from workspace (separate build)
- **Mysticeti consensus**: Uses Sui's Mysticeti for MPC message routing —
  the commit/round semantics ika's freeze and epoch-close logic rely on
  (leader rounds, commit boundaries) live in Sui's `consensus/core`, not
  in ika (see the upstream reference above)
- **Protocol v7 only (`MIN_PROTOCOL_VERSION = MAX_PROTOCOL_VERSION = 7`)**:
  **v7 is LIVE on both mainnet and testnet.** There is exactly ONE
  supported version, so **no protocol transition exists to cross** and
  every formerly gated behavior is unconditional —
  off-chain validator metadata, the cross-epoch handoff, deferred epoch
  close, aggregated (V4-tagged) network-key outputs, the STRICT
  equality-of-coefficients discrete-log bound, and short `AuthorityName`s.
  Do not add a `protocol_config.<flag>()` check for any of them.
  `noa_checkpoints` is the next flag, planned for v8 and off everywhere.
  When you introduce v8, the transition gates below have to be REBUILT —
  they were deleted, not merely disabled.
  **`AuthorityName` IS the Ed25519 consensus key, emitted as raw 32
  bytes.** The 48-byte zero-padded container (which the BLS protocol key
  occupied through v5) is no longer emitted by any supported version, so
  the ambient-width process global, the dual-width cross-epoch retry in
  handoff-cert verification, and the transition gates around them are all
  GONE. DECODING stays lenient on purpose: records written before the
  boundary hold the padded form and a node must keep reading its own
  history. The BLS protocol key still exists on chain and on `Committee`
  for BLS checkpoint-certificate verification, but it is NOT recoverable
  from a name — it is carried explicitly via
  `Committee::new_with_protocol_keys`, and a committee built through
  `Committee::new` has an empty map and fails closed at `public_key()`.
  **The inkrypto revision is strict-only**: the relaxed `-10` bound and
  the `backward_compatible` selector no longer EXIST, along with the
  backward-compatible (class-groups-only) DKG/reconfiguration parties and
  pre-aggregation (V3-tagged) output production. This binary is not
  wire-compatible with a pre-v7 committee even where older state survives.
  The `FeatureFlags` fields and the per-version arms in `get_for_version`
  stay for versions below MIN — the flag set is BCS-serialized into the
  `ProtocolConfig` digest that rides `AuthorityCapabilitiesV1` through
  consensus, so dropping a field would move every supported version's
  digest relative to deployed binaries.
  What REMAINS constrained: the networks persist pre-v7 state, so old
  `Versioned*` enum variants must stay (BCS variant indices are wire
  format). V1-tagged chain DKG anchors must remain DECODABLE (never
  rewritten on chain; they decode via the still-current
  `class_groups::dkg::PublicOutput`), and V2-tagged outputs still decode as
  `PublicOutputCore` where only the core is needed. **V3-tagged
  (pre-aggregation) outputs and the bwd-compat party outputs are NO LONGER
  decodable anywhere** — inkrypto removed their types — so any key whose
  live state is still V3-tagged must have migrated to V4 before running
  this binary, and their decode arms are hard errors. And MPC outputs must
  reach byte-identical quorum across a mixed-binary committee, so
  serialization changes to active paths need a new protocol version gate,
  never a binary-driven flip — including anything that verifies a
  RE-SERIALIZED cross-epoch payload, which is what the deleted dual-width
  retry existed to handle.
- **NOA not live**: the network-owned-address (NOA) system — both NOA
  signing AND the NOA checkpoint system (`crates/ika-core/src/noa_checkpoints/`)
  — is under active development and not deployed at all. No backward
  compatibility constraints on its serialization formats, type names, or
  derived addresses.
