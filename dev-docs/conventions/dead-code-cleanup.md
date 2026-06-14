# Dead-code cleanup — auditing and removing unused Rust

Origin: PR #1743 (removed ~1700 lines of dead Rust across the workspace).

## The compiler finds almost none of it

ika is a workspace of **library** crates. rustc's `dead_code` lint treats
every `pub` item reachable from a crate's API root as used, so an unused
`pub fn` / `struct` / `enum` / enum-variant / field / const in a lib crate
produces **no warning**. Only private / `pub(crate)` items unreachable from
any `pub` item warn — and those are usually already
`#[allow(dead_code)]`-suppressed. So `cargo check` / `clippy` give a
near-empty dead-code signal; finding dead code means **workspace-wide
reference analysis** (grep each symbol across `crates/` AND `sdk/`), not the
compiler.

## Classify before deleting — this is a Sui fork

Much unused code is intentional. Put every candidate in a bucket; only the
first is mechanical:

- **safe_remove** — unreferenced AND removing it changes no behavior or
  external contract: private helpers, dead islands (items used only by other
  dead items), orphaned/commented code, genuinely-unused deps.
- **api_change** — `pub` item with no internal refs but part of a public
  surface (`thiserror` error-enum variants, `ika-sdk` / `ika-types` API).
  Removal is an API decision, not cleanup.
- **parity_keep** — unused but mirrors upstream Sui to keep rebasing cheap
  (`consensus_adapter` submission-position logic, `ika-swarm-config`
  builders, `ika-network/src/state_sync`). Keep it.
- **needs_decision** — dead but removal has a side effect, e.g. a
  never-incremented Prometheus field whose `register_*` call in `new()` still
  publishes a series (`node_config_metrics.rs`, `AuthorityMetrics`).

When unsure, leave it and ask the owner. A wrongly-deleted `pub`/parity item
costs more than a missed dead one.

## Removing dependencies: ALWAYS gate on a build

Grep is necessary but not sufficient. The PR #1743 audit wrongly flagged
`eyre` as unused in `ika-core` — it is used (`eyre::Result` / `eyre::eyre!`
in 5 files); only `cargo check` caught it.

```bash
cargo fmt --all
cargo check --workspace --all-targets --message-format=short
```

A wrongly-removed normal/dev dep fails to compile here. But this command
does **not** cover four cases — verify these separately or don't touch:

- **`cfg(msim)` deps/code** — built only under `cargo simtest`. Do not remove
  `[target.'cfg(msim)'.dependencies]` (e.g. `sui-simulator`, `msim`, the
  `moka` cfg-split in `ika-core`) without a simtest build.
- **The WASM build** — `dwallet-mpc-centralized-party` is consumed by the
  excluded `sdk/*-wasm` crates. Deps that look unused in its source
  (`web-sys`, `console_log`, `getrandom` via the `wasm_js` feature) may be
  needed there. Leave them unless you build the wasm crate.
- **Non-default features** — `--all-targets` does not enable them. A dep used
  only behind e.g. `ika-sui-client`'s `protocol-commands` needs
  `cargo check -p ika-sui-client --features protocol-commands`.
- **Intentionally-kept deps** — `[package.metadata.cargo-udeps.ignore]`
  entries (e.g. `tikv-jemalloc-ctl` in `ika`). Respect them.

## Removing commented-out code

Comment removal can never break compilation, so a green `cargo check` does
**not** prove you cut the right lines. Read each block; delete only `//` /
`/* */` dead code — keep explanatory comments and intentional template
scaffolding (`ika-protocol-config` next-version templates). After deletion,
re-grep the enclosing item for a field/param whose only remaining reader was
that comment: it is now genuinely dead (e.g. `consensus_overload_checker`
once the disabled `vote_transaction` body is gone) — decide it field by field.

## Procedure

1. (optional, for breadth) fan out per-crate finders plus an **adversarial
   verifier** that tries to *refute* each "dead" claim — the verifier caught
   false positives (a `pub fn` used only in another crate's tests) that a
   single grep missed.
2. Classify (above); apply only `safe_remove` unless the owner approves more.
3. `cargo fmt --all` → `cargo check --workspace --all-targets`; for
   feature-gated crates also `--features <f>`.
4. Keep the full finding list (especially the deferred buckets) in a record
   (`dev-docs/reviews/` or the issue), not in the code.
