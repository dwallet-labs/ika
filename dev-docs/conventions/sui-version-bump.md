# Bumping the Sui version

The Sui version is pinned in multiple places that do NOT update
together. A partial bump produces failures far from the cause (the
classic: a mismatched local `sui` binary completes the network DKG but
silently stalls reconfiguration one epoch later). When you bump, bump
EVERYWHERE, in one PR.

`scripts/check-sui-version-consistency.sh` enforces agreement between
the locations below and runs in CI; it fails the build on drift.

## Checklist (current tag: the single `mainnet-v*` or `testnet-v*` pin in root Cargo.toml)

1. **Root `Cargo.toml`** — every Sui git dependency carries the
   `tag = "mainnet-vX.Y.Z"` (or `testnet-vX.Y.Z`) pin (~90+ occurrences; sed them together):
   ```bash
   sed -i "" "s/mainnet-v<OLD>/mainnet-v<NEW>/g" Cargo.toml   # adjust flavor if moving to/from testnet-v
   cargo update   # refresh Cargo.lock for the new revs
   ```
2. **Excluded workspaces** — `sdk/ika-wasm` (and any other
   workspace-excluded package) has its own `Cargo.lock` that must be
   regenerated; its manifests resolve `workspace = true` deps against
   the root, but the lock pins revs independently:
   ```bash
   (cd sdk/ika-wasm && cargo update)
   ```
3. **CI workflows that download the `sui` binary** — the release URL
   embeds the version twice:
   - `.github/workflows/ts-integration-tests.yaml`
   - `.github/workflows/ts-ci.yaml`
4. **`CLAUDE.md`** — the pinned-version line in Gotchas.
5. **msim / simtest rev** — `scripts/simtest/cargo-simtest` **and**
   `scripts/simtest/config-patch` (the coverage path in
   `scripts/simtest/codecov.sh` applies the same patch as a real diff,
   because `cargo llvm-cov` does not go through the `cargo simtest`
   shim — keep the two revs identical). ika applies
   the `tokio`/`futures-timer` → mysten-sim patch THERE (via `--config`),
   not in `Cargo.toml`, pinned to a git `rev`. That rev MUST match the
   `msim`/`sui-simulator` rev the new Sui tag uses: copy it from Sui's own
   `scripts/simtest/cargo-simtest` at the tag. A stale rev links two
   mysten-sim copies and simtest panics `there is no reactor running` (the
   reactor one msim sets isn't seen by the other). Also confirm that rev's
   `msim-tokio` version still equals root `Cargo.toml`'s exact `tokio` pin
   (currently `=1.52.1`), or the `[patch.crates-io.tokio]` no-ops — bump the
   pin if it changed.
6. **Local dev environments** — everyone running localnets needs the
   matching `sui` binary on PATH (announce in the PR; see
   `../playbooks/localnet.md` for why mismatches are nasty).

## After bumping

- `cargo build --release` + the integration suite (the crypto and
  consensus layers are the usual breakage points across Sui versions).
- **Diff `to_consensus_protocol_config`** (`ika-core/src/consensus_manager/mod.rs`)
  against Sui's upstream (`sui-core/src/consensus_manager/mod.rs`). Consensus
  config is decoupled from the protocol config on purpose, so new toggles (e.g.
  `enable_v3`) show up here, not in a snapshot. Source each value from the
  protocol config the way upstream does — version-gated, never an ad-hoc constant.
  If upstream starts gating a field that ika hardcodes, add the matching
  version-gated getter to `ika-protocol-config` and wire it through.
- Check for new `#[cfg(msim)]` rot in Sui-fork code paths
  (`unresolved import` under `--cfg msim` — see
  [`simtest.md`](simtest.md)).
- Run the consistency script locally before pushing:
  ```bash
  ./scripts/check-sui-version-consistency.sh
  ```
