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
5. **msim compatibility** (not the same version, but coupled): the
   `msim` pin in root `Cargo.toml` must ship the SAME tokio version as
   the new Sui workspace, or the `[patch.crates-io.tokio]` silently
   no-ops and simtest breaks. Check Sui's `Cargo.toml` tokio version
   against the msim rev's.
6. **Local dev environments** — everyone running localnets needs the
   matching `sui` binary on PATH (announce in the PR; see
   `../playbooks/localnet.md` for why mismatches are nasty).

## After bumping

- `cargo build --release` + the integration suite (the crypto and
  consensus layers are the usual breakage points across Sui versions).
- Check for new `#[cfg(msim)]` rot in Sui-fork code paths
  (`unresolved import` under `--cfg msim` — see
  [`simtest.md`](simtest.md)).
- Run the consistency script locally before pushing:
  ```bash
  ./scripts/check-sui-version-consistency.sh
  ```
