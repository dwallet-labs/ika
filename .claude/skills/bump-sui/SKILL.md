---
name: bump-sui
description: Bump the pinned Sui version everywhere it lives, per dev-docs/conventions/sui-version-bump.md. Usage - /bump-sui mainnet-v1.71.0 (or a testnet-v tag).
user-invocable: true
disable-model-invocation: true
---

Bump the Sui pin to `$ARGUMENTS` (a `mainnet-vX.Y.Z` or `testnet-vX.Y.Z`
tag). Full checklist: `dev-docs/conventions/sui-version-bump.md`. Work
on a dedicated branch.

1. Read the CURRENT tag (single distinct value) from root `Cargo.toml`.
2. Replace it in every root `Cargo.toml` pin (~90 occurrences, one sed),
   then `cargo update`.
3. Excluded workspaces: `(cd sdk/ika-wasm && cargo update)` (and any
   other excluded package with its own lock).
4. Update the sui-binary download URLs (tag appears twice per URL) in
   `.github/workflows/ts-integration-tests.yaml` and
   `.github/workflows/ts-ci.yaml`, and the pinned-version gotcha in
   `CLAUDE.md`.
5. msim compatibility: compare the new Sui workspace's tokio version
   against the `msim` rev's; if they differ, the
   `[patch.crates-io.tokio]` silently no-ops — find an msim rev shipping
   the matching tokio.
6. Verify: `./scripts/check-sui-version-consistency.sh` (CI enforces it),
   then `cargo build --release`, then dispatch the integration suite
   (`/dispatch-suites`) — crypto and consensus layers are the usual
   cross-version breakage points. Watch for `#[cfg(msim)]` rot
   (`unresolved import` under `--cfg msim`).
7. In the PR description, tell developers to update their local `sui`
   binary — a mismatched localnet binary completes DKG but silently
   stalls reconfiguration (`dev-docs/playbooks/localnet.md`).
