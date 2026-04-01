# Publishing SDK Packages to npm

Publishes `@ika.xyz/ika-wasm`, `@ika.xyz/core`, `@ika.xyz/sui`, and `@ika.xyz/sdk` (deprecated) to npm via Trusted Publishing (OIDC).

## Prerequisites

- npm Trusted Publishing configured for all packages (OIDC — no npm token needed)
- Packages must be set up for provenance publishing on npmjs.com

## Packages published

| Package | Directory | Description |
|---------|-----------|-------------|
| `@ika.xyz/ika-wasm` | `sdk/ika-wasm/` | Rust-to-WASM crypto bindings |
| `@ika.xyz/core` | `sdk/core/` | Chain-agnostic core library (2PC-MPC protocol) |
| `@ika.xyz/sui` | `sdk/sui/` | Sui blockchain integration |
| `@ika.xyz/sdk` | `sdk/typescript/` | **Deprecated** — re-exports `@ika.xyz/sui` for backward compatibility |

Publish order matters due to dependencies: `ika-wasm` → `core` → `sui` → `sdk`.

## Release Publish (via tag)

1. Update `version` in all four `package.json` files to the same version:
   - `sdk/ika-wasm/package.json`
   - `sdk/core/package.json`
   - `sdk/sui/package.json`
   - `sdk/typescript/package.json`
2. Commit and push to `main`
3. Create and push a tag:
   ```bash
   git tag sdk/typescript-<version>
   # Example:
   git tag sdk/typescript-0.6.0
   git push origin sdk/typescript-0.6.0
   ```
4. The workflow validates that the tag version matches `sdk/typescript/package.json`
5. For each package, it checks npm — if that version is already published, it skips it
6. Published with `--tag latest`

### Tag format

```
sdk/typescript-{version}
```

Examples:
- `sdk/typescript-0.6.0`
- `sdk/typescript-1.0.0`

## Pre-release Publish (manual dispatch)

For testing an SDK version before a formal release:

1. Go to **Actions** > **Publish SDKs** > **Run workflow**
2. Fill in:
   - **Version**: must include a pre-release tag (e.g., `0.6.0-beta.1`, `1.0.0-rc1`)
3. Click **Run workflow**

Bare versions like `0.6.0` are rejected on manual dispatch — they are reserved for tag-based releases.

The version override is applied to all four packages before publishing.

Pre-release versions are published with their own npm dist-tag (e.g., `0.6.0-rc1` publishes with `--tag rc`), so they don't become the default `latest` install.

## What happens

1. **Validates** version (tag match or pre-release requirement)
2. **Installs** Rust, wasm-pack, Node.js, pnpm, Sui CLI
3. **Builds all packages** in dependency order (always, even if already published — needed for workspace linking)
4. **For each package** (`ika-wasm` → `core` → `sui` → `typescript`):
   - Checks if version is already on npm — skips publish if yes
   - Publishes with `--provenance --access public`
5. **Summary** table shows published/skipped status for all packages

## npm dist-tags

| Version format | npm tag | Example |
|----------------|---------|---------|
| `0.6.0` (tag push) | `latest` | `npm install @ika.xyz/sui` |
| `0.6.0-rc1` (manual) | `rc` | `npm install @ika.xyz/sui@rc` |
| `0.6.0-beta.1` (manual) | `beta` | `npm install @ika.xyz/sui@beta` |
