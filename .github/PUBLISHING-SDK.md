# Publishing TypeScript SDK to npm

Publishes `@ika.xyz/ika-wasm` and `@ika.xyz/sdk` to npm via Trusted Publishing (OIDC).

## Prerequisites

- npm Trusted Publishing configured for both packages (OIDC — no npm token needed)
- Packages must be set up for provenance publishing on npmjs.com

## Release Publish (via tag)

1. Update `version` in `sdk/typescript/package.json` (e.g., `"version": "0.6.0"`)
2. Update `version` in `sdk/ika-wasm/package.json` to match
3. Commit and push to `main`
4. Create and push a tag:
   ```bash
   git tag sdk/typescript-<version>
   # Example:
   git tag sdk/typescript-0.6.0
   git push origin sdk/typescript-0.6.0
   ```
5. The workflow validates that the tag version matches `sdk/typescript/package.json`
6. For each package, it checks npm — if that version is already published, it skips it
7. Published with `--tag latest`

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

Pre-release versions are published with their own npm dist-tag (e.g., `0.6.0-rc1` publishes with `--tag rc`), so they don't become the default `latest` install.

## What happens

1. **Validates** version (tag match or pre-release requirement)
2. **Installs** Rust, wasm-pack, Node.js, pnpm, Sui CLI
3. **For each package** (`ika-wasm`, then `typescript`):
   - Checks if version is already on npm — skips if yes
   - Builds the package
   - Publishes with `--provenance --access public`
4. **Summary** table shows published/skipped status

## Packages published

| Package | Directory | Description |
|---------|-----------|-------------|
| `@ika.xyz/ika-wasm` | `sdk/ika-wasm/` | Rust-to-WASM crypto bindings |
| `@ika.xyz/sdk` | `sdk/typescript/` | TypeScript SDK |

## npm dist-tags

| Version format | npm tag | Example |
|----------------|---------|---------|
| `0.6.0` (tag push) | `latest` | `npm install @ika.xyz/sdk` |
| `0.6.0-rc1` (manual) | `rc` | `npm install @ika.xyz/sdk@rc` |
| `0.6.0-beta.1` (manual) | `beta` | `npm install @ika.xyz/sdk@beta` |
