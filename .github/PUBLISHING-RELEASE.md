# Release Process

Builds binaries (5 platforms), Docker images (4 images), uploads to GCP, creates a GitHub draft release, and updates the Homebrew formula.

## Prerequisites

### Secrets

| Secret | Purpose |
|--------|---------|
| `GH_DEPLOY_KEY` | SSH key for cloning `dwallet-labs/cryptography-private` (private dependency) |
| `GAR_KEY` | Google Cloud service account JSON for Artifact Registry |
| `GITHUB_TOKEN` | Automatic — creates draft releases |
| `HOMEBREW_TAP_DEPLOY_KEY` | SSH deploy key with write access to `ika-xyz/homebrew-tap` |

### Runner labels

Configured in the `version` job outputs — change there to update all jobs:

| Label | Used by |
|-------|---------|
| `linux-32-runner` | Linux builds, Docker packaging |
| `macos-13` | macOS Intel CLI build |
| `macos-latest` | macOS Apple Silicon CLI build |
| `windows-latest` | Windows CLI build |
| `ubuntu-latest` | Version resolution, uploads, release, homebrew |

## Release Publish (via tag)

1. Update `version` in root `Cargo.toml` (e.g., `version = "1.2.0"`)
2. Commit and push to `main`
3. Create and push a tag:
   ```bash
   git tag release/<network>-<version>
   # Example:
   git tag release/mainnet-1.2.0
   git push origin release/mainnet-1.2.0
   ```
4. The workflow validates that the tag version matches `Cargo.toml` workspace version
5. All builds, Docker images, GCP uploads, and GitHub release happen automatically
6. Homebrew formula is updated **only for mainnet releases**

### Tag format

```
release/{network}-{version}
```

- `network`: `mainnet`, `testnet`, or `devnet`
- `version`: must match `Cargo.toml` workspace version

Examples:
- `release/mainnet-1.2.0` — full release + Homebrew update
- `release/testnet-1.2.0` — full release, no Homebrew
- `release/devnet-1.2.0` — full release, no Homebrew

## Pre-release Build (manual dispatch)

For building and deploying a test version:

1. Go to **Actions** > **Release** > **Run workflow**
2. Fill in:
   - **Network**: mainnet, testnet, or devnet
   - **Version**: must include a pre-release tag (e.g., `1.2.0-rc1`, `1.1.9-test`)
3. Click **Run workflow**

Bare versions like `1.2.0` are rejected — they are reserved for tag-based releases.

Manual dispatch builds and uploads everything but does **not** create a GitHub release or update Homebrew.

## What gets built

### Binaries

| Platform | Binaries | Method |
|----------|----------|--------|
| linux-x64 | ika, ika-validator, ika-fullnode, ika-notifier, ika-proxy | Docker (reproducible) |
| linux-arm64 | ika, ika-validator, ika-fullnode, ika-notifier | Docker (cross-compile) |
| macos-x64 | ika | Native runner |
| macos-arm64 | ika | Native runner |
| windows-x64 | ika.exe | Native runner |

### Docker images

| Image | Registry | Binary |
|-------|----------|--------|
| ika-validator | `us-docker.pkg.dev/.../ika-common-public-containers` | ika-validator |
| ika-fullnode | `us-docker.pkg.dev/.../ika-common-public-containers` | ika-fullnode |
| ika-notifier | `us-docker.pkg.dev/.../ika-common-public-containers` | ika-notifier |
| ika-proxy | `us-docker.pkg.dev/.../ika-common-containers` | ika-proxy |

Docker tag format: `{network}-v{version}` (e.g., `mainnet-v1.2.0`)

## Job dependency graph

```
version ──┬── build-linux (x64, arm64) ──┬── docker (4x parallel) ──┐
          │                               │                          │
          └── build-desktop (3x parallel) ┼── upload-binaries (5x) ──┼── release ── homebrew
                                          │                          │   (mainnet only)
                                          └── summary                │
```

## Where artifacts end up

| Destination | What | When |
|-------------|------|------|
| GCP Artifact Registry (binaries) | All platform binaries | Always |
| GCP Artifact Registry (Docker) | 4 Docker images | Always |
| GitHub Release (draft) | Platform tarballs | Tag push only |
| Homebrew (`ika-xyz/homebrew-tap`) | Updated formula | Mainnet tag push only |

## After the release

The GitHub release is created as a **draft**. After verifying:

1. Go to the [Releases page](https://github.com/dwallet-labs/ika/releases)
2. Find the draft release
3. Review the auto-generated notes
4. Click **Publish release**

Users can then install via:
```bash
brew install ika-xyz/tap/ika
```
