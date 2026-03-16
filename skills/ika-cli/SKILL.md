---
name: ika-cli
version: 1.0.0
description: Guide for using the Ika CLI tool for dWallet operations, validator management, system deployment, and network administration. Use when performing CLI-based dWallet creation, signing, presigning, key management, validator operations, system initialization, or querying Ika network state via the terminal. Triggers on tasks involving `ika` CLI commands, dWallet CLI operations, Ika system deployment, or MCP tool integration with Ika.
metadata:
  openclaw:
    requires:
      bins:
        - ika
        - sui
    emoji: "🔐"
    homepage: "https://ika.xyz"
    tags:
      - crypto
      - mpc
      - dwallet
      - sui
      - signing
      - cli
---

# Ika CLI

Command-line interface for the Ika decentralized MPC signing network on Sui.

## References (detailed command reference and JSON schemas)

- `references/commands.md` - Full command reference with all flags, arguments, and examples
- `references/json-output.md` - JSON output schemas for `--json` flag on every command

## Install

```bash
# Via Homebrew (macOS/Linux)
brew install ika

# Or build from source
cargo build --release -p ika
```

Requires: Sui CLI (`sui keytool` for key management)

## Global Flags

All commands support these flags:

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON (machine-parseable). Errors also output as JSON. |
| `--client.config <PATH>` | Custom Sui client config path |
| `--ika-config <PATH>` | Custom Ika network config path (default for all dwallet subcommands) |
| `--gas-budget <MIST>` | Override default gas budget (default for all dwallet subcommands) |
| `-y, --yes` | Skip confirmation prompts |
| `-q, --quiet` | Suppress human-readable output (JSON still printed with `--json -q`) |

## Command Overview

```
ika
├── start                      # Start local Ika network
├── network                    # Network info and addresses
├── dwallet                    # dWallet operations
│   ├── create                 # Create dWallet via DKG
│   ├── sign                   # Request signature
│   ├── future-sign            # Conditional/future signing
│   ├── presign                # Request presign
│   ├── global-presign         # Global presign with network key
│   ├── import                 # Import external key as dWallet
│   ├── register-encryption-key
│   ├── get-encryption-key
│   ├── verify-presign
│   ├── get                    # Query dWallet info
│   ├── pricing                # Current pricing info
│   ├── generate-keypair       # Offline keypair generation
│   └── share                  # User share management
│       ├── make-public
│       ├── re-encrypt
│       └── accept
├── config                     # Configuration management
│   ├── init                   # Fetch addresses + create Sui envs
│   ├── add-env                # Add env from local ika_config.json
│   ├── sync                   # Re-fetch latest contract addresses
│   └── show                   # Show current config
├── validator                  # Validator operations (30+ subcommands)
├── protocol                   # Protocol governance (feature-gated)
└── completion                 # Shell completions (bash/zsh/fish)
```

## Quick Start

### Create a dWallet
```bash
# Register encryption key first (derives from active Sui address by default)
ika dwallet register-encryption-key --curve secp256k1

# Create a secp256k1 dWallet (IKA/SUI coins auto-detected from wallet)
ika dwallet create \
  --curve secp256k1 \
  --output-secret ./my_dwallet_secret.bin
# Output: dWallet ID, Cap ID, Public Key

# Sign a message (curve, DKG output, and presign output auto-fetched from chain)
ika dwallet sign \
  --dwallet-cap-id <CAP_ID> \
  --dwallet-id <DWALLET_ID> \
  --message <HEX_MESSAGE> \
  --signature-algorithm 0 \
  --hash-scheme 0 \
  --secret-share ./my_dwallet_secret.bin \
  --presign-cap-id <PRESIGN_CAP_ID>
```

**Seed derivation:** Encryption keys are derived stateless from the active Sui keystore address. Use `--seed-file <PATH>` for raw 32-byte seed, `--address <ADDR>` for a specific keystore address, or `--encryption-key-index <N>` for multiple keys per address. Pass `--legacy-hash` for keys registered before the V2 hash fix (only affects non-SECP256K1 curves).

**Auto-detection:** IKA/SUI coins are auto-detected from the active wallet. Curve, DKG output, and presign output are auto-fetched from chain when `--dwallet-id` and `--presign-cap-id` are provided.

### Validator Operations
```bash
# Create validator info
ika validator make-validator-info <NAME> <DESC> <IMG_URL> <PROJECT_URL> <HOST> <GAS_PRICE> <ADDRESS>

# Become a validator candidate
ika validator become-candidate <VALIDATOR_INFO_PATH>

# Join the committee
ika validator join-committee --validator-cap-id <CAP_ID>
```

## Key Management

Sui wallet keys are managed by `sui keytool`:

```bash
sui keytool generate ed25519          # Generate new keypair
sui keytool list                       # List known keys
sui keytool import <MNEMONIC>          # Import key from mnemonic
```

dWallet encryption keys are derived stateless from Sui keystore addresses (no local file storage). The CLI uses `keccak256(keypair_bytes || index)` to derive a 32-byte seed, then hashes with domain separators to produce class-groups and Ed25519 keys.

## JSON Output

All commands support `--json` for structured output:

```bash
ika dwallet get --dwallet-id <ID> --json
ika validator get-validator-metadata --json
```
