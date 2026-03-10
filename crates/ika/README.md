# Ika CLI

Command-line interface for the Ika decentralized MPC signing network on Sui.

## Install

```bash
# Homebrew
brew install ika

# From source
cargo build --release --bin ika
```

Requires the [Sui CLI](https://docs.sui.io/guides/developer/getting-started/sui-install) for key management.

## Setup

```bash
# Fetch deployed contract addresses
ika config init

# Configure Sui environments
sui client new-env --alias testnet --rpc https://fullnode.testnet.sui.io:443
sui client switch --env testnet
```

## Commands

```
ika
├── dwallet                    # dWallet operations
│   ├── create                 # Create dWallet via DKG
│   ├── sign                   # Request signature (--wait for result)
│   ├── future-sign            # Conditional/future signing
│   ├── presign                # Request presign
│   ├── global-presign         # Global presign with network key
│   ├── import                 # Import external key as dWallet
│   ├── register-encryption-key
│   ├── get-encryption-key
│   ├── verify-presign
│   ├── get                    # Query dWallet info
│   ├── pricing                # Current pricing
│   ├── generate-keypair       # Offline keypair generation
│   └── share                  # User share management
│       ├── make-public
│       ├── re-encrypt
│       └── accept
├── validator                  # Validator operations (30+ subcommands)
├── protocol                   # Protocol governance (feature-gated: --features protocol-commands)
│   ├── set-approved-upgrade-by-cap
│   ├── perform-approved-upgrade
│   ├── try-migrate-system
│   ├── try-migrate-coordinator
│   └── set-supported-and-pricing
├── system                     # System deployment (internal, feature-gated)
│   ├── publish-modules        # Publish Move contracts to Sui
│   ├── mint-tokens            # Mint IKA tokens
│   ├── init-env               # Initialize environment
│   └── initialize             # Full system init + encryption key DKG
├── config                     # Configuration management
│   ├── init                   # Fetch contract addresses from GitHub
│   └── show                   # Show current config
├── start                      # Start local network
├── network                    # Display network info
└── completion                 # Shell completions (bash/zsh/fish)
```

## Quick Start

```bash
# Register encryption key
ika dwallet register-encryption-key --curve secp256k1

# Create a dWallet
ika dwallet create \
  --curve secp256k1 \
  --encryption-key-id <ENCRYPTION_KEY_ID> \
  --output-secret ./my_secret.bin

# Request a presign
ika dwallet presign --dwallet-id <DWALLET_ID> --signature-algorithm 0

# Sign a message (waits for completion)
ika dwallet sign \
  --dwallet-cap-id <CAP_ID> \
  --dwallet-id <DWALLET_ID> \
  --message <HEX_MESSAGE> \
  --signature-algorithm 0 \
  --hash-scheme 0 \
  --secret-share ./my_secret.bin \
  --presign-cap-id <PRESIGN_CAP_ID> \
  --wait
```

IKA/SUI coins are auto-detected from the active wallet. Curve, DKG output, and presign output are auto-fetched from chain. Unverified presign caps are auto-verified.

## Global Flags

| Flag | Description |
|------|-------------|
| `--json` | Structured JSON output |
| `--client.config <PATH>` | Sui client config path |
| `--ika-config <PATH>` | Ika network config path |
| `--gas-budget <MIST>` | Override gas budget |
| `-q, --quiet` | Suppress human-readable output |

## Documentation

Full documentation at [docs.ika.xyz](https://docs.ika.xyz/docs/cli).
