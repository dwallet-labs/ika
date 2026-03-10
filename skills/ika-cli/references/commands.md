# Ika CLI Command Reference

## `ika start`

Start a local Ika network.

```bash
ika start [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--network.config <PATH>` | `~/.ika/network.yml` | Config directory |
| `--force-reinitiation` | false | Fresh state each run |
| `--sui-fullnode-rpc-url <URL>` | `http://127.0.0.1:9000` | Sui fullnode RPC |
| `--sui-faucet-url <URL>` | `http://127.0.0.1:9123/gas` | Sui faucet URL |
| `--epoch-duration-ms <MS>` | 86400000 (24h) | Epoch duration |
| `--no-full-node` | false | Skip fullnode |

---

## `ika network`

Display network information.

```bash
ika network [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--network.config <PATH>` | Config path |
| `--dump-addresses` | Show validator/fullnode addresses |

---

## `ika dwallet create`

Create a new dWallet via Distributed Key Generation (DKG). Returns the dWallet ID, Cap ID, and public key.

```bash
ika dwallet create [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--curve <CURVE>` | Yes | `secp256k1`, `secp256r1`, `ed25519`, `ristretto` |
| `--encryption-key-id <ID>` | Yes | Network encryption key object ID |
| `--output-secret <PATH>` | No | Output path (default: `dwallet_secret_share.bin`) |
| `--public-share` | No | Create shared dWallet (public user key share) |
| `--sign-message <HEX>` | No | Sign during DKG |
| `--hash-scheme <U32>` | No | Hash scheme for sign-during-DKG |
| `--encryption-seed <HEX>` | No | Seed for encryption key derivation (hex, 32 bytes). Random if omitted |
| `--ika-coin-id <ID>` | No | IKA coin for payment (auto-detected from wallet) |
| `--sui-coin-id <ID>` | No | SUI coin for payment (auto-detected from wallet) |
| `--gas-budget <MIST>` | No | Override gas budget |
| `--ika-sui-config <PATH>` | No | Ika network config path |

---

## `ika dwallet sign`

Request a signature from a dWallet. Pass `--dwallet-id` to auto-fetch curve, DKG output, and presign output from chain.

```bash
ika dwallet sign [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--dwallet-cap-id <ID>` | Yes | dWallet capability object ID |
| `--message <HEX>` | Yes | Message to sign (hex-encoded) |
| `--signature-algorithm <U32>` | Yes | Signature algorithm |
| `--hash-scheme <U32>` | Yes | Hash scheme |
| `--presign-cap-id <ID>` | Yes | Presign cap ID (verified or unverified — auto-verified if needed) |
| `--secret-share <PATH>` | Yes | Path to user secret share file |
| `--presign-output <HEX>` | No | Presign output (hex). Auto-fetched from --presign-cap-id if omitted |
| `--dkg-output <HEX>` | No | DKG public output (hex). Auto-fetched from --dwallet-id if omitted |
| `--dwallet-id <ID>` | No | dWallet ID (auto-fetches curve and DKG output from chain) |
| `--curve <CURVE>` | No* | Required if `--dwallet-id` not provided |
| `--wait` | No | Wait for sign session to complete and return the signature |
| `--ika-coin-id <ID>` | No | IKA coin for payment (auto-detected from wallet) |
| `--sui-coin-id <ID>` | No | SUI coin for payment (auto-detected from wallet) |
| `--gas-budget <MIST>` | No | Override gas budget |

**Auto-detection:** When `--dwallet-id` is provided, curve and DKG output are fetched from the dWallet object on chain (requires Active state). When `--presign-output` is omitted, it is fetched from the presign session referenced by `--presign-cap-id` (requires Completed state). The presign cap is auto-verified if unverified (composed into the same transaction). Imported key dWallets are auto-detected and routed to the correct sign flow.

---

## `ika dwallet future-sign`

Request a conditional/future signature. Curve and DKG output are auto-detected from `--dwallet-id`.

```bash
ika dwallet future-sign [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--dwallet-id <ID>` | Yes | dWallet object ID (auto-fetches curve and DKG output) |
| `--message <HEX>` | Yes | Message to sign |
| `--hash-scheme <U32>` | Yes | Hash scheme |
| `--presign-cap-id <ID>` | Yes | Verified presign cap ID |
| `--secret-share <PATH>` | Yes | Path to user secret share |
| `--presign-output <HEX>` | No | Presign output (hex). Auto-fetched from --presign-cap-id if omitted |
| `--dkg-output <HEX>` | No | DKG public output (hex). Auto-fetched from --dwallet-id if omitted |
| `--signature-algorithm <U32>` | Yes | Signature algorithm |
| `--curve <CURVE>` | No | Override auto-detected curve |
| `--ika-coin-id <ID>` | No | IKA coin for payment (auto-detected from wallet) |
| `--sui-coin-id <ID>` | No | SUI coin for payment (auto-detected from wallet) |
| `--gas-budget <MIST>` | No | Override gas budget |
| `--ika-sui-config <PATH>` | No | Ika network config path |

---

## `ika dwallet presign`

Request a presign for a dWallet. Coins are auto-detected from wallet.

```bash
ika dwallet presign [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--dwallet-id <ID>` | Yes | dWallet object ID |
| `--signature-algorithm <U32>` | Yes | Signature algorithm |
| `--ika-coin-id <ID>` | No | IKA coin for payment (auto-detected from wallet) |
| `--sui-coin-id <ID>` | No | SUI coin for payment (auto-detected from wallet) |
| `--gas-budget <MIST>` | No | Override gas budget |
| `--ika-sui-config <PATH>` | No | Ika network config path |

---

## `ika dwallet global-presign`

Request a global presign using network encryption key. Coins are auto-detected from wallet.

```bash
ika dwallet global-presign [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--curve <U32>` | Yes | Curve identifier |
| `--signature-algorithm <U32>` | Yes | Signature algorithm |
| `--ika-coin-id <ID>` | No | IKA coin for payment (auto-detected from wallet) |
| `--sui-coin-id <ID>` | No | SUI coin for payment (auto-detected from wallet) |
| `--gas-budget <MIST>` | No | Override gas budget |
| `--ika-sui-config <PATH>` | No | Ika network config path |

Network encryption key is auto-fetched from the Ika coordinator.

---

## `ika dwallet import`

Import an external key as a dWallet. Coins are auto-detected from wallet.

```bash
ika dwallet import [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--curve <CURVE>` | Yes | `secp256k1`, `secp256r1`, `ed25519`, `ristretto` |
| `--centralized-message <PATH>` | Yes | Path to the secret key file to import |
| `--encryption-key-id <ID>` | Yes | Network encryption key object ID |
| `--output-secret <PATH>` | No | Where to save user secret share (default: `imported_dwallet_secret_share.bin`) |
| `--ika-coin-id <ID>` | No | IKA coin for payment (auto-detected from wallet) |
| `--sui-coin-id <ID>` | No | SUI coin for payment (auto-detected from wallet) |
| `--gas-budget <MIST>` | No | Override gas budget |
| `--ika-sui-config <PATH>` | No | Ika network config path |

Requires a previously registered encryption key (from `register-encryption-key`). Network encryption key is auto-fetched from the Ika coordinator.

---

## `ika dwallet register-encryption-key`

Register a user encryption key for dWallet operations.

```bash
ika dwallet register-encryption-key [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--curve <CURVE>` | Yes | `secp256k1`, `secp256r1`, `ed25519`, `ristretto` |
| `--seed <HEX>` | No | Seed for key derivation (hex, 32 bytes). Random if omitted |
| `--gas-budget <MIST>` | No | Override gas budget |
| `--ika-sui-config <PATH>` | No | Ika network config path |

---

## `ika dwallet get-encryption-key`

Get an encryption key by its object ID (returned from `register-encryption-key`).

```bash
ika dwallet get-encryption-key [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--encryption-key-id <ID>` | Yes | Encryption key object ID |
| `--ika-sui-config <PATH>` | No | Ika network config path |

---

## `ika dwallet verify-presign`

Verify a presign capability.

```bash
ika dwallet verify-presign [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--presign-cap-id <ID>` | Yes | Unverified presign cap ID |
| `--gas-budget <MIST>` | No | Override gas budget |
| `--ika-sui-config <PATH>` | No | Ika network config path |

---

## `ika dwallet get`

Query dWallet information.

```bash
ika dwallet get [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--dwallet-id <ID>` | Yes | dWallet object ID |
| `--ika-sui-config <PATH>` | No | Ika network config path |

---

## `ika dwallet pricing`

Query current pricing information.

```bash
ika dwallet pricing [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--ika-sui-config <PATH>` | No | Ika network config path |

---

## `ika dwallet generate-keypair`

Generate a class-groups encryption keypair offline (useful for debugging or pre-generating keys).

```bash
ika dwallet generate-keypair --curve secp256k1 [--seed <HEX>]
```

Outputs encryption key (public), decryption key (secret), signer public key, and seed.

---

## `ika dwallet share make-public`

Make user secret key shares public (enables autonomous signing).

```bash
ika dwallet share make-public [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--dwallet-id <ID>` | Yes | dWallet object ID |
| `--secret-share <PATH>` | Yes | Path to user secret share file |
| `--ika-coin-id <ID>` | No | IKA coin for payment (auto-detected from wallet) |
| `--sui-coin-id <ID>` | No | SUI coin for payment (auto-detected from wallet) |
| `--gas-budget <MIST>` | No | Override gas budget |
| `--ika-sui-config <PATH>` | No | Ika network config path |

---

## `ika dwallet share re-encrypt`

Re-encrypt user share for a different encryption key.

```bash
ika dwallet share re-encrypt [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--dwallet-id <ID>` | Yes | dWallet object ID |
| `--destination-address <ADDR>` | Yes | Destination address to re-encrypt for |
| `--secret-share <PATH>` | Yes | Path to user secret share file |
| `--source-encrypted-share-id <ID>` | Yes | Source encrypted user secret key share ID |
| `--destination-encryption-key <HEX>` | Yes | Destination user's encryption key (hex) |
| `--curve <CURVE>` | Yes | `secp256k1`, `secp256r1`, `ed25519`, `ristretto` |
| `--ika-coin-id <ID>` | No | IKA coin for payment (auto-detected from wallet) |
| `--sui-coin-id <ID>` | No | SUI coin for payment (auto-detected from wallet) |
| `--gas-budget <MIST>` | No | Override gas budget |
| `--ika-sui-config <PATH>` | No | Ika network config path |

---

## `ika dwallet share accept`

Accept a re-encrypted user share.

```bash
ika dwallet share accept [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--dwallet-id <ID>` | Yes | dWallet object ID |
| `--encrypted-share-id <ID>` | Yes | Encrypted share object ID |
| `--user-output-signature <HEX>` | Yes | User output signature (hex) |
| `--gas-budget <MIST>` | No | Override gas budget |
| `--ika-sui-config <PATH>` | No | Ika network config path |

---

## `ika validator`

Validator operations (30+ subcommands). Use `ika validator --help` for full list.

Key subcommands:
- `make-validator-info` - Generate validator info file
- `become-candidate` - Register as validator candidate
- `join-committee` - Join the active validator committee
- `stake-validator` - Stake IKA tokens
- `leave-committee` - Leave the committee
- `set-commission` - Set commission rate
- `get-validator-metadata` - Query validator info
- `set-pricing-vote` - Set pricing vote

---

## `ika protocol`

Protocol governance operations (feature-gated with `protocol-commands`).

Key subcommands:
- `set-approved-upgrade-by-cap` - Approve package upgrade
- `perform-approved-upgrade` - Execute approved upgrade
- `try-migrate-system` / `try-migrate-coordinator` - System migration
- `set-supported-and-pricing` - Configure supported curves and pricing

---

## `ika config init`

Fetch deployed contract addresses from GitHub and generate the Ika CLI config file.

```bash
ika config init [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--network <NET>` | No | Networks to configure (comma-separated). Default: `testnet,mainnet` |
| `--output <PATH>` | No | Output path for config file. Default: `~/.ika/ika_sui_config.yaml` |

Fetches `address.yaml` from `deployed_contracts/{network}/` on GitHub, uses v2 package IDs when available, and writes the `ika_sui_config.yaml` config. Also prints Sui CLI environment setup instructions.

---

## `ika config show`

Show the current Ika CLI config.

```bash
ika config show [--config <PATH>]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--config <PATH>` | No | Path to config file. Default: `~/.ika/ika_sui_config.yaml` |

---

## `ika completion`

Generate shell completions for the given shell.

```bash
ika completion <SHELL>
```

| Argument | Description |
|----------|-------------|
| `SHELL` | `bash`, `zsh`, `fish`, `elvish`, `powershell` |

Example:
```bash
# Generate and source zsh completions
ika completion zsh > _ika && source _ika
```
