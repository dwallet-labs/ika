# Ika CLI Command Reference

## Shared Argument Groups

### Seed Derivation Args (`SeedArgs`)

Used by commands that derive encryption keys (`create`, `import`, `register-encryption-key`, `generate-keypair`).

| Flag | Description |
|------|-------------|
| `--seed-file <PATH>` | Path to a raw 32-byte seed file. Mutually exclusive with `--address` |
| `--address <ADDR>` | Derive seed from a specific Sui keystore address (default: active address) |
| `--encryption-key-index <N>` | Key derivation index (default: `0`). Used with address-based derivation |
| `--legacy-hash` | Use legacy V1 hash (curve byte always 0). Only needed for keys registered before the V2 hash fix |

Seed derivation formula: `seed = keccak256(keypair_bytes || index_le_bytes)`. The hash then uses `keccak256(domain_separator || curve_byte || seed)` where `curve_byte` is the curve number (V2) or always 0 (V1/legacy). SECP256K1 (curve=0) is unaffected by the version difference.

### Payment Args (`PaymentArgs`)

| Flag | Description |
|------|-------------|
| `--ika-coin-id <ID>` | IKA coin object ID for payment. Auto-detected from wallet if omitted |
| `--sui-coin-id <ID>` | SUI coin object ID for payment. Uses the gas coin if omitted |

### Transaction Args (`TxArgs`)

| Flag | Description |
|------|-------------|
| `--gas-budget <MIST>` | Override the default gas budget |
| `--ika-config <PATH>` | Override the Ika network config path |

---

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
| `--output-secret <PATH>` | No | Output path (default: `dwallet_secret_share.bin`) |
| `--public-share` | No | Create shared dWallet (public user key share) |
| `--sign-message <HEX>` | No | Sign during DKG |
| `--hash-scheme <U32>` | No | Hash scheme for sign-during-DKG |
| Seed args | No | `--seed-file`, `--address`, `--encryption-key-index`, `--legacy-hash` |
| Payment args | No | `--ika-coin-id`, `--sui-coin-id` |
| Transaction args | No | `--gas-budget`, `--ika-config` |

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
| Payment args | No | `--ika-coin-id`, `--sui-coin-id` |
| Transaction args | No | `--gas-budget`, `--ika-config` |

**Auto-detection:** When `--dwallet-id` is provided, curve and DKG output are fetched from the dWallet object on chain (requires Active state). When `--presign-output` is omitted, it is fetched from the presign session referenced by `--presign-cap-id` (requires Completed state). The presign cap is auto-verified if unverified (composed into the same transaction). Imported key dWallets are auto-detected and routed to the correct sign flow.

---

## `ika dwallet future-sign create`

Create a partial user signature (first step of future signing). Pass --dwallet-id to auto-fetch curve and DKG output from chain.

```bash
ika dwallet future-sign create [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--dwallet-id <ID>` | Yes | dWallet object ID (auto-fetches curve and DKG output) |
| `--message <HEX>` | Yes | Message to sign |
| `--hash-scheme <U32>` | Yes | Hash scheme |
| `--presign-cap-id <ID>` | Yes | Verified presign cap ID |
| `--secret-share <PATH>` | Yes | Path to user secret share |
| `--signature-algorithm <U32>` | Yes | Signature algorithm |
| `--presign-output <HEX>` | No | Presign output (hex). Auto-fetched from --presign-cap-id if omitted |
| `--dkg-output <HEX>` | No | DKG public output (hex). Auto-fetched from --dwallet-id if omitted |
| `--curve <CURVE>` | No | Override auto-detected curve |
| Payment args | No | `--ika-coin-id`, `--sui-coin-id` |
| Transaction args | No | `--gas-budget`, `--ika-config` |

---

## `ika dwallet future-sign fulfill`

Fulfill a future sign using a partial user signature cap (second step). Verifies the partial user signature cap, approves the message, and submits the final sign request.

```bash
ika dwallet future-sign fulfill [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--partial-cap-id <ID>` | Yes | Partial user signature cap ID (from `future-sign create`) |
| `--dwallet-cap-id <ID>` | Yes | dWallet cap ID (for message approval) |
| `--message <HEX>` | Yes | Message to sign |
| `--signature-algorithm <U32>` | Yes | Signature algorithm |
| `--hash-scheme <U32>` | Yes | Hash scheme |
| `--wait` | No | Wait for sign session to complete and return the signature |
| Payment args | No | `--ika-coin-id`, `--sui-coin-id` |
| Transaction args | No | `--gas-budget`, `--ika-config` |

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
| Payment args | No | `--ika-coin-id`, `--sui-coin-id` |
| Transaction args | No | `--gas-budget`, `--ika-config` |

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
| Payment args | No | `--ika-coin-id`, `--sui-coin-id` |
| Transaction args | No | `--gas-budget`, `--ika-config` |

Network encryption key is auto-fetched from the Ika coordinator.

---

## `ika dwallet import`

Import an external key as a dWallet. Coins are auto-detected from wallet.

The secret key file format depends on the curve:
- **secp256k1 / secp256r1**: 33 bytes (compressed public key prefix byte + 32-byte scalar)
- **ed25519 / ristretto**: 32 bytes (raw scalar, must be a valid scalar for the curve)

```bash
ika dwallet import [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--curve <CURVE>` | Yes | `secp256k1`, `secp256r1`, `ed25519`, `ristretto` |
| `--secret-key <PATH>` | Yes | Path to the secret key file to import |
| `--output-secret <PATH>` | No | Where to save user secret share (default: `imported_dwallet_secret_share.bin`) |
| Seed args | No | `--seed-file`, `--address`, `--encryption-key-index`, `--legacy-hash` |
| Payment args | No | `--ika-coin-id`, `--sui-coin-id` |
| Transaction args | No | `--gas-budget`, `--ika-config` |

Requires a previously registered encryption key (from `register-encryption-key`). Network encryption key is auto-fetched from the Ika coordinator.

---

## `ika dwallet register-encryption-key`

Register a user encryption key for dWallet operations. Encryption keys are derived stateless from the Sui keystore address.

```bash
ika dwallet register-encryption-key [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--curve <CURVE>` | Yes | `secp256k1`, `secp256r1`, `ed25519`, `ristretto` |
| Seed args | No | `--seed-file`, `--address`, `--encryption-key-index`, `--legacy-hash` |
| Transaction args | No | `--gas-budget`, `--ika-config` |

---

## `ika dwallet get-encryption-key`

Get an encryption key by its object ID (returned from `register-encryption-key`).

```bash
ika dwallet get-encryption-key [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--encryption-key-id <ID>` | Yes | Encryption key object ID |
| Transaction args | No | `--gas-budget`, `--ika-config` |

---

## `ika dwallet verify-presign`

Verify a presign capability.

```bash
ika dwallet verify-presign [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--presign-cap-id <ID>` | Yes | Unverified presign cap ID |
| Transaction args | No | `--gas-budget`, `--ika-config` |

---

## `ika dwallet get`

Query dWallet information.

```bash
ika dwallet get [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--dwallet-id <ID>` | Yes | dWallet object ID |
| Transaction args | No | `--gas-budget`, `--ika-config` |

---

## `ika dwallet pricing`

Query current pricing information.

```bash
ika dwallet pricing [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| Transaction args | No | `--gas-budget`, `--ika-config` |

---

## `ika dwallet generate-keypair`

Generate a class-groups encryption keypair offline (useful for debugging or pre-generating keys).

```bash
ika dwallet generate-keypair --curve secp256k1 [--seed-file <PATH>]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--curve <CURVE>` | Yes | `secp256k1`, `secp256r1`, `ed25519`, `ristretto` |
| Seed args | No | `--seed-file`, `--address`, `--encryption-key-index`, `--legacy-hash` |

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
| Payment args | No | `--ika-coin-id`, `--sui-coin-id` |
| Transaction args | No | `--gas-budget`, `--ika-config` |

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
| Payment args | No | `--ika-coin-id`, `--sui-coin-id` |
| Transaction args | No | `--gas-budget`, `--ika-config` |

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
| Transaction args | No | `--gas-budget`, `--ika-config` |

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

Fetch deployed contract addresses from GitHub, generate the Ika CLI config file, and create Sui CLI environments (`ika-mainnet`, `ika-testnet`, `ika-localnet`).

```bash
ika config init [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--output <PATH>` | No | Output path for Ika config file. Default: `~/.ika/ika_sui_config.yaml` |

Fetches `address.yaml` for testnet and mainnet from GitHub, writes the `ika_sui_config.yaml` config keyed by `ika-{network}`, and creates Sui CLI environments for all networks (including localnet). Localnet addresses must be added separately via `add-env`. After init, switch with `sui client switch --env ika-testnet`.

---

## `ika config add-env`

Add or update a network environment from a local `ika_config.json` file.

```bash
ika config add-env --network localnet --from-file ./ika_config.json
```

| Flag | Required | Description |
|------|----------|-------------|
| `--network <NAME>` | Yes | Network name (e.g., `localnet`). Stored as `ika-{name}` |
| `--from-file <PATH>` | Yes | Path to `ika_config.json` with contract addresses |
| `--rpc <URL>` | No | Sui RPC URL. Default: auto-detected per network |
| `--config <PATH>` | No | Path to Ika config file. Default: `~/.ika/ika_sui_config.yaml` |

Use after `ika system initialize` or `ika-swarm-config` generates `ika_config.json` for a local/custom network.

---

## `ika config sync`

Re-fetch the latest deployed contract addresses from GitHub and update the existing Ika config file.

```bash
ika config sync [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--network <NET>` | No | Networks to sync (comma-separated). Default: `testnet,mainnet` |
| `--config <PATH>` | No | Path to the Ika config file to update. Default: `~/.ika/ika_sui_config.yaml` |

Existing entries for networks not listed in `--network` are preserved.

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
