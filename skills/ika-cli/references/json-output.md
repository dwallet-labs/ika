# Ika CLI JSON Output Schemas

All commands support `--json` for structured JSON output. This document describes the output format for each command.

## `ika dwallet create --json`

```json
{
  "type": "create",
  "dwallet_id": "0x...",
  "dwallet_cap_id": "0x...",
  "public_key": "hex...",
  "secret_share_path": "/path/to/dwallet_secret_share.bin"
}
```

## `ika dwallet sign --json` / `ika dwallet future-sign --json`

```json
{
  "type": "sign",
  "digest": "base58...",
  "status": "Success"
}
```

## `ika dwallet presign --json` / `ika dwallet global-presign --json`

```json
{
  "type": "presign",
  "digest": "base58...",
  "status": "Success"
}
```

## `ika dwallet register-encryption-key --json`

```json
{
  "type": "register_encryption_key",
  "encryption_key_id": "0x...",
  "digest": "base58...",
  "status": "Success"
}
```

## `ika dwallet get --json`

```json
{
  "type": "get",
  "dwallet": {
    "fields": {
      "id": { "id": "0x..." },
      "curve": 0,
      "state": {
        "variant": "Active",
        "fields": { "public_output": [...] }
      }
    }
  }
}
```

## `ika dwallet get-encryption-key --json`

```json
{
  "type": "get",
  "dwallet": {
    "encryption_key_id": "0x...",
    "encryption_key": {
      "id": { "id": "0x..." },
      "curve": 0,
      "encryption_key": [...],
      "signer_public_key": [...],
      "signer_address": "0x..."
    }
  }
}
```

## `ika dwallet generate-keypair --json`

```json
{
  "type": "keypair",
  "encryption_key": "hex...",
  "decryption_key": "hex...",
  "signer_public_key": "hex...",
  "seed": "hex..."
}
```

## `ika dwallet pricing --json`

```json
{
  "type": "pricing",
  "pricing": {
    "dkg_price_ika": 1000000,
    "presign_price_ika": 500000,
    "sign_price_ika": 500000
  }
}
```

## Transaction-producing commands (`--json`)

Commands that produce Sui transactions (verify-presign, share operations, import, etc.) output:

```json
{
  "type": "transaction",
  "digest": "base58...",
  "status": "Success"
}
```

## `ika validator` commands (`--json`)

Validator commands serialize using `serde_json`. The output varies by subcommand but includes the full `SuiTransactionBlockResponse` when `--json` is used. Example:

```json
{
  "digest": "...",
  "transaction": { ... },
  "effects": { ... },
  "events": [ ... ],
  "objectChanges": [ ... ],
  "balanceChanges": [ ... ]
}
```

## Error Format (`--json`)

When any command fails with `--json`, errors are returned as structured JSON instead of colored terminal output:

```json
{
  "error": "description of the error"
}
```

The process still exits with code 1 on error.

## Notes

- All object IDs are hex-encoded with `0x` prefix
- All byte arrays (public keys, messages) are hex-encoded
- Transaction digests use base58 encoding (Sui standard)
- Amounts are in the smallest unit (MIST for SUI, smallest IKA unit)
- Use `--quiet` (`-q`) to suppress human-readable output; JSON output is still printed when `--json --quiet` are combined
- Global flags `--ika-config` and `--gas-budget` apply to all dwallet subcommands as defaults
