# @ika.xyz/plugins examples

Runnable usage demos for the Ika plugin system. Each file is standalone and imports from the public
subpaths exactly the way real consumers will.

## Setup

```bash
pnpm install        # from repo root or this directory
pnpm -F @ika.xyz/sdk build
```

Set the required env vars:

| Variable                  | Required for          | What                                                    |
| ------------------------- | --------------------- | ------------------------------------------------------- |
| `IKA_TESTNET_PRIVATE_KEY` | every example         | bech32 `suiprivkey...` — pays for every coordinator tx  |
| `IKA_USEK_SEED`           | every example         | any string; deterministically derives the USEK          |
| `SUI_RPC_URL`             | optional              | overrides the testnet fullnode endpoint                 |
| `SOLANA_RPC_URL`          | example 05            | overrides the Solana devnet endpoint                    |
| `ETH_RPC_URL`             | example 07            | overrides the Sepolia endpoint                          |
| `ETH_BROADCAST`           | example 07 (optional) | set to `1` to also broadcast a self-transfer to Sepolia |

The dWallet's derived address must be funded out-of-band for examples that broadcast (04, 05).

## Examples

| Script                    | File                              | Demonstrates                                                                 |
| ------------------------- | --------------------------------- | ---------------------------------------------------------------------------- |
| `pnpm shared-dwallet`     | `01-create-shared-dwallet.ts`     | Shared (Ed25519) dWallet creation; auto-decoration with `.sui` and `.solana` |
| `pnpm zero-trust-dwallet` | `02-create-zero-trust-dwallet.ts` | Zero-trust (secp256k1) dWallet; off-chain message sign                       |
| `pnpm import-key`         | `03-import-key.ts`                | Migrate an existing secp256k1 key; per-dWallet ECDSA presign                 |
| `pnpm sign-sui`           | `04-sign-sui-tx.ts`               | Build a Sui `Transaction`, sign with the dWallet, broadcast via `publish()`  |
| `pnpm sign-solana`        | `05-sign-solana-tx.ts`            | Cross-chain: same source (Sui), Solana destination + devnet publisher        |
| `pnpm sign-bitcoin`       | `06-sign-bitcoin-taproot.ts`      | All 4 BTC modes (legacy / segwit / nested / taproot script-path) via `btc()` |
| `pnpm sign-ethereum`      | `07-sign-ethereum.ts`             | EIP-191 message + EIP-1559 tx via `ika.ethereum.sign` + `ethPublisher`       |
| `pnpm compose`            | `08-compose-multi-op.ts`          | Multiple sign Move calls bundled into a single Sui PTB                       |
| `pnpm multisig-approval`  | `09-multisig-approval.ts`         | Custom `buildApproval` hook for multisig / sponsored authorization flows     |
| `pnpm recovery`           | `10-recover-partial-dkg.ts`       | Handle `ImportedKeySharedPartialError` and resume via `retryReveal()`        |

## How the examples are wired

`src/shared.ts` exports `buildIka(curve)` which constructs an `IkaClient` with the four default
plugins installed:

```typescript
return new IkaClient()
	.use(suiSource({ network: 'testnet', signer, userShareEncryptionKeys: useks, suiClient }))
	.use(sui())
	.use(suiPublisher({ suiClient }))
	.use(solana())
	.use(solanaDevnet({ confirm: true }));
```

Example 07 (`sign-ethereum`) builds its own client because it adds the Ethereum destination +
publisher on top:

```typescript
.use(suiSource({ ... }))
.use(eth())
.use(ethPublisher({ url: 'https://rpc.sepolia.org', chain: sepolia, confirm: true }));
```

Each example reuses this so the focus stays on the operation being shown.

## Conventions

- All examples run against **testnet**. Move them to mainnet by switching `network: 'testnet'` to
  `network: 'mainnet'` and pointing the Sui client at a mainnet RPC.
- Off-chain message signing (`kind: 'message'`) produces an authentication artifact, not a
  broadcastable transaction. `kind: 'transaction'` is the on-chain path.
- The USEK is derived deterministically from `IKA_USEK_SEED`. Same seed across runs gives the same
  encrypted-share recipient — useful for finding previously created dWallets. Treat the seed as
  secret material.
