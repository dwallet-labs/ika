# @ika.xyz/odws

Open dWallet Standard (OdWS) — multi-chain wallet SDK backed by Ika dWallet MPC signing. Create wallets, sign transactions on any chain, enforce on-chain policies — all secured by Ika's 2PC-MPC protocol.

## Installation

```bash
pnpm add @ika.xyz/odws
```

After installation, the `odws` CLI is available:

```bash
npx odws --help
```

Or install globally:

```bash
pnpm add -g @ika.xyz/odws
odws wallet list
```

## Quick Start

```typescript
import { IkaOWSProvider, derivePrivateKeyFromMnemonic, bytesToHex } from '@ika.xyz/odws';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Curve } from '@ika.xyz/sdk';

const provider = new IkaOWSProvider({
  network: 'mainnet',
  keypair: Ed25519Keypair.fromSecretKey(suiSecretKey),
});
await provider.initialize();

// Import a private key (secp256k1 for EVM/BTC/Cosmos)
const wallet = await provider.createWallet('evm-wallet', privateKeyHex, {
  curve: Curve.SECP256K1,
});

// Sign
const sig = await provider.signTransaction('evm-wallet', 'eip155:1', txHex);
```

## Wallet Creation

Two ways to create wallets:

### Import Private Key

You provide a 32-byte hex private key. The key is imported into Ika via 2PC-MPC — only used during import, never stored.

```typescript
// secp256k1 (EVM, Bitcoin, Cosmos, Tron, Filecoin)
const wallet = await provider.createWallet('my-wallet', privateKeyHex, {
  curve: Curve.SECP256K1,
});

// ed25519 (Solana, Sui, TON)
const wallet = await provider.createWallet('sol-wallet', ed25519ScalarHex, {
  curve: Curve.ED25519,
});
```

### DKG (Distributed Key Generation)

No private key ever exists. Generated distributedly via MPC.

```typescript
const wallet = await provider.createDWallet('mpc-wallet', {
  curve: Curve.SECP256K1,
});
```

## Mnemonic Derivation

The SDK provides helpers to derive private keys from BIP-39 mnemonics. You handle derivation, the SDK handles import.

```typescript
import { generateMnemonic, derivePrivateKeyFromMnemonic, bytesToHex } from '@ika.xyz/odws';
import { Curve } from '@ika.xyz/sdk';

const mnemonic = generateMnemonic(12);

// secp256k1: BIP-32 derivation at m/44'/60'/0'/0/{index}
const evmKey = derivePrivateKeyFromMnemonic(mnemonic, Curve.SECP256K1, 0);

// ed25519: SLIP-0010 + SHA-512 + clamp + mod L
// Produces Phantom-compatible Solana addresses
const solKey = derivePrivateKeyFromMnemonic(mnemonic, Curve.ED25519, 0);

const wallet = await provider.createWallet('sol', bytesToHex(solKey), {
  curve: Curve.ED25519,
});
// wallet address matches Phantom for the same mnemonic + index
```

For ed25519, you can also use `ed25519SeedToPrivateKey(seed)` if you handle SLIP-0010 derivation yourself.

## IKA Token Requirements

Every on-chain operation requires IKA tokens for protocol fees. Each operation uses 10 IKA.

- **Minimum balance:** 10 IKA
- **Recommended:** 1,000–10,000 IKA

## Supported Chains

A single dWallet signs for all chains on its curve:

| Chain | CAIP-2 | Curve | Signature | Hash |
|-------|--------|-------|-----------|------|
| EVM | `eip155:*` | secp256k1 | ECDSA | KECCAK256 |
| Bitcoin | `bip122:*` | secp256k1 | ECDSA | DoubleSHA256 |
| Solana | `solana:*` | ed25519 | EdDSA | SHA512 |
| Sui | `sui:*` | ed25519 | EdDSA | SHA512 |
| Cosmos | `cosmos:*` | secp256k1 | ECDSA | SHA256 |
| Tron | `tron:*` | secp256k1 | ECDSA | KECCAK256 |
| TON | `ton:*` | ed25519 | EdDSA | SHA512 |
| Filecoin | `fil:*` | secp256k1 | ECDSA | SHA256 |

## Presign Pool

Pre-computed presigns accelerate signing from ~30-60s to ~20s.

```typescript
await provider.prefillPresigns('my-wallet', 'ECDSASecp256k1', 10);
const sig = await provider.signTransaction('my-wallet', 'eip155:1', txHex); // uses pooled presign
```

## On-Chain Policy Engine

**Mainnet Package ID:** `0x9fd74e7ad831f13730ddb59072978eeb51b1eb840f97238d836b27953be52180`

The DWalletCap is custodied inside a shared PolicyEngine. The agent must collect receipts from every registered rule before signing. See [contract/README.md](contract/README.md).

```typescript
const config = await provider.setupPolicyEngine(
  '0x9fd74e7ad831f13730ddb59072978eeb51b1eb840f97238d836b27953be52180',
  'my-wallet',
  [
    { type: 'rate_limit', maxPerWindow: 100, windowMs: 3_600_000 },
    { type: 'spending_budget', maxPerWindow: 10000, maxPerTx: 500, windowMs: 86_400_000 },
  ],
);
```

## REST API

```bash
IKA_OWS_KEYPAIR=<hex> IKA_OWS_API_KEY=<secret> odws serve --port 3420
```

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/wallets` | List wallets |
| `POST` | `/wallets` | Create wallet `{ name, privateKey, curve }` |
| `POST` | `/wallets/dkg` | Create DKG wallet `{ name, curve }` |
| `POST` | `/sign/transaction` | Sign transaction |
| `POST` | `/sign/message` | Sign message |
| `POST` | `/presigns/prefill` | Pre-create presigns |

All endpoints (except `/health`) require `Authorization: Bearer <api-key>`.

## CLI

```bash
odws wallet create --name my-wallet --key <hex> --curve SECP256K1
odws wallet dkg --name mpc-wallet --curve SECP256K1
odws wallet list
odws sign tx --wallet my-wallet --chain eip155:1 --tx <hex>
odws sign message --wallet my-wallet --chain eip155:1 --message "hello"
odws presign prefill --wallet my-wallet --count 10
odws serve --port 3420
```

## Debugging

Set `ODWS_DEBUG=1` for verbose logging:

```bash
ODWS_DEBUG=1 node my-agent.js
```

## Vault Backup

```typescript
import { exportVault, importVault } from '@ika.xyz/odws';

const backup = exportVault('/path/to/vault');
fs.writeFileSync('backup.json', backup);

// Restore
importVault(fs.readFileSync('backup.json', 'utf-8'), '/path/to/new-vault');
```

## Architecture

```
src/
├── client/          # Provider, executor, presign pool
├── chain/           # CAIP-2 mapping, address derivation
├── crypto/          # Encryption, key derivation, hex utils
├── policy/          # Local policy filters (advisory)
├── server/          # REST API
├── vault/           # File-based wallet storage
├── tx/              # Move call builders (codegen)
├── cli/             # CLI
└── generated/       # Auto-generated from Move contract
```

## Building

```bash
pnpm install && pnpm build    # TypeScript SDK
cd contract && sui move build  # Move contracts
pnpm test                      # Unit tests
```

## License

BSD-3-Clause-Clear
