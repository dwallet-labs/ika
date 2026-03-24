# @ika.xyz/ows

Open Wallet Standard (OWS) implementation backed by Ika dWallet MPC signing. Provides a complete wallet SDK for agents and applications to create, manage, and sign with multi-chain wallets — all secured by Ika's 2PC-MPC protocol.

## Installation

```bash
pnpm add @ika.xyz/ows
```

## Quick Start

```typescript
import { IkaOWSProvider } from '@ika.xyz/ows';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';

const keypair = Ed25519Keypair.fromSecretKey(seed);
const provider = new IkaOWSProvider({
  network: 'mainnet',
  keypair,
});
await provider.initialize();

// Create a wallet
const wallet = await provider.createWallet('agent-wallet', 'passphrase');

// Set up on-chain policy engine (one call does everything)
const config = await provider.setupPolicyEngine('0xPOLICY_PKG', 'agent-wallet', [
  { type: 'rate_limit', maxPerWindow: 100, windowMs: 3_600_000 },
  { type: 'spending_budget', maxPerWindow: 10000, maxPerTx: 500, windowMs: 86_400_000 },
  { type: 'sender_allowlist', allowed: [keypair.toSuiAddress()] },
]);

// Sign — automatically goes through the policy engine
const sig = await provider.signTransaction('agent-wallet', 'eip155:1', txHex, {
  declaredValue: 5000,
});
```

## Architecture

```
src/
├── provider.ts          # IkaOWSProvider — main entry point
├── executor.ts          # SerialTransactionExecutor wrapper (prevents gas collisions)
├── presign-pool.ts      # Presign pool for fast signing
├── policy.ts            # Local policy engine (Layer 1)
├── server.ts            # REST API server
├── chains.ts            # CAIP-2 chain → Ika crypto parameter mapping
├── address.ts           # Public key → chain-native address derivation
├── mnemonic.ts          # BIP-39 mnemonic utilities
├── crypto.ts            # AES-256-GCM encryption, BIP-44 derivation
├── vault.ts             # Local file-based wallet storage
├── types.ts             # Type definitions
├── errors.ts            # Error codes
├── cli/index.ts         # CLI (ika-ows)
└── tx/
    ├── policy-engine.ts # Move call builders for on-chain policy engine
    └── algo-numbers.ts  # Enum → u32 conversion for Move calls

contract/                # On-chain policy engine (Move)
├── Move.toml
└── sources/
    ├── policy_engine.move
    └── rules/           # 7 composable rules
```

## Wallet Types

| Type | Creation | Key Custody | Use Case |
|------|----------|-------------|----------|
| **Mnemonic** | `createWallet()` | BIP-39 mnemonic → imported into Ika | OWS-compatible, recoverable |
| **DKG** | `createDWallet()` | No key ever exists — distributed generation | Maximum security |
| **Imported** | `importWalletPrivateKey()` | Raw private key → imported into Ika | Migration from existing wallets |

All wallet types produce signatures through Ika's 2PC-MPC protocol. The private key (if any) is only used during the import protocol and never stored in plaintext.

## Supported Chains

A single dWallet signs for all chains on its curve:

| Chain | CAIP-2 | Curve | Signature | Hash |
|-------|--------|-------|-----------|------|
| EVM (Ethereum, Base, etc.) | `eip155:*` | secp256k1 | ECDSA | KECCAK256 |
| Bitcoin | `bip122:*` | secp256k1 | ECDSA | DoubleSHA256 |
| Solana | `solana:*` | ed25519 | EdDSA | SHA512 |
| Sui | `sui:*` | ed25519 | EdDSA | SHA512 |
| Cosmos | `cosmos:*` | secp256k1 | ECDSA | SHA256 |
| Tron | `tron:*` | secp256k1 | ECDSA | KECCAK256 |
| TON | `ton:*` | ed25519 | EdDSA | SHA512 |
| Filecoin | `fil:*` | secp256k1 | ECDSA | SHA256 |

## Presign Pool

Presigns are pre-computed cryptographic values that accelerate signing. Without a pool, every sign call first creates a presign (~30-60s). With pooled presigns, signing drops to ~10-20s.

```typescript
await provider.prefillPresigns('my-wallet', 'ECDSASecp256k1', 10);
const sig = await provider.signTransaction('my-wallet', 'eip155:1', txHex);
```

Presign IDs are persisted in the vault and survive process restarts.

## On-Chain Policy Engine

The DWalletCap is custodied inside a shared `PolicyEngine` object on Sui. The agent cannot call `approve_message` directly — it must go through the engine, which enforces all registered rules via a composable receipt system. See [contract/README.md](contract/README.md) for the Move-level docs.

### One-Call Setup

```typescript
// Creates engine, registers rules, grants access cap, wires up signing
const config = await provider.setupPolicyEngine('0xPKG', 'my-wallet', [
  { type: 'rate_limit', maxPerWindow: 100, windowMs: 3_600_000 },
  { type: 'sender_allowlist', allowed: [agentAddress] },
  { type: 'spending_budget', maxPerWindow: 10000, maxPerTx: 500, windowMs: 86_400_000 },
  { type: 'expiry', expiryMs: Date.now() + 7 * 86_400_000 },
  { type: 'target_filter', allowedTargets: ['0xUNISWAP_ROUTER'], blockedTargets: [] },
]);
// Provider now routes all signing through the engine automatically.
```

### Step-by-Step

```typescript
// 1. Create engine (custodies the DWalletCap)
const { engineId, adminCapId } = await provider.createPolicyEngine('0xPKG', 'my-wallet', [
  { type: 'rate_limit', maxPerWindow: 100, windowMs: 3_600_000 },
]);

// 2. Add more rules later
await provider.addPolicyRule('0xPKG', engineId, adminCapId, {
  type: 'spending_budget', maxPerWindow: 10000, maxPerTx: 500, windowMs: 86_400_000,
});

// 3. Grant access to an agent
const { accessCapId } = await provider.grantPolicyAccess('0xPKG', engineId, adminCapId, agentAddr);

// 4. Remove a rule
await provider.removePolicyRule('0xPKG', engineId, adminCapId, 'rate_limit');

// 5. Emergency pause / unpause
await provider.pausePolicyEngine('0xPKG', engineId, adminCapId);
await provider.unpausePolicyEngine('0xPKG', engineId, adminCapId);
```

### Available Rules

| Rule | What it enforces |
|------|-----------------|
| `rate_limit` | Max N signatures per time window |
| `expiry` | Signing blocked after a timestamp |
| `sender_allowlist` | Only whitelisted `ctx.sender()` addresses |
| `allowed_algorithms` | Only specific (sig_algo, hash) pairs — controls which chains |
| `spending_budget` | Per-tx cap + cumulative budget per window (agent-declared) |
| `target_filter` | Target address allowlist/blocklist (agent-declared) |
| `time_delay` | Commit-reveal with ms-precision owner veto window |

### Time Delay Flow

```typescript
// 1. Commit (separate tx)
await provider.commitTimeDelay(messageHash);

// 2. Wait the configured delay...

// 3. Sign (enforce checks delay elapsed)
const sig = await provider.signTransaction('my-wallet', 'eip155:1', txHex);
```

### Passing Config Directly

If the engine already exists (e.g., created by the wallet owner separately):

```typescript
const provider = new IkaOWSProvider({
  network: 'mainnet',
  keypair,
  policyEngine: {
    packageId: '0xPOLICY_PKG',
    engineId: '0xENGINE',
    accessCapId: '0xACCESS_CAP',
    rules: ['rate_limit', 'sender_allowlist', 'spending_budget'],
  },
});
```

## Local Policies (Layer 1)

Evaluated in-process before any on-chain interaction:

```typescript
// Declarative rules (JSON, persisted to vault)
provider.policies.createPolicy('evm-only', {
  allowed_chains: ['eip155'],
  max_daily_transactions: 100,
  rate_limit: { max_requests: 10, window_seconds: 60 },
});

// Custom TypeScript policy functions
provider.addPolicy({
  name: 'business-hours',
  evaluate: (ctx) => {
    const hour = new Date(ctx.timestamp).getUTCHours();
    if (hour < 9 || hour > 17)
      return { allow: false, reason: 'Outside business hours' };
    return { allow: true };
  },
});
```

## REST API

### Start

```bash
IKA_OWS_KEYPAIR=<hex> IKA_OWS_API_KEY=<secret> ika-ows serve --port 3420
```

Or programmatically:

```typescript
import { IkaOWSProvider, startServer } from '@ika.xyz/ows';

const provider = new IkaOWSProvider({ network: 'mainnet', keypair });
await provider.initialize();
startServer({ provider, apiKey: 'my-secret', port: 3420 });
```

### Endpoints

All endpoints (except `/health`) require `Authorization: Bearer <api-key>`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/wallets` | List wallets |
| `GET` | `/wallets/:id` | Get wallet details |
| `POST` | `/wallets` | Create mnemonic wallet |
| `POST` | `/wallets/dkg` | Create DKG wallet |
| `POST` | `/wallets/import/mnemonic` | Import from mnemonic |
| `POST` | `/wallets/import/private-key` | Import from private key |
| `DELETE` | `/wallets/:id` | Delete wallet |
| `POST` | `/sign/transaction` | Sign transaction |
| `POST` | `/sign/message` | Sign message |
| `POST` | `/presigns/prefill` | Pre-create presigns |
| `GET` | `/presigns/available` | Check available presigns |
| `POST` | `/commit` | Commit message hash (time delay) |

### Framework Integration

```typescript
import { handleRequest } from '@ika.xyz/ows';

app.all('/ows/*', async (req, res) => {
  const response = await handleRequest(provider, apiKey, {
    method: req.method,
    path: req.path.replace('/ows', ''),
    body: req.body,
    headers: req.headers,
  });
  res.status(response.status).json(response.body);
});
```

## CLI

```bash
export IKA_OWS_KEYPAIR=<hex-encoded-ed25519-secret-key>
export IKA_OWS_PASSPHRASE=<wallet-passphrase>
export IKA_OWS_NETWORK=mainnet

ika-ows wallet create --name my-wallet
ika-ows wallet dkg --name secure-wallet
ika-ows wallet list
ika-ows wallet info --wallet my-wallet
ika-ows wallet export --wallet my-wallet
ika-ows wallet delete --wallet my-wallet

ika-ows sign tx --wallet my-wallet --chain eip155:1 --tx <hex>
ika-ows sign message --wallet my-wallet --chain eip155:1 --message "hello"

ika-ows presign prefill --wallet my-wallet --count 10
ika-ows presign list --wallet my-wallet

ika-ows mnemonic generate --words 24
ika-ows mnemonic derive --chain evm --mnemonic "abandon abandon ..."

ika-ows pay request https://api.example.com/paid-endpoint --wallet my-wallet

ika-ows policy create --name rate-limit --file rules.json
ika-ows policy list
ika-ows policy delete --id <uuid> --confirm

ika-ows serve --port 3420
```

## Building

```bash
pnpm install && pnpm build    # TypeScript SDK
cd contract && sui move build  # Move contracts
```

## License

BSD-3-Clause-Clear
