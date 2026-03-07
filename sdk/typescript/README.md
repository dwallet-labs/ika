### @ika.xyz/sdk — TypeScript SDK for Ika Network

**v0.3.0**

## Overview

TypeScript SDK for interacting with the Ika Network on Sui. Provides everything needed to create and
manage dWallets, zero-trust multi-chain signing powered by 2PC-MPC.

- Create and manage dWallets (zero-trust, imported-key, shared variants)
- Sign messages across multiple curves and signature algorithms
- Handle user share encryption, decryption, and re-encryption
- Query on-chain state (dWallets, presigns, encryption keys, protocol parameters)
- Build transaction blocks for all dWallet flows (DKG, presign, sign, future sign)

### Install

```bash
bun add @ika.xyz/sdk
```

Peer/runtime requirements:

- Node >= 18

### Build (in this repo)

From the repo root:

```bash
pnpm install
pnpm sdk build
```

Or from `sdk/typescript`:

```bash
pnpm install
pnpm run build
```

## Network configuration

Use `getNetworkConfig(network)` to obtain package/object IDs for `testnet` or `mainnet`.

```ts
import { getNetworkConfig } from '@ika.xyz/sdk';

const config = getNetworkConfig('testnet');
```

## Creating a client

`IkaClient` wraps a Sui JSON-RPC client and provides caching, encryption key management, and helpers
for fetching network objects and protocol parameters.

```ts
import { getNetworkConfig, IkaClient } from '@ika.xyz/sdk';
import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';

const suiClient = new SuiJsonRpcClient({
	url: getJsonRpcFullnodeUrl('testnet'),
	network: 'testnet',
});
const ikaClient = new IkaClient({
	suiClient,
	config: getNetworkConfig('testnet'),
	cache: true,
	encryptionKeyOptions: { autoDetect: true },
});

await ikaClient.initialize();
```

### Client options

| Option                     | Description                                                         |
| -------------------------- | ------------------------------------------------------------------- |
| `config`                   | Network configuration from `getNetworkConfig()`                     |
| `suiClient`                | A `SuiJsonRpcClient` (or any `ClientWithCoreApi`) instance          |
| `cache`                    | Enable caching for network objects (default: `false`)               |
| `timeout`                  | Polling timeout in ms for state-waiting queries                     |
| `encryptionKeyOptions`     | Encryption key selection: `{ autoDetect }` or `{ encryptionKeyID }` |
| `protocolPublicParameters` | Pre-loaded protocol public parameters to skip fetching              |

### Querying dWallets

```ts
const dWallet = await ikaClient.getDWallet('0x...');
const dWallets = await ikaClient.getMultipleDWallets(['0x...', '0x...']);
const caps = await ikaClient.getOwnedDWalletCaps('0xaddress...');

// Poll until a dWallet reaches a specific state
const ready = await ikaClient.getDWalletInParticularState('0x...', 'Completed');
```

### Querying presigns, signatures, and shares

```ts
const presign = await ikaClient.getPresign('0x...');
const sign = await ikaClient.getSign('0x...', Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256k1);
const share = await ikaClient.getEncryptedUserSecretKeyShare('0x...');
const partial = await ikaClient.getPartialUserSignature('0x...');

// All support polling for a specific state
const completedSign = await ikaClient.getSignInParticularState(
	'0x...',
	Curve.SECP256K1,
	SignatureAlgorithm.ECDSASecp256k1,
	'Completed',
);
```

### Encryption keys and protocol parameters

```ts
const allKeys = await ikaClient.getAllNetworkEncryptionKeys();
const latestKey = await ikaClient.getLatestNetworkEncryptionKey();
const encKey = await ikaClient.getActiveEncryptionKey('0xaddress...');
const pp = await ikaClient.getProtocolPublicParameters();
const epoch = await ikaClient.getEpoch();
```

## Transactions helper

`IkaTransaction` wraps a Sui `Transaction` and adds typed methods for every dWallet flow.

```ts
import { IkaClient, IkaTransaction } from '@ika.xyz/sdk';
import { Transaction } from '@mysten/sui/transactions';

const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx });
```

### DKG (distributed key generation)

```ts
// Create a dWallet in a single transaction
const result = await ikaTx.requestDWalletDKG({
	dkgRequestInput,
	sessionIdentifier,
	dwalletNetworkEncryptionKeyId,
	curve: Curve.SECP256K1,
	ikaCoin,
	suiCoin,
});

// Or with a public user share
await ikaTx.requestDWalletDKGWithPublicUserShare({ ... });
```

### Presigning

```ts
// Standard presign for a specific dWallet
const presignRef = ikaTx.requestPresign({
	dWallet,
	signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin,
	suiCoin,
});

// Global presign (not tied to a specific dWallet)
const globalPresignRef = ikaTx.requestGlobalPresign({
	dwalletNetworkEncryptionKeyId,
	curve: Curve.SECP256K1,
	signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin,
	suiCoin,
});
```

### Signing

```ts
// Sign with a zero-trust dWallet
const signRef = await ikaTx.requestSign({
	dWallet,
	messageApproval,
	hashScheme: Hash.KECCAK256,
	verifiedPresignCap,
	presign,
	encryptedUserSecretKeyShare,
	message,
	signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin,
	suiCoin,
});

// Sign with an imported key dWallet
await ikaTx.requestSignWithImportedKey({ ... });
```

### Future signing

Future signing pre-computes a partial user signature that can be used to sign multiple messages.

```ts
const futureSignRef = await ikaTx.requestFutureSign({ ... });
await ikaTx.requestFutureSignWithImportedKey({ ... });
```

### Share management

```ts
// Accept an encrypted user share
await ikaTx.acceptEncryptedUserShare({ ... });

// Re-encrypt a share for another user
await ikaTx.requestReEncryptUserShareFor({ ... });

// Register an encryption key
await ikaTx.registerEncryptionKey({ curve: Curve.SECP256K1 });

// Make user secret key shares public
await ikaTx.requestMakeDwalletUserSecretKeySharesPublic({ dWallet, secretShare, ikaCoin, suiCoin });
```

### Imported key verification

```ts
await ikaTx.requestImportedKeyDWalletVerification({ ... });
```

### Session identifiers

```ts
const sessionId = ikaTx.createSessionIdentifier();
```

## User share encryption keys

`UserShareEncryptionKeys` manages class-groups encryption/decryption keys and an Ed25519 signing
keypair derived from a root seed.

```ts
import { Curve, UserShareEncryptionKeys } from '@ika.xyz/sdk';

// Create from a root seed
const keys = await UserShareEncryptionKeys.fromRootSeedKey(rootSeed, Curve.SECP256K1);

// Serialize / deserialize
const bytes = keys.toShareEncryptionKeysBytes();
const restored = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(bytes);

// Decrypt a user share
const { verifiedPublicOutput, secretShare } = await keys.decryptUserShare(
	dWallet,
	encryptedShare,
	protocolPublicParameters,
);

// Proof-of-ownership signatures
const encKeySig = await keys.getEncryptionKeySignature();
const outputSig = await keys.getUserOutputSignature(dWallet, userPublicOutput);

// Address and public key
const address = keys.getSuiAddress();
const pubkey = keys.getSigningPublicKeyBytes();
```

## Cryptography helpers

### Key generation

```ts
import { createClassGroupsKeypair } from '@ika.xyz/sdk';

const { encryptionKey, decryptionKey } = await createClassGroupsKeypair(seed, Curve.SECP256K1);
```

### DKG preparation

```ts
// Synchronous — supply protocol parameters directly
const dkgInput = await prepareDKG(
	protocolPublicParameters,
	curve,
	encryptionKey,
	bytesToHash,
	senderAddress,
);

// Async — fetches parameters from the client
const dkgInput = await prepareDKGAsync(
	ikaClient,
	curve,
	userShareEncryptionKeys,
	bytesToHash,
	senderAddress,
);

// Lower-level DKG output creation
const { userDKGMessage, userPublicOutput, userSecretKeyShare } = await createDKGUserOutput(
	protocolPublicParameters,
	networkFirstRoundOutput,
);
```

### Signature creation and verification

```ts
// Create user sign message
const signMsg = await createUserSignMessageWithPublicOutput(...);
const signMsg = await createUserSignMessageWithCentralizedOutput(...);

// Parse and verify signatures
const signature = await parseSignatureFromSignOutput(curve, signatureAlgorithm, signOutput);
const valid = await verifySecpSignature(...);
```

### Public key derivation

```ts
const pubkey = await publicKeyFromDWalletOutput(curve, dWalletOutput);
const pubkey = await publicKeyFromCentralizedDKGOutput(curve, centralizedDkgOutput);
```

### Share encryption

```ts
const encrypted = await encryptSecretShare(
	curve,
	secretShare,
	encryptionKey,
	protocolPublicParameters,
);
const valid = await verifyUserShare(curve, secretShare, userDKGOutput, networkDkgPublicOutput);
```

### Session identifiers

```ts
import { createRandomSessionIdentifier, sessionIdentifierDigest } from '@ika.xyz/sdk';

const sessionId = createRandomSessionIdentifier();
const digest = sessionIdentifierDigest(bytesToHash, senderAddressBytes);
```

## Supported curves, signature algorithms, and hashes

| Curve     | Signature Algorithm | Valid Hashes                    |
| --------- | ------------------- | ------------------------------- |
| SECP256K1 | ECDSASecp256k1      | KECCAK256, SHA256, DoubleSHA256 |
| SECP256K1 | Taproot             | SHA256                          |
| SECP256R1 | ECDSASecp256r1      | SHA256, DoubleSHA256            |
| ED25519   | EdDSA               | SHA512                          |
| RISTRETTO | SchnorrkelSubstrate | Merlin                          |

The SDK provides compile-time type safety and runtime validation for curve/signature/hash
combinations via `hash-signature-validation`.

```ts
import { validateCurveSignatureAlgorithm, validateHashSignatureCombination } from '@ika.xyz/sdk';
```

## DWallet kinds

| Kind                  | Description                                         |
| --------------------- | --------------------------------------------------- |
| `zero-trust`          | User holds encrypted secret share; highest security |
| `imported-key`        | User imports an existing private key                |
| `imported-key-shared` | Imported key with public shares on-chain            |
| `shared`              | Public secret shares stored on-chain                |

## Types

Import enums and types from the SDK:

```ts
import {
	Curve,
	DWalletKind,
	Hash,
	SignatureAlgorithm,
	type DWallet,
	type EncryptedUserSecretKeyShare,
	type EncryptionKey,
	type EncryptionKeyOptions,
	type IkaClientOptions,
	type IkaConfig,
	type ImportedKeyDWallet,
	type Network,
	type NetworkEncryptionKey,
	type PartialUserSignature,
	type Presign,
	type SharedDWallet,
	type Sign,
	type ZeroTrustDWallet,
} from '@ika.xyz/sdk';
```

State-narrowing generics are available for polling workflows:

```ts
import type { DWalletWithState, PresignWithState, SignWithState } from '@ika.xyz/sdk';
```

## Error classes

```ts
import {
	CacheError,
	IkaClientError,
	InvalidObjectError,
	NetworkError,
	ObjectNotFoundError,
} from '@ika.xyz/sdk';
```

## Low-level transaction builders

`coordinatorTransactions` and `systemTransactions` expose the raw Move-call builders used internally
by `IkaTransaction`. Import them directly if you need fine-grained control:

```ts
import { coordinatorTransactions, systemTransactions } from '@ika.xyz/sdk';
```

Generated BCS modules are also exported:

```ts
import {
	CoordinatorInnerModule,
	CoordinatorModule,
	SessionsManagerModule,
	SystemModule,
} from '@ika.xyz/sdk';
```

## Testing

Unit and integration tests live under `test/`. Integration tests require an Ika localnet.

Start a localnet following the
[Setup Ika Localnet docs](https://docs.ika.xyz/docs/sdk/setup-localnet):

```bash
# Terminal 1 — Sui localnet
RUST_LOG="off,sui_node=info" sui start --with-faucet --force-regenesis --epoch-duration-ms 1000000000000000

# Terminal 2 — Ika localnet
cargo run --bin ika --release --no-default-features -- start
```

Run SDK tests:

```bash
pnpm --filter @ika.xyz/sdk test:unit
pnpm --filter @ika.xyz/sdk test:integration
```

System tests live under `test/system-tests/` and have their own setup; they are **not** run by the
commands above.

## Local network testing (step-by-step)

A more detailed guide for running the full local network and SDK integration tests.

### 1. Start the local Sui node

From the repo root:

```bash
bash scripts/run_sui.sh
```

Wait until you see `SuiNode started!` in the output.

### 2. Start the local Ika network

In a separate terminal, from the repo root:

```bash
bash scripts/rerun_ika_info.sh
```

This wipes previous state (`~/.ika`), publishes all Move contracts to the local Sui node,
initializes the system with 4 validators + 1 fullnode, and creates a fresh `ika_config.json` at the
repo root with the new package and object IDs.

The first run builds in release mode and takes several minutes.

### 3. Wait for network DKG to complete

Watch the Ika output for:
- `Available CPU cores for Rayon cryptographic computations` — validators starting
- Presign pool messages — network DKG is complete and presign pools are filling

This typically takes 2–5 minutes after the validators start.

### 4. Copy the config to the SDK

```bash
cp ika_config.json sdk/typescript/ika_config.json
```

**This is critical.** The SDK integration tests read `ika_config.json` to find Sui object IDs. If the
file contains stale IDs from a previous deployment, all tests fail with `Object does not exist`.

### 5. Install SDK dependencies

```bash
cd sdk/typescript
pnpm install --ignore-scripts
```

Use `--ignore-scripts` to skip the `ika-wasm` WASM build step, which may fail due to dependency
conflicts. The pre-built `dist/` is sufficient for running tests.

If the SDK needs a fresh build:

```bash
pnpm build
```

### 6. Run integration tests

Run all integration tests sequentially with per-test progress reporting:

```bash
bash scripts/run-integration-tests-sequential.sh --timeout 300
```

Options:

| Flag                  | Description                                                |
| --------------------- | ---------------------------------------------------------- |
| `--timeout <seconds>` | Per-test timeout (default: 120s; use 300+ for crypto tests)|
| `--filter <pattern>`  | Only run matching test files (e.g., `--filter "dwallet*"`) |

Tests run in dependency order: foundational tests first, comprehensive combination tests last.

### License

BSD-3-Clause-Clear © dWallet Labs, Ltd.
