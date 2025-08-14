### @ika.xyz/sdk — TypeScript SDK for Ika Network

⚠️ **Warning**: This package is currently in development and may have breaking changes.

## Overview

This package provides a TypeScript SDK for interacting with the Ika Network on Sui.

- Programmatically build transaction blocks for dWallet flows (DKG, presign, sign, imported-key
  flows)
- Query network state (coordinator/system, DWallets, presigns, encryption keys objects)
- Handle user share encryption and decryption with MPC WASM helpers

### Install

Use bun (preferred):

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

### Network configuration

Use `getNetworkConfig(network)` to obtain package/object IDs for `localnet`, `testnet`, or
`mainnet`.

_For `localnet`, the SDK reads `../../ika_config.json` at process cwd time._

```ts
import { getNetworkConfig } from '@ika.xyz/sdk';

const config = getNetworkConfig('testnet');
```

### Creating a client

`IkaClient` wraps a `SuiClient` and provides caching plus helpers for fetching network objects and
protocol parameters.

```ts
import { getNetworkConfig, IkaClient } from '@ika.xyz/sdk';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';

const suiClient = new SuiClient({ url: getFullnodeUrl('testnet') });
const ikaClient = new IkaClient({
	suiClient,
	config: getNetworkConfig('testnet'),
	network: 'testnet',
	cache: true,
});

await ikaClient.initialize();
```

Selected queries:

```ts
// DWallet by id
const dWallet = await ikaClient.getDWallet('0x...');

// Presign by id
const presign = await ikaClient.getPresign('0x...');

// Active encryption key for address
const encKey = await ikaClient.getActiveEncryptionKey('0x...');

// Protocol public parameters (bytes)
const pp = await ikaClient.getProtocolPublicParameters();
```

### Transactions helper

`IkaTransaction` wraps a Sui `Transaction` and adds typed methods for dWallet flows.

```ts
import { getNetworkConfig, IkaClient, IkaTransaction } from '@ika.xyz/sdk';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';

const suiClient = new SuiClient({ url: getFullnodeUrl('testnet') });
const ikaClient = new IkaClient({
	suiClient,
	config: getNetworkConfig('testnet'),
	network: 'testnet',
});
await ikaClient.initialize();

const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx });

// Call inner functions to mutate the transaction.
const sessionIdentifier = ikaTx.createSessionIdentifier();

tx.transferObjects([sessionIdentifier], '0x...');
```

### Cryptography helpers

Exposed utilities under `client/cryptography`:

- `createClassGroupsKeypair(seed)`
- `createDKGUserOutput(pp, firstRound, sessionId)`
- `prepareDKGSecondRound(pp, dWallet, sessionId, encKey)` and
  `prepareDKGSecondRoundAsync(ikaClient, ...)`
- `prepareImportDWalletVerification(ikaClient, sessionId, userKeys, keypair)`
- `encryptSecretShare(...)`, `decryptUserShare(...)`
- `verifyUserShare(...)`, `verifySecpSignature(...)`

### System and Coordinator transaction builders

Low-level Move-call builders are available at:

- `coordinatorTransactions` (`src/tx/coordinator.ts`)
- `systemTransactions` (`src/tx/system.ts`)

These are used internally by `IkaTransaction` but can be called directly if needed.

### Types

Import enums and types from `client/types`:

```ts
import { Curve, Hash, SignatureAlgorithm, type DWallet, type Presign } from '@ika.xyz/sdk';
```

### Testing

```bash
pnpm --filter @ika.xyz/sdk test
```

### License

BSD-3-Clause-Clear © dWallet Labs, Ltd.
