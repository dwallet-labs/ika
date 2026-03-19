### @ika.xyz/sui — Ika dWallet SDK for Sui

## Overview

TypeScript SDK for interacting with the Ika Network on Sui. Provides everything needed to create and manage dWallets, with zero-trust multi-chain signing powered by 2PC-MPC.

This package re-exports everything from `@ika.xyz/core` (chain-agnostic crypto) plus Sui-specific client, transaction builders, and utilities.

- Create and manage dWallets (zero-trust, imported-key, shared variants)
- Sign messages across multiple curves and signature algorithms
- Handle user share encryption, decryption, and re-encryption
- Query on-chain state (dWallets, presigns, encryption keys, protocol parameters)
- Build Sui transaction blocks for all dWallet flows (DKG, presign, sign, future sign)

## Install

```bash
npm install @ika.xyz/sui
```

> **Migrating from `@ika.xyz/sdk`?** This package replaces `@ika.xyz/sdk`, which is now a
> deprecated shim. See [Migration](#migrating-from-ikaxyz-sdk) below.

## Quick start

```ts
import {
  Curve,
  getNetworkConfig,
  Hash,
  IkaClient,
  IkaTransaction,
  SignatureAlgorithm,
  UserShareEncryptionKeys,
} from '@ika.xyz/sui';
import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Transaction } from '@mysten/sui/transactions';

// 1. Set up clients
const suiClient = new SuiJsonRpcClient({
  url: getJsonRpcFullnodeUrl('testnet'),
  network: 'testnet',
});
const ikaClient = new IkaClient({
  suiClient,
  config: getNetworkConfig('testnet'),
});
await ikaClient.initialize();

// 2. Create encryption keys
const keys = await UserShareEncryptionKeys.fromRootSeedKey(rootSeed, Curve.SECP256K1);

// 3. Build and execute dWallet transactions
const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: keys });
```

## Network configuration

```ts
import { getNetworkConfig } from '@ika.xyz/sui';

const config = getNetworkConfig('testnet'); // or 'mainnet'
```

## Creating a client

`IkaClient` wraps a Sui JSON-RPC client with caching and helpers for fetching dWallets, encryption keys, and protocol parameters.

```ts
const ikaClient = new IkaClient({
  suiClient,
  config: getNetworkConfig('testnet'),
  cache: true,
  encryptionKeyOptions: { autoDetect: true },
});
```

### Querying dWallets

```ts
const dWallet = await ikaClient.getDWallet('0x...');
const caps = await ikaClient.getOwnedDWalletCaps('0xaddress...');
const ready = await ikaClient.getDWalletInParticularState('0x...', 'Completed');
```

### Querying presigns, signatures, and shares

```ts
const presign = await ikaClient.getPresign('0x...');
const sign = await ikaClient.getSign('0x...', Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256k1);
const share = await ikaClient.getEncryptedUserSecretKeyShare('0x...');
```

### Encryption keys and protocol parameters

```ts
const latestKey = await ikaClient.getLatestNetworkEncryptionKey();
const pp = await ikaClient.getProtocolPublicParameters();
const epoch = await ikaClient.getEpoch();
```

## Transactions

`IkaTransaction` wraps a Sui `Transaction` with typed methods for every dWallet flow.

### DKG (distributed key generation)

```ts
await ikaTx.requestDWalletDKG({
  dkgRequestInput,
  sessionIdentifier,
  dwalletNetworkEncryptionKeyId,
  curve: Curve.SECP256K1,
  ikaCoin,
  suiCoin,
});
```

### Presigning

```ts
ikaTx.requestPresign({
  dWallet,
  signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
  ikaCoin,
  suiCoin,
});
```

### Signing

```ts
await ikaTx.requestSign({
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
```

### Future signing, share management, imported keys

```ts
await ikaTx.requestFutureSign({ ... });
await ikaTx.acceptEncryptedUserShare({ ... });
await ikaTx.requestReEncryptUserShareFor({ ... });
await ikaTx.requestImportedKeyDWalletVerification({ ... });
```

## Sui-specific utilities

These functions wrap core operations with Sui address derivation and on-chain state verification.

```ts
import {
  decryptUserShare,
  getSuiAddress,
  getUserOutputSignature,
  getUserOutputSignatureForTransferredDWallet,
  prepareDKGAsync,
  prepareImportedKeyDWalletVerification,
  verifyAndGetDWalletDKGPublicOutput,
} from '@ika.xyz/sui';

// Derive Sui address from encryption keys
const address = getSuiAddress(keys);

// Async DKG preparation (fetches protocol params from network)
const dkgInput = await prepareDKGAsync(ikaClient, Curve.SECP256K1, keys, bytesToHash, senderAddress);

// Decrypt with on-chain state verification
const { verifiedPublicOutput, secretShare } = await decryptUserShare(
  keys, dWallet, encryptedShare, protocolPublicParameters,
);

// Sign dWallet public output for authorization
const sig = await getUserOutputSignature(keys, dWallet, userPublicOutput);
```

## Supported curves, signature algorithms, and hashes

| Curve     | Signature Algorithm | Valid Hashes                    |
| --------- | ------------------- | ------------------------------- |
| SECP256K1 | ECDSASecp256k1      | KECCAK256, SHA256, DoubleSHA256 |
| SECP256K1 | Taproot             | SHA256                          |
| SECP256R1 | ECDSASecp256r1      | SHA256                          |
| ED25519   | EdDSA               | SHA512                          |
| RISTRETTO | SchnorrkelSubstrate | Merlin                          |

## DWallet kinds

| Kind                  | Description                                         |
| --------------------- | --------------------------------------------------- |
| `zero-trust`          | User holds encrypted secret share; highest security |
| `imported-key`        | User imports an existing private key                |
| `imported-key-shared` | Imported key with public shares on-chain            |
| `shared`              | Public secret shares stored on-chain                |

## Low-level transaction builders

```ts
import { coordinatorTransactions, systemTransactions } from '@ika.xyz/sui';
```

Generated BCS modules:

```ts
import { CoordinatorInnerModule, CoordinatorModule, SessionsManagerModule, SystemModule } from '@ika.xyz/sui';
```

## Migrating from @ika.xyz/sdk

`@ika.xyz/sdk` v0.5.0 is a deprecated shim that re-exports `@ika.xyz/sui`. To migrate:

1. Replace `@ika.xyz/sdk` with `@ika.xyz/sui` in your dependencies
2. Update imports: `@ika.xyz/sdk` -> `@ika.xyz/sui`
3. Update method calls that moved to standalone functions:

```ts
// Before (method on class):
keys.getSuiAddress()
keys.getUserOutputSignature(dWallet, publicOutput)
keys.decryptUserShare(dWallet, share, params)
keys.getPublicKey()

// After (standalone functions):
import { getSuiAddress, getUserOutputSignature, decryptUserShare } from '@ika.xyz/sui';
getSuiAddress(keys)
getUserOutputSignature(keys, dWallet, publicOutput)
decryptUserShare(keys, dWallet, share, params)
keys.getSigningPublicKeyBytes()
```

## Testing

Unit and integration tests live under `test/`. Integration tests require an Ika localnet.

```bash
# Unit tests
pnpm test:unit

# Integration tests (requires localnet)
pnpm test:integration
```

### License

BSD-3-Clause-Clear (c) dWallet Labs, Ltd.
