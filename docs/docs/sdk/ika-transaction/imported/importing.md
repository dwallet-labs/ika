---
id: importing-a-dwallet
title: Importing a dWallet
description: Import existing cryptographic keys as dWallets
sidebar_position: 1
sidebar_label: Importing a dWallet
---

import { Info, Warning, Construction } from '../../../../src/components/InfoBox';

# Importing a dWallet

<Construction />

Import existing cryptographic keys (generated outside the network) as dWallets. This process creates a dWallet from an existing SECP256K1 keypair.

<Info title="Prerequisites">
- Initialized `IkaClient` instance
- `UserShareEncryptionKeys` for cryptographic operations
- Existing SECP256K1 keypair to import
- IKA and SUI tokens for transaction fees
</Info>

<Warning title="Important Notes">
- Only SECP256K1 keypairs are currently supported
- All 4 steps are required to create a functional imported dWallet
- The original keypair should be securely stored/destroyed after import
- Always verify the import process in production environments
</Warning>

## Step 1: Create Session Identifier

Create a unique session identifier for the import process:

```typescript
import { IkaTransaction } from '@ika.xyz/sdk';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
});

const sessionIdentifier = ikaTx.createSessionIdentifier();
tx.transferObjects([sessionIdentifier], signerAddress);

await signAndExecuteTransaction(tx);
```

## Step 2: Register Encryption Key

Register your encryption key if you haven't done so before:

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys,
});

await ikaTx.registerEncryptionKey({
	curve: Curve.SECP256K1,
});

await signAndExecuteTransaction(tx);
```

## Step 3: Prepare Import Verification

Prepare the cryptographic data needed to verify key ownership:

```typescript
import { prepareImportdWalletVerification } from '@ika.xyz/sdk';

const importdWalletVerificationRequestInput = await prepareImportdWalletVerification(
	ikaClient,
	sessionIdentifierPreimage,
	userShareEncryptionKeys,
	existingKeypair, // Your existing SECP256K1 keypair
);
```

## Step 4: Request Import Verification

Choose one approach based on whether you want to keep or transfer the dWallet capability:

### Keep dWallet Capability

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys,
});

const { ImportedKeydWalletCap } = await ikaTx.requestImporteddWalletVerification({
	importdWalletVerificationRequestInput,
	curve: Curve.SECP256K1,
	signerPublicKey: signerPublicKeyBytes,
	sessionIdentifier: sessionIdentifierObjectId,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// Use the capability as needed
tx.moveCall({
	target: '0x...',
	typeArguments: ['0x...'],
	function: 'deposit_dwallet_for_user',
	arguments: [ImportedKeydWalletCap],
});

await signAndExecuteTransaction(tx);
```

## Step 5: Accept User Share

Accept your encrypted share to complete the import process:

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys,
});

await ikaTx.acceptEncryptedUserShare({
	dWallet: awaitingSignaturedWallet,
	userPublicOutput: importdWalletVerificationRequestInput.userPublicOutput,
	encryptedUserSecretKeyShareId: encryptedUserShareId,
});

await signAndExecuteTransaction(tx);
```

## Complete Example

For a complete working example of the dWallet import process, see the official example:

**[Creating Imported dWallet](https://github.com/dwallet-labs/ika/blob/main/sdk/typescript/examples/imported-dwallet/creating-imported-dwallet.ts)**

This example demonstrates the complete flow including all steps with proper error handling, state transitions, and best practices for importing existing keys as dWallets.
