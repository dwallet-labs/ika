---
id: importing-a-dwallet
title: Importing a DWallet
description: Import existing cryptographic keys as DWallets
sidebar_position: 2
sidebar_label: Importing a DWallet
---

import { Info, Warning, Construction } from '../../../../src/components/InfoBox';

# Importing a DWallet

<Construction />

Import existing cryptographic keys (generated outside the network) as DWallets. This process creates a DWallet from an existing SECP256K1 keypair.

<Info title="Prerequisites">
- Initialized `IkaClient` instance
- `UserShareEncryptionKeys` for cryptographic operations
- Existing SECP256K1 keypair to import
- IKA and SUI tokens for transaction fees
</Info>

<Warning title="Important Notes">
- Only SECP256K1 keypairs are currently supported
- All 4 steps are required to create a functional imported DWallet
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
```

## Step 3: Prepare Import Verification

Prepare the cryptographic data needed to verify key ownership:

```typescript
import { prepareImportDWalletVerification } from '@ika.xyz/sdk';

const importDWalletVerificationRequestInput = await prepareImportDWalletVerification(
	ikaClient,
	sessionIdentifierPreimage,
	userShareEncryptionKeys,
	existingKeypair, // Your existing SECP256K1 keypair
);
```

## Step 4: Request Import Verification

Choose one approach based on whether you want to keep or transfer the DWallet capability:

### Keep DWallet Capability

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys,
});

const { ImportedKeyDWalletCap } = await ikaTx.requestImportedDWalletVerification({
	importDWalletVerificationRequestInput,
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
	arguments: [ImportedKeyDWalletCap],
});
```

### Transfer DWallet Capability

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys,
});

await ikaTx.requestImportedDWalletVerificationAndTransferCap({
	importDWalletVerificationRequestInput,
	curve: Curve.SECP256K1,
	signerPublicKey: signerPublicKeyBytes,
	sessionIdentifier: sessionIdentifierObjectId,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
	receiver: receiverAddress, // Address or contract to receive capability
});
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
	dWallet: awaitingSignatureDWallet,
	userPublicOutput: importDWalletVerificationRequestInput.userPublicOutput,
	encryptedUserSecretKeyShareId: encryptedUserShareId,
});
```

## Complete Example

For a complete working example of the DWallet import process, see the official example:

**[Creating Imported DWallet](https://github.com/dwallet-labs/ika/blob/main/sdk/typescript/examples/imported-dwallet/creating-imported-dwallet.ts)**

This example demonstrates the complete flow including all steps with proper error handling, state transitions, and best practices for importing existing keys as DWallets.
