---
id: creating-a-dwallet
title: Creating a DWallet
description: Complete DWallet creation process with DKG
sidebar_position: 1
sidebar_label: Creating a DWallet
---

import { Info, Warning, Construction } from '../../../src/components/InfoBox';

# Creating a DWallet

<Construction />

Creating a DWallet requires completing the full Distributed Key Generation (DKG) process. Here are all the essential steps:

<Info title="Prerequisites">
- Initialized `IkaClient` instance
- `UserShareEncryptionKeys` for cryptographic operations
- IKA and SUI tokens for transaction fees
</Info>

<Warning title="Important Notes">
- All 4 steps are required to create a functional DWallet
- State transitions require waiting/polling between steps
- The capability determines who can use the DWallet for signing
- Always verify secret shares and public outputs in production
</Warning>

## Step 1: Register Encryption Key

First, register your encryption key, if you did before with your `UserShareEncryptionKeys`, you can skip this step.

```typescript
import { Curve, IkaTransaction } from '@ika.xyz/sdk';

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

## Step 2: DKG First Round

Choose one approach based on whether you want to keep or transfer the DWallet capability:

### Use DWallet Capability as you want

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys,
});

const { dwalletCap } = await ikaTx.requestDWalletDKGFirstRoundAsync({
	curve: Curve.SECP256K1,
	ikaCoin: userIkaCoin, // You can use your own IKA coin
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// Mockup contract
tx.moveCall({
	target: '0x...',
	typeArguments: ['0x...'],
	function: 'deposit_dwallet_for_user',
	arguments: [dwalletCap],
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

await ikaTx.requestDWalletDKGFirstRoundAndTransferCapAsync({
	curve: Curve.SECP256K1,
	ikaCoin: userIkaCoin, // You can use your own IKA coin or create a new one
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
	receiver,
});
```

## Step 3: DKG Second Round

Complete the key generation process:

```typescript
import { prepareDKGSecondRoundAsync } from '@ika.xyz/sdk';

const dkgSecondRoundInput = await prepareDKGSecondRoundAsync(
	ikaClient,
	dWallet,
	sessionIdentifierPreimage,
	userShareEncryptionKeys,
);

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys,
});

ikaTx.requestDWalletDKGSecondRound({
	dWallet,
	dkgSecondRoundRequestInput: dkgSecondRoundInput,
	ikaCoin: userIkaCoin, // You can use your own IKA coin or create a new one
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

## Step 4: Accept User Share

Accept your encrypted share to complete the process:

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys,
});

await ikaTx.acceptEncryptedUserShare({
	dWallet: awaitingSignatureDWallet,
	userPublicOutput,
	encryptedUserSecretKeyShareId: encryptedUserShareId,
});
```

## Complete Example

For a complete working example of the DWallet creation process, see the official zero-trust DWallet example:

**[Creating DWallet Example](https://github.com/dwallet-labs/ika/blob/main/sdk/typescript/examples/zero-trust-dwallet/creating-dwallet.ts)**

This example demonstrates the complete flow including all 4 steps with proper error handling, state transitions, and best practices for creating DWallets in a production environment.
