---
id: future-signing-public
title: Future Signing with Public dWallets
description: Pre-sign messages for later completion with public dWallets
sidebar_position: 3
sidebar_label: Future Signing
---

import { Info, Warning, Construction } from '../../../../src/components/InfoBox';

# Future Signing with Public dWallets

<Construction />

Future signing with public dWallets allows anyone to create partial signatures for later completion since the secret shares are publicly accessible on-chain.

<Info title="Prerequisites">
- A public dWallet (created through [Making a dWallet Public](./public-dwallet.md))
- A completed presign (same as regular signing)
- IKA and SUI tokens for transaction fees
- No encryption keys needed (shares are public)
</Info>

<Warning title="Trust Model">
**Public dWallet Security:** Anyone can create and complete future signatures since secret shares are on-chain. This requires trust in the IKA network infrastructure. Use only when shared signing access is specifically needed.
</Warning>

## Step 1: Create Presign

First, create a presign for the public dWallet:

```typescript
import { IkaTransaction, SignatureAlgorithm } from '@ika.xyz/sdk';
import { Transaction } from '@mysten/sui/transactions';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	// No userShareEncryptionKeys needed for public dWallets
});

const unverifiedPresignCap = ikaTx.requestPresign({
	dWallet: publicdWallet,
	signatureAlgorithm: SignatureAlgorithm.ECDSA,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// Keep the presign cap for later use
tx.transferObjects([unverifiedPresignCap], [yourKeypair.toSuiAddress()]);

await signAndExecuteTransaction(tx);
```

## Step 2: Request Future Sign with Secret Share

Create a partial signature using the public secret shares:

```typescript
import { Hash } from '@ika.xyz/sdk';
import { Transaction } from '@mysten/sui/transactions';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	// No encryption keys needed
});

// Verify the presign capability
const verifiedPresignCap = ikaTx.verifyPresignCap({
	presign: completedPresign,
});

// Request future sign using public secret shares
const unverifiedPartialUserSignatureCap = await ikaTx.requestFutureSign({
	dWallet: publicdWallet,
	verifiedPresignCap,
	presign: completedPresign,
	message: messageBytes, // Your message as Uint8Array
	hashScheme: Hash.KECCAK256,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// Keep the partial signature capability for later
tx.transferObjects([unverifiedPartialUserSignatureCap], [yourKeypair.toSuiAddress()]);

// Or deposit into your contract
tx.moveCall({
	target: '0x...',
	typeArguments: ['0x...'],
	arguments: [unverifiedPartialUserSignatureCap],
});

await signAndExecuteTransaction(tx);
```

## Step 3: Complete Future Sign

Complete the signature using public dWallet methods:

```typescript
import { Transaction } from '@mysten/sui/transactions';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	// No encryption keys needed for public dWallets
});

// Approve message using standard method (not specialized like imported)
const messageApproval = ikaTx.approveMessage({
	dWalletCap: publicdWallet.dwallet_cap_id,
	signatureAlgorithm: SignatureAlgorithm.ECDSA,
	hashScheme: Hash.KECCAK256,
	message: messageBytes, // Must be the same message
});

// Complete the future sign
ikaTx.futureSign({
	partialUserSignatureCap: partialUserSignature.cap_id,
	messageApproval,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

await signAndExecuteTransaction(tx);
```
