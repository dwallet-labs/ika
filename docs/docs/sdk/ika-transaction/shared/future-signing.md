---
id: future-signing-public
title: Future Signing with Public DWallets
description: Pre-sign messages for later completion with public DWallets
sidebar_position: 3
sidebar_label: Future Signing
---

import { Info, Warning, Construction } from '../../../../src/components/InfoBox';

# Future Signing with Public DWallets

<Construction />

Future signing with public DWallets allows anyone to create partial signatures for later completion since the secret shares are publicly accessible on-chain.

<Info title="Prerequisites">
- A public DWallet (created through [Making a DWallet Public](./public-dwallet.md))
- A completed presign (same as regular signing)
- IKA and SUI tokens for transaction fees
- No encryption keys needed (shares are public)
</Info>

<Warning title="Trust Model">
**Public DWallet Security:** Anyone can create and complete future signatures since secret shares are on-chain. This requires trust in the IKA network infrastructure. Use only when shared signing access is specifically needed.
</Warning>

## Step 1: Create Presign

First, create a presign for the public DWallet:

```typescript
import { IkaTransaction, SignatureAlgorithm } from '@ika.xyz/sdk';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	// No userShareEncryptionKeys needed for public DWallets
});

const { unverifiedPresignCap } = ikaTx.requestPresign({
	dWallet: publicDWallet,
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

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	// No encryption keys needed
});

// Verify the presign capability
const { verifiedPresignCap } = ikaTx.verifyPresignCap({
	presign: completedPresign,
});

// Request future sign using public secret shares
const { unverifiedPartialUserSignatureCap } = await ikaTx.requestFutureSignWithSecretShare({
	dWallet: publicDWallet,
	verifiedPresignCap,
	presign: completedPresign,
	secretShare: Uint8Array.from(publicDWallet.public_user_secret_key_share), // Public share
	publicOutput: Uint8Array.from(publicDWallet.state.Active?.public_output), // Public output
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

Complete the signature using public DWallet methods:

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	// No encryption keys needed for public DWallets
});

// Approve message using standard method (not specialized like imported)
const { messageApproval } = ikaTx.approveMessage({
	dWallet: publicDWallet,
	signatureAlgorithm: SignatureAlgorithm.ECDSA,
	hashScheme: Hash.KECCAK256,
	message: messageBytes, // Must be the same message
});

// Complete the future sign
ikaTx.futureSign({
	partialUserSignature,
	messageApproval,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

await signAndExecuteTransaction(tx);
```
