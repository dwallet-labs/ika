---
id: signing-with-public-dwallet
title: Signing with a Public dWallet
description: Sign messages using public dWallet shares
sidebar_position: 2
sidebar_label: Signing
---

import { Info, Warning, Construction } from '../../../../src/components/InfoBox';

# Signing with a Public dWallet

<Construction />

Sign messages using a public dWallet where secret shares are publicly accessible on-chain. This process is simpler than zero-trust signing since shares are already decrypted.

<Info title="Prerequisites">
- A public dWallet (created through [Making a dWallet Public](./public-dwallet.md))
- IKA and SUI tokens for transaction fees
- No encryption keys needed (shares are public)
</Info>

<Warning title="Trust Model">
**Public dWallet Security:** Anyone can sign with public dWallets since secret shares are on-chain. This requires trust in the IKA network infrastructure. Use only when shared signing access is specifically needed.
</Warning>

## Step 1: Request Presign

Create a presign request for performance optimization:

```typescript
import { IkaTransaction, SignatureAlgorithm } from '@ika.xyz/sdk';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
});

const { unverifiedPresignCap } = ikaTx.requestPresign({
	dWallet: publicdWallet,
	signatureAlgorithm: SignatureAlgorithm.ECDSA,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// Keep the presign cap for later use
tx.transferObjects([unverifiedPresignCap], [yourKeypair.toSuiAddress()]);

// Or deposit into your contract
tx.moveCall({
	target: '0x...',
	typeArguments: ['0x...'],
	arguments: [unverifiedPresignCap],
});

await signAndExecuteTransaction(tx);
```

## Step 2: Sign with Public Shares

Sign using the public dWallet's accessible secret shares:

```typescript
import { Hash } from '@ika.xyz/sdk';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
});

// Approve the message you want to sign
const { messageApproval } = ikaTx.approveMessage({
	dWalletCap: publicdWallet.dwallet_cap_id,
	signatureAlgorithm: SignatureAlgorithm.ECDSA,
	hashScheme: Hash.KECCAK256,
	message: messageBytes, // Your message as Uint8Array
});

// Verify the presign capability
const { verifiedPresignCap } = ikaTx.verifyPresignCap({
	presign: completedPresign,
});

// Sign with public shares (no encryption keys needed)
await ikaTx.signPublic({
	dWallet: publicdWallet,
	verifiedPresignCap,
	messageApproval,
	hashScheme: Hash.KECCAK256,
	presign: completedPresign,
	message: messageBytes,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

await signAndExecuteTransaction(tx);
```

## Working Example

For a complete working example of public dWallet signing, see:

**[Public dWallet Signing Example](https://github.com/dwallet-labs/ika/blob/main/sdk/typescript/examples/shared-dwallet/dwallet-sharing-sign.ts)**

This example demonstrates the complete flow from creating a public dWallet through signing with proper state management.
