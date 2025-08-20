---
id: signing-with-a-dwallet
title: Signing with a dWallet
description: Sign messages and transactions using your dWallet
sidebar_position: 4
sidebar_label: Signing
---

import { Info, Warning, Construction } from '../../../../src/components/InfoBox';

# Signing with a dWallet

<Construction />

Sign messages and transactions using your dWallet through a two-step process: presigning for faster performance, then signing with your encrypted user share.

<Info title="Prerequisites">
- An active dWallet (created through DKG process)
- Your encrypted user share from dWallet creation
- `UserShareEncryptionKeys` for cryptographic operations
- IKA and SUI tokens for transaction fees
</Info>

<Warning title="Two-Step Process">
**Presign First:** Create a presign request and wait for completion before signing. This optimizes performance by pre-computing cryptographic operations. **You can create unlimited amount of presigns to sign transactions with your dWallet.**
</Warning>

## Step 1: Request Presign

Create a presign request to pre-compute part of the signature:

```typescript
import { IkaTransaction, SignatureAlgorithm } from '@ika.xyz/sdk';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys,
});

const unverifiedPresignCap = ikaTx.requestPresign({
	dWallet: activedWallet,
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

## Step 2: Sign the Message

Now sign your message using the completed presign:

```typescript
import { Hash } from '@ika.xyz/sdk';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys,
});

// Approve the message you want to sign
const messageApproval = ikaTx.approveMessage({
	dWalletCap: activedWallet.dwallet_cap_id,
	signatureAlgorithm: SignatureAlgorithm.ECDSA,
	hashScheme: Hash.KECCAK256,
	message: messageBytes, // Your message as Uint8Array
});

// Verify the presign capability
const verifiedPresignCap = ikaTx.verifyPresignCap({
	presign: completedPresign,
});

// Sign the message
await ikaTx.sign({
	dWallet: activedWallet,
	messageApproval,
	verifiedPresignCap,
	hashScheme: Hash.KECCAK256,
	presign: completedPresign,
	encryptedUserSecretKeyShare: yourEncryptedUserShare,
	message: messageBytes,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

await signAndExecuteTransaction(tx);
```

## Working Example

For a complete working example of the signing process, see:

**[dWallet Sign Example](https://github.com/dwallet-labs/ika/blob/main/sdk/typescript/examples/zero-trust-dwallet/dwallet-sign.ts)**

This example demonstrates the complete flow from dWallet creation through presigning and signing with proper error handling and state management.
