---
id: future-signing-zero-trust
title: Future Signing with Zero-Trust DWallets
description: Pre-sign messages for later completion with zero-trust DWallets
sidebar_position: 5
sidebar_label: Future Signing
---

import { Info, Warning, Construction } from '../../../../src/components/InfoBox';

# Future Signing with Zero-Trust DWallets

<Construction />

Future signing allows you to create partial signatures that can be completed later without requiring immediate user interaction. This maintains zero-trust security through encryption.

<Info title="Prerequisites">
- An active zero-trust DWallet
- Your encrypted user share from DWallet creation
- `UserShareEncryptionKeys` for cryptographic operations
- A completed presign (same as regular signing)
- IKA and SUI tokens for transaction fees
</Info>

<Warning title="Two-Phase Process">
**Phase 1:** Create partial signature using your encrypted share

**Phase 2:** Complete the signature later with message approval - maintains zero-trust security
</Warning>

## Step 1: Create Presign

First, create a presign exactly like in regular signing:

```typescript
import { IkaTransaction, SignatureAlgorithm } from '@ika.xyz/sdk';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys,
});

const { unverifiedPresignCap } = ikaTx.requestPresign({
	dWallet: activeDWallet,
	signatureAlgorithm: SignatureAlgorithm.ECDSA,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// Keep the presign cap for later use
tx.transferObjects([unverifiedPresignCap], [yourKeypair.toSuiAddress()]);

await signAndExecuteTransaction(tx);
```

## Step 2: Request Future Sign

Create a partial signature for future completion:

```typescript
import { Hash } from '@ika.xyz/sdk';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys,
});

// Verify the presign capability
const { verifiedPresignCap } = ikaTx.verifyPresignCap({
	presign: completedPresign,
});

// Request future sign (creates partial signature)
const { unverifiedPartialUserSignatureCap } = await ikaTx.requestFutureSign({
	dWallet: activeDWallet,
	verifiedPresignCap,
	presign: completedPresign,
	encryptedUserSecretKeyShare: yourEncryptedUserShare,
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

Later, complete the signature maintaining zero-trust security:

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys, // Required for message approval
});

// Approve the same message
const { messageApproval } = ikaTx.approveMessage({
	dWallet: activeDWallet,
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
