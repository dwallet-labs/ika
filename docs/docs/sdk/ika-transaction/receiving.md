---
id: receiving-a-dwallet-share
title: Receiving a dWallet Share
description: Accept a transferred dWallet user share from another person
sidebar_position: 5
sidebar_label: Receiving a dWallet Share
---

import { Info, Warning, Construction } from '../../../src/components/InfoBox';

# Receiving a dWallet Share

<Construction />

Accept a dWallet user share that has been transferred to you. This process allows you to gain signing access to someone else's dWallet while maintaining zero-trust security.

<Info title="Prerequisites">
- The sender has transferred their dWallet share to your address
- Your registered encryption key with the network
- Your `UserShareEncryptionKeys`  
- dWallet object ID (provided by sender)
- Transferred encrypted share ID (provided by sender)
- IKA and SUI tokens for transaction fees
</Info>

<Warning title="Security Model">
**Zero-Trust Maintained:** The transferred share is encrypted specifically for your encryption key. Only you can decrypt and use it. The original owner retains their access.
</Warning>

## Step 1: Register Your Encryption Key

If you haven't registered your encryption key yet:

```typescript
import { Curve, IkaTransaction } from '@ika.xyz/sdk';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys: yourUserShareEncryptionKeys,
});

await ikaTx.registerEncryptionKey({
	curve: Curve.SECP256K1,
});

await signAndExecuteTransaction(tx);
```

## Step 2: Get Sender's Encryption Key

Retrieve the sender's encryption key for verification:

```typescript
// Get sender's encryption key (needed for verification)
const senderEncryptionKey = await ikaClient.getActiveEncryptionKey(senderAddress);
```

## Step 3: Accept the Transferred Share

Accept the transferred encrypted user share:

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys: yourUserShareEncryptionKeys,
});

await ikaTx.acceptEncryptedUserShare({
	dWallet: activedWallet, // dWallet object provided by sender
	sourceEncryptedUserSecretKeyShare: senderOriginalShare, // Sender's original share
	sourceEncryptionKey: senderEncryptionKey,
	encryptedUserSecretKeyShareId: transferredEncryptedShareId,
});

await signAndExecuteTransaction(tx);
```

## Complete Example

For a complete working example of the receiving process, see:

**[Transfer Secret Share Example](https://github.com/dwallet-labs/ika/blob/main/sdk/typescript/examples/zero-trust-dwallet/transfer-secret-share.ts)**

This example demonstrates both the transfer and receiving sides of the process with proper error handling and state management.
