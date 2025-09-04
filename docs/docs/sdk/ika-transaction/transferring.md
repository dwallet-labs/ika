---
id: transferring-a-dwallet-share
title: Transferring a dWallet Share
description: Transfer your dWallet user share to another person
sidebar_position: 4
sidebar_label: Transferring a dWallet Share
---

import { Info, Warning, Construction } from '../../../src/components/InfoBox';

# Transferring a dWallet Share

<Construction />

Transfer your dWallet's encrypted user share to another person. This allows them to sign with your dWallet while maintaining zero-trust security through re-encryption.

<Info title="Prerequisites">
- An active dWallet with your encrypted user share (created through normal DKG or imported)
- Recipient's Sui address
- Recipient must have registered their encryption key
- Your `UserShareEncryptionKeys`
- IKA and SUI tokens for transaction fees
</Info>

<Warning title="Security Model">
**Zero-Trust Maintained:** Your secret share is re-encrypted with the recipient's encryption key. Only they can decrypt it after transfer. You retain access to the original share.
</Warning>

## Transfer Methods

### Method 1: Transfer Encrypted Share

Standard transfer using your encrypted share:

```typescript
import { IkaTransaction } from '@ika.xyz/sdk';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys,
});

await ikaTx.requestReEncryptUserShareFor({
	dWallet: activedWallet,
	destinationEncryptionKeyAddress: recipientAddress,
	sourceEncryptedUserSecretKeyShare: yourEncryptedUserShare,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

await signAndExecuteTransaction(tx);
```

### Method 2: Transfer with Pre-decrypted Share

If you already have access to your decrypted secret share:

```typescript
await ikaTx.requestReEncryptUserShareFor({
	dWallet: activedWallet,
	destinationEncryptionKeyAddress: recipientAddress,
	sourceSecretShare: yourDecryptedSecretShare, // Already decrypted
	sourceEncryptedUserSecretKeyShare: yourEncryptedUserShare,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

await signAndExecuteTransaction(tx);
```

## Complete Example

For a complete working example of the transfer process, see:

**[Transfer Secret Share Example](https://github.com/dwallet-labs/ika/blob/main/sdk/typescript/examples/zero-trust-dwallet/transfer-secret-share.ts)**

This example demonstrates the complete transfer flow including proper error handling and state management.
