---
id: transferring-a-dwallet-share
title: Transferring a DWallet Share
description: Transfer your DWallet user share to another person
sidebar_position: 4
sidebar_label: Transferring a DWallet Share
---

import { Info, Warning, Construction } from '../../../src/components/InfoBox';

# Transferring a DWallet Share

<Construction />

Transfer your DWallet's encrypted user share to another person. This allows them to sign with your DWallet while maintaining zero-trust security through re-encryption.

<Info title="Prerequisites">
- An active DWallet with your encrypted user share (created through normal DKG or imported)
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

await ikaTx.transferUserShare({
	dWallet: activeDWallet,
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
await ikaTx.transferUserShareWithSecretShare({
	dWallet: activeDWallet,
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
