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
```

## After Transfer

After successful transfer:

1. **You retain access** - Your original encrypted share remains functional
2. **Recipient gets access** - They can accept the transferred share on their end
3. **Both can sign** - The DWallet becomes accessible to both parties

## Next Steps

Share the following information with the recipient:

- The DWallet object ID
- The transferred encrypted share ID (from transfer event)
- Your encryption key details (they'll need this to accept the share)

The recipient can then follow the [Receiving a DWallet](./receiving) guide to complete the process.

## Complete Example

For a complete working example of the transfer process, see:

**📄 [Transfer Secret Share Example](https://github.com/dwallet-labs/ika/blob/main/sdk/typescript/examples/zero-trust-dwallet/transfer-secret-share.ts)**

This example demonstrates the complete transfer flow including proper error handling and state management.
