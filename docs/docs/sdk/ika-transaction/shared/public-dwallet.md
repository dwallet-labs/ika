---
id: making-a-dwallet-public
title: Making a dWallet Public
description: Make dWallet secret shares public for shared access
sidebar_position: 1
sidebar_label: Making a dWallet Public
---

import { Info, Warning, Construction } from '../../../../src/components/InfoBox';

# Making a dWallet Public

<Construction />

Make a dWallet's secret shares public, allowing anyone to sign with it. This transforms a zero-trust dWallet into a public, publicly accessible one.

<Warning title="Trust Model Change">
**Zero-Trust dWallet:** User's secret share is encrypted - only they can decrypt and use it
**Public dWallet:** Secret shares are public on-chain - anyone can access them, requiring trust in the IKA network
</Warning>

<Info title="Prerequisites">
- An active dWallet (created through the normal DKG process)
- Access to the dWallet's decrypted secret share
- IKA and SUI tokens for transaction fees
</Info>

## Step 1: Create a dWallet(if you have one, skip this step)

First, create a normal dWallet through the standard DKG process (see [Creating a dWallet](../zero-trust/creating.md)):

```typescript
const activedWallet = await ikaClient.getDWalletInParticularState(dwalletID, 'Active');

const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
	encryptedUserSecretKeyShareId,
);
```

## Step 2: Decrypt the Secret Share

Decrypt your encrypted secret share to get the raw secret data:

```typescript
const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
	activedWallet,
	encryptedUserSecretKeyShare,
	await ikaClient.getProtocolPublicParameters(activedWallet),
);
```

## Step 3: Make Secret Shares Public

Make the secret shares publicly accessible on-chain:

```typescript
import { IkaTransaction } from '@ika.xyz/sdk';
import { Transaction } from '@mysten/sui/transactions';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
});

ikaTx.makeDWalletUserSecretKeySharesPublic({
	dWallet: activedWallet,
	secretShare: secretShare,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

await signAndExecuteTransaction(tx);
```

## Security Considerations

<Warning title="Important Security Notes">
- **Irreversible:** Once shares are made public, they cannot be made private again
- **Trust Required:** Public dWallets require trust in the IKA network infrastructure
- **Network Risk:** If the network is compromised, public dWallets are at risk
- **Use Carefully:** Only make shares public when shared access is specifically needed
</Warning>

## Complete Example

For complete working examples of the public dWallet process, see the official example:

**[dWallet Sharing Example](https://github.com/dwallet-labs/ika/blob/main/sdk/typescript/examples/shared-dwallet/dwallet-sharing.ts)**

These examples demonstrate the complete flow from creating a dWallet and making it public.
