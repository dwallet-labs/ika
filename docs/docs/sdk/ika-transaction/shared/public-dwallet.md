---
id: making-a-dwallet-public
title: Making a DWallet Public
description: Make DWallet secret shares public for shared access
sidebar_position: 1
sidebar_label: Making a DWallet Public
---

import { Info, Warning, Construction } from '../../../../src/components/InfoBox';

# Making a DWallet Public

<Construction />

Make a DWallet's secret shares public, allowing anyone to sign with it. This transforms a zero-trust DWallet into a public, publicly accessible one.

<Warning title="Trust Model Change">
**Zero-Trust DWallet:** User's secret share is encrypted - only they can decrypt and use it
**Public DWallet:** Secret shares are public on-chain - anyone can access them, requiring trust in the IKA network
</Warning>

<Info title="Prerequisites">
- An active DWallet (created through the normal DKG process)
- Access to the DWallet's decrypted secret share
- IKA and SUI tokens for transaction fees
</Info>

## Step 1: Create a DWallet(if you have one, skip this step)

First, create a normal DWallet through the standard DKG process (see [Creating a DWallet](../zero-trust/creating.md)):

```typescript
const activeDWallet = await ikaClient.getDWalletInParticularState(dwalletID, 'Active');

const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
	encryptedUserSecretKeyShareId,
);
```

## Step 2: Decrypt the Secret Share

Decrypt your encrypted secret share to get the raw secret data:

```typescript
const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
	activeDWallet,
	encryptedUserSecretKeyShare,
	await ikaClient.getProtocolPublicParameters(activeDWallet),
);
```

## Step 3: Make Secret Shares Public

Make the secret shares publicly accessible on-chain:

```typescript
import { IkaTransaction } from '@ika.xyz/sdk';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
});

ikaTx.makeDWalletUserSecretKeySharesPublic({
	dWallet: activeDWallet,
	secretShare: secretShare,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

await suiClient.signAndExecuteTransaction({
	transaction: tx,
	signer: signerKeypair,
});
```

## Security Considerations

<Warning title="Important Security Notes">
- **Irreversible:** Once shares are made public, they cannot be made private again
- **Trust Required:** Public DWallets require trust in the IKA network infrastructure
- **Network Risk:** If the network is compromised, public DWallets are at risk
- **Use Carefully:** Only make shares public when shared access is specifically needed
</Warning>

## Complete Example

For complete working examples of the public DWallet process, see the official example:

**[DWallet Sharing Example](https://github.com/dwallet-labs/ika/blob/main/sdk/typescript/examples/shared-dwallet/dwallet-sharing.ts)**

These examples demonstrate the complete flow from creating a DWallet and making it public.
