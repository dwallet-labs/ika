---
id: signing-with-imported-dwallet
title: Signing with an Imported DWallet
description: Sign messages using imported DWallet keys
sidebar_position: 2
sidebar_label: Signing
---

import { Info, Warning, Construction } from '../../../../src/components/InfoBox';

# Signing with an Imported DWallet

<Construction />

Sign messages using an imported DWallet that was created from existing cryptographic keys. The process is similar to zero-trust DWallet signing but uses imported key credentials.

<Info title="Prerequisites">
- An active imported DWallet (created through [Importing a DWallet](./importing.md))
- Your encrypted user share from the import process
- `UserShareEncryptionKeys` used during import
- IKA and SUI tokens for transaction fees
</Info>

## Step 1: Request Presign

Create a presign request to optimize signing performance:

```typescript
import { IkaTransaction, SignatureAlgorithm } from '@ika.xyz/sdk';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys, // Same keys used during import
});

const { unverifiedPresignCap } = ikaTx.requestPresign({
	dWallet: importedDWallet,
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

## Step 2: Sign with Imported DWallet

Sign using your imported DWallet's encrypted user share:

```typescript
import { Hash } from '@ika.xyz/sdk';

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys, // Required for imported DWallet signing
});

// Approve the message for imported DWallet (uses different approval method)
const { importedKeyMessageApproval } = ikaTx.approveImportedKeyMessage({
	dWallet: importedDWallet,
	signatureAlgorithm: SignatureAlgorithm.ECDSA,
	hashScheme: Hash.KECCAK256,
	message: messageBytes, // Your message as Uint8Array
});

// Verify the presign capability
const { verifiedPresignCap } = ikaTx.verifyPresignCap({
	presign: completedPresign,
});

// Sign with imported DWallet (uses specialized method)
await ikaTx.signWithImportedDWallet({
	dWallet: importedDWallet,
	encryptedUserSecretKeyShare: importedEncryptedUserShare,
	presign: completedPresign,
	hashScheme: Hash.KECCAK256,
	message: messageBytes,
	importedKeyMessageApproval,
	verifiedPresignCap,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

await signAndExecuteTransaction(tx);
```

## Working Example

For a complete working example of imported DWallet signing, see:

**[Imported DWallet Signing Example](https://github.com/dwallet-labs/ika/blob/main/sdk/typescript/examples/imported-dwallet/sign-with-imported.ts)**

This example demonstrates the complete flow from importing existing keys through signing with proper error handling and state management.
