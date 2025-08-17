---
id: future-signing-imported
title: Future Signing with Imported DWallets
description: Pre-sign messages for later completion with imported DWallets
sidebar_position: 3
sidebar_label: Future Signing
---

import { Info, Warning, Construction } from '../../../../src/components/InfoBox';

# Future Signing with Imported DWallets

<Construction />

Future signing with imported DWallets allows you to create partial signatures that can be completed later. This uses the same security model as imported DWallet signing with specialized approval methods.

<Info title="Prerequisites">
- An active imported DWallet 
- Your encrypted user share from the import process
- `UserShareEncryptionKeys` used during import
- A completed presign (same as regular signing)
- IKA and SUI tokens for transaction fees
</Info>

<Warning title="Two-Phase Process">
**Phase 1:** Create partial signature using your encrypted share
**Phase 2:** Complete signature later with imported key message approval - uses specialized imported DWallet methods
</Warning>

## Step 1: Create Presign

First, create a presign for your imported DWallet:

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
	userShareEncryptionKeys, // Required for imported DWallet operations
});

// Verify the presign capability
const { verifiedPresignCap } = ikaTx.verifyPresignCap({
	presign: completedPresign,
});

// Request future sign (creates partial signature)
const { unverifiedPartialUserSignatureCap } = await ikaTx.requestFutureSign({
	dWallet: importedDWallet,
	verifiedPresignCap,
	presign: completedPresign,
	encryptedUserSecretKeyShare: importedEncryptedUserShare,
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

## Step 3: Complete Future Sign with Imported Key

Complete the signature using imported DWallet-specific methods:

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys, // Required for imported DWallet operations
});

// Approve message using imported key method (different from zero-trust)
const { importedKeyMessageApproval } = ikaTx.approveImportedKeyMessage({
	dWallet: importedDWallet,
	signatureAlgorithm: SignatureAlgorithm.ECDSA,
	hashScheme: Hash.KECCAK256,
	message: messageBytes, // Must be the same message
});

// Complete the future sign
ikaTx.futureSign({
	partialUserSignature,
	messageApproval: importedKeyMessageApproval, // Uses imported key approval
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

await signAndExecuteTransaction(tx);
```
