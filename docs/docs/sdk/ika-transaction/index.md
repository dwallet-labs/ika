---
id: ika-transaction
title: IkaTransaction API Reference
description: Complete API reference for IkaTransaction class methods and dWallet operations
sidebar_position: 2
sidebar_label: API Reference
---

import { Info, Warning, Construction } from '../../../src/components/InfoBox';

# IkaTransaction API Reference

<Construction />

`IkaTransaction` is the client for building transactions that involve dWallet operations. It wraps Sui transactions and provides high-level methods for Distributed Key Generation (DKG), presigning, signing, and key management operations.

You need to instantiate it once in every Programmable Transaction Block (PTB) that involves dWallet operations.

<Info title="Required Setup">
Before using `IkaTransaction`, ensure you have an initialized `IkaClient` and optionally `UserShareEncryptionKeys` for cryptographic operations.
</Info>

<Warning title="Security">
Methods marked with security warnings require careful verification of inputs to maintain zero-trust security guarantees.
</Warning>

## Basic Setup

```typescript
import {
	IkaClient,
	IkaTransaction,
	UserShareEncryptionKeys,
	createRandomSessionIdentifier,
	Curve,
	SignatureAlgorithm,
	Hash
} from '@ika.xyz/sdk';
import { Transaction } from '@mysten/sui/transactions';

// Initialize somewhere in your app
const ikaClient = new IkaClient({...});
await ikaClient.initialize();

// Optional: Set up user share encryption keys for encrypted operations
const userKeys = await UserShareEncryptionKeys.fromRootSeedKey(seedKey, Curve.SECP256K1); // or other supported curves

// Get user's IKA coin for transaction fees
const userIkaCoin = tx.object('0x...'); // User's IKA coin object ID

const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys: userKeys
});
```

## DKG Operations

### requestDWalletDKG

Request the DKG (Distributed Key Generation) to create a dWallet with encrypted user shares.

```typescript
const dwalletCap = await ikaTx.requestDWalletDKG({
	dkgRequestInput: dkgRequestInput,
	sessionIdentifier: ikaTx.createSessionIdentifier(),
	dwalletNetworkEncryptionKeyId: networkEncryptionKeyId,
	curve: Curve.SECP256K1, // or Curve.SECP256R1, Curve.ED25519, etc.
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// With optional signing during DKG
const dwalletCap = await ikaTx.requestDWalletDKG({
	dkgRequestInput: dkgRequestInput,
	sessionIdentifier: ikaTx.createSessionIdentifier(),
	dwalletNetworkEncryptionKeyId: networkEncryptionKeyId,
	curve: Curve.SECP256K1,
	signDuringDKGRequest: {
		message: messageBytes,
		presign: presignObject,
		verifiedPresignCap: verifiedPresignCapObject,
		hashScheme: Hash.KECCAK256,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
	},
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `dkgRequestInput`: Cryptographic data prepared for the DKG
- `sessionIdentifier`: The session identifier object
- `dwalletNetworkEncryptionKeyId`: The dWallet network encryption key ID
- `curve`: The elliptic curve identifier (e.g., `Curve.SECP256K1`, `Curve.SECP256R1`, `Curve.ED25519`)
- `signDuringDKGRequest`: Optional: Sign a message during DKG (includes message, presign, verifiedPresignCap, hashScheme, signatureAlgorithm)
- `ikaCoin`: User's IKA coin object for fees
- `suiCoin`: SUI coin object for gas

**Returns:** `Promise<TransactionResult>` - The DWallet capability

### requestDWalletDKGWithPublicUserShare

Request the DKG with public user shares to create a shared dWallet.

```typescript
const dwalletCap = await ikaTx.requestDWalletDKGWithPublicUserShare({
	sessionIdentifier: ikaTx.createSessionIdentifier(),
	dwalletNetworkEncryptionKeyId: networkEncryptionKeyId,
	curve: Curve.SECP256K1, // or Curve.SECP256R1, Curve.ED25519, etc.
	publicKeyShareAndProof: publicKeyShareAndProofBytes,
	publicUserSecretKeyShare: publicUserSecretKeyShareBytes,
	userPublicOutput: userPublicOutputBytes,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// With optional signing during DKG
const dwalletCap = await ikaTx.requestDWalletDKGWithPublicUserShare({
	sessionIdentifier: ikaTx.createSessionIdentifier(),
	dwalletNetworkEncryptionKeyId: networkEncryptionKeyId,
	curve: Curve.SECP256K1,
	publicKeyShareAndProof: publicKeyShareAndProofBytes,
	publicUserSecretKeyShare: publicUserSecretKeyShareBytes,
	userPublicOutput: userPublicOutputBytes,
	signDuringDKGRequest: {
		message: messageBytes,
		presign: presignObject,
		verifiedPresignCap: verifiedPresignCapObject,
		hashScheme: Hash.KECCAK256,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
	},
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `sessionIdentifier`: The session identifier object
- `dwalletNetworkEncryptionKeyId`: The dWallet network encryption key ID
- `curve`: The elliptic curve identifier (e.g., `Curve.SECP256K1`, `Curve.SECP256R1`, `Curve.ED25519`)
- `publicKeyShareAndProof`: The public key share and proof
- `publicUserSecretKeyShare`: The public user secret key share
- `userPublicOutput`: The user's public output from the DKG process
- `signDuringDKGRequest`: Optional: Sign a message during DKG (includes message, presign, verifiedPresignCap, hashScheme, signatureAlgorithm)
- `ikaCoin`: User's IKA coin object for fees
- `suiCoin`: SUI coin object for gas

**Returns:** `Promise<TransactionResult>` - The DWallet capability

## Presigning Operations

### requestPresign

Requests a presign operation for a specific dWallet. Use this for ECDSA signatures with imported key dWallets.

```typescript
const unverifiedPresignCap = ikaTx.requestPresign({
	dWallet: dwalletObject,
	signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `dWallet`: The dWallet to create the presign for
- `signatureAlgorithm`: Signature algorithm to use
- `ikaCoin`: User's IKA coin object
- `suiCoin`: SUI coin object

**Returns:** `TransactionObjectArgument` - The unverified presign capability

### requestGlobalPresign

Requests a global presign operation. Use this for Schnorr, SchnorrKell, EdDSA, and Taproot signatures.

```typescript
const unverifiedPresignCap = ikaTx.requestGlobalPresign({
	dwalletNetworkEncryptionKeyId: networkEncryptionKeyId,
	curve: Curve.SECP256K1,
	signatureAlgorithm: SignatureAlgorithm.Schnorr,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `dwalletNetworkEncryptionKeyId`: The network encryption key ID to use for the presign
- `curve`: The elliptic curve to use
- `signatureAlgorithm`: The signature algorithm to use (must be valid for the curve)
- `ikaCoin`: User's IKA coin object
- `suiCoin`: SUI coin object

**Returns:** `TransactionObjectArgument` - The unverified presign capability

### verifyPresignCap

Verifies a presign capability to ensure it can be used for signing.

```typescript
const verifiedPresignCap = ikaTx.verifyPresignCap({
	presign: presignObject,
});
```

**Parameters:**

- `presign`: The presign object to verify

**Returns:** `TransactionObjectArgument` - The verified presign capability

## Message Approval

### approveMessage

Approves a message for signing with a dWallet.

```typescript
const messageApproval = ikaTx.approveMessage({
	dWalletCap: dwalletObject.dwallet_cap_id,
	curve: Curve.SECP256K1,
	signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
	hashScheme: Hash.KECCAK256,
	message: messageBytes,
});
```

**Parameters:**

- `dWalletCap`: The dWalletCap object, that owns the dWallet
- `curve`: The elliptic curve to use for the approval
- `signatureAlgorithm`: The signature algorithm to use (must be valid for the curve)
- `hashScheme`: Hash scheme to apply to the message (must be valid for the signature algorithm)
- `message`: The message bytes to approve

**Returns:** `TransactionObjectArgument` - The message approval object

### approveImportedKeyMessage

Approves a message for signing with an imported key dWallet.

```typescript
const importedKeyMessageApproval = ikaTx.approveImportedKeyMessage({
	dWalletCap: importedDWallet.dwallet_cap_id,
	curve: Curve.SECP256K1,
	signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
	hashScheme: Hash.KECCAK256,
	message: messageBytes,
});
```

**Parameters:**

- `dWalletCap`: The dWalletCap object, that owns the imported key dWallet
- `curve`: The elliptic curve to use for the approval
- `signatureAlgorithm`: The signature algorithm to use (must be valid for the curve)
- `hashScheme`: Hash scheme to apply to the message (must be valid for the signature algorithm)
- `message`: The message bytes to approve

**Returns:** `TransactionObjectArgument` - The imported key message approval object

## Signing Operations

### requestSign

Signs a message using a dWallet (ZeroTrust or Shared). Automatically detects the dWallet type and signing method based on available shares.

<Warning title="Security">
Always verify secret shares and public outputs in production environments when using unencrypted shares.
</Warning>

```typescript
// ZeroTrust DWallet with encrypted shares
const signatureId = await ikaTx.requestSign({
	dWallet: dwalletObject,
	messageApproval: messageApprovalObject,
	hashScheme: Hash.KECCAK256,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	encryptedUserSecretKeyShare: encryptedShare,
	message: messageBytes,
	signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// ZeroTrust DWallet with unencrypted shares
const signatureId = await ikaTx.requestSign({
	dWallet: dwalletObject,
	messageApproval: messageApprovalObject,
	hashScheme: Hash.KECCAK256,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	secretShare: secretShareBytes,
	publicOutput: publicOutputBytes,
	message: messageBytes,
	signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// Shared DWallet with public shares (no secret params needed)
const signatureId = await ikaTx.requestSign({
	dWallet: sharedDWallet,
	messageApproval: messageApprovalObject,
	hashScheme: Hash.KECCAK256,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	message: messageBytes,
	signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `dWallet`: The dWallet to sign with (ZeroTrust or Shared DWallet)
- `messageApproval`: Message approval from approveMessage
- `hashScheme`: Hash scheme to use for the message (must be valid for the signature algorithm)
- `verifiedPresignCap`: The verified presign capability
- `presign`: The completed presign object
- `encryptedUserSecretKeyShare`: Optional: encrypted user secret key share (for ZeroTrust DWallets)
- `secretShare`: Optional: unencrypted secret share (requires publicOutput, for ZeroTrust DWallets)
- `publicOutput`: Optional: public output (required when using secretShare, for ZeroTrust DWallets)
- `message`: The message bytes to sign
- `signatureScheme`: The signature algorithm to use
- `ikaCoin`: User's IKA coin object
- `suiCoin`: SUI coin object

**Returns:** `Promise<TransactionObjectArgument>` - The signature ID

### requestSignWithImportedKey

Signs using an Imported Key dWallet. Automatically detects the dWallet type and signing method based on available shares.

```typescript
// ImportedKeyDWallet with encrypted shares
const signatureId = await ikaTx.requestSignWithImportedKey({
	dWallet: importedKeyDWallet,
	importedKeyMessageApproval: importedKeyMessageApprovalObject,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	hashScheme: Hash.KECCAK256,
	message: messageBytes,
	encryptedUserSecretKeyShare: encryptedShare,
	signatureScheme: SignatureAlgorithm.ECDSASecp256k1, // Optional, defaults to ECDSASecp256k1
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// ImportedKeyDWallet with unencrypted shares
const signatureId = await ikaTx.requestSignWithImportedKey({
	dWallet: importedKeyDWallet,
	importedKeyMessageApproval: importedKeyMessageApprovalObject,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	hashScheme: Hash.KECCAK256,
	message: messageBytes,
	secretShare: secretShareBytes,
	publicOutput: publicOutputBytes,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// ImportedSharedDWallet with public shares (no secret params needed)
const signatureId = await ikaTx.requestSignWithImportedKey({
	dWallet: importedSharedDWallet,
	importedKeyMessageApproval: importedKeyMessageApprovalObject,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	hashScheme: Hash.KECCAK256,
	message: messageBytes,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `dWallet`: The Imported Key dWallet to sign with (ImportedKeyDWallet or ImportedSharedDWallet)
- `importedKeyMessageApproval`: Imported key message approval from approveImportedKeyMessage
- `hashScheme`: Hash scheme to use for the message (must be valid for the signature algorithm)
- `verifiedPresignCap`: The verified presign capability
- `presign`: The completed presign object
- `encryptedUserSecretKeyShare`: Optional: encrypted user secret key share (for ImportedKeyDWallet)
- `secretShare`: Optional: unencrypted secret share (requires publicOutput, for ImportedKeyDWallet)
- `publicOutput`: Optional: public output (required when using secretShare, for ImportedKeyDWallet)
- `message`: The message bytes to sign
- `signatureScheme`: Optional: signature algorithm (defaults to ECDSASecp256k1)
- `ikaCoin`: User's IKA coin object
- `suiCoin`: SUI coin object

**Returns:** `Promise<TransactionObjectArgument>` - The signature ID

## Future Signing

### requestFutureSign

Creates a partial signature for later completion. Automatically detects dWallet type and signing method based on available shares.

```typescript
// ZeroTrust DWallet with encrypted shares
const unverifiedPartialUserSignatureCap = await ikaTx.requestFutureSign({
	dWallet: dwalletObject,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	encryptedUserSecretKeyShare: encryptedShare,
	message: messageBytes,
	hashScheme: Hash.KECCAK256,
	signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// ZeroTrust DWallet with unencrypted shares
const unverifiedPartialUserSignatureCap = await ikaTx.requestFutureSign({
	dWallet: dwalletObject,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	secretShare: secretShareBytes,
	publicOutput: publicOutputBytes,
	message: messageBytes,
	hashScheme: Hash.KECCAK256,
	signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// Shared DWallet with public shares (no secret params needed)
const unverifiedPartialUserSignatureCap = await ikaTx.requestFutureSign({
	dWallet: sharedDWallet,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	message: messageBytes,
	hashScheme: Hash.KECCAK256,
	signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `dWallet`: The dWallet to create the future sign for (ZeroTrust or Shared DWallet)
- `verifiedPresignCap`: The verified presign capability
- `presign`: The completed presign object
- `encryptedUserSecretKeyShare`: Optional: encrypted user secret key share (for ZeroTrust DWallets)
- `secretShare`: Optional: unencrypted secret share (requires publicOutput, for ZeroTrust DWallets)
- `publicOutput`: Optional: public output (required when using secretShare, for ZeroTrust DWallets)
- `message`: The message bytes to pre-sign
- `hashScheme`: The hash scheme to use for the message
- `signatureScheme`: The signature algorithm to use
- `ikaCoin`: User's IKA coin object
- `suiCoin`: SUI coin object

**Returns:** `Promise<TransactionObjectArgument>` - The unverified partial user signature capability

### requestFutureSignWithImportedKey

Creates a partial signature for later completion using Imported Key dWallets. Automatically detects dWallet type and signing method based on available shares.

```typescript
// ImportedKeyDWallet with encrypted shares
const unverifiedPartialUserSignatureCap = await ikaTx.requestFutureSignWithImportedKey({
	dWallet: importedKeyDWallet,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	encryptedUserSecretKeyShare: encryptedShare,
	message: messageBytes,
	hashScheme: Hash.KECCAK256,
	signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// ImportedKeyDWallet with unencrypted shares
const unverifiedPartialUserSignatureCap = await ikaTx.requestFutureSignWithImportedKey({
	dWallet: importedKeyDWallet,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	secretShare: secretShareBytes,
	publicOutput: publicOutputBytes,
	message: messageBytes,
	hashScheme: Hash.KECCAK256,
	signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});

// ImportedSharedDWallet with public shares (no secret params needed)
const unverifiedPartialUserSignatureCap = await ikaTx.requestFutureSignWithImportedKey({
	dWallet: importedSharedDWallet,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	message: messageBytes,
	hashScheme: Hash.KECCAK256,
	signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `dWallet`: The Imported Key dWallet to create the future sign for (ImportedKeyDWallet or ImportedSharedDWallet)
- `verifiedPresignCap`: The verified presign capability
- `presign`: The completed presign object
- `encryptedUserSecretKeyShare`: Optional: encrypted user secret key share (for ImportedKeyDWallet)
- `secretShare`: Optional: unencrypted secret share (requires publicOutput, for ImportedKeyDWallet)
- `publicOutput`: Optional: public output (required when using secretShare, for ImportedKeyDWallet)
- `message`: The message bytes to pre-sign
- `hashScheme`: The hash scheme to use for the message
- `signatureScheme`: The signature algorithm to use
- `ikaCoin`: User's IKA coin object
- `suiCoin`: SUI coin object

**Returns:** `Promise<TransactionObjectArgument>` - The unverified partial user signature capability

### futureSign

Completes a future sign operation using a partial signature.

```typescript
const signatureId = ikaTx.futureSign({
	partialUserSignatureCap: partialSignatureObject.cap_id,
	messageApproval: messageApprovalObject,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `partialUserSignatureCap`: The partial user signature capability created by requestFutureSign
- `messageApproval`: The message approval from approveMessage
- `ikaCoin`: User's IKA coin object
- `suiCoin`: SUI coin object

**Returns:** `TransactionObjectArgument` - The signature ID

### futureSignWithImportedKey

Completes a future sign operation for imported key using a partial signature.

```typescript
const signatureId = ikaTx.futureSignWithImportedKey({
	partialUserSignatureCap: partialSignatureObject.cap_id,
	importedKeyMessageApproval: importedKeyMessageApprovalObject,
	ikaCoin: userIkaCoin,
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `partialUserSignatureCap`: The partial user signature capability created by requestFutureSignWithImportedKey
- `importedKeyMessageApproval`: The imported key message approval from approveImportedKeyMessage
- `ikaCoin`: User's IKA coin object
- `suiCoin`: SUI coin object

**Returns:** `TransactionObjectArgument` - The signature ID

## Imported Key Operations

### requestImportedKeyDWalletVerification

Creates a dWallet from an existing cryptographic key.

```typescript
const importedKeyDWalletCap = await ikaTx.requestImportedKeyDWalletVerification({
	importDWalletVerificationRequestInput: verificationInput,
	curve: Curve.SECP256K1,
	signerPublicKey: publicKeyBytes,
	sessionIdentifier: createRandomSessionIdentifier(),
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `importDWalletVerificationRequestInput`: The prepared verification data from prepareImportedKeyDWalletVerification
- `curve`: The elliptic curve identifier used for the imported key
- `signerPublicKey`: The public key of the transaction signer
- `sessionIdentifier`: Unique session identifier for this operation
- `ikaCoin`: User's IKA coin object
- `suiCoin`: SUI coin object

**Returns:** `Promise<TransactionObjectArgument>` - The imported key dWallet capability

## User Share Management

### acceptEncryptedUserShare

Accepts an encrypted user share for a dWallet. This method has two overloads:

**For regular dWallet:**

```typescript
await ikaTx.acceptEncryptedUserShare({
	dWallet: dwalletObject,
	userPublicOutput: userPublicOutputBytes,
	encryptedUserSecretKeyShareId: 'share_id',
});
```

**For transferred dWallet:**

```typescript
await ikaTx.acceptEncryptedUserShare({
	dWallet: dwalletObject,
	sourceEncryptionKey: sourceEncryptionKeyObject,
	sourceEncryptedUserSecretKeyShare: sourceEncryptedShare,
	destinationEncryptedUserSecretKeyShare: destinationEncryptedShare,
});
```

**Parameters:**

For regular dWallet:

- `dWallet`: The dWallet object to accept the share for
- `userPublicOutput`: The user's public output from the DKG process
- `encryptedUserSecretKeyShareId`: The ID of the encrypted user secret key share

For transferred dWallet:

- `dWallet`: The dWallet object to accept the share for
- `sourceEncryptionKey`: The encryption key used to encrypt the user's secret share
- `sourceEncryptedUserSecretKeyShare`: The encrypted user secret key share
- `destinationEncryptedUserSecretKeyShare`: The encrypted user secret key share

**Returns:** `Promise<IkaTransaction>` - The updated IkaTransaction instance

### requestReEncryptUserShareFor

Re-encrypts and transfers user shares to another address. This method has two overloads:

**Using encrypted shares (automatic decryption):**

```typescript
await ikaTx.requestReEncryptUserShareFor({
	dWallet: dwalletObject,
	destinationEncryptionKeyAddress: '0x...',
	sourceEncryptedUserSecretKeyShare: encryptedShare,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Using unencrypted secret shares:**

```typescript
await ikaTx.requestReEncryptUserShareFor({
	dWallet: dwalletObject,
	destinationEncryptionKeyAddress: '0x...',
	sourceSecretShare: secretShareBytes,
	sourceEncryptedUserSecretKeyShare: encryptedShare,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `dWallet`: The dWallet whose user share is being transferred
- `destinationEncryptionKeyAddress`: The Sui address that will receive the re-encrypted share
- `sourceEncryptedUserSecretKeyShare`: The current user's encrypted secret key share
- `sourceSecretShare`: Optional: The current user's unencrypted secret share
- `ikaCoin`: User's IKA coin object
- `suiCoin`: SUI coin object

**Returns:** `Promise<IkaTransaction>` - The updated IkaTransaction instance

### makeDWalletUserSecretKeySharesPublic

Converts encrypted shares to public shares.

```typescript
ikaTx.makeDWalletUserSecretKeySharesPublic({
	dWallet: dwalletObject,
	secretShare: secretShareBytes,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `dWallet`: The dWallet to make the shares public for
- `secretShare`: The secret share data to make public
- `ikaCoin`: User's IKA coin object
- `suiCoin`: SUI coin object

**Returns:** `IkaTransaction` - The updated IkaTransaction instance

## Key Management

### registerEncryptionKey

Registers an encryption key for the current user.

```typescript
await ikaTx.registerEncryptionKey({
	curve: Curve.SECP256K1,
});
```

**Parameters:**

- `curve`: The elliptic curve identifier to register the key for

**Returns:** `Promise<IkaTransaction>` - The updated IkaTransaction instance

## Session Management

### createSessionIdentifier

Creates a unique session identifier for the transaction.

```typescript
const sessionId = ikaTx.createSessionIdentifier();
```

**Returns:** `TransactionObjectArgument` - Session identifier object

### registerSessionIdentifier

Registers a unique session identifier for the current transaction.

```typescript
const sessionId = ikaTx.registerSessionIdentifier(sessionIdentifierBytes);
```

**Parameters:**

- `sessionIdentifier`: The session identifier bytes to register

**Returns:** `TransactionObjectArgument` - The session identifier transaction object argument

## Utility Methods

### hasDWallet

Checks if a DWallet with the specified ID exists in the coordinator.

```typescript
const exists = ikaTx.hasDWallet({
	dwalletId: '0x...',
});
```

**Parameters:**

- `dwalletId`: The ID of the DWallet to check

**Returns:** `TransactionObjectArgument` - Transaction result indicating whether the DWallet exists (returns a boolean)

### getDWallet

Gets a reference to a DWallet object from the coordinator.

```typescript
const dwalletRef = ikaTx.getDWallet({
	dwalletId: '0x...',
});
```

**Parameters:**

- `dwalletId`: The ID of the DWallet to retrieve

**Returns:** `TransactionObjectArgument` - Transaction result containing a reference to the DWallet object

<Warning title="Security Warning">
Methods marked with security warnings require careful verification of inputs to maintain zero-trust security guarantees.
</Warning>
