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
const userKeys = UserShareEncryptionKeys.fromRootSeedKey(seedKey);

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

### requestdWalletDKGFirstRoundAsync

Requests the first round of DKG with automatic decryption key ID fetching.

```typescript
const { dwalletCap } = await ikaTx.requestdWalletDKGFirstRoundAsync({
	curve: Curve.SECP256K1, // Currently only SECP256K1 is supported
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `curve`: The elliptic curve identifier (`Curve.SECP256K1` - currently only SECP256K1 is supported)
- `ikaCoin`: User's IKA coin object to use for transaction fees
- `suiCoin`: The SUI coin object to use for gas fees

**Returns:** `{ dwalletCap, transaction }`

### requestdWalletDKGFirstRound

Requests the first round of DKG with explicit decryption key ID.

```typescript
const { dwalletCap } = ikaTx.requestdWalletDKGFirstRound({
	curve: Curve.SECP256K1,
	networkEncryptionKeyID: 'key_id',
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `curve`: The elliptic curve identifier (`Curve.SECP256K1`)
- `networkEncryptionKeyID`: The specific network encryption key ID
- `ikaCoin`: User's IKA coin object for fees
- `suiCoin`: SUI coin object for gas

### requestdWalletDKGFirstRoundAndTransferCap

Creates a dWallet and transfers the capability to a specified receiver.

```typescript
await ikaTx.requestdWalletDKGFirstRoundAndTransferCapAsync({
	curve: Curve.SECP256K1,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
	receiver: '0x...',
});
```

**Parameters:**

- `curve`: Elliptic curve identifier (`Curve.SECP256K1`)
- `ikaCoin`: User's IKA coin object
- `suiCoin`: SUI coin object
- `receiver`: Address that will receive the dWalletCap

### requestdWalletDKGSecondRound

Completes the DKG process with the second round.

```typescript
ikaTx.requestdWalletDKGSecondRound({
	dWallet: dwalletObject,
	dkgSecondRoundRequestInput: secondRoundInput,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `dWallet`: The dWallet object from the first round
- `dkgSecondRoundRequestInput`: Cryptographic data for the second round
- `ikaCoin`: User's IKA coin object
- `suiCoin`: SUI coin object

## Presigning Operations

### requestPresign

Requests a presign operation for faster signature generation.

```typescript
const { unverifiedPresignCap } = ikaTx.requestPresign({
	dWallet: dwalletObject,
	signatureAlgorithm: SignatureAlgorithm.ECDSA,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

**Parameters:**

- `dWallet`: The dWallet to create the presign for
- `signatureAlgorithm`: Signature algorithm (`SignatureAlgorithm.ECDSA` - currently only ECDSA is supported)
- `ikaCoin`: User's IKA coin object
- `suiCoin`: SUI coin object

**Returns:** `{ unverifiedPresignCap, transaction }`

### requestPresignAndTransferCap

Requests a presign and transfers the capability to another address.

```typescript
ikaTx.requestPresignAndTransferCap({
	dWallet: dwalletObject,
	signatureAlgorithm: SignatureAlgorithm.ECDSA,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
	receiver: '0x...',
});
```

### verifyPresignCap

Verifies a presign capability to ensure it can be used for signing.

```typescript
const { verifiedPresignCap } = ikaTx.verifyPresignCap({
	presign: presignObject,
});
```

**Parameters:**

- `presign`: The presign object to verify

**Returns:** `{ verifiedPresignCap, transaction }`

## Message Approval

### approveMessage

Approves a message for signing with a dWallet.

```typescript
const { messageApproval } = ikaTx.approveMessage({
	dWallet: dwalletObject,
	signatureAlgorithm: SignatureAlgorithm.ECDSA,
	hashScheme: Hash.KECCAK256,
	message: messageBytes,
});
```

**Parameters:**

- `dWallet`: The dWallet to approve the message for
- `signatureAlgorithm`: The signature algorithm (`SignatureAlgorithm.ECDSA`)
- `hashScheme`: Hash scheme (`Hash.KECCAK256` | `Hash.SHA256`)
- `message`: The message bytes to approve

**Returns:** `{ messageApproval, transaction }`

### approveImportedKeyMessage

Approves a message for signing with an imported key dWallet.

```typescript
const { importedKeyMessageApproval } = ikaTx.approveImportedKeyMessage({
	dWallet: importeddWallet,
	signatureAlgorithm: SignatureAlgorithm.ECDSA,
	hashScheme: Hash.KECCAK256,
	message: messageBytes,
});
```

## Signing Operations

### sign

Signs a message using a dWallet with encrypted user shares.

<Warning title="Security">
Always verify secret shares and public outputs in production environments.
</Warning>

```typescript
await ikaTx.sign({
	dWallet: dwalletObject,
	messageApproval: messageApprovalObject,
	hashScheme: Hash.KECCAK256,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	encryptedUserSecretKeyShare: encryptedShare,
	message: messageBytes,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

### signWithSecretShare

Signs using unencrypted secret share (requires manual verification).

```typescript
await ikaTx.signWithSecretShare({
	dWallet: dwalletObject,
	messageApproval: messageApprovalObject,
	hashScheme: Hash.KECCAK256,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	secretShare: secretShareBytes,
	publicOutput: publicOutputBytes,
	message: messageBytes,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

### signPublic

Signs using a dWallet with public user shares.

```typescript
await ikaTx.signPublic({
	dWallet: publicdWallet,
	verifiedPresignCap: verifiedPresignCapObject,
	messageApproval: messageApprovalObject,
	hashScheme: Hash.KECCAK256,
	presign: presignObject,
	message: messageBytes,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

### signWithImporteddWallet

Signs using an imported dWallet with encrypted shares.

```typescript
await ikaTx.signWithImporteddWallet({
	dWallet: importeddWallet,
	importedKeyMessageApproval: importedKeyMessageApprovalObject,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	hashScheme: Hash.KECCAK256,
	message: messageBytes,
	encryptedUserSecretKeyShare: encryptedShare,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

## Future Signing

### requestFutureSign

Creates a partial signature for later completion.

```typescript
const { unverifiedPartialUserSignatureCap } = await ikaTx.requestFutureSign({
	dWallet: dwalletObject,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	encryptedUserSecretKeyShare: encryptedShare,
	message: messageBytes,
	hashScheme: Hash.KECCAK256,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

### requestFutureSignAndTransferCap

Creates a partial signature and transfers the capability.

```typescript
await ikaTx.requestFutureSignAndTransferCap({
	dWallet: dwalletObject,
	verifiedPresignCap: verifiedPresignCapObject,
	presign: presignObject,
	encryptedUserSecretKeyShare: encryptedShare,
	message: messageBytes,
	hashScheme: Hash.KECCAK256,
	receiver: '0x...',
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

### futureSign

Completes a future sign operation using a partial signature.

```typescript
ikaTx.futureSign({
	partialUserSignature: partialSignatureObject,
	messageApproval: messageApprovalObject,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

## Imported Key Operations

### requestImporteddWalletVerification

Creates a dWallet from an existing cryptographic key.

```typescript
const { ImportedKeydWalletCap } = await ikaTx.requestImporteddWalletVerification({
	importdWalletVerificationRequestInput: verificationInput,
	curve: Curve.SECP256K1,
	signerPublicKey: publicKeyBytes,
	sessionIdentifier: createRandomSessionIdentifier(),
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

### requestImporteddWalletVerificationAndTransferCap

Creates an imported dWallet and transfers the capability.

```typescript
await ikaTx.requestImporteddWalletVerificationAndTransferCap({
	importdWalletVerificationRequestInput: verificationInput,
	curve: Curve.SECP256K1,
	signerPublicKey: publicKeyBytes,
	sessionIdentifier: createRandomSessionIdentifier(),
	receiver: '0x...',
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

## User Share Management

### acceptEncryptedUserShare

Accepts an encrypted user share for a dWallet.

```typescript
await ikaTx.acceptEncryptedUserShare({
	dWallet: dwalletObject,
	userPublicOutput: userPublicOutputBytes,
	encryptedUserSecretKeyShareId: 'share_id',
});
```

### acceptEncryptedUserShareForTransferreddWallet

Accepts an encrypted share for a transferred dWallet.

```typescript
await ikaTx.acceptEncryptedUserShareForTransferreddWallet({
	dWallet: dwalletObject,
	sourceEncryptionKey: sourceEncryptionKeyObject,
	sourceEncryptedUserSecretKeyShare: sourceEncryptedShare,
	destinationEncryptedUserSecretKeyShare: destinationEncryptedShare,
});
```

### transferUserShare

Re-encrypts and transfers user shares to another address.

```typescript
await ikaTx.transferUserShare({
	dWallet: dwalletObject,
	destinationEncryptionKeyAddress: '0x...',
	sourceEncryptedUserSecretKeyShare: encryptedShare,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

### transferUserShareWithSecretShare

Transfers shares using unencrypted secret share.

```typescript
await ikaTx.transferUserShareWithSecretShare({
	dWallet: dwalletObject,
	destinationEncryptionKeyAddress: '0x...',
	sourceSecretShare: secretShareBytes,
	sourceEncryptedUserSecretKeyShare: encryptedShare,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

### makedWalletUserSecretKeySharesPublic

Converts encrypted shares to public shares.

```typescript
ikaTx.makedWalletUserSecretKeySharesPublic({
	dWallet: dwalletObject,
	secretShare: secretShareBytes,
	ikaCoin: userIkaCoin, // User's IKA coin object
	suiCoin: tx.splitCoins(tx.gas, [1000000]),
});
```

## Key Management

### registerEncryptionKey

Registers an encryption key for the current user.

```typescript
await ikaTx.registerEncryptionKey({
	curve: Curve.SECP256K1,
});
```

### createSessionIdentifier

Creates a unique session identifier for the transaction.

```typescript
const sessionId = ikaTx.createSessionIdentifier();
```

**Returns:** `TransactionObjectArgument` - Session identifier object

<Warning title="Security Warning">
Methods marked with security warnings require careful verification of inputs to maintain zero-trust security guarantees.
</Warning>
