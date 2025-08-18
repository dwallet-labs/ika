---
id: user-share-encryption-keys
title: User Share Encryption Keys
description: Managing cryptographic keys for secure user share operations in dWallet
sidebar_position: 5
sidebar_label: User Share Encryption Keys
---

import { Info, Warning, Construction } from '../../src/components/InfoBox';

# User Share Encryption Keys

<Construction />

The `UserShareEncryptionKeys` class is a core component for managing cryptographic keys in the dWallet network. It handles the creation and management of encryption/decryption keys and signing keypairs needed for secure user share operations. You pass it to `IkaTransaction` to perform user share operations.

## Overview

In the dWallet network, users need to securely manage their secret shares while maintaining the ability to prove ownership and authorization. The `UserShareEncryptionKeys` class provides a unified interface for:

1. **Encrypting secret shares** - Protecting sensitive cryptographic material
2. **Proving ownership** - Creating signatures to demonstrate control over keys
3. **Authorizing operations** - Signing dWallet public outputs for various operations
4. **Key management** - Deriving, storing, and retrieving cryptographic keys

<Info title="Security Reminder">
UserShareEncryptionKeys handles extremely sensitive cryptographic material. Always follow security best practices, conduct security reviews, and consider getting security audits for production applications.
</Info>

## Creating UserShareEncryptionKeys

There are several ways to create a `UserShareEncryptionKeys` instance depending on your use case.

### From Root Seed Key

The most common way is to create keys from a root seed. This method deterministically derives all necessary keys from a single seed:

```typescript
import { UserShareEncryptionKeys } from '@ika.xyz/sdk';

// Generate a random 32-byte seed (in practice, derive this securely)
const rootSeedKey = new Uint8Array(32);
crypto.getRandomValues(rootSeedKey);

// Create UserShareEncryptionKeys from the seed
const userShareKeys = UserShareEncryptionKeys.fromRootSeedKey(rootSeedKey);

console.log('Sui address:', userShareKeys.getSuiAddress());
```

<Info title="Key Derivation">
When using a root seed key, the class automatically derives:
- **Class groups encryption/decryption keys** using domain separator `CLASS_GROUPS_DECRYPTION_KEY_V1`
- **Ed25519 signing keypair** using domain separator `ED25519_SIGNING_KEY_V1`

This ensures deterministic key generation from the same seed.
</Info>

### From Serialized Bytes

If you have previously serialized keys, you can restore them:

```typescript
// Restore from previously serialized bytes
const serializedBytes: Uint8Array = loadKeysFromStorage(); // Your storage logic
const userShareKeys = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(serializedBytes);
```

### Serializing Keys for Storage

You can serialize keys for persistent storage:

```typescript
const userShareKeys = UserShareEncryptionKeys.fromRootSeedKey(rootSeedKey);

// Serialize keys to bytes for storage
const serializedBytes = userShareKeys.toShareEncryptionKeysBytes();

// Store securely (example - implement your own secure storage)
await secureStorage.store('user-share-keys', serializedBytes);
```

<Warning title="Security Warning">
Always store serialized keys securely. The serialized data contains sensitive cryptographic material including private keys. Use appropriate encryption and access controls for storage.
</Warning>

## Key Methods and Operations

### Getting Key Information

Access basic information about your keys:

```typescript
const userShareKeys = UserShareEncryptionKeys.fromRootSeedKey(rootSeedKey);

// Get the Ed25519 public key
const publicKey = userShareKeys.getPublicKey();

// Get the Sui address derived from the signing keypair
const suiAddress = userShareKeys.getSuiAddress();
console.log('Address:', suiAddress);

// Get raw public key bytes for lower-level operations
const publicKeyBytes = userShareKeys.getSigningPublicKeyBytes();
```

### Signature Operations

#### Verifying Signatures

Verify signatures over messages using the public key:

```typescript
const message = new TextEncoder().encode('Hello, dWallet!');
const signature: Uint8Array = getSignatureFromSomewhere(); // Your signature source

const isValid = await userShareKeys.verifySignature(message, signature);
console.log('Signature valid:', isValid);
```

#### Creating Encryption Key Signatures

Create a signature over your own encryption key to prove ownership:

```typescript
// Sign your own encryption key to prove ownership
const encryptionKeySignature = await userShareKeys.getEncryptionKeySignature();

// This signature can be used to prove you control this encryption key
```

### dWallet Authorization Signatures

#### For Newly Created dWallets

When you participate in dWallet creation, you need to sign the public output to authorize its use:

```typescript
import { IkaClient } from '@ika.xyz/sdk';

// Assume you have a dWallet in the awaiting key holder signature state
const dWallet = await ikaClient.getdWallet(dWalletId);
const userPublicOutput: Uint8Array = getUserDKGOutput(); // From your DKG participation

try {
	const signature = await userShareKeys.getUserOutputSignature(dWallet, userPublicOutput);
	console.log('Authorization signature created successfully');

	// Use this signature in your dWallet activation transaction
} catch (error) {
	if (error.message.includes('not in awaiting key holder signature state')) {
		console.error('dWallet is not ready for signature');
	} else if (error.message.includes('User public output does not match')) {
		console.error('Public output mismatch - check your DKG participation');
	}
}
```

#### For Transferred dWallets

When receiving a transferred dWallet, you need to verify the sender and create your authorization signature:

```typescript
// When receiving a transferred dWallet
const dWallet = await ikaClient.getdWallet(transferreddWalletId);
const sourceEncryptedShare = await ikaClient.getEncryptedUserSecretKeyShare(shareId);
const sourceEncryptionKey = await ikaClient.getActiveEncryptionKey(senderAddress);

try {
	const signature = await userShareKeys.getUserOutputSignatureForTransferreddWallet(
		dWallet,
		sourceEncryptedShare,
		sourceEncryptionKey,
	);

	console.log('Transfer authorization signature created');
} catch (error) {
	console.error('Failed to create transfer signature:', error.message);
}
```

<Warning title="Security Warning">
When handling transferred dWallets, always verify that `sourceEncryptionKey` belongs to the expected sender. Don't fetch this from the network without proper verification - the sender's public key should be known to you through secure channels.
</Warning>

### Decrypting User Shares

The most critical operation is decrypting your encrypted user secret key shares:

```typescript
// Decrypt a user share for a specific dWallet
const dWallet = await ikaClient.getdWallet(dWalletId);
const encryptedUserShare = await ikaClient.getEncryptedUserSecretKeyShare(shareId);

// Get protocol parameters for the dWallet's encryption key
const protocolParameters = await ikaClient.getProtocolPublicParameters(dWallet);

try {
	const { verifiedPublicOutput, secretShare } = await userShareKeys.decryptUserShare(
		dWallet,
		encryptedUserShare,
		protocolParameters,
	);

	console.log('Successfully decrypted user share');
	console.log('Verified public output length:', verifiedPublicOutput.length);
	console.log('Secret share length:', secretShare.length);

	// Use the decrypted secret share for signing operations
	// IMPORTANT: Handle secretShare securely - it contains sensitive cryptographic material
} catch (error) {
	if (error.message.includes('dWallet is not active')) {
		console.error('Cannot decrypt share - dWallet is not in active state');
	} else if (error.message.includes('verification fails')) {
		console.error('Share verification failed - check encryption key and dWallet state');
	} else {
		console.error('Decryption failed:', error.message);
	}
}
```

<Info title="Decryption Process">
The `decryptUserShare` method performs several security checks:

1. **Verifies the dWallet state** - Ensures the dWallet is active and has valid public output
2. **Validates the encrypted share** - Checks the encrypted share signature against your public key
3. **Decrypts the share** - Uses your decryption key to recover the secret share
4. **Verifies consistency** - Ensures the decrypted share matches the dWallet's public output

This multi-layer verification ensures the integrity and authenticity of your secret shares.
</Info>
