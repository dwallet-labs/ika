---
id: querying
title: Querying
description: Querying the Ika protocol state and objects
sidebar_position: 2
sidebar_label: Querying
---

import { Construction } from '../../../src/components/InfoBox';

# Querying

<Construction />

You can use `IkaClient` to query the Ika protocol state and objects. This guide covers all available query methods.

## Client Initialization

Before making any queries, ensure your client is properly initialized:

```typescript
// Initialize the client (recommended for better performance)
await ikaClient.initialize();

// Or let the client auto-initialize on first query
// The client will automatically initialize itself when needed
```

## Basic Object Queries

### Get DWallet

Retrieve a single DWallet by its ID:

```typescript
try {
	const dWallet = await ikaClient.getDWallet(dWalletID);
	console.log('DWallet state:', dWallet.state.$kind);
} catch (error) {
	if (error instanceof ObjectNotFoundError) {
		console.error('DWallet not found:', dWalletID);
	} else if (error instanceof NetworkError) {
		console.error('Network error:', error.message);
	}
}
```

### Get Multiple DWallets

Efficiently retrieve multiple DWallets in a single batch request:

```typescript
const dWalletIDs = ['0x123...', '0x456...', '0x789...'];
const dWallets = await ikaClient.getMultipleDWallets(dWalletIDs);

// Process each DWallet
dWallets.forEach((dWallet, index) => {
	console.log(`DWallet ${dWalletIDs[index]}: ${dWallet.state.$kind}`);
});
```

### Get DWallet Capabilities

Query DWallet capabilities owned by an address with pagination support:

```typescript
let cursor: string | null | undefined = undefined;
const allCaps: DWalletCap[] = [];

do {
	const {
		dWalletCaps,
		cursor: nextCursor,
		hasNextPage,
	} = await ikaClient.getOwnedDWalletCaps(
		address,
		cursor,
		50, // limit per page
	);

	allCaps.push(...dWalletCaps);
	cursor = nextCursor;

	if (!hasNextPage) break;
} while (cursor);

console.log(`Found ${allCaps.length} DWallet capabilities`);
```

### Get Presign

Retrieve a presign session object:

```typescript
const presign = await ikaClient.getPresign(presignID);
console.log('Presign state:', presign.state.$kind);
```

### Get Encrypted User Secret Key Share

Query an encrypted user secret key share:

```typescript
const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
	encryptedUserSecretKeyShareID,
);
```

### Get Partial User Signature

Retrieve a partial user signature object:

```typescript
const partialUserSignature = await ikaClient.getPartialUserSignature(partialUserSignatureID);
```

## State-Based Queries

### Polling for State Changes

Query objects in specific states with customizable polling behavior:

```typescript
// Wait for DWallet to become active with custom timeout and interval
try {
	const dWallet = await ikaClient.getDWalletInParticularState(dWalletID, DWalletState.ACTIVE, {
		timeout: 60000, // 60 seconds
		interval: 2000, // poll every 2 seconds
	});
	console.log('DWallet is now active!');
} catch (error) {
	console.error('Timeout waiting for DWallet to become active');
}
```

### Presign State Polling

```typescript
const presign = await ikaClient.getPresignInParticularState(presignID, PresignState.ACTIVE, {
	timeout: 30000,
	interval: 1000,
});
```

### Encrypted User Secret Key Share State Polling

```typescript
const encryptedShare = await ikaClient.getEncryptedUserSecretKeyShareInParticularState(
	encryptedUserSecretKeyShareID,
	EncryptedUserSecretKeyShareState.ACTIVE,
	{ timeout: 45000, interval: 1500 },
);
```

### Partial User Signature State Polling

```typescript
const partialSignature = await ikaClient.getPartialUserSignatureInParticularState(
	partialUserSignatureID,
	PartialUserSignatureState.ACTIVE,
);
```

## Encryption Key Queries

### Get Active Encryption Key

Retrieve the active encryption key for a specific address:

```typescript
const encryptionKey = await ikaClient.getActiveEncryptionKey(address);
console.log('Encryption key ID:', encryptionKey.id.id);
```

### Get All Network Encryption Keys

Retrieve all available network encryption keys:

```typescript
const allKeys = await ikaClient.getAllNetworkEncryptionKeys();
console.log(`Found ${allKeys.length} encryption keys`);

allKeys.forEach((key) => {
	console.log(`Key ${key.id}: epoch ${key.epoch}`);
});
```

### Get Latest Network Encryption Key

Get the most recent encryption key:

```typescript
const latestKey = await ikaClient.getLatestNetworkEncryptionKey();
console.log('Latest encryption key:', latestKey.id);
```

### Get Specific Network Encryption Key

Retrieve a specific encryption key by ID:

```typescript
try {
	const encryptionKey = await ikaClient.getNetworkEncryptionKey(encryptionKeyID);
	console.log('Encryption key epoch:', encryptionKey.epoch);
} catch (error) {
	if (error instanceof ObjectNotFoundError) {
		console.error('Encryption key not found:', encryptionKeyID);
	}
}
```

### Get DWallet's Network Encryption Key

Automatically detect which encryption key a DWallet uses:

```typescript
const dwalletEncryptionKey = await ikaClient.getDWalletNetworkEncryptionKey(dWalletID);
console.log('DWallet uses encryption key:', dwalletEncryptionKey.id);
```

## Protocol Parameters and Configuration

### Get Protocol Public Parameters

Retrieve cryptographic parameters for the network:

```typescript
// Get parameters for a specific DWallet
const dWallet = await ikaClient.getDWallet(dWalletID);
const parameters = await ikaClient.getProtocolPublicParameters(dWallet);

// Or get parameters using client's configured encryption key
const defaultParameters = await ikaClient.getProtocolPublicParameters();
```

### Get Current Epoch

Retrieve the current network epoch:

```typescript
const epoch = await ikaClient.getEpoch();
console.log('Current epoch:', epoch);
```

### Configure Encryption Key Options

Manage client encryption key settings:

```typescript
// Get current options
const currentOptions = ikaClient.getEncryptionKeyOptions();

// Set specific encryption key
ikaClient.setEncryptionKeyID(specificEncryptionKeyID);

// Set comprehensive options
ikaClient.setEncryptionKeyOptions({
	encryptionKeyID: specificEncryptionKeyID,
	autoDetect: false,
});
```

## Cache Management

### Check Cached Parameters

Check if protocol parameters are cached for an encryption key:

```typescript
const isCached = ikaClient.isProtocolPublicParametersCached(encryptionKeyID);
if (isCached) {
	const cachedParams = ikaClient.getCachedProtocolPublicParameters(encryptionKeyID);
}
```

### Cache Invalidation

Manage client cache for optimal performance:

```typescript
// Invalidate all caches
ikaClient.invalidateCache();

// Invalidate only object cache
ikaClient.invalidateObjectCache();

// Invalidate only encryption key cache
ikaClient.invalidateEncryptionKeyCache();

// Invalidate specific protocol parameters
ikaClient.invalidateProtocolPublicParametersCache(encryptionKeyID);

// Invalidate all protocol parameters
ikaClient.invalidateProtocolPublicParametersCache();
```
