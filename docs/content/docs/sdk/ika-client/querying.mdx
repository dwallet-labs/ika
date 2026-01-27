---
id: querying
title: Querying
description: Querying the Ika protocol state and objects
sidebar_position: 2
sidebar_label: Querying
---

# Querying

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

### Get dWallet

Retrieve a single dWallet by its ID:

```typescript
try {
	const dWallet = await ikaClient.getDWallet(dWalletID);
	console.log('dWallet state:', dWallet.state.$kind);
	console.log('dWallet kind:', dWallet.kind);
} catch (error) {
	if (error instanceof ObjectNotFoundError) {
		console.error('dWallet not found:', dWalletID);
	} else if (error instanceof NetworkError) {
		console.error('Network error:', error.message);
	}
}
```

### Get Multiple dWallets

Efficiently retrieve multiple dWallets in a single batch request:

```typescript
const dWalletIDs = ['0x123...', '0x456...', '0x789...'];
const dWallets = await ikaClient.getMultipleDWallets(dWalletIDs);

// Process each dWallet
dWallets.forEach((dWallet, index) => {
	console.log(`dWallet ${dWalletIDs[index]}: ${dWallet.state.$kind} (${dWallet.kind})`);
});
```

### Get dWallet Capabilities

Query dWallet capabilities owned by an address with pagination support:

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

console.log(`Found ${allCaps.length} dWallet capabilities`);
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

### Get Sign Session

Retrieve a sign session object with signature parsing:

```typescript
const sign = await ikaClient.getSign(signID, 'SECP256K1', 'ECDSASecp256k1');
console.log('Sign session state:', sign.state.$kind);

// When completed, the signature is automatically parsed based on the curve and algorithm
if (sign.state.$kind === 'Completed') {
	console.log('Signature:', sign.state.Completed.signature);
}
```

## State-Based Queries

### Polling for State Changes

Query objects in specific states with customizable polling behavior:

```typescript
// Wait for dWallet to become active with custom timeout and interval
try {
	const dWallet = await ikaClient.getDWalletInParticularState(dWalletID, 'Active', {
		timeout: 60000, // 60 seconds
		interval: 2000, // poll every 2 seconds
	});
	console.log('dWallet is now active!');
} catch (error) {
	console.error('Timeout waiting for dWallet to become active');
}
```

### Presign State Polling

```typescript
const presign = await ikaClient.getPresignInParticularState(presignID, 'Completed', {
	timeout: 30000,
	interval: 1000,
});
```

### Encrypted User Secret Key Share State Polling

```typescript
const encryptedShare = await ikaClient.getEncryptedUserSecretKeyShareInParticularState(
	encryptedUserSecretKeyShareID,
	'KeyHolderSigned',
	{ timeout: 45000, interval: 1500 },
);
```

### Partial User Signature State Polling

```typescript
const partialSignature = await ikaClient.getPartialUserSignatureInParticularState(
	partialUserSignatureID,
	'Completed',
);
```

### Sign Session State Polling

```typescript
const sign = await ikaClient.getSignInParticularState(
	signID,
	'SECP256K1',
	'ECDSASecp256k1',
	'Completed',
	{
		timeout: 30000,
		interval: 1000,
	},
);
console.log('Sign session completed:', sign.state.Completed.signature);
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

### Get dWallet's Network Encryption Key

Automatically detect which encryption key a dWallet uses:

```typescript
const dwalletEncryptionKey = await ikaClient.getDWalletNetworkEncryptionKey(dWalletID);
console.log('dWallet uses encryption key:', dwalletEncryptionKey.id);
```

### Get Configured Network Encryption Key

Get the network encryption key based on client configuration:

```typescript
// Returns the configured encryption key if set, otherwise returns the latest
const configuredKey = await ikaClient.getConfiguredNetworkEncryptionKey();
console.log('Configured encryption key:', configuredKey.id);
```

## Protocol Parameters and Configuration

### Get Protocol Public Parameters

Retrieve cryptographic parameters for the network. Parameters are cached by encryption key ID and curve:

```typescript
// Get parameters for a specific dWallet (automatically detects encryption key and curve)
const dWallet = await ikaClient.getDWallet(dWalletID);
const parameters = await ikaClient.getProtocolPublicParameters(dWallet);

// Get parameters using client's configured encryption key with a specific curve
const parametersForCurve = await ikaClient.getProtocolPublicParameters(undefined, 'SECP256K1');

// Get parameters using client's configured encryption key (defaults to SECP256K1)
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

Check if protocol parameters are cached for an encryption key and curve:

```typescript
const isCached = ikaClient.isProtocolPublicParametersCached(encryptionKeyID, 'SECP256K1');
if (isCached) {
	const cachedParams = ikaClient.getCachedProtocolPublicParameters(encryptionKeyID, 'SECP256K1');
	console.log('Using cached parameters');
}
```

### Cache Invalidation

Manage client cache for optimal performance:

```typescript
// Invalidate all caches (objects, encryption keys, and protocol parameters)
ikaClient.invalidateCache();

// Invalidate only object cache (coordinator and system inner objects)
ikaClient.invalidateObjectCache();

// Invalidate only encryption key cache
ikaClient.invalidateEncryptionKeyCache();

// Invalidate specific protocol parameters for a key and curve combination
ikaClient.invalidateProtocolPublicParametersCache(encryptionKeyID, 'SECP256K1');

// Invalidate all curves for a specific encryption key
ikaClient.invalidateProtocolPublicParametersCache(encryptionKeyID);

// Invalidate all protocol parameters for all keys and curves
ikaClient.invalidateProtocolPublicParametersCache();
```
