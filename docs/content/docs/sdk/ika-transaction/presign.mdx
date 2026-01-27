---
id: presign
title: Presign
description: Guide about presign functionalities
sidebar_position: 3
sidebar_label: Presign
---

# Presign

Presign is a way to pre-compute part of a signature that can be used later to speed up the signing process. Ika uses presigns to optimize signature generation.

## Presign Types

There are two types of presigns:

- DWallet Specific Presign
- Global Presign

### DWallet Specific Presign

A DWallet Specific Presign is a presign that is tied to a particular dWallet. It is used to speed up the signing process for ECDSA signatures with imported key dWallets. You must always use this function when working with ECDSA signatures for imported key dWallets or dWallets created before the v2 upgrade.

#### Requesting a DWallet Specific Presign

You can request a presign by calling the `requestPresign` function.

```typescript
const presignCap = await ikaTransaction.requestPresign({
	dWallet,
	signatureAlgorithm,
	ikaCoin,
	suiCoin,
});

transaction.transferObjects([presignCap], signerAddress);
```

### Global Presign

A Global Presign is a presign that is not specific to a dWallet. It can be generated at any time and used with any dWallet, except when using ECDSA signatures with imported key dWallets or dWallets created before the v2 upgrade (in those cases, use DWallet Specific Presign instead).

#### Requesting a Global Presign

You can request a global presign by calling the `requestGlobalPresign` function.

```typescript
const presignCap = await ikaTransaction.requestGlobalPresign({
	curve,
	signatureAlgorithm,
	ikaCoin,
	suiCoin,
	dWalletNetworkEncryptionKeyId:
		'the network encryption key id that you want to use for the presign',
});

transaction.transferObjects([presignCap], signerAddress);
```

## Verifying a Presign Cap

You can verify a presign cap by calling the `verifyPresignCap` function.

```typescript
const verifiedPresignCap = await ikaTransaction.verifyPresignCap({
	unverifiedPresignCap, // <-- Directly by providing an object or object ID string
});

const verifiedPresignCap = await ikaTransaction.verifyPresignCap({
	presign, // <-- Alternatively, by providing the presign object, it takes the cap from your wallet
});
```
