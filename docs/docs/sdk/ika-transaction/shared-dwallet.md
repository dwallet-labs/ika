---
id: shared-dwallet
title: Shared dWallet
description: Guide about shared dWallet functionalities
sidebar_position: 4
sidebar_label: Shared dWallet
---

# Shared dWallet

A Shared dWallet is a dWallet where the user's secret share is publicly stored on the network, creating a simplified trust model where the network has full access to both shares.

:::tip Need user-controlled signing?
For applications where users should maintain full control over their wallets, use a [Zero-Trust dWallet](./zero-trust.md) instead, which requires user participation for every signature.
:::

## Architecture

The dWallet consists of two cryptographic shares:

- **Public User Share**: A publicly visible share stored on the network
- **Network Share**: A share held by the Ika network

Unlike zero-trust dWallets, both shares are accessible to the network, which means you're trusting the network to operate correctly.

## When to Use Shared dWallets

Shared dWallets are appropriate when:

1. **DAOs and Multi-Sig Automation**: Enable automated signing for DAO treasuries and governance actions
2. **Smart Contract-Controlled Wallets**: Allow smart contracts to programmatically sign transactions
3. **Automated Systems**: Build systems that need to sign without user interaction (bots, automated traders, etc.)
4. **Simplified Wallet Management**: Applications where you want to delegate signing authority to the network

**Important**: Shared dWallets require trusting the network to handle signing operations. This is a different security model from zero-trust dWallets, where you maintain signing control. Both have legitimate production use cases depending on your requirements.

## Creating a Shared dWallet

Creating a Shared dWallet is simpler than zero-trust since you don't need encryption keys for the user share. The dWallet becomes active immediately after DKG completion.

### Basic DKG Creation

```typescript
const signerAddress = '0xabcdef1234567890';
const curve = Curve.SECP256R1; // or Curve.SECP256K1, Curve.ED25519, Curve.RISTRETTO

// Note: You still need UserShareEncryptionKeys for the DKG protocol itself,
// but not for the encrypted user share storage
const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
	new TextEncoder().encode('seed'),
	curve,
);

const transaction = new Transaction();
const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
	userShareEncryptionKeys, // <-- Needed for DKG protocol, not for storage
});

const identifier = createRandomSessionIdentifier();

// Prepare DKG - this generates the necessary cryptographic materials
const dkgRequestInput = await prepareDKGAsync(
	ikaClient,
	curve,
	userShareEncryptionKeys,
	identifier,
	signerAddress,
);

const dWalletEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

// Create a shared dWallet using requestDWalletDKGWithPublicUserShare
// The key difference: we pass publicUserSecretKeyShare instead of encrypted share
const [dWalletCap] = await ikaTransaction.requestDWalletDKGWithPublicUserShare({
	publicKeyShareAndProof: dkgRequestInput.userDKGMessage,
	publicUserSecretKeyShare: dkgRequestInput.userSecretKeyShare, // <-- Public, not encrypted
	userPublicOutput: dkgRequestInput.userPublicOutput,
	curve,
	dwalletNetworkEncryptionKeyId: dWalletEncryptionKey.id,
	ikaCoin,
	suiCoin,
	sessionIdentifier: ikaTransaction.registerSessionIdentifier(identifier),
});

transaction.transferObjects([dWalletCap], signerAddress);

await executeTransaction(suiClient, transaction);

// Wait for the dWallet to become active (no user confirmation needed)
const activeDWallet = await ikaClient.getDWalletInParticularState(dWalletID, 'Active', {
	timeout: 30000,
	interval: 1000,
});

// Verify it's a shared dWallet
expect(activeDWallet.public_user_secret_key_share).toBeDefined();
```

### DKG Creation with Immediate Signing

This example shows how to create a shared dWallet and sign a message in a single transaction during the DKG process.

```typescript
const signerAddress = '0xabcdef1234567890';
const curve = Curve.SECP256R1; // or Curve.SECP256K1, Curve.ED25519, Curve.RISTRETTO

// Request a global presign first (this must be done before DKG with signing)
const globalPresign = await ikaClient.getPresignInParticularState(
	'global presign id that you requested beforehand',
	'Completed',
);

const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
	new TextEncoder().encode('test seed'),
	curve,
);

const transaction = new Transaction();
const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
	userShareEncryptionKeys,
});

const identifier = createRandomSessionIdentifier();

const dkgRequestInput = await prepareDKGAsync(
	ikaClient,
	curve,
	userShareEncryptionKeys,
	identifier,
	signerAddress,
);

const dWalletEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

// Create shared dWallet and sign during DKG
const [dWalletCap, signId] = await ikaTransaction.requestDWalletDKGWithPublicUserShare({
	publicKeyShareAndProof: dkgRequestInput.userDKGMessage,
	publicUserSecretKeyShare: dkgRequestInput.userSecretKeyShare,
	userPublicOutput: dkgRequestInput.userPublicOutput,
	curve,
	dwalletNetworkEncryptionKeyId: dWalletEncryptionKey.id,
	ikaCoin,
	suiCoin,
	sessionIdentifier: ikaTransaction.registerSessionIdentifier(identifier),
	signDuringDKGRequest: {
		message: new TextEncoder().encode('test message'),
		presign: globalPresign,
		verifiedPresignCap: ikaTransaction.verifyPresignCap({
			presign: globalPresign,
		}),
		hashScheme: Hash.SHA256,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256r1,
	},
});

// You can later use that signId to retrieve the signature from events or returns
transaction.transferObjects([dWalletCap], signerAddress);

await executeTransaction(suiClient, transaction);

// Wait for signature completion
const signature = await ikaClient.getSignInParticularState(
	signId,
	curve,
	SignatureAlgorithm.ECDSASecp256r1,
	'Completed',
	{ timeout: 60000, interval: 1000 },
);

const rawSignature = Uint8Array.from(signature.state.Completed.signature);
```

## Signing a Message

Signing with a shared dWallet is simpler than zero-trust since you don't need to provide the encrypted user share - the network already has access to the public user share.

```typescript
const curve = Curve.SECP256R1; // or Curve.SECP256K1, Curve.ED25519, Curve.RISTRETTO
const presign = await ikaClient.getPresignInParticularState(
	'global presign id that you requested beforehand',
	'Completed',
);

const dWallet = await ikaClient.getDWalletInParticularState(
	'dWallet id that you requested beforehand',
	'Active',
);

// Verify it's a shared dWallet
expect(dWallet.public_user_secret_key_share).toBeDefined();

const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
	new TextEncoder().encode('test seed'),
	curve,
);

const transaction = new Transaction();
const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
	userShareEncryptionKeys,
});

const message = new TextEncoder().encode('test message');

const messageApproval = ikaTransaction.approveMessage({
	message,
	curve,
	dWalletCap: dWallet.dwallet_cap_id,
	signatureAlgorithm: SignatureAlgorithm.ECDSASecp256r1,
	hashScheme: Hash.SHA256,
});

const optionSignId = await ikaTransaction.requestSign({
	dWallet: dWallet as SharedDWallet,
	hashScheme: Hash.SHA256,
	verifiedPresignCap: ikaTransaction.verifyPresignCap({
		presign,
	}),
	presign,
	// No encryptedUserSecretKeyShare needed - network uses public share automatically
	message,
	signatureScheme: SignatureAlgorithm.ECDSASecp256r1,
	ikaCoin,
	suiCoin,
	messageApproval,
});

await executeTransaction(suiClient, transaction);

// Fetch the signature from the sign id
const signature = await ikaClient.getSignInParticularState(
	'the sign id you got from event',
	curve,
	SignatureAlgorithm.ECDSASecp256r1,
	'Completed',
);

const rawSignature = Uint8Array.from(signature.state.Completed.signature);
```

## Future Signing

Future signing with shared dWallets follows a two-step process similar to zero-trust dWallets, but without the need to handle encrypted user shares.

### Creating a Partial User Signature

To initiate a future sign with a shared dWallet, call `requestFutureSign` without providing an encrypted user secret key share. The network will automatically use the public share.

```typescript
const curve = Curve.SECP256R1;
const dWallet = await ikaClient.getDWalletInParticularState('dWallet id', 'Active');

// Verify it's a shared dWallet
expect(dWallet.public_user_secret_key_share).toBeDefined();

const presign = await ikaClient.getPresignInParticularState('presign id', 'Completed');

const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
	new TextEncoder().encode('test seed'),
	curve,
);

const transaction = new Transaction();
const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
	userShareEncryptionKeys,
});

const message = new TextEncoder().encode('test message');

const partialUserSignatureCap = await ikaTransaction.requestFutureSign({
	dWallet: dWallet as SharedDWallet,
	hashScheme: Hash.SHA256,
	ikaCoin,
	message,
	presign,
	signatureScheme: SignatureAlgorithm.ECDSASecp256r1,
	suiCoin,
	verifiedPresignCap: ikaTransaction.verifyPresignCap({
		presign,
	}),
	// Note: No encryptedUserSecretKeyShare parameter for shared dWallets
});

transaction.transferObjects([partialUserSignatureCap], signerAddress);

await executeTransaction(suiClient, transaction);

// Wait for the partial signature to be verified by the network
const verifiedPartialSignature = await ikaClient.getPartialUserSignatureInParticularState(
	partialUserSignatureCapId,
	'NetworkVerificationCompleted',
	{ timeout: 60000, interval: 1000 },
);
```

### Completing the Signature

To finalize a future sign, call `futureSign` with the partial user signature cap and the message approval.

```typescript
// Should match your curve and signature scheme used previously in requestFutureSign
const messageApproval = ikaTransaction.approveMessage({
	message,
	curve,
	dWalletCap: dWallet.dwallet_cap_id,
	signatureAlgorithm: SignatureAlgorithm.ECDSASecp256r1,
	hashScheme: Hash.SHA256,
});

const signId = await ikaTransaction.futureSign({
	suiCoin,
	ikaCoin,
	messageApproval,
	partialUserSignatureCap: verifiedPartialSignature.cap_id,
});

await executeTransaction(suiClient, transaction);

// Fetch the completed signature
const signature = await ikaClient.getSignInParticularState(
	signId,
	curve,
	SignatureAlgorithm.ECDSASecp256r1,
	'Completed',
	{ timeout: 60000, interval: 1000 },
);

const rawSignature = Uint8Array.from(signature.state.Completed.signature);
```

## Converting from Zero-Trust to Shared

You can convert a zero-trust dWallet to a shared dWallet by making the user secret key share public. This operation is irreversible.

**Warning**: This operation fundamentally changes the trust model of the dWallet. By making the user secret share public, you are sharing the secret with the network, which means you must now trust the network rather than relying on the zero-trust 2PC model.

```typescript
const curve = Curve.SECP256R1;

// Get your zero-trust dWallet
const zeroTrustDWallet = await ikaClient.getDWalletInParticularState('dWallet id', 'Active');

// Verify it's zero-trust (has no public share)
expect(zeroTrustDWallet.public_user_secret_key_share).toBeNull();

const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
	'encrypted user secret key share id',
);

const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
	new TextEncoder().encode('test seed'),
	curve,
);

// Decrypt the user share
const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(zeroTrustDWallet);
const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
	zeroTrustDWallet,
	encryptedUserSecretKeyShare,
	protocolPublicParameters,
);

// Make the user share public
const transaction = new Transaction();
const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
	userShareEncryptionKeys,
});

ikaTransaction.makeDWalletUserSecretKeySharesPublic({
	dWallet: zeroTrustDWallet,
	secretShare,
	ikaCoin,
	suiCoin,
});

await executeTransaction(suiClient, transaction);

// Wait for the dWallet to have public shares
const sharedDWallet = await ikaClient.getDWalletInParticularState(
	zeroTrustDWallet.id.id,
	'Active',
	{ timeout: 30000, interval: 2000 },
);

// Verify it's now a shared dWallet
expect(sharedDWallet.public_user_secret_key_share).toBeDefined();
```
