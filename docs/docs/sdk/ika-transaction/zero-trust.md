---
id: zero-trust-dwallet
title: Zero-Trust dWallet
description: Guide about zero-trust dWallet functionalities
sidebar_position: 3
sidebar_label: Zero-Trust dWallet
---

# Zero-Trust dWallet

A Zero-Trust dWallet is a dWallet that operates under a zero-trust security model, created using a two-party computation (2PC) protocol.

:::tip Need automated signing?
If you're building DAOs, smart contracts, or automated systems that need network-controlled signing, consider using a [Shared dWallet](./shared-dwallet.md) instead.
:::

## Architecture

The dWallet consists of two cryptographic shares:

- **User Share**: An encrypted share that is controlled by the user
- **Network Share**: A share held by the Ika network

Both shares are required to create a valid signature, ensuring that neither party can unilaterally access the wallet.

## Signing Process

To generate a signature, the user must:

1. Decrypt their user share using their decryption key to obtain the raw secret share
2. Use this secret share to generate a commitment message
3. Combine it with the network share to produce the final signature

This design ensures that the private key never exists in its complete form in any single location, maintaining the zero-trust security guarantee.

## Creating a Zero-Trust dWallet

Creating a Zero-Trust dWallet involves the following steps:

1. Register an encryption key with the network
2. Execute a Distributed Key Generation (DKG) protocol to create the dWallet

You can register an encryption key during the DKG process (thanks to PTBs) or beforehand.

### Basic DKG Creation

```typescript
const signerAddress = '0xabcdef1234567890';
const curve = Curve.SECP256R1; // or Curve.SECP256K1, Curve.ED25519, Curve.RISTRETTO

const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
	new TextEncoder().encode('seed'),
	curve,
);

const transaction = new Transaction();
const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
	userShareEncryptionKeys, // <-- This is optional, but you absolutely need to pass for zero trust dWallets
});

// Register an encryption key before the DKG, or if you did already you can skip this step
await ikaTransaction.registerEncryptionKey({
	curve,
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

// Tuple's first element is the dWallet cap, second element is the option sign id if you have requested to sign during DKG
const [dWalletCap, _signId] = await ikaTransaction.requestDWalletDKG({
	curve,
	dkgRequestInput,
	sessionIdentifier: ikaTransaction.registerSessionIdentifier(identifier),
	ikaCoin,
	suiCoin,
	dwalletNetworkEncryptionKeyId: dWalletEncryptionKey.id,
});

transaction.transferObjects([dWalletCap], signerAddress);

await executeTransaction(suiClient, transaction);
```

### DKG Creation with Immediate Signing

This example shows how to create a dWallet and sign a message in a single transaction during the DKG process.

```typescript
const signerAddress = '0xabcdef1234567890';
const curve = Curve.SECP256R1; // or Curve.SECP256K1, Curve.ED25519, Curve.RISTRETTO
const globalPresign = await ikaClient.getPresignInParticularState(
	'global presign id that you requested before hand',
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
	userShareEncryptionKeys, // <-- This is optional, but you absolutely need to pass for zero trust dWallets
});

// Register an encryption key before the DKG, or if you did already you can skip this step
await ikaTransaction.registerEncryptionKey({
	curve,
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

// Tuple's first element is the dWallet cap, second element is the option sign id if you have requested to sign during DKG
const [dWalletCap, signId] = await ikaTransaction.requestDWalletDKG({
	curve,
	dkgRequestInput,
	sessionIdentifier: ikaTransaction.registerSessionIdentifier(identifier),
	ikaCoin,
	suiCoin,
	dwalletNetworkEncryptionKeyId: dWalletEncryptionKey.id,
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

// You can later on use that signId to put into a contract or return it and get the id of the signature, or you can get it from the events

transaction.transferObjects([dWalletCap], signerAddress);

await executeTransaction(suiClient, transaction);
```

## Activating Your dWallet

After creating a zero-trust dWallet through the DKG process, you must accept your encrypted user share to activate it. You can call `acceptEncryptedUserShare` to accept the encrypted user share and activate the dWallet. This can be done before signing a message (in the same PTB) or after creating your dWallet.

```typescript
const curve = Curve.SECP256R1; // or Curve.SECP256K1, Curve.ED25519, Curve.RISTRETTO

const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
	new TextEncoder().encode('test seed'),
	curve,
);

const dWallet = await ikaClient.getDWalletInParticularState(
	'dWallet id that you requested before hand',
	'AwaitingKeyHolderSignature',
);

const transaction = new Transaction();
const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
	userShareEncryptionKeys,
});

await ikaTransaction.acceptEncryptedUserShare({
	dWallet: dWallet as ZeroTrustDWallet,
	encryptedUserSecretKeyShareId: 'encrypted user secret key share id',
	userPublicOutput: new Uint8Array(dWallet.state.AwaitingKeyHolderSignature?.public_output),
});

await executeTransaction(suiClient, transaction);
```

## Signing a Message

You can sign a message using a zero-trust dWallet by calling `requestSign` and passing the message and the dWallet.

```typescript
const curve = Curve.SECP256R1; // or Curve.SECP256K1, Curve.ED25519, Curve.RISTRETTO
const presign = await ikaClient.getPresignInParticularState(
	'global presign id that you requested before hand',
	'Completed',
);
const dWallet = await ikaClient.getDWalletInParticularState(
	'dWallet id that you requested before hand',
	'Active',
);

const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
	'encrypted user secret key share id',
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

const message = new TextEncoder().encode('test message');

const messageApproval = ikaTransaction.approveMessage({
	message,
	curve,
	dWalletCap: dWallet.dwallet_cap_id,
	signatureAlgorithm: SignatureAlgorithm.ECDSASecp256r1,
	hashScheme: Hash.SHA256,
});

const optionSignId = await ikaTransaction.requestSign({
	dWallet: dWallet as ZeroTrustDWallet,
	hashScheme: Hash.SHA256,
	verifiedPresignCap: ikaTransaction.verifyPresignCap({
		presign,
	}),
	presign,
	encryptedUserSecretKeyShare: encryptedUserSecretKeyShare,
	message,
	signatureScheme: SignatureAlgorithm.ECDSASecp256r1,
	ikaCoin,
	suiCoin,
	messageApproval,
	publicOutput, // <-- You can also use this optional parameter to pass the public output of the dWallet, but check it before using it, if you use it, you wouldn't need to fetch the dWallet
	secretShare, // <-- You can also use this optional parameter to pass the secret share of the dWallet, but check it before using it, if you use it, you wouldn't need to fetch the dWallet
});

await executeTransaction(suiClient, transaction);

// You can later on fetch the signature from the sign id you got from events, returns or how you want to get it
const signature = await ikaClient.getSignInParticularState(
	'the sign id you got from event',
	curve,
	SignatureAlgorithm.ECDSASecp256r1,
	'Completed',
);

const rawSignature = Uint8Array.from(signature.state.Completed.signature);
```

## Future Signing

Future signing is a two-step process that allows you to separate the user's signature creation from the network's signature completion.

### Creating a Partial User Signature

To initiate a future sign, call `requestFutureSign` with the message and the dWallet. This function returns an unverified partial user signature cap, which can later be used to complete the signing process by having the network add its signature.

```typescript
const partialUserSignatureCap = await ikaTransaction.requestFutureSign({
	dWallet,
	encryptedUserSecretKeyShare,
	hashScheme,
	ikaCoin,
	message,
	presign,
	signatureScheme,
	suiCoin,
	verifiedPresignCap,
});

transaction.transferObjects([partialUserSignatureCap], signerAddress);

// Or you can directly pass the decrypted secret share and public output that you verified instead of dWallet parameters.

const partialUserSignatureCap = await ikaTransaction.requestFutureSign({
	secretShare,
	publicOutput,
	hashScheme,
	ikaCoin,
	message,
	presign,
	signatureScheme,
	suiCoin,
	verifiedPresignCap,
});

transaction.transferObjects([partialUserSignatureCap], signerAddress);
```

### Completing the Signature

To finalize a future sign, call `futureSign` with the partial user signature cap and the message approval. This combines the user's partial signature with the network's signature to create the complete signature.

```typescript
// Should match your curve and signature scheme you used previously in requestFutureSign
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
	partialUserSignatureCap,
});
```

## Transferring a dWallet Share

You can transfer your dWallet's encrypted user share to another user by calling `requestReEncryptUserShareFor`. This allows the recipient to sign with your dWallet while maintaining zero-trust security through re-encryption. Your secret share is re-encrypted using the recipient's encryption key, ensuring only they can decrypt it after transfer. You retain access to your original share.

**Important:** The dWallet cap is still required for message approvals. While the transferred encrypted share provides the recipient with the cryptographic material needed for signing, they cannot complete the signing process (specifically message approval) without also having access to the dWallet cap. You can choose to transfer the dWallet cap separately to grant the recipient full signing capability.

The recipient must have registered their encryption key before you can transfer the share to them.

### Transfer Using Encrypted Share

```typescript
const curve = Curve.SECP256R1; // or Curve.SECP256K1, Curve.ED25519, Curve.RISTRETTO
const dWallet = await ikaClient.getDWalletInParticularState(
	'dWallet id that you requested before hand',
	'Active',
);

const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
	'encrypted user secret key share id',
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

await ikaTransaction.requestReEncryptUserShareFor({
	dWallet: dWallet as ZeroTrustDWallet,
	destinationEncryptionKeyAddress: recipientAddress,
	sourceEncryptedUserSecretKeyShare: encryptedUserSecretKeyShare,
	ikaCoin,
	suiCoin,
});

const result = await executeTransaction(suiClient, transaction);

// Extract the transferred encrypted share ID from the event
const reEncryptEvent = result.events?.find((event) =>
	event.type.includes('EncryptedShareVerificationRequestEvent'),
);

const transferredEncryptedShareId = /* extract from event */;

// Wait for the transferred share to be verified by the network
const transferredShare = await ikaClient.getEncryptedUserSecretKeyShareInParticularState(
	transferredEncryptedShareId,
	'NetworkVerificationCompleted',
);
```

### Transfer Using Pre-Decrypted Share

If you have already decrypted your secret share, you can pass it directly to optimize the process:

```typescript
const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
	dWallet,
	encryptedUserSecretKeyShare,
	await ikaClient.getProtocolPublicParameters(dWallet),
);

await ikaTransaction.requestReEncryptUserShareFor({
	dWallet: dWallet as ZeroTrustDWallet,
	destinationEncryptionKeyAddress: recipientAddress,
	sourceSecretShare: secretShare, // <-- Pre-decrypted secret share
	sourceEncryptedUserSecretKeyShare: encryptedUserSecretKeyShare,
	ikaCoin,
	suiCoin,
});

const result = await executeTransaction(suiClient, transaction);

// Extract the transferred encrypted share ID from the event
const reEncryptEvent = result.events?.find((event) =>
	event.type.includes('EncryptedShareVerificationRequestEvent'),
);

const transferredEncryptedShareId = /* extract from event */;

// Wait for the transferred share to be verified by the network
const transferredShare = await ikaClient.getEncryptedUserSecretKeyShareInParticularState(
	transferredEncryptedShareId,
	'NetworkVerificationCompleted',
);
```

## Receiving a dWallet Share

You can accept a dWallet user share that has been transferred to you by calling `acceptEncryptedUserShare`. This process grants you signing access to another user's dWallet while maintaining zero-trust security. The transferred share is encrypted specifically for your encryption key, ensuring only you can decrypt and use it. The original owner retains access to their share.

**Important:** To complete the signing process, you will also need the dWallet cap for message approvals. The encrypted share alone provides the cryptographic material, but message approval requires the dWallet cap. The sender should transfer the dWallet cap to you separately if they want to grant you full signing capability.

Before accepting a transferred share, you must register your encryption key with the network. The sender will provide you with the dWallet object ID and the transferred encrypted share ID.

```typescript
const curve = Curve.SECP256R1; // or Curve.SECP256K1, Curve.ED25519, Curve.RISTRETTO

// Register your encryption key if you haven't already
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

// Register encryption key (skip this step if you already registered)
await ikaTransaction.registerEncryptionKey({
	curve,
});

// Get the dWallet object (provided by sender)
const dWallet = await ikaClient.getDWalletInParticularState(
	'dWallet id provided by sender',
	'Active',
);

// Get sender's original encrypted share
const senderOriginalShare = await ikaClient.getEncryptedUserSecretKeyShare(
	'sender original encrypted share id',
);

// Get sender's encryption key for verification (using the encryption_key_address from the share)
const senderEncryptionKey = await ikaClient.getActiveEncryptionKey(
	senderOriginalShare.encryption_key_address,
);

// Get the transferred encrypted share (provided by sender)
const transferredEncryptedShare = await ikaClient.getEncryptedUserSecretKeyShare(
	'transferred encrypted share id',
);

// Accept the transferred share
await ikaTransaction.acceptEncryptedUserShare({
	dWallet: dWallet as ZeroTrustDWallet,
	sourceEncryptedUserSecretKeyShare: senderOriginalShare,
	sourceEncryptionKey: senderEncryptionKey,
	destinationEncryptedUserSecretKeyShare: transferredEncryptedShare,
});

await executeTransaction(suiClient, transaction);
```

## Converting to a Shared dWallet

You can convert a zero-trust dWallet to a shared dWallet by calling `makeDWalletUserSecretKeySharesPublic` and passing the dWallet.

**Warning:** This operation fundamentally changes the trust model of the dWallet. By making the user secret share public, you are sharing the secret with the network, which means you must now trust the network rather than relying on the zero-trust 2PC model. This conversion is irreversible.

```typescript
const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
	activedWallet,
	encryptedUserSecretKeyShare,
	await ikaClient.getProtocolPublicParameters(activedWallet),
);

ikaTx.makeDWalletUserSecretKeySharesPublic({
	dWallet,
	secretShare,
	ikaCoin,
	suiCoin,
});

await executeTransaction(suiClient, transaction);
```
