---
id: zero-trust-dwallet
title: Zero-Trust dWallet
description: Guide about zero-trust dWallet functionalities
sidebar_position: 1
sidebar_label: Zero-Trust dWallet
---

# Zero-Trust dWallet

A Zero-Trust dWallet is a dWallet that operates under a zero-trust security model, created using a two-party computation (2PC) protocol.

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
2. Going through a protocol called DKG (Distributed Key Generation) to create the dWallet

You can register an encryption key while going through the DKG(thanks to PTBs) or before the DKG.

### Creating a Zero-Trust dWallet using typescript, without signing during DKG

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

### Creating a Zero-Trust dWallet using typescript, with signing during DKG

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

## Accepting Encrypted Share

You can call `acceptEncryptedUserShare` to accept the encrypted user share and activate the dWallet. You can do this before sign a message(in the same PTB) or after creating your dWallet.

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

## Signing a message

You can sign a message using a Zero-Trust dWallet by calling `requestSign` and passing the message and the dWallet.

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
