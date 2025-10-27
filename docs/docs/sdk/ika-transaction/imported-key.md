---
id: imported-key-dwallet
title: Imported Key dWallet
description: Guide about imported key dWallet functionalities
sidebar_position: 5
sidebar_label: Imported Key dWallet
---

# Imported Key dWallet

An Imported Key dWallet allows you to import an existing private key into the Ika network, enabling you to leverage the network's distributed signing capabilities while maintaining control over your existing keys.

:::tip Already have a key?
Imported Key dWallets are ideal when you need to use an existing private key (e.g., from Bitcoin, Ethereum, or other blockchains) within the Ika network's signing infrastructure. For new wallets, consider [Zero-Trust dWallets](./zero-trust.md) or [Shared dWallets](./shared-dwallet.md).
:::

## Architecture

The Imported Key dWallet consists of two cryptographic shares:

- **User Share**: An encrypted share derived from your original private key, controlled by you
- **Network Share**: A share held by the Ika network, also derived from your original private key

The original private key is cryptographically split into these shares during the import process, maintaining security while enabling distributed signing. The complete private key never exists in any single location after import.

## When to Use Imported Key dWallets

Imported Key dWallets are appropriate when:

1. **Migrating Existing Keys**: You have existing private keys (Bitcoin, Ethereum, etc.) that you want to use with Ika's signing infrastructure
2. **Cross-Chain Operations**: You need to sign transactions on multiple blockchains using the same underlying key material
3. **Key Recovery**: You want to restore a wallet from a known private key
4. **Legacy System Integration**: You need to integrate with systems that use specific pre-existing keys

**Important**: The private key is split into shares during import. For maximum security with new wallets, consider zero-trust dWallets created through DKG.

## Security Model

Imported Key dWallets can operate in two security modes:

### Zero-Trust Mode (Default)

By default, imported key dWallets operate in zero-trust mode:

- Your user share is encrypted and requires your decryption key for signing
- You must explicitly provide your encrypted share for each signature
- The network cannot sign without your participation

### Shared Mode (Optional)

You can optionally convert to shared mode by making the user share public:

- The user share becomes publicly visible on the network
- The network can sign without your direct participation
- Useful for automation, DAOs, and smart contract-controlled wallets
- **Warning**: This conversion is irreversible

See [Converting to Shared Mode](#converting-to-shared-mode) for details.

## Creating an Imported Key dWallet

Creating an Imported Key dWallet involves importing an existing private key and verifying it with the network.

### Step 1: Prepare the Import

```typescript
import {
	createRandomSessionIdentifier,
	Curve,
	IkaClient,
	prepareImportedKeyDWalletVerification,
	UserShareEncryptionKeys,
} from '@ika-network/ika-sdk';

const signerAddress = '0xabcdef1234567890';
const curve = Curve.SECP256K1; // Choose based on your key type

// Your existing private key (32 bytes)
const privateKey = Uint8Array.from(
	Buffer.from('20255a048b64a9930517e91a2ee6b3aa6ea78131a4ad88f20cb3d351f28d6fe653', 'hex'),
);

// Generate encryption keys for protecting your user share
const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
	new TextEncoder().encode('your-seed-phrase'),
	curve,
);

// Create a session identifier for this import operation
const sessionIdentifier = createRandomSessionIdentifier();

// Prepare the import verification input
const importDWalletVerificationInput = await prepareImportedKeyDWalletVerification(
	ikaClient,
	curve,
	sessionIdentifier,
	signerAddress,
	userShareEncryptionKeys,
	privateKey, // Your existing private key, encode it to BCS before passing it to the function
);
```

### Step 2: Request Import Verification

```typescript
import { IkaTransaction } from '@ika-network/ika-sdk';
import { Transaction } from '@mysten/sui/transactions';

const suiTransaction = new Transaction();
const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction: suiTransaction,
	userShareEncryptionKeys,
});

// Register your encryption key (required for encrypted share storage)
await ikaTransaction.registerEncryptionKey({ curve });

// Create IKA token for transaction fees
const ikaToken = createEmptyIkaToken(suiTransaction, ikaClient.ikaConfig);

// Register the session identifier
const registeredSessionIdentifier = ikaTransaction.registerSessionIdentifier(sessionIdentifier);

// Request imported key dWallet verification
const importedKeyDWalletCap = await ikaTransaction.requestImportedKeyDWalletVerification({
	importDWalletVerificationRequestInput: importDWalletVerificationInput,
	curve,
	signerPublicKey: userShareEncryptionKeys.getSigningPublicKeyBytes(),
	sessionIdentifier: registeredSessionIdentifier,
	ikaCoin: ikaToken,
	suiCoin: suiTransaction.gas,
});

// Transfer the dWallet cap to your address
suiTransaction.transferObjects([importedKeyDWalletCap], signerAddress);
destroyEmptyIkaToken(suiTransaction, ikaClient.ikaConfig, ikaToken);

// Execute the transaction
const result = await executeTransaction(suiClient, suiTransaction);
```

### Step 3: Wait for Verification

```typescript
import {
	CoordinatorInnerModule,
	ImportedKeyDWallet,
	SessionsManagerModule,
} from '@ika-network/ika-sdk';

// Find the verification event
const verificationEvent = result.events?.find((event) =>
	event.type.includes('DWalletImportedKeyVerificationRequestEvent'),
);

const parsedVerificationEvent = SessionsManagerModule.DWalletSessionEvent(
	CoordinatorInnerModule.DWalletImportedKeyVerificationRequestEvent,
).fromBase64(verificationEvent?.bcs);

const dWalletID = parsedVerificationEvent.event_data.dwallet_id;
const encryptedUserSecretKeyShareId =
	parsedVerificationEvent.event_data.encrypted_user_secret_key_share_id;

// Wait for dWallet to be verified (AwaitingKeyHolderSignature state)
const importedKeyDWallet = (await ikaClient.getDWalletInParticularState(
	dWalletID,
	'AwaitingKeyHolderSignature',
	{ timeout: 30000, interval: 1000 },
)) as ImportedKeyDWallet;

// Verify it's an imported key dWallet
console.log(importedKeyDWallet.is_imported_key_dwallet); // true
```

## Activating Your Imported Key dWallet

After the network verifies your imported key, you must accept the encrypted user share to activate the dWallet for signing.

```typescript
// Get the encrypted user secret key share
const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
	encryptedUserSecretKeyShareId,
);

// Create a transaction to accept the share
const acceptShareTransaction = new Transaction();
const acceptShareIkaTransaction = new IkaTransaction({
	ikaClient,
	transaction: acceptShareTransaction,
	userShareEncryptionKeys,
});

// Accept the encrypted user share
await acceptShareIkaTransaction.acceptEncryptedUserShare({
	dWallet: importedKeyDWallet,
	encryptedUserSecretKeyShareId: encryptedUserSecretKeyShare.id.id,
	userPublicOutput: importDWalletVerificationInput.userPublicOutput,
});

await executeTransaction(suiClient, acceptShareTransaction);

// Wait for the dWallet to become Active
const activeDWallet = (await ikaClient.getDWalletInParticularState(dWalletID, 'Active', {
	timeout: 30000,
	interval: 2000,
})) as ImportedKeyDWallet;
```

## Signing a Message

Once active, you can sign messages using your imported key dWallet. The signing process requires a presign and your encrypted user share (for zero-trust mode).

### Requesting a Presign

Presigns are pre-computed cryptographic nonces required for signature generation. The type of presign depends on the signature algorithm:

- **Global Presign**: Required for EdDSA, Taproot, and SchnorrkelSubstrate
- **DWallet-Specific Presign**: Required for ECDSA algorithms (ECDSASecp256k1, ECDSASecp256r1)

```typescript
import { Hash, SignatureAlgorithm } from '@ika-network/ika-sdk';

const signatureAlgorithm = SignatureAlgorithm.ECDSASecp256k1;
const hashScheme = Hash.KECCAK256;

const suiTransaction = new Transaction();
const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction: suiTransaction,
	userShareEncryptionKeys,
});

const ikaToken = createEmptyIkaToken(suiTransaction, ikaClient.ikaConfig);

let unverifiedPresignCap;

// For EdDSA, Taproot, and SchnorrkelSubstrate: use global presign
if (
	signatureAlgorithm === SignatureAlgorithm.EdDSA ||
	signatureAlgorithm === SignatureAlgorithm.SchnorrkelSubstrate ||
	signatureAlgorithm === SignatureAlgorithm.Taproot
) {
	const latestNetworkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();
	unverifiedPresignCap = ikaTransaction.requestGlobalPresign({
		signatureAlgorithm,
		ikaCoin: ikaToken,
		suiCoin: suiTransaction.gas,
		curve: curve,
		dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
	});
} else {
	// For ECDSA algorithms: use dWallet-specific presign
	unverifiedPresignCap = ikaTransaction.requestPresign({
		signatureAlgorithm,
		ikaCoin: ikaToken,
		suiCoin: suiTransaction.gas,
		dWallet: activeDWallet,
	});
}

suiTransaction.transferObjects([unverifiedPresignCap], signerAddress);
destroyEmptyIkaToken(suiTransaction, ikaClient.ikaConfig, ikaToken);

const result = await executeTransaction(suiClient, suiTransaction);

// Extract presign ID from event
const presignEvent = result.events?.find((event) => event.type.includes('PresignRequestEvent'));

const parsedPresignEvent = SessionsManagerModule.DWalletSessionEvent(
	CoordinatorInnerModule.PresignRequestEvent,
).fromBase64(presignEvent?.bcs);

// Wait for presign to complete
const presign = await ikaClient.getPresignInParticularState(
	parsedPresignEvent.event_data.presign_id,
	'Completed',
	{ timeout: 30000, interval: 2000 },
);
```

### Signing the Message

```typescript
const message = new TextEncoder().encode('Message to sign');

const signTransaction = new Transaction();
const signIkaTransaction = new IkaTransaction({
	ikaClient,
	transaction: signTransaction,
	userShareEncryptionKeys,
});

// Approve the message for signing (specific to imported keys)
const importedKeyMessageApproval = signIkaTransaction.approveImportedKeyMessage({
	dWalletCap: activeDWallet.dwallet_cap_id,
	curve,
	signatureAlgorithm,
	hashScheme,
	message,
});

// Verify the presign cap
const verifiedPresignCap = signIkaTransaction.verifyPresignCap({
	presign,
});

const emptyIKACoin = createEmptyIkaToken(signTransaction, ikaClient.ikaConfig);

// Get the encrypted user secret key share (required for zero-trust mode)
const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
	encryptedUserSecretKeyShareId,
);

// Request the signature
await signIkaTransaction.requestSignWithImportedKey({
	dWallet: activeDWallet,
	importedKeyMessageApproval,
	verifiedPresignCap,
	hashScheme,
	presign,
	encryptedUserSecretKeyShare, // Required for zero-trust mode
	message,
	signatureScheme: signatureAlgorithm,
	ikaCoin: emptyIKACoin,
	suiCoin: signTransaction.gas,
});

destroyEmptyIkaToken(signTransaction, ikaClient.ikaConfig, emptyIKACoin);

// Execute the signing transaction
const signResult = await executeTransaction(suiClient, signTransaction);

// Extract sign ID from event
const signEvent = signResult.events?.find((event) => event.type.includes('SignRequestEvent'));

const signEventData = SessionsManagerModule.DWalletSessionEvent(
	CoordinatorInnerModule.SignRequestEvent,
).fromBase64(signEvent?.bcs);

// Wait for signature completion
const sign = await ikaClient.getSignInParticularState(
	signEventData.event_data.sign_id,
	curve,
	signatureAlgorithm,
	'Completed',
	{ timeout: 60000, interval: 1000 },
);

// Extract the signature
const signature = Uint8Array.from(sign.state.Completed?.signature ?? []);
```

## Future Signing

Future signing is a two-step process that allows you to separate the user's signature creation from the network's signature completion. This is particularly useful for scenarios where message approval happens at a different time than the actual signing.

### Creating a Partial User Signature

To initiate a future sign with an imported key dWallet, call `requestFutureSignWithImportedKey` with the message and presign. This function returns an unverified partial user signature cap, which can later be used to complete the signing process.

#### For Zero-Trust Mode (with encrypted share)

```typescript
const curve = Curve.SECP256K1;
const dWallet = await ikaClient.getDWalletInParticularState('dWallet id', 'Active');

// Verify it's zero-trust (no public share)
console.log(dWallet.public_user_secret_key_share === null); // true

const presign = await ikaClient.getPresignInParticularState('presign id', 'Completed');

const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
	new TextEncoder().encode('your-seed-phrase'),
	curve,
);

const transaction = new Transaction();
const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
	userShareEncryptionKeys,
});

const message = new TextEncoder().encode('Message to sign later');

const verifiedPresignCap = ikaTransaction.verifyPresignCap({
	presign,
});

const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

// Get the encrypted user secret key share (required for zero-trust mode)
const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
	encryptedUserSecretKeyShareId,
);

const partialUserSignatureCap = await ikaTransaction.requestFutureSignWithImportedKey({
	dWallet: dWallet as ImportedKeyDWallet,
	verifiedPresignCap,
	presign,
	encryptedUserSecretKeyShare, // Required for zero-trust mode
	message,
	hashScheme: Hash.KECCAK256,
	signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin: emptyIKACoin,
	suiCoin: transaction.gas,
});

transaction.transferObjects([partialUserSignatureCap], signerAddress);
destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

await executeTransaction(suiClient, transaction);

// Wait for the partial signature to be verified by the network
const verifiedPartialSignature = await ikaClient.getPartialUserSignatureInParticularState(
	partialUserSignatureCapId,
	'NetworkVerificationCompleted',
	{ timeout: 60000, interval: 1000 },
);
```

#### For Shared Mode (with public share)

If your imported key dWallet has been converted to shared mode (public share), future signing becomes simpler:

```typescript
const curve = Curve.SECP256K1;
const dWallet = await ikaClient.getDWalletInParticularState('dWallet id', 'Active');

// Verify it's shared mode (has public share)
console.log(dWallet.public_user_secret_key_share !== null); // true

const presign = await ikaClient.getPresignInParticularState('presign id', 'Completed');

const transaction = new Transaction();
const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
	userShareEncryptionKeys,
});

const message = new TextEncoder().encode('Message to sign later');

const verifiedPresignCap = ikaTransaction.verifyPresignCap({
	presign,
});

const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

// No encryptedUserSecretKeyShare needed for shared mode
const partialUserSignatureCap = await ikaTransaction.requestFutureSignWithImportedKey({
	dWallet: dWallet as ImportedSharedDWallet,
	verifiedPresignCap,
	presign,
	// No encryptedUserSecretKeyShare parameter for shared mode
	message,
	hashScheme: Hash.KECCAK256,
	signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin: emptyIKACoin,
	suiCoin: transaction.gas,
});

transaction.transferObjects([partialUserSignatureCap], signerAddress);
destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

await executeTransaction(suiClient, transaction);

// Wait for the partial signature to be verified by the network
const verifiedPartialSignature = await ikaClient.getPartialUserSignatureInParticularState(
	partialUserSignatureCapId,
	'NetworkVerificationCompleted',
	{ timeout: 60000, interval: 1000 },
);
```

### Completing the Signature

To finalize a future sign with an imported key dWallet, call `futureSignWithImportedKey` with the partial user signature cap and the message approval. Note that for imported keys, you must use `approveImportedKeyMessage` (not `approveMessage`).

```typescript
const transaction = new Transaction();
const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
	userShareEncryptionKeys,
});

const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

// Use approveImportedKeyMessage for imported key dWallets
const importedKeyMessageApproval = ikaTransaction.approveImportedKeyMessage({
	dWalletCap: dWallet.dwallet_cap_id,
	curve,
	signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
	hashScheme: Hash.KECCAK256,
	message,
});

// Complete the future sign
ikaTransaction.futureSignWithImportedKey({
	partialUserSignatureCap: verifiedPartialSignature.cap_id,
	importedKeyMessageApproval,
	ikaCoin: emptyIKACoin,
	suiCoin: transaction.gas,
});

destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

await executeTransaction(suiClient, transaction);

// Fetch the completed signature
const signEvent = result.events?.find((event) => event.type.includes('SignRequestEvent'));

const signEventData = SessionsManagerModule.DWalletSessionEvent(
	CoordinatorInnerModule.SignRequestEvent,
).fromBase64(signEvent?.bcs);

const signature = await ikaClient.getSignInParticularState(
	signEventData.event_data.sign_id,
	curve,
	SignatureAlgorithm.ECDSASecp256k1,
	'Completed',
	{ timeout: 60000, interval: 1000 },
);

const rawSignature = Uint8Array.from(signature.state.Completed?.signature ?? []);
```

## Converting to Shared Mode

You can convert an imported key dWallet from zero-trust mode to shared mode by making the user share public. This allows the network to sign without requiring your encrypted share for each operation.

**Warning**: This operation is irreversible and fundamentally changes the trust model. Once public, the network can sign without your participation.

```typescript
// Get the encrypted user secret key share
const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
	encryptedUserSecretKeyShareId,
);

// Decrypt the user share
const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(activeDWallet);
const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
	activeDWallet,
	encryptedUserSecretKeyShare,
	protocolPublicParameters,
);

// Create transaction to make user share public
const transaction = new Transaction();
const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
	userShareEncryptionKeys,
});

const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

ikaTransaction.makeDWalletUserSecretKeySharesPublic({
	dWallet: activeDWallet,
	secretShare,
	ikaCoin: emptyIKACoin,
	suiCoin: transaction.gas,
});

destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

await executeTransaction(suiClient, transaction);

// Wait for dWallet to have public shares
const publicDWallet = await ikaClient.getDWalletInParticularState(activeDWallet.id.id, 'Active', {
	timeout: 30000,
	interval: 2000,
});

// Verify it now has public shares
console.log(publicDWallet.public_user_secret_key_share !== null); // true
```
