import { Transaction } from '@mysten/sui/transactions';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { randomBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';

import {
	CoordinatorInnerModule,
	createRandomSessionIdentifier,
	Curve,
	Hash,
	IkaClient,
	prepareImportedKeyDWalletVerification,
	Presign,
	publicKeyFromCentralizedDKGOutput,
	publicKeyFromDWalletOutput,
	SessionsManagerModule,
	SignatureAlgorithm,
} from '../../src';
import { ImportedKeyDWallet } from '../../src/client/types';
import { UserShareEncryptionKeys } from '../../src/client/user-share-encryption-keys';
import {
	createEmptyTestIkaToken,
	createTestIkaClient,
	createTestIkaTransaction,
	createTestMessage,
	createTestSuiClient,
	destroyEmptyTestIkaToken,
	executeTestTransaction,
	generateTestKeypair,
	requestTestFaucetFunds,
	retryUntil,
} from '../helpers/test-utils';

/**
 * Generate a private key for the given curve
 */
function generatePrivateKey(curve: Curve): Uint8Array {
	switch (curve) {
		case Curve.SECP256K1:
			return secp256k1.utils.randomSecretKey();
		case Curve.SECP256R1:
			return p256.utils.randomSecretKey();
		case Curve.ED25519:
			return ed25519.utils.randomSecretKey();
		case Curve.RISTRETTO:
			// For Ristretto/Schnorrkel, use 32 random bytes
			return randomBytes(32);
		default:
			throw new Error(`Unsupported curve: ${curve}`);
	}
}

/**
 * Derive public key from private key for the given curve
 */
function derivePublicKey(privateKey: Uint8Array, curve: Curve): Uint8Array {
	switch (curve) {
		case Curve.SECP256K1:
			return secp256k1.getPublicKey(privateKey, true); // compressed
		case Curve.SECP256R1:
			return p256.getPublicKey(privateKey, true); // compressed
		case Curve.ED25519:
			return ed25519.getPublicKey(privateKey);
		case Curve.RISTRETTO:
			// For Ristretto/Schnorrkel, we can't derive public key client-side easily
			// Return the private key as placeholder - verification will be done on-chain
			return privateKey;
		default:
			throw new Error(`Unsupported curve: ${curve}`);
	}
}

/**
 * Compute hash based on the hash scheme
 */
function computeHash(message: Uint8Array, hashScheme: Hash): Uint8Array {
	switch (hashScheme) {
		case Hash.KECCAK256:
			return keccak_256(message);
		case Hash.SHA256:
			return sha256(message);
		case Hash.DoubleSHA256:
			return sha256(sha256(message));
		case Hash.SHA512:
			return sha512(message);
		case Hash.Merlin:
			throw new Error('Merlin hash computation not supported client-side');
		default:
			throw new Error(`Unsupported hash scheme: ${hashScheme}`);
	}
}

/**
 * Verify signature based on the curve and hash
 */
function verifySignatureWithPublicKey(
	signature: Uint8Array,
	hash: Uint8Array,
	publicKey: Uint8Array,
	signatureAlgorithm: SignatureAlgorithm,
	message?: Uint8Array,
): boolean {
	switch (signatureAlgorithm) {
		case SignatureAlgorithm.ECDSASecp256k1:
			return secp256k1.verify(signature, hash, publicKey, { prehash: false });
		case SignatureAlgorithm.Taproot:
			return schnorr.verify(signature, hash, publicKey.slice(1));
		case SignatureAlgorithm.ECDSASecp256r1:
			return p256.verify(signature, hash, publicKey, { prehash: false });
		case SignatureAlgorithm.EdDSA:
			if (!message) {
				throw new Error('Message is required for EdDSA');
			}
			return ed25519.verify(signature, message, publicKey);
		case SignatureAlgorithm.SchnorrkelSubstrate:
			// Schnorrkel verification would require special handling
			return true;
		default:
			throw new Error(`Unsupported signature algorithm: ${signatureAlgorithm}`);
	}
}

/**
 * Setup test environment for imported key DWallet
 */
async function setupImportedKeyTest(
	testName: string,
	curve: Curve,
): Promise<{
	ikaClient: IkaClient;
	userShareEncryptionKeys: UserShareEncryptionKeys;
	signerAddress: string;
	privateKey: Uint8Array;
	originalPublicKey: Uint8Array;
}> {
	const suiClient = createTestSuiClient();
	const ikaClient = createTestIkaClient(suiClient);
	await ikaClient.initialize();

	const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName, curve);
	await requestTestFaucetFunds(signerAddress);

	// Generate a private key for the imported key scenario
	const privateKey = generatePrivateKey(curve);
	const originalPublicKey = derivePublicKey(privateKey, curve);

	return {
		ikaClient,
		userShareEncryptionKeys,
		signerAddress,
		privateKey,
		originalPublicKey,
	};
}

/**
 * Request presign for imported key DWallet
 */
async function requestPresignForImportedKey(
	ikaClient: IkaClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	importedKeyDWallet: ImportedKeyDWallet,
	signatureAlgorithm: SignatureAlgorithm,
	signerAddress: string,
	testName: string,
): Promise<Presign> {
	const suiClient = createTestSuiClient();
	const suiTransaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(
		ikaClient,
		suiTransaction,
		userShareEncryptionKeys,
	);

	const ikaToken = createEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig);

	const unverifiedPresignCap = ikaTransaction.requestPresign({
		dWallet: importedKeyDWallet,
		signatureAlgorithm,
		ikaCoin: ikaToken,
		suiCoin: suiTransaction.gas,
	});

	suiTransaction.transferObjects([unverifiedPresignCap], signerAddress);
	destroyEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig, ikaToken);

	const result = await executeTestTransaction(suiClient, suiTransaction, testName);

	const presignEvent = result.events?.find((event) => event.type.includes('PresignRequestEvent'));
	expect(presignEvent).toBeDefined();

	const parsedPresignEvent = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.PresignRequestEvent,
	).fromBase64(presignEvent?.bcs as string);

	const presign = await retryUntil(
		() =>
			ikaClient.getPresignInParticularState(parsedPresignEvent.event_data.presign_id, 'Completed'),
		(presign) => presign !== null,
		30,
		2000,
	);

	expect(presign).toBeDefined();
	expect(presign.state.$kind).toBe('Completed');

	return presign;
}

/**
 * Test imported key DWallet creation and signing with verification
 */
async function testImportedKeyScenario(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hashScheme: Hash,
	testNameSuffix: string,
) {
	const testName = `imported-key-${testNameSuffix}`;
	const suiClient = createTestSuiClient();

	const { ikaClient, userShareEncryptionKeys, signerAddress, privateKey, originalPublicKey } =
		await setupImportedKeyTest(testName, curve);

	// Prepare imported key DWallet verification
	const sessionIdentifier = createRandomSessionIdentifier();
	const importDWalletVerificationInput = await prepareImportedKeyDWalletVerification(
		ikaClient,
		curve,
		sessionIdentifier,
		signerAddress,
		userShareEncryptionKeys,
		privateKey,
	);

	expect(importDWalletVerificationInput).toBeDefined();
	expect(importDWalletVerificationInput.userPublicOutput).toBeDefined();
	expect(importDWalletVerificationInput.userMessage).toBeDefined();
	expect(importDWalletVerificationInput.encryptedUserShareAndProof).toBeDefined();

	// Request imported key DWallet verification
	const suiTransaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(
		ikaClient,
		suiTransaction,
		userShareEncryptionKeys,
	);

	await ikaTransaction.registerEncryptionKey({ curve });

	const ikaToken = createEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig);

	const registeredSessionIdentifier = ikaTransaction.registerSessionIdentifier(sessionIdentifier);

	const importedKeyDWalletCap = await ikaTransaction.requestImportedKeyDWalletVerification({
		importDWalletVerificationRequestInput: importDWalletVerificationInput,
		curve,
		signerPublicKey: userShareEncryptionKeys.getSigningPublicKeyBytes(),
		sessionIdentifier: registeredSessionIdentifier,
		ikaCoin: ikaToken,
		suiCoin: suiTransaction.gas,
	});

	suiTransaction.transferObjects([importedKeyDWalletCap], signerAddress);
	destroyEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig, ikaToken);

	const result = await executeTestTransaction(suiClient, suiTransaction, testName);

	// Find the DWallet verification event
	const verificationEvent = result.events?.find((event) =>
		event.type.includes('DWalletImportedKeyVerificationRequestEvent'),
	);
	expect(verificationEvent).toBeDefined();

	const parsedVerificationEvent = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletImportedKeyVerificationRequestEvent,
	).fromBase64(verificationEvent?.bcs as string);

	expect(parsedVerificationEvent).toBeDefined();

	const dWalletID = parsedVerificationEvent.event_data.dwallet_id;
	expect(dWalletID).toBeDefined();

	// Wait for DWallet to be verified and active
	const importedKeyDWallet = (await retryUntil(
		() => ikaClient.getDWalletInParticularState(dWalletID, 'Active'),
		(wallet) => wallet !== null,
		30,
		1000,
	)) as ImportedKeyDWallet;

	expect(importedKeyDWallet).toBeDefined();
	expect(importedKeyDWallet.state.$kind).toBe('Active');
	expect(importedKeyDWallet.is_imported_key_dwallet).toBe(true);

	// Get the encrypted user secret key share
	const encryptedUserSecretKeyShareId =
		parsedVerificationEvent.event_data.encrypted_user_secret_key_share_id;
	expect(encryptedUserSecretKeyShareId).toBeDefined();

	const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		encryptedUserSecretKeyShareId as string,
	);
	expect(encryptedUserSecretKeyShare).toBeDefined();

	// Request presign
	const presign = await requestPresignForImportedKey(
		ikaClient,
		userShareEncryptionKeys,
		importedKeyDWallet,
		signatureAlgorithm,
		signerAddress,
		testName,
	);

	// Sign a message
	const message = createTestMessage(testName);

	const signTransaction = new Transaction();
	const signIkaTransaction = createTestIkaTransaction(
		ikaClient,
		signTransaction,
		userShareEncryptionKeys,
	);

	const importedKeyMessageApproval = signIkaTransaction.approveImportedKeyMessage({
		dWalletCap: importedKeyDWallet.dwallet_cap_id,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const verifiedPresignCap = signIkaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(signTransaction, ikaClient.ikaConfig);

	await signIkaTransaction.requestSignWithImportedKey({
		dWallet: importedKeyDWallet,
		importedKeyMessageApproval,
		verifiedPresignCap,
		hashScheme,
		presign,
		encryptedUserSecretKeyShare,
		message,
		signatureScheme: signatureAlgorithm,
		ikaCoin: emptyIKACoin,
		suiCoin: signTransaction.gas,
	});

	destroyEmptyTestIkaToken(signTransaction, ikaClient.ikaConfig, emptyIKACoin);

	// Execute the signing transaction
	const signResult = await executeTestTransaction(suiClient, signTransaction, testName);

	const signEvent = signResult.events?.find((event) => event.type.includes('SignRequestEvent'));
	expect(signEvent).toBeDefined();

	const signEventData = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.SignRequestEvent,
	).fromBase64(signEvent?.bcs as string);

	expect(signEventData).toBeDefined();

	// Wait for signature to complete
	const sign = await ikaClient.getSignInParticularState(
		signEventData.event_data.sign_id,
		signatureAlgorithm,
		'Completed',
		{ timeout: 60000, interval: 1000 },
	);

	expect(sign).toBeDefined();
	expect(sign.state.$kind).toBe('Completed');
	expect(sign.state.Completed?.signature).toBeDefined();

	const signature = Uint8Array.from(sign.state.Completed?.signature ?? []);

	// Get the public key from DWallet output
	const dWalletPublicKey = await publicKeyFromDWalletOutput(
		curve,
		Uint8Array.from(importedKeyDWallet.state.Active?.public_output ?? []),
	);

	// Get the public key from centralized DKG output (user public output)
	const centralizedPublicKey = await publicKeyFromCentralizedDKGOutput(
		curve,
		importDWalletVerificationInput.userPublicOutput,
	);

	// Verify signature only for algorithms where we have client-side verification
	if (hashScheme !== Hash.Merlin) {
		const expectedHash = computeHash(message, hashScheme);

		// Verify with original public key (from private key)
		if (curve !== Curve.RISTRETTO) {
			const verifiedWithOriginal = verifySignatureWithPublicKey(
				signature,
				expectedHash,
				originalPublicKey,
				signatureAlgorithm,
				message,
			);
			expect(verifiedWithOriginal).toBe(true);
		}

		// Verify with DWallet public key
		const verifiedWithDWallet = verifySignatureWithPublicKey(
			signature,
			expectedHash,
			dWalletPublicKey,
			signatureAlgorithm,
			message,
		);
		expect(verifiedWithDWallet).toBe(true);

		// Verify with centralized public key
		const verifiedWithCentralized = verifySignatureWithPublicKey(
			signature,
			expectedHash,
			centralizedPublicKey,
			signatureAlgorithm,
			message,
		);
		expect(verifiedWithCentralized).toBe(true);

		// Verify that DWallet public key matches centralized public key
		expect(dWalletPublicKey).toEqual(centralizedPublicKey);

		// For non-Ristretto curves, verify that DWallet public key matches original
		if (curve !== Curve.RISTRETTO) {
			expect(dWalletPublicKey).toEqual(originalPublicKey);
		}
	}
}

describe('Imported Key DWallet Creation and Signing', () => {
	describe('ECDSASecp256k1 on SECP256K1', () => {
		it('should create imported key DWallet and sign with KECCAK256', async () => {
			await testImportedKeyScenario(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.KECCAK256,
				'ecdsa-secp256k1-keccak256',
			);
		});

		it('should create imported key DWallet and sign with SHA256', async () => {
			await testImportedKeyScenario(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.SHA256,
				'ecdsa-secp256k1-sha256',
			);
		});
	});

	describe('Taproot on SECP256K1', () => {
		it('should create imported key DWallet and sign with SHA256', async () => {
			await testImportedKeyScenario(
				Curve.SECP256K1,
				SignatureAlgorithm.Taproot,
				Hash.SHA256,
				'taproot-sha256',
			);
		});
	});

	describe('ECDSASecp256r1 on SECP256R1', () => {
		it('should create imported key DWallet and sign with SHA256', async () => {
			await testImportedKeyScenario(
				Curve.SECP256R1,
				SignatureAlgorithm.ECDSASecp256r1,
				Hash.SHA256,
				'ecdsa-secp256r1-sha256',
			);
		});
	});

	describe('EdDSA on ED25519', () => {
		it('should create imported key DWallet and sign with SHA512', async () => {
			await testImportedKeyScenario(
				Curve.ED25519,
				SignatureAlgorithm.EdDSA,
				Hash.SHA512,
				'eddsa-sha512',
			);
		});
	});

	describe('SchnorrkelSubstrate on RISTRETTO', () => {
		it('should create imported key DWallet and sign with Merlin', async () => {
			await testImportedKeyScenario(
				Curve.RISTRETTO,
				SignatureAlgorithm.SchnorrkelSubstrate,
				Hash.Merlin,
				'schnorrkel-merlin',
			);
		});
	});
});
