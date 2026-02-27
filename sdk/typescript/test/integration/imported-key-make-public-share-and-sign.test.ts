import { Transaction } from '@mysten/sui/transactions';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { describe, expect, it } from 'vitest';

import {
	CoordinatorInnerModule,
	createRandomSessionIdentifier,
	Curve,
	Hash,
	IkaClient,
	prepareImportedKeyDWalletVerification,
	Presign,
	publicKeyFromDWalletOutput,
	SessionsManagerModule,
	SignatureAlgorithm,
} from '../../src';
import { fromNumberToCurve } from '../../src/client/hash-signature-validation';
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
			return Uint8Array.from(
				Buffer.from('20255a048b64a9930517e91a2ee6b3aa6ea78131a4ad88f20cb3d351f28d6fe653', 'hex'),
			);
		case Curve.SECP256R1:
			return Uint8Array.from(
				Buffer.from('20c53afc96882df03726eba161dcddfc4a44c08dea525700692b99db108125ed5f', 'hex'),
			);
		case Curve.ED25519:
			return Uint8Array.from(
				Buffer.from('7aca0549f93cc4a2052a23f10fc8577d1aba9058766eeebdaa0a7f39bbe91606', 'hex'),
			);
		case Curve.RISTRETTO:
			return Uint8Array.from(
				Buffer.from('1ac94bd6e52bc134b6d482f6443d3c61bd987366dffc2c717bcb35dc62e5650b', 'hex'),
			);
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
function verifySignature(
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
			return true; // Skip client-side verification for Schnorrkel
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
}> {
	const suiClient = createTestSuiClient();
	const ikaClient = createTestIkaClient(suiClient);
	await ikaClient.initialize();

	const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName, curve);
	await requestTestFaucetFunds(signerAddress);

	const privateKey = generatePrivateKey(curve);

	return {
		ikaClient,
		userShareEncryptionKeys,
		signerAddress,
		privateKey,
	};
}

/**
 * Create imported key DWallet
 */
async function createImportedKeyDWallet(
	ikaClient: IkaClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	signerAddress: string,
	privateKey: Uint8Array,
	curve: Curve,
	testName: string,
): Promise<{
	importedKeyDWallet: ImportedKeyDWallet;
	encryptedUserSecretKeyShareId: string;
	userPublicOutput: Uint8Array;
}> {
	const suiClient = createTestSuiClient();

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

	const verificationEvent = result.events?.find((event) =>
		event.type.includes('DWalletImportedKeyVerificationRequestEvent'),
	);
	expect(verificationEvent).toBeDefined();

	const parsedVerificationEvent = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletImportedKeyVerificationRequestEvent,
	).fromBase64(verificationEvent?.bcs as string);

	const dWalletID = parsedVerificationEvent.event_data.dwallet_id;
	expect(dWalletID).toBeDefined();

	const encryptedUserSecretKeyShareId =
		parsedVerificationEvent.event_data.encrypted_user_secret_key_share_id;
	expect(encryptedUserSecretKeyShareId).toBeDefined();

	// Wait for DWallet to be verified and active
	const importedKeyDWallet = (await retryUntil(
		() => ikaClient.getDWalletInParticularState(dWalletID, 'AwaitingKeyHolderSignature'),
		(wallet) => wallet !== null,
		30,
		1000,
	)) as ImportedKeyDWallet;

	expect(importedKeyDWallet).toBeDefined();
	expect(importedKeyDWallet.state.$kind).toBe('AwaitingKeyHolderSignature');
	expect(importedKeyDWallet.is_imported_key_dwallet).toBe(true);

	return {
		importedKeyDWallet,
		encryptedUserSecretKeyShareId: encryptedUserSecretKeyShareId as string,
		userPublicOutput: importDWalletVerificationInput.userPublicOutput,
	};
}

/**
 * Accept encrypted user share and activate imported key DWallet
 */
async function acceptAndActivateImportedKeyDWallet(
	ikaClient: IkaClient,
	importedKeyDWallet: ImportedKeyDWallet,
	encryptedUserSecretKeyShareId: string,
	userPublicOutput: Uint8Array,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	testName: string,
): Promise<ImportedKeyDWallet> {
	const suiClient = createTestSuiClient();

	const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		encryptedUserSecretKeyShareId,
	);
	expect(encryptedUserSecretKeyShare).toBeDefined();

	// Accept encrypted user share
	const acceptShareTransaction = new Transaction();
	const acceptShareIkaTransaction = createTestIkaTransaction(
		ikaClient,
		acceptShareTransaction,
		userShareEncryptionKeys,
	);

	await acceptShareIkaTransaction.acceptEncryptedUserShare({
		dWallet: importedKeyDWallet,
		encryptedUserSecretKeyShareId: encryptedUserSecretKeyShare.id.id,
		userPublicOutput: userPublicOutput,
	});

	await executeTestTransaction(suiClient, acceptShareTransaction, testName);

	// Wait for wallet to become Active
	const activeDWallet = (await retryUntil(
		() => ikaClient.getDWalletInParticularState(importedKeyDWallet.id.id, 'Active'),
		(wallet) => wallet !== null,
		30,
		2000,
	)) as ImportedKeyDWallet;

	expect(activeDWallet).toBeDefined();
	expect(activeDWallet.state.$kind).toBe('Active');

	return activeDWallet;
}

/**
 * Make imported key DWallet user share public
 */
async function makeImportedKeyDWalletPublic(
	ikaClient: IkaClient,
	activeDWallet: ImportedKeyDWallet,
	encryptedUserSecretKeyShareId: string,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	testName: string,
): Promise<ImportedKeyDWallet> {
	const suiClient = createTestSuiClient();

	// Get the encrypted user secret key share
	const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		encryptedUserSecretKeyShareId,
	);
	expect(encryptedUserSecretKeyShare).toBeDefined();

	// Decrypt the user share
	const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(activeDWallet);
	const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
		activeDWallet,
		encryptedUserSecretKeyShare,
		protocolPublicParameters,
	);

	// Create transaction to make user share public
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.makeDWalletUserSecretKeySharesPublic({
		dWallet: activeDWallet,
		secretShare,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);

	// Wait for DWallet to have public shares
	const publicDWallet = await retryUntil(
		() => ikaClient.getDWalletInParticularState(activeDWallet.id.id, 'Active'),
		(wallet) => wallet !== null && wallet.public_user_secret_key_share !== null,
		30,
		2000,
	);

	expect(publicDWallet).toBeDefined();
	expect(publicDWallet.public_user_secret_key_share).toBeDefined();

	return publicDWallet as ImportedKeyDWallet;
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

	let unverifiedPresignCap;

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
			curve: fromNumberToCurve(importedKeyDWallet.curve),
			dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
		});
	} else {
		unverifiedPresignCap = ikaTransaction.requestPresign({
			signatureAlgorithm,
			ikaCoin: ikaToken,
			suiCoin: suiTransaction.gas,
			dWallet: importedKeyDWallet,
		});
	}

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
 * Sign with public user share and verify
 */
async function signWithPublicShareAndVerify(
	ikaClient: IkaClient,
	activeDWallet: ImportedKeyDWallet,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	presign: Presign,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	curve: Curve,
	testName: string,
): Promise<void> {
	const suiClient = createTestSuiClient();

	// Verify that DWallet has public shares
	expect(activeDWallet.public_user_secret_key_share).toBeDefined();

	// Create a transaction to sign the message
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const importedKeyMessageApproval = ikaTransaction.approveImportedKeyMessage({
		dWalletCap: activeDWallet.dwallet_cap_id,
		curve: curve,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	// Sign without providing encrypted share - should use public shares automatically
	await ikaTransaction.requestSignWithImportedKey({
		dWallet: activeDWallet,
		importedKeyMessageApproval,
		verifiedPresignCap,
		hashScheme,
		presign,
		// Not providing encryptedUserSecretKeyShare or secretShare - should use public shares
		message,
		signatureScheme: signatureAlgorithm,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	// Execute the signing transaction
	const result = await executeTestTransaction(suiClient, transaction, testName);

	const signEvent = result.events?.find((event) => event.type.includes('SignRequestEvent'));
	expect(signEvent).toBeDefined();

	const signEventData = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.SignRequestEvent,
	).fromBase64(signEvent?.bcs as string);

	expect(signEventData).toBeDefined();

	const sign = await ikaClient.getSignInParticularState(
		signEventData.event_data.sign_id,
		curve,
		signatureAlgorithm,
		'Completed',
		{ timeout: 60000, interval: 1000 },
	);

	const dWallet = await ikaClient.getDWalletInParticularState(
		signEventData.event_data.dwallet_id,
		'Active',
	);

	expect(sign).toBeDefined();
	expect(sign.state.$kind).toBe('Completed');
	expect(sign.state.Completed?.signature).toBeDefined();

	const signature = Uint8Array.from(sign.state.Completed?.signature ?? []);

	const pkOutput = await publicKeyFromDWalletOutput(
		curve,
		Uint8Array.from(dWallet.state.Active?.public_output ?? []),
	);

	// Verify signature only for algorithms where we have client-side verification
	if (hashScheme !== Hash.Merlin) {
		const expectedHash = computeHash(message, hashScheme);

		const verified = verifySignature(
			signature,
			expectedHash,
			pkOutput,
			signatureAlgorithm,
			message,
		);

		expect(verified).toBe(true);
	}
}

/**
 * Test complete flow: create imported key wallet, make public, and sign
 */
async function testMakeImportedKeyPublicAndSign(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
	testNameSuffix: string,
) {
	const testName = `imported-key-make-public-${testNameSuffix}`;

	// Setup test environment
	const { ikaClient, userShareEncryptionKeys, signerAddress, privateKey } =
		await setupImportedKeyTest(testName, curve);

	// Create imported key DWallet
	const { importedKeyDWallet, encryptedUserSecretKeyShareId, userPublicOutput } =
		await createImportedKeyDWallet(
			ikaClient,
			userShareEncryptionKeys,
			signerAddress,
			privateKey,
			curve,
			testName,
		);

	// Accept and activate
	const activeDWallet = await acceptAndActivateImportedKeyDWallet(
		ikaClient,
		importedKeyDWallet,
		encryptedUserSecretKeyShareId,
		userPublicOutput,
		userShareEncryptionKeys,
		testName,
	);

	// Make imported key DWallet user share public
	const publicDWallet = await makeImportedKeyDWalletPublic(
		ikaClient,
		activeDWallet,
		encryptedUserSecretKeyShareId,
		userShareEncryptionKeys,
		testName,
	);

	// Request presign
	const presign = await requestPresignForImportedKey(
		ikaClient,
		userShareEncryptionKeys,
		publicDWallet,
		signatureAlgorithm,
		signerAddress,
		testName,
	);

	// Sign with public share and verify
	const message = createTestMessage(testName);

	await signWithPublicShareAndVerify(
		ikaClient,
		publicDWallet,
		userShareEncryptionKeys,
		presign,
		message,
		hash,
		signatureAlgorithm,
		curve,
		testName,
	);
}

describe('Make Imported Key DWallet User Share Public and Sign', () => {
	describe('ECDSASecp256k1 on SECP256K1', () => {
		it('should create imported key wallet, make share public, and sign with KECCAK256', async () => {
			await testMakeImportedKeyPublicAndSign(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.KECCAK256,
				'ecdsa-secp256k1-keccak256',
			);
		});

		it('should create imported key wallet, make share public, and sign with SHA256', async () => {
			await testMakeImportedKeyPublicAndSign(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.SHA256,
				'ecdsa-secp256k1-sha256',
			);
		});

		it('should create imported key wallet, make share public, and sign with DoubleSHA256', async () => {
			await testMakeImportedKeyPublicAndSign(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.DoubleSHA256,
				'ecdsa-secp256k1-double-sha256',
			);
		});
	});

	describe('Taproot on SECP256K1', () => {
		it('should create imported key wallet, make share public, and sign with SHA256', async () => {
			await testMakeImportedKeyPublicAndSign(
				Curve.SECP256K1,
				SignatureAlgorithm.Taproot,
				Hash.SHA256,
				'taproot-sha256',
			);
		});
	});

	describe('ECDSASecp256r1 on SECP256R1', () => {
		it('should create imported key wallet, make share public, and sign with SHA256', async () => {
			await testMakeImportedKeyPublicAndSign(
				Curve.SECP256R1,
				SignatureAlgorithm.ECDSASecp256r1,
				Hash.SHA256,
				'ecdsa-secp256r1-sha256',
			);
		});
	});

	describe('EdDSA on ED25519', () => {
		it('should create imported key wallet, make share public, and sign with SHA512', async () => {
			await testMakeImportedKeyPublicAndSign(
				Curve.ED25519,
				SignatureAlgorithm.EdDSA,
				Hash.SHA512,
				'eddsa-sha512',
			);
		});
	});

	describe('SchnorrkelSubstrate on RISTRETTO', () => {
		it('should create imported key wallet, make share public, and sign with Merlin', async () => {
			await testMakeImportedKeyPublicAndSign(
				Curve.RISTRETTO,
				SignatureAlgorithm.SchnorrkelSubstrate,
				Hash.Merlin,
				'schnorrkel-merlin',
			);
		});
	});
});
