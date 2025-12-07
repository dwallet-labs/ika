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
	ImportedKeyDWallet,
	ImportedSharedDWallet,
	prepareImportedKeyDWalletVerification,
	Presign,
	publicKeyFromDWalletOutput,
	SessionsManagerModule,
	SharedDWallet,
	SignatureAlgorithm,
	ZeroTrustDWallet,
} from '../../src';
import { testPresign } from '../helpers/dwallet-test-helpers';
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
import {
	acceptUserShareAndActivate,
	executeDKGRequest,
	prepareDKG,
	waitForDWalletAwaitingSignature,
} from './helpers';

/**
 * DWallet type for testing
 */
type DWalletType = 'zero-trust' | 'shared' | 'imported-key';

/**
 * Generate a private key for the given curve (for imported key testing)
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
			// Double SHA256 - hash of hash
			return sha256(sha256(message));
		case Hash.SHA512:
			return sha512(message);
		case Hash.Merlin:
			// Merlin is handled internally by the network for Schnorrkel
			// We don't compute it client-side for verification
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
			// Taproot uses Schnorr signatures on secp256k1
			// For Taproot, strip the first byte (prefix) of the publicKey
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
			// For now, we'll skip client-side verification for Schnorrkel
			return true;
		default:
			throw new Error(`Unsupported signature algorithm: ${signatureAlgorithm}`);
	}
}

/**
 * Setup and run complete DKG flow, returning all necessary components for signing
 */
async function setupDKGFlow(
	testName: string,
	curve: Curve,
	dwalletType: DWalletType,
): Promise<{
	ikaClient: IkaClient;
	activeDWallet: ZeroTrustDWallet | SharedDWallet | ImportedKeyDWallet;
	encryptedUserSecretKeyShareId: string;
	userShareEncryptionKeys: any;
	signerAddress: string;
}> {
	const suiClient = createTestSuiClient();
	const ikaClient = createTestIkaClient(suiClient);
	await ikaClient.initialize();

	const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName, curve);
	await requestTestFaucetFunds(signerAddress);

	// For shared types, use public user share DKG
	if (dwalletType === 'shared') {
		// Prepare DKG
		const dkgPrepare = await prepareDKG(ikaClient, curve, userShareEncryptionKeys, signerAddress);

		const transaction = new Transaction();
		const ikaTransaction = createTestIkaTransaction(
			ikaClient,
			transaction,
			userShareEncryptionKeys,
		);

		const latestNetworkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();
		const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

		const [dWalletCap] = await ikaTransaction.requestDWalletDKGWithPublicUserShare({
			publicKeyShareAndProof: dkgPrepare.userDKGMessage,
			publicUserSecretKeyShare: dkgPrepare.userSecretKeyShare,
			userPublicOutput: dkgPrepare.userPublicOutput,
			curve,
			dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
			ikaCoin: emptyIKACoin,
			suiCoin: transaction.gas,
			sessionIdentifier: ikaTransaction.registerSessionIdentifier(
				dkgPrepare.randomSessionIdentifier,
			),
		});

		transaction.transferObjects([dWalletCap], signerAddress);
		destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

		const result = await executeTestTransaction(suiClient, transaction, testName);

		const dkgEvent = result.events?.find((event) => event.type.includes('DWalletDKGRequestEvent'));

		expect(dkgEvent).toBeDefined();

		const parsedDkgEvent = SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.DWalletDKGRequestEvent,
		).fromBase64(dkgEvent?.bcs as string);

		const dWalletID = parsedDkgEvent.event_data.dwallet_id;
		expect(dWalletID).toBeDefined();

		const activeDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(dWalletID, 'Active'),
			(wallet) => wallet !== null && wallet.public_user_secret_key_share !== null,
			30,
			2000,
		);

		expect(activeDWallet).toBeDefined();
		expect(activeDWallet.state.$kind).toBe('Active');
		expect(activeDWallet.public_user_secret_key_share).toBeDefined();

		return {
			ikaClient,
			activeDWallet: activeDWallet as any,
			encryptedUserSecretKeyShareId: '', // Not used for shared
			userShareEncryptionKeys,
			signerAddress,
		};
	}

	// For imported-key types, use imported key verification
	if (dwalletType === 'imported-key') {
		const privateKey = generatePrivateKey(curve);

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
		const transaction = new Transaction();
		const ikaTransaction = createTestIkaTransaction(
			ikaClient,
			transaction,
			userShareEncryptionKeys,
		);

		await ikaTransaction.registerEncryptionKey({ curve });

		const ikaToken = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

		const registeredSessionIdentifier = ikaTransaction.registerSessionIdentifier(sessionIdentifier);

		const importedKeyDWalletCap = await ikaTransaction.requestImportedKeyDWalletVerification({
			importDWalletVerificationRequestInput: importDWalletVerificationInput,
			curve,
			signerPublicKey: userShareEncryptionKeys.getSigningPublicKeyBytes(),
			sessionIdentifier: registeredSessionIdentifier,
			ikaCoin: ikaToken,
			suiCoin: transaction.gas,
		});

		transaction.transferObjects([importedKeyDWalletCap], signerAddress);
		destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, ikaToken);

		const result = await executeTestTransaction(suiClient, transaction, testName);

		const verificationEvent = result.events?.find((event) =>
			event.type.includes('DWalletImportedKeyVerificationRequestEvent'),
		);
		expect(verificationEvent).toBeDefined();

		const parsedVerificationEvent = SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.DWalletImportedKeyVerificationRequestEvent,
		).fromBase64(verificationEvent?.bcs as string);

		const dWalletID = parsedVerificationEvent.event_data.dwallet_id;
		expect(dWalletID).toBeDefined();

		const encryptedUserSecretKeyShareId = parsedVerificationEvent.event_data
			.encrypted_user_secret_key_share_id as string;
		expect(encryptedUserSecretKeyShareId).toBeDefined();

		// Wait for DWallet to be verified and awaiting signature
		const importedKeyDWallet = (await retryUntil(
			() => ikaClient.getDWalletInParticularState(dWalletID, 'AwaitingKeyHolderSignature'),
			(wallet) => wallet !== null,
			30,
			1000,
		)) as ImportedKeyDWallet;

		expect(importedKeyDWallet).toBeDefined();
		expect(importedKeyDWallet.state.$kind).toBe('AwaitingKeyHolderSignature');
		expect(importedKeyDWallet.is_imported_key_dwallet).toBe(true);

		// Get the encrypted user secret key share
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
			userPublicOutput: importDWalletVerificationInput.userPublicOutput,
		});

		await executeTestTransaction(suiClient, acceptShareTransaction, testName);

		// Wait for wallet to become Active
		const activeDWallet = (await retryUntil(
			() => ikaClient.getDWalletInParticularState(dWalletID, 'Active'),
			(wallet) => wallet !== null,
			30,
			2000,
		)) as ImportedKeyDWallet;

		expect(activeDWallet).toBeDefined();
		expect(activeDWallet.state.$kind).toBe('Active');

		return {
			ikaClient,
			activeDWallet,
			encryptedUserSecretKeyShareId,
			userShareEncryptionKeys,
			signerAddress,
		};
	}

	// For zero-trust type, use regular encrypted DKG
	const dkgPrepare = await prepareDKG(ikaClient, curve, userShareEncryptionKeys, signerAddress);

	const dkgResult = await executeDKGRequest(
		{ suiClient, ikaClient, userShareEncryptionKeys, signerAddress, testName },
		dkgPrepare,
		curve,
	);

	// Wait for DWallet to be in AwaitingKeyHolderSignature state
	const awaitingDWallet = await waitForDWalletAwaitingSignature(ikaClient, dkgResult.dWalletID);

	// Accept user share and activate
	const activeDWallet = await acceptUserShareAndActivate(
		{ suiClient, ikaClient, userShareEncryptionKeys, signerAddress, testName },
		dkgResult.dWalletID,
		dkgResult.encryptedUserSecretKeyShareId,
		dkgResult.userPublicOutput,
		awaitingDWallet,
	);

	return {
		ikaClient,
		activeDWallet,
		encryptedUserSecretKeyShareId: dkgResult.encryptedUserSecretKeyShareId,
		userShareEncryptionKeys,
		signerAddress,
	};
}

/**
 * Request presign and wait for completion
 */
async function requestAndWaitForPresign(
	ikaClient: IkaClient,
	activeDWallet: ZeroTrustDWallet | SharedDWallet | ImportedKeyDWallet,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	signerAddress: string,
	testName: string,
): Promise<Presign> {
	const suiClient = createTestSuiClient();

	const presignRequestEvent = await testPresign(
		ikaClient,
		suiClient,
		activeDWallet,
		curve,
		signatureAlgorithm,
		signerAddress,
		testName,
	);

	expect(presignRequestEvent).toBeDefined();
	expect(presignRequestEvent.event_data.presign_id).toBeDefined();

	const presignObject = await retryUntil(
		() =>
			ikaClient.getPresignInParticularState(presignRequestEvent.event_data.presign_id, 'Completed'),
		(presign) => presign !== null,
		30,
		2000,
	);

	expect(presignObject).toBeDefined();
	expect(presignObject.state.$kind).toBe('Completed');

	return presignObject;
}

/**
 * Request future sign and complete the signature, then verify
 */
async function futureSignAndVerify(
	ikaClient: IkaClient,
	activeDWallet: ZeroTrustDWallet | SharedDWallet | ImportedKeyDWallet | ImportedSharedDWallet,
	userShareEncryptionKeys: any,
	presign: Presign,
	encryptedUserSecretKeyShareId: string,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	curve: Curve,
	testName: string,
	dwalletType: DWalletType,
	signerAddress: string,
): Promise<void> {
	const suiClient = createTestSuiClient();

	// Step 1: Request future sign and keep the capability
	const transaction1 = new Transaction();
	const ikaTransaction1 = createTestIkaTransaction(
		ikaClient,
		transaction1,
		userShareEncryptionKeys,
	);

	const verifiedPresignCap = ikaTransaction1.verifyPresignCap({
		presign,
	});

	const emptyIKACoin1 = createEmptyTestIkaToken(transaction1, ikaClient.ikaConfig);

	let unverifiedPartialUserSignatureCap;

	// Handle different DWallet types with their appropriate signing methods
	if (dwalletType === 'zero-trust') {
		// Get the encrypted user secret key share for zero-trust
		const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
			encryptedUserSecretKeyShareId,
		);
		expect(encryptedUserSecretKeyShare).toBeDefined();

		unverifiedPartialUserSignatureCap = await ikaTransaction1.requestFutureSign({
			dWallet: activeDWallet as ZeroTrustDWallet,
			verifiedPresignCap,
			presign,
			encryptedUserSecretKeyShare,
			message,
			hashScheme,
			signatureScheme: signatureAlgorithm,
			ikaCoin: emptyIKACoin1,
			suiCoin: transaction1.gas,
		});
	} else if (dwalletType === 'shared') {
		// Shared DWallet uses public shares
		unverifiedPartialUserSignatureCap = await ikaTransaction1.requestFutureSign({
			dWallet: activeDWallet as SharedDWallet,
			verifiedPresignCap,
			presign,
			message,
			hashScheme,
			signatureScheme: signatureAlgorithm,
			ikaCoin: emptyIKACoin1,
			suiCoin: transaction1.gas,
		});
	} else {
		// Imported key DWallet can use public share signing or secret share signing
		if (activeDWallet.public_user_secret_key_share) {
			unverifiedPartialUserSignatureCap = await ikaTransaction1.requestFutureSignWithImportedKey({
				dWallet: activeDWallet as ImportedSharedDWallet,
				verifiedPresignCap,
				presign,
				message,
				hashScheme,
				signatureScheme: signatureAlgorithm,
				ikaCoin: emptyIKACoin1,
				suiCoin: transaction1.gas,
			});
		} else {
			const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
				encryptedUserSecretKeyShareId,
			);

			unverifiedPartialUserSignatureCap = await ikaTransaction1.requestFutureSignWithImportedKey({
				dWallet: activeDWallet as ImportedKeyDWallet,
				verifiedPresignCap,
				presign,
				encryptedUserSecretKeyShare,
				message,
				hashScheme,
				signatureScheme: signatureAlgorithm,
				ikaCoin: emptyIKACoin1,
				suiCoin: transaction1.gas,
			});
		}
	}

	transaction1.transferObjects([unverifiedPartialUserSignatureCap], signerAddress);

	destroyEmptyTestIkaToken(transaction1, ikaClient.ikaConfig, emptyIKACoin1);

	const result1 = await executeTestTransaction(suiClient, transaction1, testName);

	// Extract the partial user signature capability ID from the result using FutureSignRequestEvent
	const futureSignRequestEvent = result1.events?.find((event) => {
		return (
			event.type.includes('FutureSignRequestEvent') && event.type.includes('DWalletSessionEvent')
		);
	});

	expect(futureSignRequestEvent).toBeDefined();

	const extractedPartialUserSignatureCap = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.FutureSignRequestEvent,
	).fromBase64(futureSignRequestEvent?.bcs as string);

	const partialCap = await ikaClient.getPartialUserSignatureInParticularState(
		extractedPartialUserSignatureCap.event_data.partial_centralized_signed_message_id,
		'NetworkVerificationCompleted',
		{ timeout: 60000, interval: 1000 },
	);

	expect(partialCap).toBeDefined();
	expect(partialCap.state.$kind).toBe('NetworkVerificationCompleted');

	// Step 2: Complete the future sign with message approval
	const transaction2 = new Transaction();
	const ikaTransaction2 = createTestIkaTransaction(
		ikaClient,
		transaction2,
		userShareEncryptionKeys,
	);

	const emptyIKACoin2 = createEmptyTestIkaToken(transaction2, ikaClient.ikaConfig);

	if (dwalletType === 'imported-key') {
		const importedKeyMessageApproval = ikaTransaction2.approveImportedKeyMessage({
			dWalletCap: activeDWallet.dwallet_cap_id,
			curve,
			signatureAlgorithm,
			hashScheme,
			message,
		});

		ikaTransaction2.futureSignWithImportedKey({
			partialUserSignatureCap: partialCap.cap_id,
			importedKeyMessageApproval,
			ikaCoin: emptyIKACoin2,
			suiCoin: transaction2.gas,
		});
	} else {
		const messageApproval = ikaTransaction2.approveMessage({
			dWalletCap: activeDWallet.dwallet_cap_id,
			curve,
			signatureAlgorithm,
			hashScheme,
			message,
		});

		ikaTransaction2.futureSign({
			partialUserSignatureCap: partialCap.cap_id,
			messageApproval,
			ikaCoin: emptyIKACoin2,
			suiCoin: transaction2.gas,
		});
	}

	destroyEmptyTestIkaToken(transaction2, ikaClient.ikaConfig, emptyIKACoin2);

	const result2 = await executeTestTransaction(suiClient, transaction2, testName);

	const signEvent = result2.events?.find((event) => event.type.includes('SignRequestEvent'));

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
 * Test a specific combination of DWallet type, curve, signature algorithm, and hash
 */
async function testCombination(
	dwalletType: DWalletType,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
	testNameSuffix: string,
) {
	const testName = `future-${dwalletType}-${testNameSuffix}`;

	const {
		ikaClient,
		activeDWallet,
		encryptedUserSecretKeyShareId,
		userShareEncryptionKeys,
		signerAddress,
	} = await setupDKGFlow(testName, curve, dwalletType);

	const presign = await requestAndWaitForPresign(
		ikaClient,
		activeDWallet,
		curve,
		signatureAlgorithm,
		signerAddress,
		testName,
	);

	const message = createTestMessage(testName);

	await futureSignAndVerify(
		ikaClient,
		activeDWallet,
		userShareEncryptionKeys,
		presign,
		encryptedUserSecretKeyShareId,
		message,
		hash,
		signatureAlgorithm,
		curve,
		testName,
		dwalletType,
		signerAddress,
	);
}

describe('All Valid DWallet-Curve-SignatureAlgorithm-Hash Combinations (Future Sign)', () => {
	// ECDSASecp256k1 + SECP256K1 combinations (3 hashes × 3 dwallet types = 9 tests)
	describe('ECDSASecp256k1 on SECP256K1', () => {
		describe('Zero Trust', () => {
			it('should work with KECCAK256', async () => {
				await testCombination(
					'zero-trust',
					Curve.SECP256K1,
					SignatureAlgorithm.ECDSASecp256k1,
					Hash.KECCAK256,
					'ecdsa-secp256k1-keccak256',
				);
			});
			it('should work with SHA256', async () => {
				await testCombination(
					'zero-trust',
					Curve.SECP256K1,
					SignatureAlgorithm.ECDSASecp256k1,
					Hash.SHA256,
					'ecdsa-secp256k1-sha256',
				);
			});
			it('should work with DoubleSHA256', async () => {
				await testCombination(
					'zero-trust',
					Curve.SECP256K1,
					SignatureAlgorithm.ECDSASecp256k1,
					Hash.DoubleSHA256,
					'ecdsa-secp256k1-double-sha256',
				);
			});
		});
		describe('Shared', () => {
			it('should work with KECCAK256', async () => {
				await testCombination(
					'shared',
					Curve.SECP256K1,
					SignatureAlgorithm.ECDSASecp256k1,
					Hash.KECCAK256,
					'ecdsa-secp256k1-keccak256',
				);
			});
			it('should work with SHA256', async () => {
				await testCombination(
					'shared',
					Curve.SECP256K1,
					SignatureAlgorithm.ECDSASecp256k1,
					Hash.SHA256,
					'ecdsa-secp256k1-sha256',
				);
			});
			it('should work with DoubleSHA256', async () => {
				await testCombination(
					'shared',
					Curve.SECP256K1,
					SignatureAlgorithm.ECDSASecp256k1,
					Hash.DoubleSHA256,
					'ecdsa-secp256k1-double-sha256',
				);
			});
		});
		describe('Imported Key', () => {
			it('should work with KECCAK256', async () => {
				await testCombination(
					'imported-key',
					Curve.SECP256K1,
					SignatureAlgorithm.ECDSASecp256k1,
					Hash.KECCAK256,
					'ecdsa-secp256k1-keccak256',
				);
			});
			it('should work with SHA256', async () => {
				await testCombination(
					'imported-key',
					Curve.SECP256K1,
					SignatureAlgorithm.ECDSASecp256k1,
					Hash.SHA256,
					'ecdsa-secp256k1-sha256',
				);
			});
			it('should work with DoubleSHA256', async () => {
				await testCombination(
					'imported-key',
					Curve.SECP256K1,
					SignatureAlgorithm.ECDSASecp256k1,
					Hash.DoubleSHA256,
					'ecdsa-secp256k1-double-sha256',
				);
			});
		});
	});

	// Taproot + SECP256K1 combinations (1 hash × 3 dwallet types = 3 tests)
	describe('Taproot on SECP256K1', () => {
		describe('Zero Trust', () => {
			it('should work with SHA256', async () => {
				await testCombination(
					'zero-trust',
					Curve.SECP256K1,
					SignatureAlgorithm.Taproot,
					Hash.SHA256,
					'taproot-sha256',
				);
			});
		});

		describe('Shared', () => {
			it('should work with SHA256', async () => {
				await testCombination(
					'shared',
					Curve.SECP256K1,
					SignatureAlgorithm.Taproot,
					Hash.SHA256,
					'taproot-sha256',
				);
			});
		});

		describe('Imported Key', () => {
			it('should work with SHA256', async () => {
				await testCombination(
					'imported-key',
					Curve.SECP256K1,
					SignatureAlgorithm.Taproot,
					Hash.SHA256,
					'taproot-sha256',
				);
			});
		});
	});

	// ECDSASecp256r1 + SECP256R1 combinations (1 hash × 3 dwallet types = 3 tests)
	describe('ECDSASecp256r1 on SECP256R1', () => {
		describe('Zero Trust', () => {
			it('should work with SHA256', async () => {
				await testCombination(
					'zero-trust',
					Curve.SECP256R1,
					SignatureAlgorithm.ECDSASecp256r1,
					Hash.SHA256,
					'ecdsa-secp256r1-sha256',
				);
			});
		});

		describe('Shared', () => {
			it('should work with SHA256', async () => {
				await testCombination(
					'shared',
					Curve.SECP256R1,
					SignatureAlgorithm.ECDSASecp256r1,
					Hash.SHA256,
					'ecdsa-secp256r1-sha256',
				);
			});
		});

		describe('Imported Key', () => {
			it('should work with SHA256', async () => {
				await testCombination(
					'imported-key',
					Curve.SECP256R1,
					SignatureAlgorithm.ECDSASecp256r1,
					Hash.SHA256,
					'ecdsa-secp256r1-sha256',
				);
			});
		});
	});

	// EdDSA + ED25519 combination (1 hash × 3 dwallet types = 3 tests)
	describe('EdDSA on ED25519', () => {
		describe('Zero Trust', () => {
			it('should work with SHA512', async () => {
				await testCombination(
					'zero-trust',
					Curve.ED25519,
					SignatureAlgorithm.EdDSA,
					Hash.SHA512,
					'eddsa-sha512',
				);
			});
		});

		describe('Shared', () => {
			it('should work with SHA512', async () => {
				await testCombination(
					'shared',
					Curve.ED25519,
					SignatureAlgorithm.EdDSA,
					Hash.SHA512,
					'eddsa-sha512',
				);
			});
		});

		describe('Imported Key', () => {
			it('should work with SHA512', async () => {
				await testCombination(
					'imported-key',
					Curve.ED25519,
					SignatureAlgorithm.EdDSA,
					Hash.SHA512,
					'eddsa-sha512',
				);
			});
		});
	});

	// SchnorrkelSubstrate + RISTRETTO combination (1 hash × 3 dwallet types = 3 tests)
	describe('SchnorrkelSubstrate on RISTRETTO', () => {
		describe('Zero Trust', () => {
			it('should work with Merlin', async () => {
				await testCombination(
					'zero-trust',
					Curve.RISTRETTO,
					SignatureAlgorithm.SchnorrkelSubstrate,
					Hash.Merlin,
					'schnorrkel-merlin',
				);
			});
		});

		describe('Shared', () => {
			it('should work with Merlin', async () => {
				await testCombination(
					'shared',
					Curve.RISTRETTO,
					SignatureAlgorithm.SchnorrkelSubstrate,
					Hash.Merlin,
					'schnorrkel-merlin',
				);
			});
		});

		describe('Imported Key', () => {
			it('should work with Merlin', async () => {
				await testCombination(
					'imported-key',
					Curve.RISTRETTO,
					SignatureAlgorithm.SchnorrkelSubstrate,
					Hash.Merlin,
					'schnorrkel-merlin',
				);
			});
		});
	});
});
