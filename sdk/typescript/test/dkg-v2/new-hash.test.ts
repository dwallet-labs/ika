import { bcs } from '@mysten/sui/bcs';
import { Transaction } from '@mysten/sui/transactions';
import { verifySignature } from '@mysten/sui/verify';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { describe, expect, it } from 'vitest';

import {
	CoordinatorInnerModule,
	Curve,
	Hash,
	IkaClient,
	Presign,
	publicKeyFromDWalletOutput,
	SessionsManagerModule,
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
		default:
			throw new Error(`Unsupported hash scheme: ${hashScheme}`);
	}
}

/**
 * Setup and run complete DKG flow, returning all necessary components for signing
 */
async function setupDKGFlowForHashTest(
	testName: string,
	curve: Curve,
): Promise<{
	ikaClient: IkaClient;
	activeDWallet: ZeroTrustDWallet;
	encryptedUserSecretKeyShareId: string;
	userShareEncryptionKeys: any;
	signerAddress: string;
}> {
	const suiClient = createTestSuiClient();
	const ikaClient = createTestIkaClient(suiClient);
	await ikaClient.initialize();

	const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName, curve);
	await requestTestFaucetFunds(signerAddress);

	// Prepare DKG
	const dkgPrepare = await prepareDKG(ikaClient, curve, userShareEncryptionKeys, signerAddress);

	// Execute DKG request
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
	activeDWallet: ZeroTrustDWallet,
	signatureAlgorithm: SignatureAlgorithm,
	signerAddress: string,
	testName: string,
): Promise<Presign> {
	const suiClient = createTestSuiClient();

	const presignRequestEvent = await testPresign(
		ikaClient,
		suiClient,
		activeDWallet,
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
 * Sign a message with a specific hash scheme and verify the hash matches what we compute
 */
async function signAndVerifyHash(
	ikaClient: IkaClient,
	activeDWallet: ZeroTrustDWallet,
	userShareEncryptionKeys: any,
	presign: Presign,
	encryptedUserSecretKeyShareId: string,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	testName: string,
): Promise<void> {
	const suiClient = createTestSuiClient();

	// Compute the expected hash locally
	const expectedHash = computeHash(message, hashScheme);

	// Get the encrypted user secret key share
	const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		encryptedUserSecretKeyShareId,
	);

	expect(encryptedUserSecretKeyShare).toBeDefined();

	// Create a transaction to sign the message
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const messageApproval = ikaTransaction.approveMessage({
		dWalletCap: activeDWallet.dwallet_cap_id,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestSign({
		dWallet: activeDWallet,
		messageApproval,
		verifiedPresignCap,
		hashScheme,
		presign,
		encryptedUserSecretKeyShare,
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

	// Verify that our computed hash is correct
	expect(expectedHash).toBeDefined();
	expect(expectedHash.length).toBeGreaterThan(0);

	const sign = await ikaClient.getSignInParticularState(
		signEventData.event_data.sign_id,
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
		activeDWallet.curve as Curve,
		Uint8Array.from(dWallet.state.Active?.public_output ?? []),
	);

	const verified = secp256k1.verify(signature, expectedHash, pkOutput, {
		prehash: false,
	});

	expect(verified).toBe(true);
}

describe('Hash Type Verification', () => {
	it('should compute correct hash for KECCAK256', async () => {
		const testName = 'hash-test-keccak256';
		const curve = Curve.SECP256K1;

		const {
			ikaClient,
			activeDWallet,
			encryptedUserSecretKeyShareId,
			userShareEncryptionKeys,
			signerAddress,
		} = await setupDKGFlowForHashTest(testName, curve);

		const presign = await requestAndWaitForPresign(
			ikaClient,
			activeDWallet,
			SignatureAlgorithm.ECDSASecp256k1,
			signerAddress,
			testName,
		);

		const message = createTestMessage(testName);

		await signAndVerifyHash(
			ikaClient,
			activeDWallet,
			userShareEncryptionKeys,
			presign,
			encryptedUserSecretKeyShareId,
			message,
			Hash.KECCAK256,
			SignatureAlgorithm.ECDSASecp256k1,
			testName,
		);
	});

	it('should compute correct hash for SHA256', async () => {
		const testName = 'hash-test-sha256';
		const curve = Curve.SECP256K1;

		const {
			ikaClient,
			activeDWallet,
			encryptedUserSecretKeyShareId,
			userShareEncryptionKeys,
			signerAddress,
		} = await setupDKGFlowForHashTest(testName, curve);

		const presign = await requestAndWaitForPresign(
			ikaClient,
			activeDWallet,
			SignatureAlgorithm.ECDSASecp256k1,
			signerAddress,
			testName,
		);

		const message = createTestMessage(testName);

		await signAndVerifyHash(
			ikaClient,
			activeDWallet,
			userShareEncryptionKeys,
			presign,
			encryptedUserSecretKeyShareId,
			message,
			Hash.SHA256,
			SignatureAlgorithm.ECDSASecp256k1,
			testName,
		);
	});

	it('should compute correct hash for DoubleSHA256', async () => {
		const testName = 'hash-test-double-sha256';
		const curve = Curve.SECP256K1;

		const {
			ikaClient,
			activeDWallet,
			encryptedUserSecretKeyShareId,
			userShareEncryptionKeys,
			signerAddress,
		} = await setupDKGFlowForHashTest(testName, curve);

		const presign = await requestAndWaitForPresign(
			ikaClient,
			activeDWallet,
			SignatureAlgorithm.ECDSASecp256k1,
			signerAddress,
			testName,
		);

		const message = createTestMessage(testName);

		await signAndVerifyHash(
			ikaClient,
			activeDWallet,
			userShareEncryptionKeys,
			presign,
			encryptedUserSecretKeyShareId,
			message,
			Hash.DoubleSHA256,
			SignatureAlgorithm.ECDSASecp256k1,
			testName,
		);
	});

	it('should compute correct hash for SHA512', async () => {
		const testName = 'hash-test-sha512';
		const curve = Curve.SECP256K1;

		const {
			ikaClient,
			activeDWallet,
			encryptedUserSecretKeyShareId,
			userShareEncryptionKeys,
			signerAddress,
		} = await setupDKGFlowForHashTest(testName, curve);

		const presign = await requestAndWaitForPresign(
			ikaClient,
			activeDWallet,
			SignatureAlgorithm.ECDSASecp256k1,
			signerAddress,
			testName,
		);

		const message = createTestMessage(testName);

		await signAndVerifyHash(
			ikaClient,
			activeDWallet,
			userShareEncryptionKeys,
			presign,
			encryptedUserSecretKeyShareId,
			message,
			Hash.SHA512,
			SignatureAlgorithm.ECDSASecp256k1,
			testName,
		);
	});

	it('should produce different hashes for different hash schemes with same message', async () => {
		const testName = 'hash-comparison-test';
		const message = createTestMessage(testName);

		const keccakHash = computeHash(message, Hash.KECCAK256);
		const sha256Hash = computeHash(message, Hash.SHA256);
		const doubleSha256Hash = computeHash(message, Hash.DoubleSHA256);
		const sha512Hash = computeHash(message, Hash.SHA512);

		// All hashes should be defined and different
		expect(keccakHash).toBeDefined();
		expect(sha256Hash).toBeDefined();
		expect(doubleSha256Hash).toBeDefined();
		expect(sha512Hash).toBeDefined();

		// KECCAK256 vs SHA256 should be different
		expect(Buffer.from(keccakHash).toString('hex')).not.toBe(
			Buffer.from(sha256Hash).toString('hex'),
		);

		// SHA256 vs DoubleSHA256 should be different
		expect(Buffer.from(sha256Hash).toString('hex')).not.toBe(
			Buffer.from(doubleSha256Hash).toString('hex'),
		);

		// SHA256 vs SHA512 should be different lengths
		expect(sha256Hash.length).toBe(32);
		expect(sha512Hash.length).toBe(64);
	});
});
