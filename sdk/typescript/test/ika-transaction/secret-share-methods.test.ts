// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Transaction } from '@mysten/sui/transactions';
import { beforeAll, describe, expect, it } from 'vitest';

import { Hash, SignatureAlgorithm } from '../../src/client/types';
import {
	createCompleteDWallet,
	registerTestEncryptionKey,
	testPresign,
} from '../helpers/dwallet-test-helpers';
import { createIndividualTestSetup, getSharedTestSetup } from '../helpers/shared-test-setup';
import {
	createEmptyTestIkaToken,
	createTestIkaTransaction,
	createTestMessage,
	destroyEmptyTestIkaToken,
	executeTestTransaction,
	generateTestKeypair,
	requestTestFaucetFunds,
	retryUntil,
} from '../helpers/test-utils';

// Setup shared resources before all tests
beforeAll(async () => {
	await getSharedTestSetup();
}, 60000);

/**
 * Creates a complete DWallet setup for secret share testing
 */
async function setupSecretShareTest(testName: string) {
	const { suiClient, ikaClient } = await createIndividualTestSetup(testName);
	const dWalletSetup = await createCompleteDWallet(ikaClient, suiClient, testName);

	return {
		suiClient,
		ikaClient,
		...dWalletSetup,
	};
}

/**
 * Creates and waits for presign completion
 */
async function createPresignForSecretShare(
	ikaClient: any,
	suiClient: any,
	activeDWallet: any,
	signerAddress: string,
	testName: string,
) {
	const presignRequestEvent = await testPresign(
		ikaClient,
		suiClient,
		activeDWallet,
		SignatureAlgorithm.ECDSA,
		signerAddress,
		testName,
	);

	const presignObject = await retryUntil(
		() =>
			ikaClient.getPresignInParticularState(presignRequestEvent.event_data.presign_id, 'Completed'),
		(presign) => presign !== null,
		30,
		2000,
	);

	expect(presignObject).toBeDefined();
	expect((presignObject as any).state.$kind).toBe('Completed');

	return { presignRequestEvent, presignObject };
}

/**
 * Decrypts user share to get secret share
 */
async function getSecretShare(
	userShareEncryptionKeys: any,
	activeDWallet: any,
	encryptedUserSecretKeyShare: any,
	ikaClient: any,
) {
	const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
		activeDWallet,
		encryptedUserSecretKeyShare,
		await ikaClient.getProtocolPublicParameters(activeDWallet),
	);

	expect(secretShare).toBeDefined();
	return secretShare;
}

/**
 * Creates transaction setup for secret share operations
 */
function createSecretShareTransaction(ikaClient: any, userShareEncryptionKeys: any) {
	const tx = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, tx, userShareEncryptionKeys);
	const emptyIKACoin = createEmptyTestIkaToken(tx, ikaClient.ikaConfig);

	return { tx, ikaTransaction, emptyIKACoin };
}

describe('IkaTransaction Secret Share Methods', () => {
	it('should sign using signWithSecretShare method', async () => {
		const testName = 'secret-share-sign-test';

		// Setup test environment using helper
		const {
			suiClient,
			ikaClient,
			dWallet: activeDWallet,
			encryptedUserSecretKeyShare,
			userShareEncryptionKeys,
			signerAddress,
		} = await setupSecretShareTest(testName);

		// Create presign using helper
		const { presignObject } = await createPresignForSecretShare(
			ikaClient,
			suiClient,
			activeDWallet,
			signerAddress,
			testName,
		);

		// Get secret share using helper
		const secretShare = await getSecretShare(
			userShareEncryptionKeys,
			activeDWallet,
			encryptedUserSecretKeyShare,
			ikaClient,
		);

		// Create transaction setup using helper
		const { tx, ikaTransaction, emptyIKACoin } = createSecretShareTransaction(
			ikaClient,
			userShareEncryptionKeys,
		);

		const message = createTestMessage(testName);

		// Validate DWallet state before signing
		expect(activeDWallet.state.Active?.public_output).toBeDefined();
		expect(activeDWallet.state.$kind).toBe('Active');

		const { messageApproval } = ikaTransaction.approveMessage({
			dWalletCap: activeDWallet.dwallet_cap_id,
			signatureAlgorithm: SignatureAlgorithm.ECDSA,
			hashScheme: Hash.KECCAK256,
			message,
		});

		const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
			presign: presignObject as any,
		});

		// Validate setup objects before signing
		expect(messageApproval).toBeDefined();
		expect(verifiedPresignCap).toBeDefined();
		expect(secretShare).toBeInstanceOf(Uint8Array);
		expect(secretShare.length).toBeGreaterThan(0);

		// Use signWithSecretShare method
		await ikaTransaction.sign({
			dWallet: activeDWallet,
			messageApproval,
			hashScheme: Hash.KECCAK256,
			verifiedPresignCap,
			presign: presignObject as any,
			secretShare,
			publicOutput: new Uint8Array(activeDWallet.state.Active?.public_output ?? []),
			message,
			ikaCoin: emptyIKACoin,
			suiCoin: tx.gas,
		});

		destroyEmptyTestIkaToken(tx, ikaClient.ikaConfig, emptyIKACoin);

		const result = await executeTestTransaction(suiClient, tx, testName);

		// Comprehensive transaction validation
		expect(result).toBeDefined();
		expect(result.digest).toBeDefined();
		expect(result.digest).toMatch(/^[a-zA-Z0-9]+$/);
		expect(result.digest.length).toBeGreaterThan(20);

		// Validate secret share signing events
		expect(result.events).toBeDefined();
		expect(result.events!.length).toBeGreaterThan(0);

		const hasSigningEvents = result.events!.some(
			(event) =>
				event.type.includes('Sign') ||
				event.type.includes('Message') ||
				event.type.includes('SecretShare'),
		);
		expect(hasSigningEvents).toBe(true);

		// Verify transaction execution
		expect(result.confirmedLocalExecution).toBe(false);

		// Validate DWallet remains active after secret share signing
		const dWalletAfterSigning = await ikaClient.getDWalletInParticularState(
			activeDWallet.id.id,
			'Active',
		);
		expect(dWalletAfterSigning).toBeDefined();
		expect(dWalletAfterSigning.state.$kind).toBe('Active');
	});

	it('should request fsk uture sign with secret share', async () => {
		const testName = 'secret-share-future-sign-test';
		const { suiClient, ikaClient } = await createIndividualTestSetup(testName);

		// Create a complete dWallet
		const {
			dWallet: activeDWallet,
			encryptedUserSecretKeyShare,
			userShareEncryptionKeys,
			signerAddress,
		} = await createCompleteDWallet(ikaClient, suiClient, testName);

		// Create a presign
		const presignRequestEvent = await testPresign(
			ikaClient,
			suiClient,
			activeDWallet,
			SignatureAlgorithm.ECDSA,
			signerAddress,
			testName,
		);

		const presignObject = await retryUntil(
			() =>
				ikaClient.getPresignInParticularState(
					presignRequestEvent.event_data.presign_id,
					'Completed',
				),
			(presign) => presign !== null,
			30,
			2000,
		);

		// Decrypt the user share to get the secret share
		const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
			activeDWallet,
			encryptedUserSecretKeyShare,
			await ikaClient.getProtocolPublicParameters(activeDWallet),
		);

		// Test requesting future sign with secret share
		const tx = new Transaction();
		const ikaTransaction = createTestIkaTransaction(ikaClient, tx, userShareEncryptionKeys);

		const message = createTestMessage(testName);

		const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
			presign: presignObject,
		});

		const emptyIKACoin = createEmptyTestIkaToken(tx, ikaClient.ikaConfig);

		expect(activeDWallet.state.Active?.public_output).toBeDefined();

		// Use requestFutureSignWithSecretShare instead of regular requestFutureSign
		const { unverifiedPartialUserSignatureCap } =
			await ikaTransaction.requestFutureSignWithSecretShare({
				dWallet: activeDWallet,
				verifiedPresignCap,
				presign: presignObject,
				secretShare,
				publicOutput: new Uint8Array(activeDWallet.state.Active?.public_output ?? []),
				message,
				hashScheme: Hash.KECCAK256,
				ikaCoin: emptyIKACoin,
				suiCoin: tx.gas,
			});

		// Transfer the capability to avoid UnusedValueWithoutDrop error
		tx.transferObjects([unverifiedPartialUserSignatureCap], signerAddress);

		destroyEmptyTestIkaToken(tx, ikaClient.ikaConfig, emptyIKACoin);

		expect(unverifiedPartialUserSignatureCap).toBeDefined();

		const result = await executeTestTransaction(suiClient, tx, testName);

		// Should have future sign request event
		const futureSignEvent = result.events?.find((event) =>
			event.type.includes('FutureSignRequestEvent'),
		);
		expect(futureSignEvent).toBeDefined();
	});

	it('should request future sign and transfer capability with secret share', async () => {
		const testName = 'secret-share-future-sign-transfer-test';
		const { suiClient, ikaClient } = await createIndividualTestSetup(testName);

		// Create a complete dWallet
		const {
			dWallet: activeDWallet,
			encryptedUserSecretKeyShare,
			userShareEncryptionKeys,
			signerAddress,
		} = await createCompleteDWallet(ikaClient, suiClient, testName);

		// Create a presign
		const presignRequestEvent = await testPresign(
			ikaClient,
			suiClient,
			activeDWallet,
			SignatureAlgorithm.ECDSA,
			signerAddress,
			testName,
		);

		const presignObject = await retryUntil(
			() =>
				ikaClient.getPresignInParticularState(
					presignRequestEvent.event_data.presign_id,
					'Completed',
				),
			(presign) => presign !== null,
			30,
			2000,
		);

		// Decrypt the user share to get the secret share
		const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
			activeDWallet,
			encryptedUserSecretKeyShare,
			await ikaClient.getProtocolPublicParameters(activeDWallet),
		);

		// Test requesting future sign and transfer with secret share
		const tx = new Transaction();
		const ikaTransaction = createTestIkaTransaction(ikaClient, tx, userShareEncryptionKeys);

		const message = createTestMessage(testName);

		const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
			presign: presignObject,
		});

		const emptyIKACoin = createEmptyTestIkaToken(tx, ikaClient.ikaConfig);

		expect(activeDWallet.state.Active?.public_output).toBeDefined();

		// Use requestFutureSignAndTransferCapWithSecretShare
		await ikaTransaction.requestFutureSignAndTransferCapWithSecretShare({
			dWallet: activeDWallet,
			verifiedPresignCap,
			presign: presignObject,
			secretShare,
			publicOutput: new Uint8Array(activeDWallet.state.Active?.public_output ?? []),
			message,
			hashScheme: Hash.KECCAK256,
			receiver: signerAddress,
			ikaCoin: emptyIKACoin,
			suiCoin: tx.gas,
		});

		destroyEmptyTestIkaToken(tx, ikaClient.ikaConfig, emptyIKACoin);

		const result = await executeTestTransaction(suiClient, tx, testName);

		// Should have future sign request event
		const futureSignEvent = result.events?.find((event) =>
			event.type.includes('FutureSignRequestEvent'),
		);
		expect(futureSignEvent).toBeDefined();
	});

	it('should transfer user share with secret share', async () => {
		const testName = 'secret-share-transfer-test';
		const { suiClient, ikaClient } = await createIndividualTestSetup(testName);

		// Create a complete dWallet
		const {
			dWallet: activeDWallet,
			encryptedUserSecretKeyShare,
			userShareEncryptionKeys,
		} = await createCompleteDWallet(ikaClient, suiClient, testName);

		// Generate destination encryption keys and register them
		const destinationKeypair = generateTestKeypair(testName + '-destination');
		const destinationEncryptionKeyAddress =
			destinationKeypair.userShareEncryptionKeys.getSuiAddress();

		// Register encryption key for destination address
		await requestTestFaucetFunds(destinationKeypair.signerAddress);
		await registerTestEncryptionKey(
			ikaClient,
			suiClient,
			destinationKeypair.userShareEncryptionKeys,
			testName + '-destination',
		);

		// Decrypt the user share to get the secret share
		const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
			activeDWallet,
			encryptedUserSecretKeyShare,
			await ikaClient.getProtocolPublicParameters(activeDWallet),
		);

		// Test transferring user share with secret share
		const tx = new Transaction();
		const ikaTransaction = createTestIkaTransaction(ikaClient, tx, userShareEncryptionKeys);

		const emptyIKACoin = createEmptyTestIkaToken(tx, ikaClient.ikaConfig);

		// Use transferUserShareWithSecretShare
		await ikaTransaction.transferUserShareWithSecretShare({
			dWallet: activeDWallet,
			destinationEncryptionKeyAddress,
			sourceSecretShare: secretShare,
			sourceEncryptedUserSecretKeyShare: encryptedUserSecretKeyShare,
			ikaCoin: emptyIKACoin,
			suiCoin: tx.gas,
		});

		destroyEmptyTestIkaToken(tx, ikaClient.ikaConfig, emptyIKACoin);

		const result = await executeTestTransaction(suiClient, tx, testName);

		// Should have transfer event
		const transferEvent = result.events?.find((event) =>
			event.type.includes('EncryptedShareVerificationRequestEvent'),
		);
		expect(transferEvent).toBeDefined();
	});

	it('should handle invalid secret share gracefully', async () => {
		const testName = 'invalid-secret-share-test';

		// Setup test environment
		const {
			suiClient,
			ikaClient,
			dWallet: activeDWallet,
			userShareEncryptionKeys,
			signerAddress,
		} = await setupSecretShareTest(testName);

		// Create presign
		const { presignObject } = await createPresignForSecretShare(
			ikaClient,
			suiClient,
			activeDWallet,
			signerAddress,
			testName,
		);

		// Create transaction setup
		const { tx, ikaTransaction, emptyIKACoin } = createSecretShareTransaction(
			ikaClient,
			userShareEncryptionKeys,
		);

		const message = createTestMessage(testName);

		const { messageApproval } = ikaTransaction.approveMessage({
			dWalletCap: activeDWallet.dwallet_cap_id,
			signatureAlgorithm: SignatureAlgorithm.ECDSA,
			hashScheme: Hash.KECCAK256,
			message,
		});

		const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
			presign: presignObject as any,
		});

		// Create invalid secret share (wrong length)
		const invalidSecretShare = new Uint8Array(10).fill(1); // Too short

		// Should throw error with invalid secret share
		await expect(
			ikaTransaction.sign({
				dWallet: activeDWallet,
				messageApproval,
				hashScheme: Hash.KECCAK256,
				verifiedPresignCap,
				presign: presignObject as any,
				secretShare: invalidSecretShare,
				publicOutput: new Uint8Array(activeDWallet.state.Active?.public_output ?? []),
				message,
				ikaCoin: emptyIKACoin,
				suiCoin: tx.gas,
			}),
		).rejects.toThrow();

		destroyEmptyTestIkaToken(tx, ikaClient.ikaConfig, emptyIKACoin);
	});

	it('should validate secret share method inputs properly', async () => {
		const testName = 'secret-share-validation-test';

		// Setup test environment
		const {
			suiClient,
			ikaClient,
			dWallet: activeDWallet,
			encryptedUserSecretKeyShare,
			userShareEncryptionKeys,
			signerAddress,
		} = await setupSecretShareTest(testName);

		// Create presign
		const { presignObject } = await createPresignForSecretShare(
			ikaClient,
			suiClient,
			activeDWallet,
			signerAddress,
			testName,
		);

		// Get valid secret share
		const secretShare = await getSecretShare(
			userShareEncryptionKeys,
			activeDWallet,
			encryptedUserSecretKeyShare,
			ikaClient,
		);

		// Create transaction setup
		const { tx, ikaTransaction, emptyIKACoin } = createSecretShareTransaction(
			ikaClient,
			userShareEncryptionKeys,
		);

		const message = createTestMessage(testName);

		// Validate secret share properties
		expect(secretShare).toBeDefined();
		expect(secretShare).toBeInstanceOf(Uint8Array);
		expect(secretShare.length).toBeGreaterThan(30); // Should be substantial for cryptographic operations
		expect(secretShare.length).toBeLessThan(1000); // Reasonable upper bound

		// Validate that secret share contains non-zero data
		const hasNonZeroBytes = Array.from(secretShare).some((byte) => byte !== 0);
		expect(hasNonZeroBytes).toBe(true);

		// Validate message approval structure
		const { messageApproval } = ikaTransaction.approveMessage({
			dWalletCap: activeDWallet.dwallet_cap_id,
			signatureAlgorithm: SignatureAlgorithm.ECDSA,
			hashScheme: Hash.KECCAK256,
			message,
		});

		expect(messageApproval).toBeDefined();
		expect(typeof messageApproval).toBe('object');

		// Validate presign cap verification
		const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
			presign: presignObject as any,
		});

		expect(verifiedPresignCap).toBeDefined();
		expect(typeof verifiedPresignCap).toBe('object');

		destroyEmptyTestIkaToken(tx, ikaClient.ikaConfig, emptyIKACoin);
	});
});
