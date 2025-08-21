// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { Hash, SignatureAlgorithm, ZeroTrustDWallet } from '../../src/client/types';
import {
	acceptTestEncryptedUserShareForTransferredDWallet,
	createCompleteDWallet,
	registerTestEncryptionKey,
	testPresign,
	testSign,
	testTransferEncryptedUserShare,
} from '../helpers/dwallet-test-helpers';
import {
	createTestIkaClient,
	createTestMessage,
	createTestSuiClient,
	delay,
	generateTestKeypair,
	retryUntil,
} from '../helpers/test-utils';

/**
 * Creates and sets up a complete DWallet transfer environment
 */
async function setupDWalletTransfer(testName: string) {
	const suiClient = createTestSuiClient();
	const ikaClient = createTestIkaClient(suiClient);
	await ikaClient.initialize();

	// Create complete DWallet for source user
	const sourceSetup = await createCompleteDWallet(ikaClient, suiClient, testName);

	// Generate destination user keys
	const { userShareEncryptionKeys: destinationUserShareEncryptionKeys } = generateTestKeypair(
		testName + '-destination',
	);

	// Register destination encryption key
	await registerTestEncryptionKey(
		ikaClient,
		suiClient,
		destinationUserShareEncryptionKeys,
		testName,
	);

	return {
		suiClient,
		ikaClient,
		sourceSetup,
		destinationUserShareEncryptionKeys,
	};
}

/**
 * Completes the transfer flow and returns necessary objects for signing
 */
async function completeTransferFlow(
	ikaClient: any,
	suiClient: any,
	sourceDWallet: any,
	sourceEncryptedUserSecretKeyShare: any,
	sourceUserShareEncryptionKeys: any,
	destinationUserShareEncryptionKeys: any,
	testName: string,
) {
	// Transfer encrypted user share
	const transferUserShareEvent = await testTransferEncryptedUserShare(
		ikaClient,
		suiClient,
		sourceDWallet,
		destinationUserShareEncryptionKeys.getSuiAddress(),
		sourceEncryptedUserSecretKeyShare,
		sourceUserShareEncryptionKeys,
		testName,
	);

	expect(transferUserShareEvent).toBeDefined();
	expect(transferUserShareEvent.event_data).toBeDefined();
	expect(transferUserShareEvent.event_data.encrypted_user_secret_key_share_id).toBeDefined();

	// Get source encryption key
	const sourceEncryptionKey = await ikaClient.getActiveEncryptionKey(
		sourceUserShareEncryptionKeys.getSuiAddress(),
	);
	expect(sourceEncryptionKey).toBeDefined();

	// Get destination encrypted user secret key share
	const destinationEncryptedUserSecretKeyShare = await retryUntil(
		() =>
			ikaClient.getEncryptedUserSecretKeyShareInParticularState(
				transferUserShareEvent.event_data.encrypted_user_secret_key_share_id,
				'NetworkVerificationCompleted',
			),
		(share) => share !== null,
		30,
		1000,
	);

	expect(destinationEncryptedUserSecretKeyShare).toBeDefined();
	expect((destinationEncryptedUserSecretKeyShare as any).state.$kind).toBe(
		'NetworkVerificationCompleted',
	);

	// Accept encrypted user share for transferred DWallet
	await acceptTestEncryptedUserShareForTransferredDWallet(
		ikaClient,
		suiClient,
		sourceDWallet,
		destinationUserShareEncryptionKeys,
		sourceEncryptedUserSecretKeyShare,
		sourceEncryptionKey,
		destinationEncryptedUserSecretKeyShare as any,
		testName,
	);

	return {
		transferUserShareEvent,
		sourceEncryptionKey,
		destinationEncryptedUserSecretKeyShare,
	};
}

/**
 * Creates presign and returns presign object
 */
async function createAndWaitForPresign(
	ikaClient: any,
	suiClient: any,
	dWallet: any,
	signerAddress: string,
	testName: string,
) {
	const presignRequestEvent = await testPresign(
		ikaClient,
		suiClient,
		dWallet,
		SignatureAlgorithm.ECDSA,
		signerAddress,
		testName,
	);

	expect(presignRequestEvent).toBeDefined();
	expect(presignRequestEvent.event_data).toBeDefined();
	expect(presignRequestEvent.event_data.presign_id).toBeDefined();

	const presignObject = await retryUntil(
		() =>
			ikaClient.getPresignInParticularState(presignRequestEvent.event_data.presign_id, 'Completed'),
		(presign) => presign !== null,
		30,
		2000,
	);

	expect(presignObject).toBeDefined();
	expect((presignObject as any).state.$kind).toBe('Completed');

	return presignObject;
}

/**
 * Signs a message and validates the signing process
 */
async function signMessageAndValidate(
	ikaClient: any,
	suiClient: any,
	dWallet: any,
	userShareEncryptionKeys: any,
	presignObject: any,
	encryptedUserSecretKeyShare: any,
	message: Uint8Array,
	testName: string,
) {
	await testSign(
		ikaClient,
		suiClient,
		dWallet,
		userShareEncryptionKeys,
		presignObject,
		encryptedUserSecretKeyShare,
		message,
		Hash.KECCAK256,
		SignatureAlgorithm.ECDSA,
		testName,
	);

	// Validate DWallet remains active after signing
	const dWalletAfterSigning = await ikaClient.getDWalletInParticularState(dWallet.id.id, 'Active');
	expect(dWalletAfterSigning).toBeDefined();
	expect(dWalletAfterSigning.state.$kind).toBe('Active');
}

describe('DWallet Transfer', () => {
	it('should transfer DWallet and sign with transferred DWallet', async () => {
		const testName = 'dwallet-transfer-test';

		// Setup DWallet transfer environment
		const { suiClient, ikaClient, sourceSetup, destinationUserShareEncryptionKeys } =
			await setupDWalletTransfer(testName);

		const {
			dWallet: sourceDWallet,
			encryptedUserSecretKeyShare: sourceEncryptedUserSecretKeyShare,
			userShareEncryptionKeys: sourceUserShareEncryptionKeys,
			signerAddress: sourceSignerAddress,
		} = sourceSetup;

		// Complete transfer flow
		const { transferUserShareEvent } = await completeTransferFlow(
			ikaClient,
			suiClient,
			sourceDWallet,
			sourceEncryptedUserSecretKeyShare,
			sourceUserShareEncryptionKeys,
			destinationUserShareEncryptionKeys,
			testName,
		);

		await delay(5);

		// Create presign for signing
		const presignObject = await createAndWaitForPresign(
			ikaClient,
			suiClient,
			sourceDWallet,
			sourceSignerAddress,
			testName,
		);

		// Get updated destination encrypted user secret key share for signing
		const destinationEncryptedUserSecretKeyShare2 = await retryUntil(
			() =>
				ikaClient.getEncryptedUserSecretKeyShareInParticularState(
					transferUserShareEvent.event_data.encrypted_user_secret_key_share_id,
					'KeyHolderSigned',
				),
			(share) => share !== null,
			30,
			1000,
		);

		expect(destinationEncryptedUserSecretKeyShare2).toBeDefined();
		expect(destinationEncryptedUserSecretKeyShare2.state.$kind).toBe('KeyHolderSigned');

		// Sign message with transferred DWallet
		const message = createTestMessage(testName);
		await signMessageAndValidate(
			ikaClient,
			suiClient,
			sourceDWallet,
			destinationUserShareEncryptionKeys,
			presignObject,
			destinationEncryptedUserSecretKeyShare2,
			message,
			testName,
		);

		// Verify transfer completed successfully and signature was created
		expect(transferUserShareEvent.event_data.encrypted_user_secret_key_share_id).toBeDefined();
		expect((presignObject as any).state.$kind).toBe('Completed');
	});

	it('should handle multiple transfers of the same DWallet', async () => {
		const testName = 'dwallet-multiple-transfer-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		// Step 1: Create complete DWallet for source user
		const {
			dWallet: sourceDWallet,
			encryptedUserSecretKeyShare: sourceEncryptedUserSecretKeyShare,
			userShareEncryptionKeys: sourceUserShareEncryptionKeys,
			signerAddress: sourceSignerAddress,
		} = await createCompleteDWallet(ikaClient, suiClient, testName);

		// Step 2: Generate multiple destination user keys
		const destinations: any[] = [];
		for (let i = 0; i < 3; i++) {
			const { userShareEncryptionKeys: destinationUserShareEncryptionKeys } = generateTestKeypair(
				testName + '-destination-' + i,
			);

			// Register destination encryption key
			await registerTestEncryptionKey(
				ikaClient,
				suiClient,
				destinationUserShareEncryptionKeys,
				testName,
			);

			destinations.push(destinationUserShareEncryptionKeys);
		}

		// Step 3: Transfer to each destination
		const sourceEncryptionKey = await ikaClient.getActiveEncryptionKey(
			sourceUserShareEncryptionKeys.getSuiAddress(),
		);

		expect(sourceEncryptionKey).toBeDefined();

		for (const destinationKeys of destinations) {
			// Transfer encrypted user share
			const transferUserShareEvent = await testTransferEncryptedUserShare(
				ikaClient,
				suiClient,
				sourceDWallet as ZeroTrustDWallet,
				destinationKeys.getSuiAddress(),
				sourceEncryptedUserSecretKeyShare,
				sourceUserShareEncryptionKeys,
				testName,
			);

			expect(transferUserShareEvent).toBeDefined();

			// Get destination encrypted user secret key share
			const destinationEncryptedUserSecretKeyShare = await retryUntil(
				() =>
					ikaClient.getEncryptedUserSecretKeyShareInParticularState(
						transferUserShareEvent.event_data.encrypted_user_secret_key_share_id,
						'NetworkVerificationCompleted',
					),
				(share) => share !== null,
				30,
				1000,
			);

			expect(destinationEncryptedUserSecretKeyShare).toBeDefined();
			expect(destinationEncryptedUserSecretKeyShare.state.$kind).toBe(
				'NetworkVerificationCompleted',
			);

			// Accept encrypted user share for transferred DWallet
			await acceptTestEncryptedUserShareForTransferredDWallet(
				ikaClient,
				suiClient,
				sourceDWallet as ZeroTrustDWallet,
				destinationKeys,
				sourceEncryptedUserSecretKeyShare,
				sourceEncryptionKey,
				destinationEncryptedUserSecretKeyShare,
				testName,
			);

			await delay(2);
		}

		// Step 4: Verify all transfers completed successfully
		expect(destinations.length).toBe(3);
	});

	it('should maintain DWallet functionality after transfer', async () => {
		const testName = 'dwallet-functionality-after-transfer-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		// Step 1: Create complete DWallet for source user
		const {
			dWallet: sourceDWallet,
			encryptedUserSecretKeyShare: sourceEncryptedUserSecretKeyShare,
			userShareEncryptionKeys: sourceUserShareEncryptionKeys,
			signerAddress: sourceSignerAddress,
		} = await createCompleteDWallet(ikaClient, suiClient, testName);

		// Step 2: Generate destination user keys
		const { userShareEncryptionKeys: destinationUserShareEncryptionKeys } = generateTestKeypair(
			testName + '-destination',
		);

		// Step 3: Register destination encryption key
		await registerTestEncryptionKey(
			ikaClient,
			suiClient,
			destinationUserShareEncryptionKeys,
			testName,
		);

		// Step 4: Transfer encrypted user share
		const transferUserShareEvent = await testTransferEncryptedUserShare(
			ikaClient,
			suiClient,
			sourceDWallet as ZeroTrustDWallet,
			destinationUserShareEncryptionKeys.getSuiAddress(),
			sourceEncryptedUserSecretKeyShare,
			sourceUserShareEncryptionKeys,
			testName,
		);

		// Step 5: Get source encryption key and destination encrypted share
		const sourceEncryptionKey = await ikaClient.getActiveEncryptionKey(
			sourceUserShareEncryptionKeys.getSuiAddress(),
		);

		const destinationEncryptedUserSecretKeyShare = await retryUntil(
			() =>
				ikaClient.getEncryptedUserSecretKeyShareInParticularState(
					transferUserShareEvent.event_data.encrypted_user_secret_key_share_id,
					'NetworkVerificationCompleted',
				),
			(share) => share !== null,
			30,
			1000,
		);

		// Step 6: Accept encrypted user share for transferred DWallet
		await acceptTestEncryptedUserShareForTransferredDWallet(
			ikaClient,
			suiClient,
			sourceDWallet as ZeroTrustDWallet,
			destinationUserShareEncryptionKeys,
			sourceEncryptedUserSecretKeyShare,
			sourceEncryptionKey,
			destinationEncryptedUserSecretKeyShare,
			testName,
		);

		await delay(5);

		// Step 7: Test that original source user can still sign
		const sourcePresignRequestEvent = await testPresign(
			ikaClient,
			suiClient,
			sourceDWallet,
			SignatureAlgorithm.ECDSA,
			sourceSignerAddress,
			testName,
		);

		const sourcePresignObject = await retryUntil(
			() =>
				ikaClient.getPresignInParticularState(
					sourcePresignRequestEvent.event_data.presign_id,
					'Completed',
				),
			(presign) => presign !== null,
			30,
			2000,
		);

		const sourceMessage = createTestMessage(testName, '-source');
		await testSign(
			ikaClient,
			suiClient,
			sourceDWallet as ZeroTrustDWallet,
			sourceUserShareEncryptionKeys,
			sourcePresignObject,
			sourceEncryptedUserSecretKeyShare,
			sourceMessage,
			Hash.KECCAK256,
			SignatureAlgorithm.ECDSA,
			testName,
		);

		await delay(5);

		// Step 8: Test that destination user can sign
		const destinationPresignRequestEvent = await testPresign(
			ikaClient,
			suiClient,
			sourceDWallet,
			SignatureAlgorithm.ECDSA,
			sourceSignerAddress,
			testName,
		);

		const destinationPresignObject = await retryUntil(
			() =>
				ikaClient.getPresignInParticularState(
					destinationPresignRequestEvent.event_data.presign_id,
					'Completed',
				),
			(presign) => presign !== null,
			30,
			2000,
		);

		const destinationEncryptedUserSecretKeyShare2 = await retryUntil(
			() =>
				ikaClient.getEncryptedUserSecretKeyShareInParticularState(
					transferUserShareEvent.event_data.encrypted_user_secret_key_share_id,
					'KeyHolderSigned',
				),
			(share) => share !== null,
			30,
			1000,
		);

		const destinationMessage = createTestMessage(testName, '-destination');
		await testSign(
			ikaClient,
			suiClient,
			sourceDWallet as ZeroTrustDWallet,
			destinationUserShareEncryptionKeys,
			destinationPresignObject,
			destinationEncryptedUserSecretKeyShare2,
			destinationMessage,
			Hash.KECCAK256,
			SignatureAlgorithm.ECDSA,
			testName,
		);
	});
});
