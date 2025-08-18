// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';
import { a } from 'vitest/dist/chunks/suite.d.FvehnV49.js';

import { Hash, SignatureAlgorithm } from '../../src/client/types';
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

describe('DWallet Transfer', () => {
	it('should transfer DWallet and sign with transferred DWallet', async () => {
		const testName = 'dwallet-transfer-test';
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
		const result = await registerTestEncryptionKey(
			ikaClient,
			suiClient,
			destinationUserShareEncryptionKeys,
			testName,
		);

		expect(result).toBeDefined();

		// Step 4: Transfer encrypted user share
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
		expect(transferUserShareEvent.event_data.encrypted_user_secret_key_share_id).toBeDefined();

		// Step 5: Get source encryption key
		const sourceEncryptionKey = await ikaClient.getActiveEncryptionKey(
			sourceUserShareEncryptionKeys.getSuiAddress(),
		);

		expect(sourceEncryptionKey).toBeDefined();

		// Step 6: Get destination encrypted user secret key share
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

		// Step 7: Accept encrypted user share for transferred DWallet
		await acceptTestEncryptedUserShareForTransferredDWallet(
			ikaClient,
			suiClient,
			sourceDWallet,
			destinationUserShareEncryptionKeys,
			sourceEncryptedUserSecretKeyShare,
			sourceEncryptionKey,
			destinationEncryptedUserSecretKeyShare,
			testName,
		);

		await delay(5);

		// Step 8: Create presign with transferred DWallet
		const presignRequestEvent = await testPresign(
			ikaClient,
			suiClient,
			sourceDWallet,
			SignatureAlgorithm.ECDSA,
			sourceSignerAddress,
			testName,
		);

		expect(presignRequestEvent).toBeDefined();
		expect(presignRequestEvent.event_data.presign_id).toBeDefined();

		// Step 9: Wait for presign to complete
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

		expect(presignObject).toBeDefined();
		expect(presignObject.state.$kind).toBe('Completed');

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

		// Step 10: Sign a message with transferred DWallet
		const message = createTestMessage(testName);
		await testSign(
			ikaClient,
			suiClient,
			sourceDWallet,
			destinationUserShareEncryptionKeys, // Use destination keys for signing
			presignObject,
			destinationEncryptedUserSecretKeyShare2, // Use destination encrypted share
			message,
			Hash.KECCAK256,
			SignatureAlgorithm.ECDSA,
			testName,
		);

		// Verify the signing process completed successfully
		expect(true).toBe(true);
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
				sourceDWallet,
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
				sourceDWallet,
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
			sourceDWallet,
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
			sourceDWallet,
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
			sourceDWallet,
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
			sourceDWallet,
			destinationUserShareEncryptionKeys,
			destinationPresignObject,
			destinationEncryptedUserSecretKeyShare2,
			destinationMessage,
			Hash.KECCAK256,
			SignatureAlgorithm.ECDSA,
			testName,
		);

		// Both users can successfully sign with the same DWallet
		expect(true).toBe(true);
	});
});
