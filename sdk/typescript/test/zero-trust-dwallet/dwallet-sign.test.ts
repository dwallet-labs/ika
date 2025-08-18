// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
import { describe, expect, it } from 'vitest';

import { Hash, SignatureAlgorithm } from '../../src/client/types';
import { createCompleteDWallet, testPresign, testSign } from '../helpers/dwallet-test-helpers';
import {
	createTestIkaClient,
	createTestMessage,
	createTestSuiClient,
	DEFAULT_TIMEOUT,
	delay,
	retryUntil,
	runSignFullFlow,
} from '../helpers/test-utils';

describe('DWallet Signing', () => {
	it(
		'should create a DWallet and sign a message',
		async () => {
			const testName = 'dwallet-sign-test';
			const suiClient = createTestSuiClient();
			const ikaClient = createTestIkaClient(suiClient);
			await ikaClient.initialize();

			// Step 1: Create complete DWallet
			await runSignFullFlow(ikaClient, suiClient, testName);
		},
	);

	it(
		'should sign multiple messages with the same DWallet',
		async () => {
			const testName = 'dwallet-multi-sign-test';
			const suiClient = createTestSuiClient();
			const ikaClient = createTestIkaClient(suiClient);
			await ikaClient.initialize();

			// Create complete DWallet
			const {
				dWallet: activeDWallet,
				encryptedUserSecretKeyShare,
				userShareEncryptionKeys,
				signerAddress,
			} = await createCompleteDWallet(ikaClient, suiClient, testName);

			// Create multiple presigns and sign multiple messages
			const messages = [
				createTestMessage(testName, '-message-1'),
				createTestMessage(testName, '-message-2'),
				createTestMessage(testName, '-message-3'),
			];

			for (let i = 0; i < messages.length; i++) {
				// Create presign for each message
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

				// Sign the message
				await testSign(
					ikaClient,
					suiClient,
					activeDWallet,
					userShareEncryptionKeys,
					presignObject,
					encryptedUserSecretKeyShare,
					messages[i],
					Hash.KECCAK256,
					SignatureAlgorithm.ECDSA,
					testName,
				);

				await delay(2);
			}

			// All signatures completed successfully
			expect(messages.length).toBe(3);
		},
	);

	it(
		'should handle different hash schemes',
		async () => {
			const testName = 'dwallet-hash-schemes-test';
			const suiClient = createTestSuiClient();
			const ikaClient = createTestIkaClient(suiClient);
			await ikaClient.initialize();

			// Create complete DWallet
			const {
				dWallet: activeDWallet,
				encryptedUserSecretKeyShare,
				userShareEncryptionKeys,
				signerAddress,
			} = await createCompleteDWallet(ikaClient, suiClient, testName);

			// Test different hash schemes
			const hashSchemes = [Hash.KECCAK256, Hash.SHA256];
			const message = createTestMessage(testName);

			for (const hashScheme of hashSchemes) {
				// Create presign
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

				// Sign with different hash scheme
				await testSign(
					ikaClient,
					suiClient,
					activeDWallet,
					userShareEncryptionKeys,
					presignObject,
					encryptedUserSecretKeyShare,
					message,
					hashScheme,
					SignatureAlgorithm.ECDSA,
					testName,
				);

				await delay(2);
			}

			// All hash schemes worked
			expect(hashSchemes.length).toBe(2);
		},
	);
});
