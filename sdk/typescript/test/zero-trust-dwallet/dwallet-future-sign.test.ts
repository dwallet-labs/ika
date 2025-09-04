// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { Hash, SignatureAlgorithm, ZeroTrustDWallet } from '../../src/client/types';
import {
	createCompleteDWallet,
	requestTestFutureSign,
	testFutureSign,
	testPresign,
} from '../helpers/dwallet-test-helpers';
import {
	createTestIkaClient,
	createTestMessage,
	createTestSuiClient,
	delay,
	retryUntil,
} from '../helpers/test-utils';

describe('DWallet Future Signing', () => {
	it('should create a DWallet and perform future signing', async () => {
		const testName = 'dwallet-future-sign-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		// Step 1: Create complete DWallet
		const {
			dWallet: activeDWallet,
			encryptedUserSecretKeyShare,
			userShareEncryptionKeys,
			signerAddress,
		} = await createCompleteDWallet(ikaClient, suiClient, testName);

		// Step 2: Create presign
		const presignRequestEvent = await testPresign(
			ikaClient,
			suiClient,
			activeDWallet,
			SignatureAlgorithm.ECDSA,
			signerAddress,
			testName,
		);

		expect(presignRequestEvent).toBeDefined();
		expect(presignRequestEvent.event_data.presign_id).toBeDefined();

		// Step 3: Wait for presign to complete
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

		// Step 4: Request future sign
		const message = createTestMessage(testName);
		const futureSignRequest = await requestTestFutureSign(
			ikaClient,
			suiClient,
			activeDWallet as ZeroTrustDWallet,
			presignObject,
			userShareEncryptionKeys,
			encryptedUserSecretKeyShare,
			message,
			Hash.KECCAK256,
			signerAddress,
			testName,
		);

		expect(futureSignRequest).toBeDefined();
		expect(futureSignRequest.event_data.partial_centralized_signed_message_id).toBeDefined();

		// Step 5: Wait for partial user signature to be ready
		const partialUserSignature = await retryUntil(
			() =>
				ikaClient.getPartialUserSignatureInParticularState(
					futureSignRequest.event_data.partial_centralized_signed_message_id,
					'NetworkVerificationCompleted',
				),
			(signature) => signature !== null,
			30,
			2000,
		);

		expect(partialUserSignature).toBeDefined();
		expect(partialUserSignature.state.$kind).toBe('NetworkVerificationCompleted');

		// Step 6: Complete future sign
		await testFutureSign(
			ikaClient,
			suiClient,
			activeDWallet,
			partialUserSignature,
			userShareEncryptionKeys,
			message,
			Hash.KECCAK256,
			SignatureAlgorithm.ECDSA,
			testName,
		);
	});

	it('should handle multiple future sign requests', async () => {
		const testName = 'dwallet-multi-future-sign-test';
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

		// Create multiple future sign requests
		const messages = [
			createTestMessage(testName, '-future-message-1'),
			createTestMessage(testName, '-future-message-2'),
		];

		const futureSignRequests: any[] = [];
		const presignObjects: any[] = [];

		// Create presigns and future sign requests for each message
		for (let i = 0; i < messages.length; i++) {
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

			presignObjects.push(presignObject);

			// Request future sign
			const futureSignRequest = await requestTestFutureSign(
				ikaClient,
				suiClient,
				activeDWallet as ZeroTrustDWallet,
				presignObject,
				userShareEncryptionKeys,
				encryptedUserSecretKeyShare,
				messages[i],
				Hash.KECCAK256,
				signerAddress,
				testName,
			);

			futureSignRequests.push(futureSignRequest);
			await delay(2);
		}

		// Complete all future signs
		for (let i = 0; i < messages.length; i++) {
			const partialUserSignature = await retryUntil(
				() =>
					ikaClient.getPartialUserSignatureInParticularState(
						futureSignRequests[i].event_data.partial_centralized_signed_message_id,
						'NetworkVerificationCompleted',
					),
				(signature) => signature !== null,
				30,
				2000,
			);

			await testFutureSign(
				ikaClient,
				suiClient,
				activeDWallet,
				partialUserSignature,
				userShareEncryptionKeys,
				messages[i],
				Hash.KECCAK256,
				SignatureAlgorithm.ECDSA,
				testName,
			);

			await delay(2);
		}

		// All future signatures completed successfully
		expect(futureSignRequests.length).toBe(2);
		expect(presignObjects.length).toBe(2);
	});

	it('should handle future signing with different hash schemes', async () => {
		const testName = 'dwallet-future-sign-hash-test';
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

		// Test future signing with different hash schemes
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

			// Request future sign with specific hash scheme
			const futureSignRequest = await requestTestFutureSign(
				ikaClient,
				suiClient,
				activeDWallet as ZeroTrustDWallet,
				presignObject,
				userShareEncryptionKeys,
				encryptedUserSecretKeyShare,
				message,
				hashScheme,
				signerAddress,
				testName,
			);

			const partialUserSignature = await retryUntil(
				() =>
					ikaClient.getPartialUserSignatureInParticularState(
						futureSignRequest.event_data.partial_centralized_signed_message_id,
						'NetworkVerificationCompleted',
					),
				(signature) => signature !== null,
				30,
				2000,
			);

			// Complete future sign with the same hash scheme
			await testFutureSign(
				ikaClient,
				suiClient,
				activeDWallet,
				partialUserSignature,
				userShareEncryptionKeys,
				message,
				hashScheme,
				SignatureAlgorithm.ECDSA,
				testName,
			);

			await delay(2);
		}

		// All hash schemes worked for future signing
		expect(hashSchemes.length).toBe(2);
	});
});
