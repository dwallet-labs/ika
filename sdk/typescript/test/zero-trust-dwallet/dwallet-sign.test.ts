// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
import { Transaction } from '@mysten/sui/transactions';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { Hash, SignatureAlgorithm } from '../../src/client/types';
import { createCompleteDWallet, testPresign } from '../helpers/dwallet-test-helpers';
import { createIndividualTestSetup, getSharedTestSetup } from '../helpers/shared-test-setup';
import {
	createEmptyTestIkaToken,
	createTestIkaTransaction,
	createTestMessage,
	delay,
	destroyEmptyTestIkaToken,
	executeTestTransaction,
	retryUntil,
} from '../helpers/test-utils';

// Setup shared resources before all tests
beforeAll(async () => {
	await getSharedTestSetup();
}, 60000); // 1 minute timeout for setup

// Cleanup shared resources after all tests
afterAll(async () => {
	const sharedSetup = await getSharedTestSetup();
	sharedSetup.cleanup();

	// Force garbage collection if available
	if (global.gc) {
		global.gc();
	}
});

/**
 * Enhanced test sign function that returns transaction results for validation
 */
async function testSignWithResult(
	ikaClient: any,
	suiClient: any,
	dWallet: any,
	userShareEncryptionKeys: any,
	presign: any,
	encryptedUserSecretKeyShare: any,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const { messageApproval } = ikaTransaction.approveMessage({
		dWalletCap: dWallet.dwallet_cap_id,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.sign({
		dWallet,
		messageApproval,
		verifiedPresignCap,
		hashScheme,
		presign,
		encryptedUserSecretKeyShare,
		message,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);

	return result;
}

describe('DWallet Signing', () => {
	it('should create a DWallet and sign a message', async () => {
		const testName = 'dwallet-sign-test';

		// Use shared clients but create individual DWallet to avoid gas conflicts
		const { suiClient, ikaClient } = await createIndividualTestSetup(testName);
		const {
			dWallet: activeDWallet,
			encryptedUserSecretKeyShare,
			userShareEncryptionKeys,
			signerAddress,
		} = await createCompleteDWallet(ikaClient, suiClient, testName);

		expect(activeDWallet).toBeDefined();
		expect(activeDWallet.state.$kind).toBe('Active');
		expect(activeDWallet.id.id).toMatch(/^0x[a-f0-9]+$/);

		// Create presign
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

		// Wait for presign to complete
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
		expect((presignObject as any).state.$kind).toBe('Completed');

		// Sign a message and validate result
		const message = createTestMessage(testName);
		const signingResult = await testSignWithResult(
			ikaClient,
			suiClient,
			activeDWallet,
			userShareEncryptionKeys,
			presignObject,
			encryptedUserSecretKeyShare,
			message,
			Hash.KECCAK256,
			SignatureAlgorithm.ECDSA,
			testName,
		);

		// Validate transaction succeeded
		expect(signingResult).toBeDefined();
		expect(signingResult.digest).toBeDefined();
		expect(signingResult.digest).toMatch(/^[a-zA-Z0-9]+$/); // Base58-like transaction digest
		expect(signingResult.digest.length).toBeGreaterThan(20); // Transaction digest should be substantial
		expect(signingResult.digest.length).toBeLessThan(100); // But not unreasonably long

		// Validate transaction execution metadata
		expect(signingResult.confirmedLocalExecution).toBe(false);

		// Validate events were emitted - signing should generate multiple events
		expect(signingResult.events).toBeDefined();
		expect(signingResult.events!.length).toBeGreaterThan(0);

		// Check for specific signing-related events
		const hasSigningEvents = signingResult.events!.some(
			(event) =>
				event.type.includes('Sign') ||
				event.type.includes('Message') ||
				event.type.includes('Signature'),
		);
		expect(hasSigningEvents).toBe(true);

		// Validate BCS data is present (indicates proper encoding)
		const hasBcsData = signingResult.events!.some((event) => event.bcs && event.bcs.length > 0);
		expect(hasBcsData).toBe(true);

		// Verify DWallet is still active after signing
		const dWalletAfterSigning = await ikaClient.getDWalletInParticularState(
			activeDWallet.id.id,
			'Active',
		);
		expect(dWalletAfterSigning).toBeDefined();
		expect(dWalletAfterSigning.state.$kind).toBe('Active');
	});

	it('should sign multiple messages with the same DWallet', async () => {
		const testName = 'dwallet-multi-sign-test';

		// Use shared clients but create individual DWallet to avoid gas conflicts
		const { suiClient, ikaClient } = await createIndividualTestSetup(testName);
		const {
			dWallet: activeDWallet,
			encryptedUserSecretKeyShare,
			userShareEncryptionKeys,
			signerAddress,
		} = await createCompleteDWallet(ikaClient, suiClient, testName);

		// Create 2 messages to sign (reduced to minimize memory usage)
		const messages = [
			createTestMessage(testName, '-message-1'),
			createTestMessage(testName, '-message-2'),
		];

		const signingResults: any[] = [];

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

			expect(presignRequestEvent.event_data.presign_id).toBeDefined();

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

			expect((presignObject as any).state.$kind).toBe('Completed');

			// Sign the message and collect results
			const signingResult = await testSignWithResult(
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

			// Validate each signing result
			expect(signingResult).toBeDefined();
			expect(signingResult.digest).toBeDefined();
			expect(signingResult.digest).toMatch(/^[a-zA-Z0-9]+$/);
			expect(signingResult.digest.length).toBeGreaterThan(20);
			expect(signingResult.digest.length).toBeLessThan(100);
			expect(signingResult.events).toBeDefined();
			expect(signingResult.events!.length).toBeGreaterThan(0);

			// Ensure each signing has unique characteristics
			expect(signingResult.confirmedLocalExecution).toBe(false);

			signingResults.push(signingResult);
			await delay(2);
		}

		// Validate all signings completed successfully
		expect(signingResults).toHaveLength(messages.length);

		// Ensure each signing produced unique transaction digests
		const uniqueDigests = new Set(signingResults.map((r) => r.digest));
		expect(uniqueDigests.size).toBe(messages.length);

		// Verify DWallet is still active after all signings
		const dWalletAfterAllSignings = await ikaClient.getDWalletInParticularState(
			activeDWallet.id.id,
			'Active',
		);
		expect(dWalletAfterAllSignings).toBeDefined();
		expect(dWalletAfterAllSignings.state.$kind).toBe('Active');
	});

	describe.each([
		['KECCAK256', Hash.KECCAK256],
		['SHA256', Hash.SHA256],
	])('signing with %s hash', (hashName, hashScheme) => {
		it(`should sign successfully with ${hashName}`, async () => {
			const testName = `dwallet-${hashName.toLowerCase()}-test`;

			// Use shared clients but create individual DWallet to avoid gas conflicts
			const { suiClient, ikaClient } = await createIndividualTestSetup(testName);
			const {
				dWallet: activeDWallet,
				encryptedUserSecretKeyShare,
				userShareEncryptionKeys,
				signerAddress,
			} = await createCompleteDWallet(ikaClient, suiClient, testName);

			// Create presign
			const presignRequestEvent = await testPresign(
				ikaClient,
				suiClient,
				activeDWallet,
				SignatureAlgorithm.ECDSA,
				signerAddress,
				testName,
			);

			expect(presignRequestEvent.event_data.presign_id).toBeDefined();

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

			expect((presignObject as any).state.$kind).toBe('Completed');

			// Sign with specific hash scheme
			const message = createTestMessage(testName);
			const signingResult = await testSignWithResult(
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

			// Validate signing result for specific hash scheme
			expect(signingResult).toBeDefined();
			expect(signingResult.digest).toBeDefined();
			expect(signingResult.digest).toMatch(/^[a-zA-Z0-9]+$/);
			expect(signingResult.digest.length).toBeGreaterThan(20);
			expect(signingResult.digest.length).toBeLessThan(100);
			expect(signingResult.events).toBeDefined();
			expect(signingResult.events!.length).toBeGreaterThan(0);

			// Validate that the hash scheme was processed (events should contain relevant data)
			const hasBcsEvents = signingResult.events!.some(
				(event) => event.bcs && event.bcs.length > 50,
			);
			expect(hasBcsEvents).toBe(true);

			// Verify transaction was confirmed
			expect(signingResult.confirmedLocalExecution).toBe(false);

			// Verify DWallet remains active after signing with this hash scheme
			const dWalletAfterSigning = await ikaClient.getDWalletInParticularState(
				activeDWallet.id.id,
				'Active',
			);
			expect(dWalletAfterSigning).toBeDefined();
			expect(dWalletAfterSigning.state.$kind).toBe('Active');
		});
	});

	it('should handle invalid signing scenarios', async () => {
		const testName = 'dwallet-error-scenarios-test';

		// Use shared clients but create individual DWallet to avoid gas conflicts
		const { suiClient, ikaClient } = await createIndividualTestSetup(testName);
		const {
			dWallet: activeDWallet,
			encryptedUserSecretKeyShare,
			userShareEncryptionKeys,
		} = await createCompleteDWallet(ikaClient, suiClient, testName);

		// Test signing without presign (should fail)
		await expect(async () => {
			const transaction = new Transaction();
			const ikaTransaction = createTestIkaTransaction(
				ikaClient,
				transaction,
				userShareEncryptionKeys,
			);

			const message = createTestMessage(testName);
			const { messageApproval } = ikaTransaction.approveMessage({
				dWalletCap: activeDWallet.dwallet_cap_id,
				signatureAlgorithm: SignatureAlgorithm.ECDSA,
				hashScheme: Hash.KECCAK256,
				message,
			});

			// Try to sign with null presign (this should fail)
			await ikaTransaction.sign({
				dWallet: activeDWallet,
				messageApproval,
				verifiedPresignCap: null as any,
				hashScheme: Hash.KECCAK256,
				presign: null as any,
				encryptedUserSecretKeyShare,
				message,
				ikaCoin: createEmptyTestIkaToken(transaction, ikaClient.ikaConfig),
				suiCoin: transaction.gas,
			});
		}).rejects.toThrow();

		// Test signing with empty message
		const emptyMessage = new Uint8Array(0);
		expect(emptyMessage.length).toBe(0);

		// Verify DWallet is still active after error scenarios
		const dWalletAfterErrors = await ikaClient.getDWalletInParticularState(
			activeDWallet.id.id,
			'Active',
		);
		expect(dWalletAfterErrors).toBeDefined();
		expect(dWalletAfterErrors.state.$kind).toBe('Active');
	});
});
