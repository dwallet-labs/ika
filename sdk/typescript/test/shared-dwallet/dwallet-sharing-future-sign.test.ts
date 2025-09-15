// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Transaction } from '@mysten/sui/transactions';
import { describe, expect, it } from 'vitest';

import { prepareDKGSecondRoundAsync } from '../../src/client/cryptography';
import { Hash, SharedDWallet, SignatureAlgorithm, ZeroTrustDWallet } from '../../src/client/types';
import * as CoordinatorInnerModule from '../../src/generated/ika_dwallet_2pc_mpc/coordinator_inner.js';
import * as SessionsManagerModule from '../../src/generated/ika_dwallet_2pc_mpc/sessions_manager.js';
import {
	acceptTestEncryptedUserShare,
	makeTestDWalletUserSecretKeySharesPublic,
	registerTestEncryptionKey,
	requestTestDKGFirstRound,
	requestTestDkgSecondRound,
	testFutureSign,
	testPresign,
} from '../helpers/dwallet-test-helpers';
import {
	createEmptyTestIkaToken,
	createTestIkaClient,
	createTestIkaTransaction,
	createTestMessage,
	createTestSuiClient,
	delay,
	destroyEmptyTestIkaToken,
	executeTestTransaction,
	generateTestKeypair,
	requestTestFaucetFunds,
	retryUntil,
} from '../helpers/test-utils';

/**
 * Request future sign for shared DWallet testing
 */
async function requestTestSharedFutureSign(
	ikaClient: any,
	suiClient: any,
	dWallet: SharedDWallet,
	presign: any,
	message: Uint8Array,
	hashScheme: Hash,
	signerAddress: string,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	const unverifiedPartialUserSignatureCap = await ikaTransaction.requestFutureSign({
		dWallet,
		presign,
		verifiedPresignCap,
		message,
		hashScheme,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	transaction.transferObjects([unverifiedPartialUserSignatureCap], signerAddress);

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);

	const futureSignRequestEvent = result.events?.find((event) => {
		return (
			event.type.includes('FutureSignRequestEvent') && event.type.includes('DWalletSessionEvent')
		);
	});

	if (!futureSignRequestEvent) {
		throw new Error('Failed to find FutureSignRequestEvent');
	}

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.FutureSignRequestEvent,
	).fromBase64(futureSignRequestEvent.bcs as string);
}

describe('Shared DWallet Future Signing', () => {
	it('should perform future signing with shared DWallet (public user shares)', async () => {
		const testName = 'shared-dwallet-future-sign-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName);

		await requestTestFaucetFunds(signerAddress);

		// Step 1: Create DWallet through DKG process
		const { dwalletID, sessionIdentifierPreimage } = await requestTestDKGFirstRound(
			ikaClient,
			suiClient,
			signerAddress,
			testName,
		);

		await delay(5);

		await registerTestEncryptionKey(ikaClient, suiClient, userShareEncryptionKeys, testName);

		const dWallet = await retryUntil(
			() =>
				ikaClient.getDWalletInParticularState(dwalletID, 'AwaitingUserDKGVerificationInitiation'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		const dkgSecondRoundRequestInput = await prepareDKGSecondRoundAsync(
			ikaClient,
			dWallet,
			userShareEncryptionKeys,
		);

		const secondRoundMoveResponse = await requestTestDkgSecondRound(
			ikaClient,
			suiClient,
			dWallet,
			dkgSecondRoundRequestInput,
			userShareEncryptionKeys,
			testName,
		);

		const awaitingKeyHolderSignatureDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(dwalletID, 'AwaitingKeyHolderSignature'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		// Accept encrypted user share
		await acceptTestEncryptedUserShare(
			ikaClient,
			suiClient,
			awaitingKeyHolderSignatureDWallet as ZeroTrustDWallet,
			dkgSecondRoundRequestInput.userPublicOutput,
			secondRoundMoveResponse,
			userShareEncryptionKeys,
			testName,
		);

		const activeDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(dwalletID, 'Active'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		const encryptedUserSecretKeyShare = await retryUntil(
			() =>
				ikaClient.getEncryptedUserSecretKeyShare(
					secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
				),
			(share) => share !== null,
			30,
			2000,
		);

		const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
			activeDWallet,
			encryptedUserSecretKeyShare,
			await ikaClient.getProtocolPublicParameters(activeDWallet),
		);

		// Step 2: Make user secret key shares public (convert to SharedDWallet)
		await makeTestDWalletUserSecretKeySharesPublic(
			ikaClient,
			suiClient,
			activeDWallet as ZeroTrustDWallet,
			secretShare,
			testName,
		);

		await delay(5);

		// Step 3: Create presign
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

		// Step 4: Wait for presign to complete
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

		// Step 5: Get the shared DWallet
		const sharedDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(activeDWallet.id.id, 'Active'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		expect(sharedDWallet.kind).toBe('shared');

		// Step 6: Request future sign with shared DWallet
		const message = createTestMessage(testName);
		const futureSignRequest = await requestTestSharedFutureSign(
			ikaClient,
			suiClient,
			sharedDWallet as SharedDWallet,
			presignObject,
			message,
			Hash.KECCAK256,
			signerAddress,
			testName,
		);

		expect(futureSignRequest).toBeDefined();
		expect(futureSignRequest.event_data.partial_centralized_signed_message_id).toBeDefined();

		// Step 7: Wait for partial user signature to be ready
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

		// Step 8: Complete future sign
		await testFutureSign(
			ikaClient,
			suiClient,
			sharedDWallet,
			partialUserSignature,
			userShareEncryptionKeys,
			message,
			Hash.KECCAK256,
			SignatureAlgorithm.ECDSA,
			testName,
		);
	});

	it('should handle multiple future sign requests with shared DWallet', async () => {
		const testName = 'shared-dwallet-multi-future-sign-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName);

		await requestTestFaucetFunds(signerAddress);

		// Create shared DWallet through complete DKG process
		const { dwalletID } = await requestTestDKGFirstRound(
			ikaClient,
			suiClient,
			signerAddress,
			testName,
		);

		await delay(5);

		await registerTestEncryptionKey(ikaClient, suiClient, userShareEncryptionKeys, testName);

		const dWallet = await retryUntil(
			() =>
				ikaClient.getDWalletInParticularState(dwalletID, 'AwaitingUserDKGVerificationInitiation'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		const dkgSecondRoundRequestInput = await prepareDKGSecondRoundAsync(
			ikaClient,
			dWallet,
			userShareEncryptionKeys,
		);

		const secondRoundMoveResponse = await requestTestDkgSecondRound(
			ikaClient,
			suiClient,
			dWallet,
			dkgSecondRoundRequestInput,
			userShareEncryptionKeys,
			testName,
		);

		const awaitingKeyHolderSignatureDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(dwalletID, 'AwaitingKeyHolderSignature'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		await acceptTestEncryptedUserShare(
			ikaClient,
			suiClient,
			awaitingKeyHolderSignatureDWallet as ZeroTrustDWallet,
			dkgSecondRoundRequestInput.userPublicOutput,
			secondRoundMoveResponse,
			userShareEncryptionKeys,
			testName,
		);

		const activeDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(dwalletID, 'Active'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		const encryptedUserSecretKeyShare = await retryUntil(
			() =>
				ikaClient.getEncryptedUserSecretKeyShare(
					secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
				),
			(share) => share !== null,
			30,
			2000,
		);

		const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
			activeDWallet,
			encryptedUserSecretKeyShare,
			await ikaClient.getProtocolPublicParameters(activeDWallet),
		);

		// Make shares public
		await makeTestDWalletUserSecretKeySharesPublic(
			ikaClient,
			suiClient,
			activeDWallet as ZeroTrustDWallet,
			secretShare,
			testName,
		);

		await delay(5);

		const sharedDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(activeDWallet.id.id, 'Active'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		// Create multiple future sign requests
		const messages = [
			createTestMessage(testName, '-shared-future-message-1'),
			createTestMessage(testName, '-shared-future-message-2'),
		];

		const futureSignRequests: any[] = [];
		const presignObjects: any[] = [];

		// Create presigns and future sign requests for each message
		for (let i = 0; i < messages.length; i++) {
			// Create presign
			const presignRequestEvent = await testPresign(
				ikaClient,
				suiClient,
				sharedDWallet,
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
			const futureSignRequest = await requestTestSharedFutureSign(
				ikaClient,
				suiClient,
				sharedDWallet as SharedDWallet,
				presignObject,
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
				sharedDWallet,
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

	it('should handle future signing with different hash schemes for shared DWallet', async () => {
		const testName = 'shared-dwallet-future-sign-hash-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName);

		await requestTestFaucetFunds(signerAddress);

		// Create shared DWallet through complete DKG process
		const { dwalletID } = await requestTestDKGFirstRound(
			ikaClient,
			suiClient,
			signerAddress,
			testName,
		);

		await delay(5);

		await registerTestEncryptionKey(ikaClient, suiClient, userShareEncryptionKeys, testName);

		const dWallet = await retryUntil(
			() =>
				ikaClient.getDWalletInParticularState(dwalletID, 'AwaitingUserDKGVerificationInitiation'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		const dkgSecondRoundRequestInput = await prepareDKGSecondRoundAsync(
			ikaClient,
			dWallet,
			userShareEncryptionKeys,
		);

		const secondRoundMoveResponse = await requestTestDkgSecondRound(
			ikaClient,
			suiClient,
			dWallet,
			dkgSecondRoundRequestInput,
			userShareEncryptionKeys,
			testName,
		);

		const awaitingKeyHolderSignatureDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(dwalletID, 'AwaitingKeyHolderSignature'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		await acceptTestEncryptedUserShare(
			ikaClient,
			suiClient,
			awaitingKeyHolderSignatureDWallet as ZeroTrustDWallet,
			dkgSecondRoundRequestInput.userPublicOutput,
			secondRoundMoveResponse,
			userShareEncryptionKeys,
			testName,
		);

		const activeDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(dwalletID, 'Active'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		const encryptedUserSecretKeyShare = await retryUntil(
			() =>
				ikaClient.getEncryptedUserSecretKeyShare(
					secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
				),
			(share) => share !== null,
			30,
			2000,
		);

		const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
			activeDWallet,
			encryptedUserSecretKeyShare,
			await ikaClient.getProtocolPublicParameters(activeDWallet),
		);

		// Make shares public
		await makeTestDWalletUserSecretKeySharesPublic(
			ikaClient,
			suiClient,
			activeDWallet as ZeroTrustDWallet,
			secretShare,
			testName,
		);

		await delay(5);

		const sharedDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(activeDWallet.id.id, 'Active'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		// Test future signing with different hash schemes
		const hashSchemes = [Hash.KECCAK256, Hash.SHA256];
		const message = createTestMessage(testName);

		for (const hashScheme of hashSchemes) {
			// Create presign
			const presignRequestEvent = await testPresign(
				ikaClient,
				suiClient,
				sharedDWallet,
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
			const futureSignRequest = await requestTestSharedFutureSign(
				ikaClient,
				suiClient,
				sharedDWallet as SharedDWallet,
				presignObject,
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
				sharedDWallet,
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
