// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { prepareDKGSecondRoundAsync } from '../../src/client/cryptography';
import { Hash, SignatureAlgorithm } from '../../src/client/types';
import {
	acceptTestEncryptedUserShare,
	makeTestDWalletUserSecretKeySharesPublic,
	registerTestEncryptionKey,
	requestTestDKGFirstRound,
	requestTestDkgSecondRound,
	testPresign,
	testSignPublicUserShare,
} from '../helpers/dwallet-test-helpers';
import {
	createTestIkaClient,
	createTestMessage,
	createTestSuiClient,
	DEFAULT_TIMEOUT,
	delay,
	generateTestKeypair,
	requestTestFaucetFunds,
	retryUntil,
} from '../helpers/test-utils';

describe('Shared DWallet Signing (public user shares)', () => {
	it(
		'should sign a message using public user shares',
		async () => {
			const testName = 'dwallet-sharing-sign-test';
			const suiClient = createTestSuiClient();
			const ikaClient = createTestIkaClient(suiClient);
			await ikaClient.initialize();

			const { userShareEncryptionKeys, signerAddress } = generateTestKeypair(testName);

			await requestTestFaucetFunds(signerAddress);

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
				sessionIdentifierPreimage,
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
				awaitingKeyHolderSignatureDWallet,
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

			await makeTestDWalletUserSecretKeySharesPublic(
				ikaClient,
				suiClient,
				activeDWallet,
				secretShare,
				testName,
			);

			await delay(5);

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

			const message = createTestMessage(testName);

			const sharedDWallet = await retryUntil(
				() => ikaClient.getDWalletInParticularState(activeDWallet.id.id, 'Active'),
				(wallet) => wallet !== null,
				30,
				2000,
			);

			await testSignPublicUserShare(
				ikaClient,
				suiClient,
				sharedDWallet,
				presignObject,
				message,
				Hash.KECCAK256,
				SignatureAlgorithm.ECDSA,
				testName,
			);

			expect(true).toBe(true);
		},
	);
});
