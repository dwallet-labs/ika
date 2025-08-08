// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { prepareDKGSecondRoundAsync } from '../../src/client/cryptography';
import {
	acceptTestEncryptedUserShare,
	makeTestDWalletUserSecretKeySharesPublic,
	registerTestEncryptionKey,
	requestTestDKGFirstRound,
	requestTestDkgSecondRound,
} from '../helpers/dwallet-test-helpers';
import {
	createTestIkaClient,
	createTestSuiClient,
	DEFAULT_TIMEOUT,
	delay,
	generateTestKeypair,
	requestTestFaucetFunds,
	retryUntil,
} from '../helpers/test-utils';

describe('Shared DWallet (make shares public)', () => {
	it(
		'should make user secret key shares public after DWallet activation',
		async () => {
			const testName = 'dwallet-sharing-test';
			const suiClient = createTestSuiClient();
			const ikaClient = createTestIkaClient(suiClient);
			await ikaClient.initialize();

			const { userShareEncryptionKeys, signerPublicKey, signerAddress } =
				generateTestKeypair(testName);

			await requestTestFaucetFunds(signerAddress);

			const { dwalletID, sessionIdentifierPreimage } = await requestTestDKGFirstRound(
				ikaClient,
				suiClient,
				signerAddress,
				testName,
			);

			await delay(5);

			await registerTestEncryptionKey(ikaClient, suiClient, userShareEncryptionKeys, testName);

			await delay(3);

			const dWallet = await retryUntil(
				() =>
					ikaClient.getDWalletInParticularState(dwalletID, 'AwaitingUserDKGVerificationInitiation'),
				(wallet) => wallet !== null,
				30,
				2000,
			);

			const preparedSecondRound = await prepareDKGSecondRoundAsync(
				ikaClient,
				dWallet,
				sessionIdentifierPreimage,
				userShareEncryptionKeys,
			);

			const secondRoundMoveResponse = await requestTestDkgSecondRound(
				ikaClient,
				suiClient,
				dWallet,
				preparedSecondRound,
				userShareEncryptionKeys,
				signerPublicKey,
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

			await makeTestDWalletUserSecretKeySharesPublic(
				ikaClient,
				suiClient,
				activeDWallet,
				await userShareEncryptionKeys.decryptUserShare(
					activeDWallet,
					encryptedUserSecretKeyShare,
					await ikaClient.getProtocolPublicParameters(),
				),
				testName,
			);

			expect(true).toBe(true);
		},
		DEFAULT_TIMEOUT,
	);
});
