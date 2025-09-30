// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { prepareDKGSecondRoundAsync } from '../../src/client/cryptography';
import { ZeroTrustDWallet } from '../../src/client/types';
import {
	acceptTestEncryptedUserShare,
	createCompleteDWalletV2,
	makeTestDWalletUserSecretKeySharesPublic,
	registerTestEncryptionKey,
	requestTestDKGFirstRound,
	requestTestDkgSecondRound,
} from '../helpers/dwallet-test-helpers';
import {
	createTestIkaClient,
	createTestSuiClient,
	delay,
	generateTestKeypair,
	requestTestFaucetFunds,
	retryUntil,
} from '../helpers/test-utils';

describe('Shared DWallet (make shares public)', () => {
	it('should make user secret key shares public after DWallet activation', async () => {
		const testName = 'dwallet-sharing-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName);

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

		// Type assertion: DKG flow only creates ZeroTrust DWallets
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

		await makeTestDWalletUserSecretKeySharesPublic(
			ikaClient,
			suiClient,
			activeDWallet as ZeroTrustDWallet,
			secretShare,
			testName,
		);
	});

	it('should make user secret key shares public after v2 DWallet activation', async () => {
		const testName = 'dwallet-sharing-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName);

		await requestTestFaucetFunds(signerAddress);

		const { dWallet: activeDWallet, encryptedUserSecretKeyShare } = await createCompleteDWalletV2(ikaClient, suiClient, testName);

		const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
			activeDWallet,
			encryptedUserSecretKeyShare,
			await ikaClient.getProtocolPublicParameters(activeDWallet),
		);

		await makeTestDWalletUserSecretKeySharesPublic(
			ikaClient,
			suiClient,
			activeDWallet as ZeroTrustDWallet,
			secretShare,
			testName,
		);
	});
});
