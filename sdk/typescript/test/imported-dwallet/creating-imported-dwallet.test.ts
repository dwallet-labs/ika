// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { prepareImportDWalletVerification } from '../../src/client/cryptography';
import { Curve } from '../../src/client/types';
import {
	acceptTestEncryptedUserShare,
	createTestSessionIdentifier,
	registerTestEncryptionKey,
	requestTestImportedDWalletVerification,
} from '../helpers/dwallet-test-helpers';
import {
	createTestIkaClient,
	createTestSuiClient,
	DEFAULT_TIMEOUT,
	delay,
	generateTestKeypairForImportedDWallet,
	requestTestFaucetFunds,
	retryUntil,
} from '../helpers/test-utils';

describe('Imported DWallet Creation', () => {
	it(
		'should create an imported DWallet and activate it',
		async () => {
			const testName = 'imported-dwallet-creation-test';
			const suiClient = createTestSuiClient();
			const ikaClient = createTestIkaClient(suiClient);
			await ikaClient.initialize();

			const { userShareEncryptionKeys, signerPublicKey, dWalletKeypair, signerAddress } =
				generateTestKeypairForImportedDWallet(testName);

			await requestTestFaucetFunds(signerAddress);

			const { sessionIdentifier, sessionIdentifierPreimage } = await createTestSessionIdentifier(
				ikaClient,
				suiClient,
				signerAddress,
				testName,
			);

			await delay(3);

			await registerTestEncryptionKey(ikaClient, suiClient, userShareEncryptionKeys, testName);

			await delay(3);

			const importDWalletVerificationRequestInput = await prepareImportDWalletVerification(
				ikaClient,
				sessionIdentifierPreimage,
				userShareEncryptionKeys,
				dWalletKeypair,
			);

			const importedKeyDWalletVerificationRequestEvent =
				await requestTestImportedDWalletVerification(
					ikaClient,
					suiClient,
					importDWalletVerificationRequestInput,
					Curve.SECP256K1,
					signerPublicKey,
					sessionIdentifier,
					userShareEncryptionKeys,
					signerAddress,
					testName,
				);

			expect(importedKeyDWalletVerificationRequestEvent).toBeDefined();
			expect(importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id).toBeDefined();

			const awaitingKeyHolderSignatureDWallet = await retryUntil(
				() =>
					ikaClient.getDWalletInParticularState(
						importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
						'AwaitingKeyHolderSignature',
					),
				(wallet) => wallet !== null,
				30,
				2000,
			);

			expect(awaitingKeyHolderSignatureDWallet).toBeDefined();
			expect(awaitingKeyHolderSignatureDWallet.state.$kind).toBe('AwaitingKeyHolderSignature');

			await acceptTestEncryptedUserShare(
				ikaClient,
				suiClient,
				awaitingKeyHolderSignatureDWallet,
				importedKeyDWalletVerificationRequestEvent,
				userShareEncryptionKeys,
				testName,
			);

			const activeDWallet = await retryUntil(
				() =>
					ikaClient.getDWalletInParticularState(
						importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
						'Active',
					),
				(wallet) => wallet !== null,
				30,
				2000,
			);

			expect(activeDWallet).toBeDefined();
			expect(activeDWallet.state.$kind).toBe('Active');

			const encryptedUserSecretKeyShare = await retryUntil(
				() =>
					ikaClient.getEncryptedUserSecretKeyShare(
						importedKeyDWalletVerificationRequestEvent.event_data
							.encrypted_user_secret_key_share_id,
					),
				(share) => share !== null,
				30,
				1000,
			);

			expect(encryptedUserSecretKeyShare).toBeDefined();
			expect(encryptedUserSecretKeyShare.dwallet_id).toBe(
				importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
			);
		},
		DEFAULT_TIMEOUT,
	);
});
