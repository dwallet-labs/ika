// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { prepareImportDWalletVerification } from '../../src/client/cryptography';
import { Curve, Hash, SignatureAlgorithm } from '../../src/client/types';
import {
	acceptTestEncryptedUserShare,
	createTestSessionIdentifier,
	registerTestEncryptionKey,
	requestTestImportedDWalletVerification,
	testPresign,
	testSignWithImportedDWallet,
} from '../helpers/dwallet-test-helpers';
import {
	createTestIkaClient,
	createTestMessage,
	createTestSuiClient,
	DEFAULT_TIMEOUT,
	delay,
	generateTestKeypairForImportedDWallet,
	requestTestFaucetFunds,
	retryUntil,
} from '../helpers/test-utils';

describe('Imported DWallet Signing', () => {
	it(
		'should create an imported DWallet and sign a message',
		async () => {
			const testName = 'imported-dwallet-sign-test';
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

			await testSignWithImportedDWallet(
				ikaClient,
				suiClient,
				activeDWallet,
				presignObject,
				message,
				Hash.KECCAK256,
				SignatureAlgorithm.ECDSA,
				encryptedUserSecretKeyShare,
				userShareEncryptionKeys,
				testName,
			);

			expect(true).toBe(true);
		},
		DEFAULT_TIMEOUT,
	);
});
