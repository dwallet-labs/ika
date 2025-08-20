// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { prepareImportDWalletVerification } from '../../src/client/cryptography';
import { Curve, ImportedKeyDWallet } from '../../src/client/types';
import {
	acceptTestEncryptedUserShare,
	createTestSessionIdentifier,
	registerTestEncryptionKey,
	requestTestImportedKeyDWalletVerification,
} from '../helpers/dwallet-test-helpers';
import {
	createTestIkaClient,
	createTestSuiClient,
	delay,
	generateTestKeypairForImportedKeyDWallet,
	requestTestFaucetFunds,
	retryUntil,
} from '../helpers/test-utils';

describe('Imported Key DWallet Creation', () => {
	it('should create an Imported Key DWallet and activate it', async () => {
		const testName = 'imported-dwallet-creation-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const { userShareEncryptionKeys, signerPublicKey, dWalletKeypair, signerAddress } =
			generateTestKeypairForImportedKeyDWallet(testName);

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
			await requestTestImportedKeyDWalletVerification(
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
			awaitingKeyHolderSignatureDWallet as ImportedKeyDWallet,
			importDWalletVerificationRequestInput.userPublicOutput,
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
					importedKeyDWalletVerificationRequestEvent.event_data.encrypted_user_secret_key_share_id,
				),
			(share) => share !== null,
			30,
			1000,
		);

		expect(encryptedUserSecretKeyShare).toBeDefined();
		expect(encryptedUserSecretKeyShare.dwallet_id).toBe(
			importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
		);

		// Additional validations for successful creation
		expect(activeDWallet.id).toBeDefined();
		expect(activeDWallet.id.id).toBe(
			importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
		);
		expect(encryptedUserSecretKeyShare.id).toBeDefined();
		expect(encryptedUserSecretKeyShare.encryption_key_address).toBeDefined();
	});

	it('should handle different session identifier inputs correctly', async () => {
		const testName = 'session-identifier-edge-cases-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const { userShareEncryptionKeys, dWalletKeypair, signerAddress } =
			generateTestKeypairForImportedKeyDWallet(testName);

		await requestTestFaucetFunds(signerAddress);

		await registerTestEncryptionKey(ikaClient, suiClient, userShareEncryptionKeys, testName);

		// Test with all zeros session identifier - should work (as evidenced by test output)
		const zeroSessionIdentifierPreimage = new Uint8Array(32).fill(0);
		const verificationInput = await prepareImportDWalletVerification(
			ikaClient,
			zeroSessionIdentifierPreimage,
			userShareEncryptionKeys,
			dWalletKeypair,
		);

		// Validate that the function returns proper structure even with edge case input
		expect(verificationInput).toBeDefined();
		expect(verificationInput.userPublicOutput).toBeDefined();
		expect(verificationInput.userPublicOutput).toBeInstanceOf(Uint8Array);
		expect(verificationInput.userPublicOutput.length).toBeGreaterThan(0);

		// Test with maximum values session identifier
		const maxSessionIdentifierPreimage = new Uint8Array(32).fill(255);
		const verificationInput2 = await prepareImportDWalletVerification(
			ikaClient,
			maxSessionIdentifierPreimage,
			userShareEncryptionKeys,
			dWalletKeypair,
		);

		expect(verificationInput2).toBeDefined();
		expect(verificationInput2.userPublicOutput).toBeDefined();

		// Different session identifiers should produce different outputs
		expect(verificationInput.userPublicOutput).not.toEqual(verificationInput2.userPublicOutput);
	});

	it('should handle invalid keypair gracefully', async () => {
		const testName = 'invalid-keypair-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const { userShareEncryptionKeys, signerAddress } =
			generateTestKeypairForImportedKeyDWallet(testName);

		await requestTestFaucetFunds(signerAddress);

		const { sessionIdentifier, sessionIdentifierPreimage } = await createTestSessionIdentifier(
			ikaClient,
			suiClient,
			signerAddress,
			testName,
		);

		await delay(3);

		await registerTestEncryptionKey(ikaClient, suiClient, userShareEncryptionKeys, testName);

		// This should fail when trying to use uninitialized keypair
		await expect(
			prepareImportDWalletVerification(
				ikaClient,
				sessionIdentifierPreimage,
				userShareEncryptionKeys,
				null as any, // Invalid keypair
			),
		).rejects.toThrow();
	});

	it('should validate DWallet state transitions correctly', async () => {
		const testName = 'state-validation-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const { userShareEncryptionKeys, signerPublicKey, dWalletKeypair, signerAddress } =
			generateTestKeypairForImportedKeyDWallet(testName);

		await requestTestFaucetFunds(signerAddress);

		const { sessionIdentifier, sessionIdentifierPreimage } = await createTestSessionIdentifier(
			ikaClient,
			suiClient,
			signerAddress,
			testName,
		);

		await delay(3);

		await registerTestEncryptionKey(ikaClient, suiClient, userShareEncryptionKeys, testName);

		const importDWalletVerificationRequestInput = await prepareImportDWalletVerification(
			ikaClient,
			sessionIdentifierPreimage,
			userShareEncryptionKeys,
			dWalletKeypair,
		);

		// Validate verification request input structure
		expect(importDWalletVerificationRequestInput).toBeDefined();
		expect(importDWalletVerificationRequestInput.userPublicOutput).toBeDefined();
		expect(typeof importDWalletVerificationRequestInput).toBe('object');

		await delay(3);

		const importedKeyDWalletVerificationRequestEvent =
			await requestTestImportedKeyDWalletVerification(
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

		// Validate event structure
		expect(importedKeyDWalletVerificationRequestEvent.event_data).toBeDefined();
		expect(importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id).toMatch(
			/^0x[a-f0-9]+$/,
		);
		expect(
			importedKeyDWalletVerificationRequestEvent.event_data.encrypted_user_secret_key_share_id,
		).toMatch(/^0x[a-f0-9]+$/);

		// Verify DWallet is in correct initial state
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

		expect(awaitingKeyHolderSignatureDWallet.state.$kind).toBe('AwaitingKeyHolderSignature');
		expect(awaitingKeyHolderSignatureDWallet.id.id).toBe(
			importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
		);

		// Test that DWallet cannot be retrieved in wrong state
		const incorrectStateDWallet = await ikaClient
			.getDWalletInParticularState(
				importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
				'Active',
			)
			.catch(() => null);
		expect(incorrectStateDWallet).toBeNull(); // Should not be Active yet
	});
});
