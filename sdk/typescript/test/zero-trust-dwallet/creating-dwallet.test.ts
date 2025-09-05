// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Transaction } from '@mysten/sui/transactions';
import { describe, expect, it } from 'vitest';

import { SessionsManagerModule } from '../../src';
import {
	prepareDKGAsync,
	prepareDKGSecondRoundAsync,
	sessionIdentifierDigest,
} from '../../src/client/cryptography';
import { ZeroTrustDWallet } from '../../src/client/types';
import {
	acceptTestEncryptedUserShare,
	registerTestEncryptionKey,
	requestTestDkg,
	requestTestDKGFirstRound,
	requestTestDkgSecondRound,
} from '../helpers/dwallet-test-helpers';
import {
	createEmptyTestIkaToken,
	createTestIkaClient,
	createTestIkaTransaction,
	createTestSuiClient,
	delay,
	destroyEmptyTestIkaToken,
	executeTestTransaction,
	generateTestKeypair,
	requestTestFaucetFunds,
	retryUntil,
} from '../helpers/test-utils';

describe('DWallet Creation', () => {
	it('should create a new DWallet through the complete DKG process', async () => {
		const testName = 'dwallet-creation-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		// Generate deterministic keypair for this test
		const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName);

		// Request faucet funds for the test address
		await requestTestFaucetFunds(signerAddress);

		// Step 1: Request DKG first round
		const { dwalletID, sessionIdentifierPreimage } = await requestTestDKGFirstRound(
			ikaClient,
			suiClient,
			signerAddress,
			testName,
		);

		await delay(5); // Wait for 5 seconds to ensure the DWallet is created

		expect(dwalletID).toBeDefined();
		expect(dwalletID).toHaveLength(66); // Standard object ID length
		expect(sessionIdentifierPreimage).toBeInstanceOf(Uint8Array);
		expect(sessionIdentifierPreimage.length).toBeGreaterThan(0);

		// Step 2: Register encryption key
		const encryptionKeyEvent = await registerTestEncryptionKey(
			ikaClient,
			suiClient,
			userShareEncryptionKeys,
			testName,
		);

		expect(encryptionKeyEvent).toBeDefined();
		expect(encryptionKeyEvent.encryption_key_id).toBeDefined();

		// Step 3: Wait for DWallet to be in AwaitingUserDKGVerificationInitiation state
		const dWallet = await retryUntil(
			() =>
				ikaClient.getDWalletInParticularState(dwalletID, 'AwaitingUserDKGVerificationInitiation'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		expect(dWallet).toBeDefined();
		expect(dWallet.state.$kind).toBe('AwaitingUserDKGVerificationInitiation');

		// Step 4: Prepare DKG second round
		const dkgSecondRoundRequestInput = await prepareDKGSecondRoundAsync(
			ikaClient,
			dWallet,
			userShareEncryptionKeys,
		);

		expect(dkgSecondRoundRequestInput).toBeDefined();
		expect(dkgSecondRoundRequestInput.encryptedUserShareAndProof).toBeInstanceOf(Uint8Array);
		expect(dkgSecondRoundRequestInput.userDKGMessage).toBeInstanceOf(Uint8Array);
		expect(dkgSecondRoundRequestInput.userPublicOutput).toBeDefined();

		// Step 5: Request DKG second round
		const secondRoundMoveResponse = await requestTestDkgSecondRound(
			ikaClient,
			suiClient,
			dWallet,
			dkgSecondRoundRequestInput,
			userShareEncryptionKeys,
			testName,
		);

		expect(secondRoundMoveResponse).toBeDefined();
		expect(secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id).toBeDefined();

		// Step 6: Wait for DWallet to be AwaitingKeyHolderSignature
		const awaitingKeyHolderSignatureDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(dwalletID, 'AwaitingKeyHolderSignature'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		expect(awaitingKeyHolderSignatureDWallet).toBeDefined();
		expect(awaitingKeyHolderSignatureDWallet.state.$kind).toBe('AwaitingKeyHolderSignature');

		// Step 7: Accept encrypted user share
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

		// Step 8: Wait for DWallet to be Active
		const activeDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(dwalletID, 'Active'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		expect(activeDWallet).toBeDefined();
		expect(activeDWallet.state.$kind).toBe('Active');

		// Verify the encrypted user secret key share exists and is accessible
		const encryptedUserSecretKeyShare = await retryUntil(
			() =>
				ikaClient.getEncryptedUserSecretKeyShare(
					secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
				),
			(share) => share !== null,
			30,
			1000,
		);

		expect(encryptedUserSecretKeyShare).toBeDefined();
		expect(encryptedUserSecretKeyShare.dwallet_id).toBe(dwalletID);

		// Final verification: DWallet should still be active and fully functional
		const finalDWallet = await ikaClient.getDWalletInParticularState(dwalletID, 'Active');
		expect(finalDWallet).toBeDefined();
		expect(finalDWallet.state.$kind).toBe('Active');
		expect(finalDWallet.id.id).toBe(dwalletID);
	});

	it('should create a new DWallet through the v2 one round DKG process', async () => {
		const testName = 'dwallet-creation-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		// Generate deterministic keypair for this test
		const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName);

		// Request faucet funds for the test address
		await requestTestFaucetFunds(signerAddress);

		// Step 2: Register encryption key
		const encryptionKeyEvent = await registerTestEncryptionKey(
			ikaClient,
			suiClient,
			userShareEncryptionKeys,
			testName,
		);

		expect(encryptionKeyEvent).toBeDefined();
		expect(encryptionKeyEvent.encryption_key_id).toBeDefined();

		const createSessionIDTx = new Transaction();
		const createSessionIDIkaTx = createTestIkaTransaction(
			ikaClient,
			createSessionIDTx,
			userShareEncryptionKeys,
		);
		createSessionIDIkaTx.createSessionIdentifier();
		const registerSessionIDResult = await executeTestTransaction(
			suiClient,
			createSessionIDTx,
			testName,
		);
		let registeredSessionIDEvent = registerSessionIDResult.events?.find((event) => {
			return event.type.includes('UserSessionIdentifierRegisteredEvent');
		});
		let parsedEvent = SessionsManagerModule.UserSessionIdentifierRegisteredEvent.fromBase64(
			registeredSessionIDEvent?.bcs as string,
		);

		// Step 4: Prepare network DKG input
		const dkgSecondRoundRequestInput = await prepareDKGAsync(
			ikaClient,
			userShareEncryptionKeys,
			sessionIdentifierDigest(Uint8Array.from(parsedEvent.session_identifier_preimage)),
		);

		expect(dkgSecondRoundRequestInput).toBeDefined();
		expect(dkgSecondRoundRequestInput.encryptedUserShareAndProof).toBeInstanceOf(Uint8Array);
		expect(dkgSecondRoundRequestInput.userDKGMessage).toBeInstanceOf(Uint8Array);
		expect(dkgSecondRoundRequestInput.userPublicOutput).toBeDefined();

		// Step 5: Request DKG chain round
		const secondRoundMoveResponse = await requestTestDkg(
			ikaClient,
			suiClient,
			dkgSecondRoundRequestInput,
			userShareEncryptionKeys,
			testName,
			parsedEvent.session_object_id,
		);

		expect(secondRoundMoveResponse).toBeDefined();
		expect(secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id).toBeDefined();

		// Step 6: Wait for DWallet to be Active
		const dwalletID = secondRoundMoveResponse.event_data.dwallet_id;
		const finalDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(dwalletID, 'Active'),
			(wallet) => wallet !== null,
			30,
			2000,
		);

		// Step 7: Accept encrypted user share
		// Type assertion: DKG flow only creates ZeroTrust DWallets
		await acceptTestEncryptedUserShare(
			ikaClient,
			suiClient,
			finalDWallet as ZeroTrustDWallet,
			dkgSecondRoundRequestInput.userPublicOutput,
			secondRoundMoveResponse,
			userShareEncryptionKeys,
			testName,
		);

		// Verify the encrypted user secret key share exists and is accessible
		const encryptedUserSecretKeyShare = await retryUntil(
			() =>
				ikaClient.getEncryptedUserSecretKeyShare(
					secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
				),
			(share) => share !== null,
			30,
			1000,
		);

		expect(encryptedUserSecretKeyShare).toBeDefined();
		expect(encryptedUserSecretKeyShare.dwallet_id).toBe(dwalletID);

		expect(finalDWallet).toBeDefined();
		expect(finalDWallet.state.$kind).toBe('Active');
		expect(finalDWallet.id.id).toBe(dwalletID);
	});

	it('should create multiple DWallets with different deterministic seeds', async () => {
		const testName1 = 'dwallet-creation-multi-test-1';
		const testName2 = 'dwallet-creation-multi-test-2';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		// Generate different keypairs for each test
		const keypair1 = await generateTestKeypair(testName1);
		const keypair2 = await generateTestKeypair(testName2);

		// Verify the keypairs are different
		expect(keypair1.signerAddress).not.toBe(keypair2.signerAddress);
		expect(keypair1.signerPublicKey).not.toEqual(keypair2.signerPublicKey);

		// Request faucet funds for both addresses
		await requestTestFaucetFunds(keypair1.signerAddress);
		await requestTestFaucetFunds(keypair2.signerAddress);

		// Create first DWallet
		const { dwalletID: dwalletID1 } = await requestTestDKGFirstRound(
			ikaClient,
			suiClient,
			keypair1.signerAddress,
			testName1,
		);

		// Create second DWallet
		const { dwalletID: dwalletID2 } = await requestTestDKGFirstRound(
			ikaClient,
			suiClient,
			keypair2.signerAddress,
			testName2,
		);

		// Verify the DWallets have different IDs
		expect(dwalletID1).not.toBe(dwalletID2);
		expect(dwalletID1).toBeDefined();
		expect(dwalletID2).toBeDefined();
	});
});
