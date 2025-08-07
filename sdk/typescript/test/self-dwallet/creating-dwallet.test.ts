import { describe, expect, it } from 'vitest';

import { prepareDKGSecondRoundAsync } from '../../src/client/cryptography';
import {
	acceptTestEncryptedUserShare,
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

describe('DWallet Creation', () => {
	it(
		'should create a new DWallet through the complete DKG process',
		async () => {
			const testName = 'dwallet-creation-test';
			const suiClient = createTestSuiClient();
			const ikaClient = createTestIkaClient(suiClient);
			await ikaClient.initialize();

			// Generate deterministic keypair for this test
			const { userShareEncryptionKeys, signerPublicKey, signerAddress } =
				generateTestKeypair(testName);

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
			const preparedSecondRound = await prepareDKGSecondRoundAsync(
				ikaClient,
				dWallet,
				sessionIdentifierPreimage,
				userShareEncryptionKeys,
			);

			expect(preparedSecondRound).toBeDefined();
			expect(preparedSecondRound.centralizedSecretKeyShare).toBeInstanceOf(Uint8Array);
			expect(preparedSecondRound.centralizedPublicOutput).toBeDefined();

			// Step 5: Request DKG second round
			const secondRoundMoveResponse = await requestTestDkgSecondRound(
				ikaClient,
				suiClient,
				dWallet,
				preparedSecondRound,
				userShareEncryptionKeys,
				signerPublicKey,
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
			await acceptTestEncryptedUserShare(
				ikaClient,
				suiClient,
				awaitingKeyHolderSignatureDWallet,
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
			expect(finalDWallet.id).toBe(dwalletID);
		},
		DEFAULT_TIMEOUT,
	);

	it(
		'should create multiple DWallets with different deterministic seeds',
		async () => {
			const testName1 = 'dwallet-creation-multi-test-1';
			const testName2 = 'dwallet-creation-multi-test-2';
			const suiClient = createTestSuiClient();
			const ikaClient = createTestIkaClient(suiClient);
			await ikaClient.initialize();

			// Generate different keypairs for each test
			const keypair1 = generateTestKeypair(testName1);
			const keypair2 = generateTestKeypair(testName2);

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
		},
		DEFAULT_TIMEOUT,
	);
});
