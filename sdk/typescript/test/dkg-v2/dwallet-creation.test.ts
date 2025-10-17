import { Transaction } from '@mysten/sui/transactions';
import { describe, expect, it } from 'vitest';

import {
	CoordinatorInnerModule,
	createRandomSessionIdentifier,
	Curve,
	prepareDKGAsync,
	SessionsManagerModule,
} from '../../src';
import {
	createEmptyTestIkaToken,
	createTestIkaClient,
	createTestIkaTransaction,
	createTestSuiClient,
	destroyEmptyTestIkaToken,
	executeTestTransaction,
	generateTestKeypair,
	requestTestFaucetFunds,
	retryUntil,
} from '../helpers/test-utils';
import { runCompleteDKGFlow } from './helpers';

describe('DWallet Creation', () => {
	it('should create a new zero trust DWallet through the complete DKG v2 process - Secp256k1', async () => {
		await runCompleteDKGFlow('dwallet-creation-dkg-v2-test-secp256k1', Curve.SECP256K1);
	});

	it('should create a new zero trust DWallet through the complete DKG v2 process - Secp256r1', async () => {
		await runCompleteDKGFlow('dwallet-creation-dkg-v2-test-secp256r1', Curve.SECP256R1);
	});

	it('should create a new zero trust DWallet through the complete DKG v2 process - Ed25519', async () => {
		await runCompleteDKGFlow('dwallet-creation-dkg-v2-test-ed25519', Curve.ED25519);
	});

	it('should create a new zero trust DWallet through the complete DKG v2 process - Ristretto', async () => {
		await runCompleteDKGFlow('dwallet-creation-dkg-v2-test-ristretto', Curve.RISTRETTO);
	});

	it('should create a new shared DWallet through the complete DKG v2 process', async () => {
		const testName = 'dwallet-creation-dkg-v2-test';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName);

		await requestTestFaucetFunds(signerAddress);

		const randomSessionIdentifier = createRandomSessionIdentifier();

		const { encryptedUserShareAndProof, userDKGMessage, userPublicOutput, userSecretKeyShare } =
			await prepareDKGAsync(
				ikaClient,
				Curve.SECP256K1,
				userShareEncryptionKeys,
				randomSessionIdentifier,
				signerAddress,
			);

		expect(encryptedUserShareAndProof).toBeDefined();
		expect(userDKGMessage).toBeDefined();
		expect(userPublicOutput).toBeDefined();
		expect(userSecretKeyShare).toBeDefined();

		const suiTransaction = new Transaction();

		const ikaTransaction = createTestIkaTransaction(
			ikaClient,
			suiTransaction,
			userShareEncryptionKeys,
		);

		const latestNetworkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

		expect(latestNetworkEncryptionKey).toBeDefined();

		const emptyIKACoin = createEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig);

		const [dWalletCap] = await ikaTransaction.requestDWalletDKGWithPublicUserShare({
			publicKeyShareAndProof: userDKGMessage,
			publicUserSecretKeyShare: userSecretKeyShare,
			userPublicOutput: userPublicOutput,
			curve: Curve.SECP256K1,
			dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
			ikaCoin: emptyIKACoin,
			suiCoin: suiTransaction.gas,
			sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
		});

		suiTransaction.transferObjects([dWalletCap], signerAddress);

		destroyEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig, emptyIKACoin);

		const result = await executeTestTransaction(suiClient, suiTransaction, testName);

		const dkgEvent = result.events?.find((event) => {
			return (
				event.type.includes('DWalletDKGRequestEvent') && event.type.includes('DWalletSessionEvent')
			);
		});

		expect(dkgEvent).toBeDefined();

		const parsedDkgEvent = SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.DWalletDKGRequestEvent,
		).fromBase64(dkgEvent?.bcs as string);

		expect(parsedDkgEvent).toBeDefined();

		const dWalletID = parsedDkgEvent.event_data.dwallet_id;

		expect(dWalletID).toBeDefined();

		const activeDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(dWalletID, 'Active'),
			(wallet) => wallet !== null,
			30,
			1000,
		);

		expect(activeDWallet).toBeDefined();
		expect(activeDWallet.state.$kind).toBe('Active');
		expect(activeDWallet.id.id).toBe(dWalletID);
	});
});
