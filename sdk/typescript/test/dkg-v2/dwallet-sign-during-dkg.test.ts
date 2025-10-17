import { Transaction } from '@mysten/sui/transactions';
import { describe, expect, it } from 'vitest';

import {
	CoordinatorInnerModule,
	createRandomSessionIdentifier,
	Curve,
	Hash,
	prepareDKGAsync,
	SessionsManagerModule,
	SignatureAlgorithm,
	ZeroTrustDWallet,
} from '../../src';
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
	it('should sign during DKG v2 for a new zero trust DWallet - Secp256k1', async () => {
		const testName = 'dwallet-creation-dkg-v2-test-secp256k1';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(
			testName,
			Curve.SECP256K1,
		);

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

		const suiTransaction0 = new Transaction();

		const ikaTransaction0 = createTestIkaTransaction(
			ikaClient,
			suiTransaction0,
			userShareEncryptionKeys,
		);

		const ikaToken2 = createEmptyTestIkaToken(suiTransaction0, ikaClient.ikaConfig);

		const latestNetworkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

		const unverifiedPresignCap = ikaTransaction0.requestGlobalPresign({
			curve: Curve.SECP256K1,
			signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
			ikaCoin: ikaToken2,
			suiCoin: suiTransaction0.gas,
			dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
		});

		suiTransaction0.transferObjects([unverifiedPresignCap], signerAddress);

		destroyEmptyTestIkaToken(suiTransaction0, ikaClient.ikaConfig, ikaToken2);

		const result0 = await executeTestTransaction(suiClient, suiTransaction0, testName);

		const presignEvent = result0.events?.find((event) => {
			return event.type.includes('PresignRequestEvent');
		});

		expect(presignEvent).toBeDefined();

		const parsedPresignEvent = SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.PresignRequestEvent,
		).fromBase64(presignEvent?.bcs as string);

		const presign = await retryUntil(
			() =>
				ikaClient.getPresignInParticularState(
					parsedPresignEvent.event_data.presign_id,
					'Completed',
				),
			(presign) => presign !== null,
			30,
			2000,
		);

		expect(presign).toBeDefined();
		expect(presign.state.$kind).toBe('Completed');

		const suiTransaction = new Transaction();

		const ikaTransaction = createTestIkaTransaction(
			ikaClient,
			suiTransaction,
			userShareEncryptionKeys,
		);

		await ikaTransaction.registerEncryptionKey({
			curve: Curve.SECP256K1,
		});

		const emptyIKACoin = createEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig);

		const [dWalletCap, _] = await ikaTransaction.requestDWalletDKG({
			dkgRequestInput: {
				userDKGMessage,
				encryptedUserShareAndProof,
				userPublicOutput,
				userSecretKeyShare,
			},
			curve: Curve.SECP256K1,
			dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
			ikaCoin: emptyIKACoin,
			suiCoin: suiTransaction.gas,
			sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
			signDuringDKGRequest: {
				hashScheme: Hash.SHA256,
				message: Buffer.from('test message'),
				signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
				presign,
			},
		});

		destroyEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig, emptyIKACoin);

		suiTransaction.transferObjects([dWalletCap], signerAddress);

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

		const awaitingKeyHolderSignatureDWallet = await retryUntil(
			() => ikaClient.getDWalletInParticularState(dWalletID, 'AwaitingKeyHolderSignature'),
			(wallet) => wallet !== null,
			30,
			1000,
		);

		expect(awaitingKeyHolderSignatureDWallet).toBeDefined();
		expect(awaitingKeyHolderSignatureDWallet.state.$kind).toBe('AwaitingKeyHolderSignature');
		expect(awaitingKeyHolderSignatureDWallet.id.id).toBe(dWalletID);
		expect(
			parsedDkgEvent.event_data.user_secret_key_share.Encrypted?.encrypted_user_secret_key_share_id,
		).toBeDefined();

		const encryptedUserSecretKeyShare = await retryUntil(
			() =>
				ikaClient.getEncryptedUserSecretKeyShare(
					parsedDkgEvent.event_data.user_secret_key_share.Encrypted
						?.encrypted_user_secret_key_share_id as string,
				),
			(share) => share !== null,
			30,
			1000,
		);

		expect(encryptedUserSecretKeyShare).toBeDefined();
		expect(encryptedUserSecretKeyShare.dwallet_id).toBe(dWalletID);

		const suiTransaction2 = new Transaction();
		const ikaTransaction2 = createTestIkaTransaction(
			ikaClient,
			suiTransaction2,
			userShareEncryptionKeys,
		);

		await ikaTransaction2.acceptEncryptedUserShare({
			dWallet: awaitingKeyHolderSignatureDWallet as ZeroTrustDWallet,
			encryptedUserSecretKeyShareId: encryptedUserSecretKeyShare.id.id,
			userPublicOutput: new Uint8Array(parsedDkgEvent.event_data.user_public_output as number[]),
		});

		await executeTestTransaction(suiClient, suiTransaction2, testName);

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

	// it('should create a new shared DWallet through the complete DKG v2 process', async () => {
	// 	const testName = 'dwallet-creation-dkg-v2-test';
	// 	const suiClient = createTestSuiClient();
	// 	const ikaClient = createTestIkaClient(suiClient);
	// 	await ikaClient.initialize();

	// 	const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName);

	// 	await requestTestFaucetFunds(signerAddress);

	// 	const randomSessionIdentifier = createRandomSessionIdentifier();

	// 	const { encryptedUserShareAndProof, userDKGMessage, userPublicOutput, userSecretKeyShare } =
	// 		await prepareDKGAsync(
	// 			ikaClient,
	// 			userShareEncryptionKeys,
	// 			randomSessionIdentifier,
	// 			signerAddress,
	// 		);

	// 	expect(encryptedUserShareAndProof).toBeDefined();
	// 	expect(userDKGMessage).toBeDefined();
	// 	expect(userPublicOutput).toBeDefined();
	// 	expect(userSecretKeyShare).toBeDefined();

	// 	const suiTransaction = new Transaction();

	// 	const ikaTransaction = createTestIkaTransaction(
	// 		ikaClient,
	// 		suiTransaction,
	// 		userShareEncryptionKeys,
	// 	);

	// 	const latestNetworkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

	// 	expect(latestNetworkEncryptionKey).toBeDefined();

	// 	const emptyIKACoin = createEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig);

	// 	const [dWalletCap] = await ikaTransaction.requestDWalletDKGWithPublicUserShare({
	// 		publicKeyShareAndProof: userDKGMessage,
	// 		publicUserSecretKeyShare: userSecretKeyShare,
	// 		userPublicOutput: userPublicOutput,
	// 		curve: Curve.SECP256K1,
	// 		dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
	// 		ikaCoin: emptyIKACoin,
	// 		suiCoin: suiTransaction.gas,
	// 		sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
	// 	});

	// 	suiTransaction.transferObjects([dWalletCap], signerAddress);

	// 	destroyEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig, emptyIKACoin);

	// 	const result = await executeTestTransaction(suiClient, suiTransaction, testName);

	// 	const dkgEvent = result.events?.find((event) => {
	// 		return (
	// 			event.type.includes('DWalletDKGRequestEvent') && event.type.includes('DWalletSessionEvent')
	// 		);
	// 	});

	// 	expect(dkgEvent).toBeDefined();

	// 	const parsedDkgEvent = SessionsManagerModule.DWalletSessionEvent(
	// 		CoordinatorInnerModule.DWalletDKGRequestEvent,
	// 	).fromBase64(dkgEvent?.bcs as string);

	// 	expect(parsedDkgEvent).toBeDefined();

	// 	const dWalletID = parsedDkgEvent.event_data.dwallet_id;

	// 	expect(dWalletID).toBeDefined();

	// 	const activeDWallet = await retryUntil(
	// 		() => ikaClient.getDWalletInParticularState(dWalletID, 'Active'),
	// 		(wallet) => wallet !== null,
	// 		30,
	// 		1000,
	// 	);

	// 	expect(activeDWallet).toBeDefined();
	// 	expect(activeDWallet.state.$kind).toBe('Active');
	// 	expect(activeDWallet.id.id).toBe(dWalletID);
	// });
});
