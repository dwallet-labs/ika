import { Transaction } from '@mysten/sui/transactions';
import { describe, expect, it } from 'vitest';

import {
	CoordinatorInnerModule,
	createRandomSessionIdentifier,
	Curve,
	prepareDKGAsync,
	SessionsManagerModule,
	ZeroTrustDWallet,
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

describe('DWallet Creation', () => {
	it('should create a new zero trust DWallet through the complete DKG v2 process - Secp256k1', async () => {
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
		});

		destroyEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig, emptyIKACoin);

		expect(dWalletCap).toBeDefined();

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

	it('should create a new zero trust DWallet through the complete DKG v2 process - Secp256r1', async () => {
		const testName = 'dwallet-creation-dkg-v2-test-secp256r1';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(
			testName,
			Curve.SECP256R1,
		);

		await requestTestFaucetFunds(signerAddress);

		const randomSessionIdentifier = createRandomSessionIdentifier();

		const { encryptedUserShareAndProof, userDKGMessage, userPublicOutput, userSecretKeyShare } =
			await prepareDKGAsync(
				ikaClient,
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
			curve: Curve.SECP256R1,
			dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
			ikaCoin: emptyIKACoin,
			suiCoin: suiTransaction.gas,
			sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
		});

		destroyEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig, emptyIKACoin);

		expect(dWalletCap).toBeDefined();

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

	it('should create a new zero trust DWallet through the complete DKG v2 process - Ed25519', async () => {
		const testName = 'dwallet-creation-dkg-v2-test-ed25519';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(
			testName,
			Curve.ED25519,
		);

		await requestTestFaucetFunds(signerAddress);

		const randomSessionIdentifier = createRandomSessionIdentifier();

		const { encryptedUserShareAndProof, userDKGMessage, userPublicOutput, userSecretKeyShare } =
			await prepareDKGAsync(
				ikaClient,
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
			curve: Curve.ED25519,
			dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
			ikaCoin: emptyIKACoin,
			suiCoin: suiTransaction.gas,
			sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
		});

		destroyEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig, emptyIKACoin);

		expect(dWalletCap).toBeDefined();

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

	it('should create a new zero trust DWallet through the complete DKG v2 process - Ristretto', async () => {
		const testName = 'dwallet-creation-dkg-v2-test-ristretto';
		const suiClient = createTestSuiClient();
		const ikaClient = createTestIkaClient(suiClient);
		await ikaClient.initialize();

		const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(
			testName,
			Curve.RISTRETTO,
		);

		await requestTestFaucetFunds(signerAddress);

		const randomSessionIdentifier = createRandomSessionIdentifier();

		const { encryptedUserShareAndProof, userDKGMessage, userPublicOutput, userSecretKeyShare } =
			await prepareDKGAsync(
				ikaClient,
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
			curve: Curve.RISTRETTO,
			dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
			ikaCoin: emptyIKACoin,
			suiCoin: suiTransaction.gas,
			sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
		});

		destroyEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig, emptyIKACoin);

		expect(dWalletCap).toBeDefined();

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
