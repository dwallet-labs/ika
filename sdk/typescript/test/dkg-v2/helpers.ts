import { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { expect } from 'vitest';

import {
	CoordinatorInnerModule,
	createRandomSessionIdentifier,
	Curve,
	Hash,
	IkaClient,
	prepareDKGAsync,
	Presign,
	SessionsManagerModule,
	SignatureAlgorithm,
	ZeroTrustDWallet,
} from '../../src';
import { UserShareEncryptionKeys } from '../../src/client/user-share-encryption-keys';
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

export interface DKGTestSetup {
	suiClient: SuiClient;
	ikaClient: IkaClient;
	userShareEncryptionKeys: UserShareEncryptionKeys;
	signerAddress: string;
	testName: string;
}

export interface DKGPrepareResult {
	encryptedUserShareAndProof: Uint8Array;
	userDKGMessage: Uint8Array;
	userPublicOutput: Uint8Array;
	userSecretKeyShare: Uint8Array;
	randomSessionIdentifier: Uint8Array;
}

export interface DKGExecuteResult {
	dWalletID: string;
	encryptedUserSecretKeyShareId: string;
	userPublicOutput: number[];
}

export async function setupDKGTest(testName: string, curve: Curve): Promise<DKGTestSetup> {
	const suiClient = createTestSuiClient();
	const ikaClient = createTestIkaClient(suiClient);
	await ikaClient.initialize();

	const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName, curve);

	await requestTestFaucetFunds(signerAddress);

	return {
		suiClient,
		ikaClient,
		userShareEncryptionKeys,
		signerAddress,
		testName,
	};
}

export async function prepareDKG(
	ikaClient: IkaClient,
	curve: Curve,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	signerAddress: string,
): Promise<DKGPrepareResult> {
	const randomSessionIdentifier = createRandomSessionIdentifier();

	const { encryptedUserShareAndProof, userDKGMessage, userPublicOutput, userSecretKeyShare } =
		await prepareDKGAsync(
			ikaClient,
			curve,
			userShareEncryptionKeys,
			randomSessionIdentifier,
			signerAddress,
		);

	expect(encryptedUserShareAndProof).toBeDefined();
	expect(userDKGMessage).toBeDefined();
	expect(userPublicOutput).toBeDefined();
	expect(userSecretKeyShare).toBeDefined();

	return {
		encryptedUserShareAndProof,
		userDKGMessage,
		userPublicOutput,
		userSecretKeyShare,
		randomSessionIdentifier,
	};
}

export async function requestPresignForDKG(
	setup: DKGTestSetup,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
): Promise<Presign> {
	const { suiClient, ikaClient, userShareEncryptionKeys, signerAddress, testName } = setup;

	const suiTransaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(
		ikaClient,
		suiTransaction,
		userShareEncryptionKeys,
	);

	const ikaToken = createEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig);
	const latestNetworkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

	const unverifiedPresignCap = ikaTransaction.requestGlobalPresign({
		curve,
		signatureAlgorithm,
		ikaCoin: ikaToken,
		suiCoin: suiTransaction.gas,
		dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
	});

	suiTransaction.transferObjects([unverifiedPresignCap], signerAddress);
	destroyEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig, ikaToken);

	const result = await executeTestTransaction(suiClient, suiTransaction, testName);

	const presignEvent = result.events?.find((event) => event.type.includes('PresignRequestEvent'));
	expect(presignEvent).toBeDefined();

	const parsedPresignEvent = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.PresignRequestEvent,
	).fromBase64(presignEvent?.bcs as string);

	const presign = await retryUntil(
		() =>
			ikaClient.getPresignInParticularState(parsedPresignEvent.event_data.presign_id, 'Completed'),
		(presign) => presign !== null,
		30,
		2000,
	);

	expect(presign).toBeDefined();
	expect(presign.state.$kind).toBe('Completed');

	return presign;
}

export async function executeDKGRequest(
	setup: DKGTestSetup,
	dkgPrepare: DKGPrepareResult,
	curve: Curve,
	signDuringDKGOptions?: {
		presign: Presign;
		message: Buffer;
		hashScheme: Hash;
		signatureAlgorithm: SignatureAlgorithm;
	},
): Promise<DKGExecuteResult> {
	const { suiClient, ikaClient, userShareEncryptionKeys, signerAddress, testName } = setup;
	const {
		encryptedUserShareAndProof,
		userDKGMessage,
		userPublicOutput,
		userSecretKeyShare,
		randomSessionIdentifier,
	} = dkgPrepare;

	const suiTransaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(
		ikaClient,
		suiTransaction,
		userShareEncryptionKeys,
	);

	const latestNetworkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();
	expect(latestNetworkEncryptionKey).toBeDefined();

	await ikaTransaction.registerEncryptionKey({ curve });

	const emptyIKACoin = createEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig);

	const [dWalletCap, _] = await ikaTransaction.requestDWalletDKG({
		dkgRequestInput: {
			userDKGMessage,
			encryptedUserShareAndProof,
			userPublicOutput,
			userSecretKeyShare,
		},
		curve,
		dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
		ikaCoin: emptyIKACoin,
		suiCoin: suiTransaction.gas,
		sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
		...(signDuringDKGOptions && {
			signDuringDKGRequest: {
				hashScheme: signDuringDKGOptions.hashScheme,
				message: signDuringDKGOptions.message,
				verifiedPresignCap: ikaTransaction.verifyPresignCap({
					presign: signDuringDKGOptions.presign,
				}),
				signatureAlgorithm: signDuringDKGOptions.signatureAlgorithm,
				presign: signDuringDKGOptions.presign,
			},
		}),
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

	const encryptedUserSecretKeyShareId =
		parsedDkgEvent.event_data.user_secret_key_share.Encrypted?.encrypted_user_secret_key_share_id;
	expect(encryptedUserSecretKeyShareId).toBeDefined();

	return {
		dWalletID,
		encryptedUserSecretKeyShareId: encryptedUserSecretKeyShareId as string,
		userPublicOutput: parsedDkgEvent.event_data.user_public_output as number[],
	};
}

export async function waitForDWalletAwaitingSignature(
	ikaClient: IkaClient,
	dWalletID: string,
): Promise<ZeroTrustDWallet> {
	const awaitingKeyHolderSignatureDWallet = await retryUntil(
		() => ikaClient.getDWalletInParticularState(dWalletID, 'AwaitingKeyHolderSignature'),
		(wallet) => wallet !== null,
		30,
		1000,
	);

	expect(awaitingKeyHolderSignatureDWallet).toBeDefined();
	expect(awaitingKeyHolderSignatureDWallet.state.$kind).toBe('AwaitingKeyHolderSignature');
	expect(awaitingKeyHolderSignatureDWallet.id.id).toBe(dWalletID);

	return awaitingKeyHolderSignatureDWallet as ZeroTrustDWallet;
}

export async function acceptUserShareAndActivate(
	setup: DKGTestSetup,
	dWalletID: string,
	encryptedUserSecretKeyShareId: string,
	userPublicOutput: number[],
	awaitingKeyHolderSignatureDWallet: ZeroTrustDWallet,
): Promise<ZeroTrustDWallet> {
	const { suiClient, ikaClient, userShareEncryptionKeys, testName } = setup;

	const encryptedUserSecretKeyShare = await retryUntil(
		() => ikaClient.getEncryptedUserSecretKeyShare(encryptedUserSecretKeyShareId),
		(share) => share !== null,
		30,
		1000,
	);

	expect(encryptedUserSecretKeyShare).toBeDefined();
	expect(encryptedUserSecretKeyShare.dwallet_id).toBe(dWalletID);

	const suiTransaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(
		ikaClient,
		suiTransaction,
		userShareEncryptionKeys,
	);

	await ikaTransaction.acceptEncryptedUserShare({
		dWallet: awaitingKeyHolderSignatureDWallet,
		encryptedUserSecretKeyShareId: encryptedUserSecretKeyShare.id.id,
		userPublicOutput: new Uint8Array(userPublicOutput),
	});

	await executeTestTransaction(suiClient, suiTransaction, testName);

	const activeDWallet = await retryUntil(
		() => ikaClient.getDWalletInParticularState(dWalletID, 'Active'),
		(wallet) => wallet !== null,
		30,
		1000,
	);

	expect(activeDWallet).toBeDefined();
	expect(activeDWallet.state.$kind).toBe('Active');
	expect(activeDWallet.id.id).toBe(dWalletID);

	return activeDWallet as ZeroTrustDWallet;
}

export async function runCompleteDKGFlow(
	testName: string,
	curve: Curve,
	signDuringDKGOptions?: {
		message: Buffer;
		hashScheme: Hash;
		signatureAlgorithm: SignatureAlgorithm;
	},
): Promise<void> {
	const setup = await setupDKGTest(testName, curve);
	const dkgPrepare = await prepareDKG(
		setup.ikaClient,
		curve,
		setup.userShareEncryptionKeys,
		setup.signerAddress,
	);

	let presign: Presign | undefined;
	if (signDuringDKGOptions) {
		presign = await requestPresignForDKG(setup, curve, signDuringDKGOptions.signatureAlgorithm);
	}

	const dkgResult = await executeDKGRequest(
		setup,
		dkgPrepare,
		curve,
		presign
			? {
					presign,
					message: signDuringDKGOptions!.message,
					hashScheme: signDuringDKGOptions!.hashScheme,
					signatureAlgorithm: signDuringDKGOptions!.signatureAlgorithm,
				}
			: undefined,
	);

	const awaitingDWallet = await waitForDWalletAwaitingSignature(
		setup.ikaClient,
		dkgResult.dWalletID,
	);

	await acceptUserShareAndActivate(
		setup,
		dkgResult.dWalletID,
		dkgResult.encryptedUserSecretKeyShareId,
		dkgResult.userPublicOutput,
		awaitingDWallet,
	);
}

export async function runCompleteSharedDKGFlow(testName: string, curve: Curve): Promise<void> {
	const setup = await setupDKGTest(testName, curve);
	const { suiClient, ikaClient, userShareEncryptionKeys, signerAddress } = setup;

	const randomSessionIdentifier = createRandomSessionIdentifier();

	const { encryptedUserShareAndProof, userDKGMessage, userPublicOutput, userSecretKeyShare } =
		await prepareDKGAsync(
			ikaClient,
			curve,
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
		curve: curve,
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
}

export async function runCompleteSharedDKGFlowWithSign(
	testName: string,
	curve: Curve,
	signDuringDKGOptions: {
		message: Buffer;
		hashScheme: Hash;
		signatureAlgorithm: SignatureAlgorithm;
	},
): Promise<void> {
	const setup = await setupDKGTest(testName, curve);
	const { suiClient, ikaClient, userShareEncryptionKeys, signerAddress } = setup;

	const presign = await requestPresignForDKG(setup, curve, signDuringDKGOptions.signatureAlgorithm);

	const randomSessionIdentifier = createRandomSessionIdentifier();

	const { encryptedUserShareAndProof, userDKGMessage, userPublicOutput, userSecretKeyShare } =
		await prepareDKGAsync(
			ikaClient,
			curve,
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

	const [dWalletCap, signatureCap] = await ikaTransaction.requestDWalletDKGWithPublicUserShare({
		publicKeyShareAndProof: userDKGMessage,
		publicUserSecretKeyShare: userSecretKeyShare,
		userPublicOutput: userPublicOutput,
		curve: curve,
		dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
		ikaCoin: emptyIKACoin,
		suiCoin: suiTransaction.gas,
		sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
		signDuringDKGRequest: {
			hashScheme: signDuringDKGOptions.hashScheme,
			message: signDuringDKGOptions.message,
			verifiedPresignCap: ikaTransaction.verifyPresignCap({
				presign: presign,
			}),
			signatureAlgorithm: signDuringDKGOptions.signatureAlgorithm,
			presign: presign,
		},
	});

	suiTransaction.transferObjects([dWalletCap, signatureCap], signerAddress);

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
}

export async function runGlobalPresignTest(
	testName: string,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
): Promise<void> {
	const suiClient = createTestSuiClient();
	const ikaClient = createTestIkaClient(suiClient);
	await ikaClient.initialize();

	const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName, curve);

	await requestTestFaucetFunds(signerAddress);

	const suiTransaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(
		ikaClient,
		suiTransaction,
		userShareEncryptionKeys,
	);

	const emptyIKACoin = createEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig);
	const latestNetworkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

	const unverifiedPresignCap = ikaTransaction.requestGlobalPresign({
		dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
		curve: curve,
		signatureAlgorithm: signatureAlgorithm,
		ikaCoin: emptyIKACoin,
		suiCoin: suiTransaction.gas,
	});

	destroyEmptyTestIkaToken(suiTransaction, ikaClient.ikaConfig, emptyIKACoin);

	suiTransaction.transferObjects([unverifiedPresignCap], signerAddress);

	const result = await executeTestTransaction(suiClient, suiTransaction, testName);

	const presignEvent = result.events?.find((event) => {
		return event.type.includes('PresignRequestEvent') && event.type.includes('DWalletSessionEvent');
	});

	expect(presignEvent).toBeDefined();

	const parsedPresignEvent = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.PresignRequestEvent,
	).fromBase64(presignEvent?.bcs as string);

	expect(parsedPresignEvent).toBeDefined();
	expect(parsedPresignEvent.event_data.presign_id).toBeDefined();

	const presign = await retryUntil(
		() =>
			ikaClient.getPresignInParticularState(parsedPresignEvent.event_data.presign_id, 'Completed'),
		(presign) => presign !== null,
		30,
		2000,
	);

	expect(presign).toBeDefined();
	expect(presign.state.$kind).toBe('Completed');
}
