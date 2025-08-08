import { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';

import { IkaClient } from '../../src/client';
import {
	PreparedImportDWalletVerification,
	prepareDKGSecondRoundAsync,
	PreparedSecondRound,
} from '../../src/client/cryptography';
import {
	Curve,
	DWallet,
	EncryptedUserSecretKeyShare,
	EncryptionKeyCurve,
	Hash,
	PartialUserSignature,
	Presign,
	SignatureAlgorithm,
} from '../../src/client/types';
import { UserShareEncrytionKeys } from '../../src/client/user-share-encryption-keys';
import * as CoordinatorInnerModule from '../../src/generated/ika_dwallet_2pc_mpc/coordinator_inner.js';
import * as SessionsManagerModule from '../../src/generated/ika_dwallet_2pc_mpc/sessions_manager.js';
import {
	createEmptyTestIkaToken,
	createTestIkaTransaction,
	delay,
	destroyEmptyTestIkaToken,
	executeTestTransaction,
	generateTestKeypair,
	requestTestFaucetFunds,
	retryUntil,
} from './test-utils';

/**
 * Complete DWallet creation process for testing.
 * This combines all the steps needed to create an active DWallet with an encrypted user share.
 */
export async function createCompleteDWallet(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	testName: string,
): Promise<{
	dWallet: DWallet;
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
	userShareEncryptionKeys: UserShareEncrytionKeys;
	signerPublicKey: Uint8Array;
	signerAddress: string;
}> {
	// Generate deterministic keypair for this test
	const { userShareEncryptionKeys, signerPublicKey, signerAddress } = generateTestKeypair(testName);

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

	// Step 2: Register encryption key
	await registerTestEncryptionKey(ikaClient, suiClient, userShareEncryptionKeys, testName);

	// Step 3: Wait for DWallet to be in AwaitingUserDKGVerificationInitiation state
	const dWallet = await retryUntil(
		() => ikaClient.getDWalletInParticularState(dwalletID, 'AwaitingUserDKGVerificationInitiation'),
		(wallet) => wallet !== null,
		30,
		2000,
	);

	// Step 4: Prepare DKG second round
	const preparedSecondRound = await prepareDKGSecondRoundAsync(
		ikaClient,
		dWallet,
		sessionIdentifierPreimage,
		userShareEncryptionKeys,
	);

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

	// Step 6: Wait for DWallet to be AwaitingKeyHolderSignature
	const awaitingKeyHolderSignatureDWallet = await retryUntil(
		() => ikaClient.getDWalletInParticularState(dwalletID, 'AwaitingKeyHolderSignature'),
		(wallet) => wallet !== null,
		30,
		2000,
	);

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

	// Step 9: Get the encrypted user secret key share
	const encryptedUserSecretKeyShare = await retryUntil(
		() =>
			ikaClient.getEncryptedUserSecretKeyShare(
				secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
			),
		(share) => share !== null,
		30,
		1000,
	);

	return {
		dWallet: activeDWallet,
		encryptedUserSecretKeyShare,
		userShareEncryptionKeys,
		signerPublicKey,
		signerAddress,
	};
}

/**
 * Request DKG first round for testinginitial_shared_version
 */
export async function requestTestDKGFirstRound(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	signerAddress: string,
	testName: string,
): Promise<{
	dwalletID: string;
	sessionIdentifierPreimage: Uint8Array;
}> {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestDWalletDKGFirstRoundAndKeepAsync({
		curve: 0,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
		receiver: signerAddress,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);

	const startDKGFirstRoundEvents = result.events
		?.map((event) =>
			event.type.includes('DWalletDKGFirstRoundRequestEvent') &&
			event.type.includes('DWalletSessionEvent')
				? SessionsManagerModule.DWalletSessionEvent(
						CoordinatorInnerModule.DWalletDKGFirstRoundRequestEvent,
					).fromBase64(event.bcs)
				: null,
		)
		.filter(Boolean);

	const dwalletID = startDKGFirstRoundEvents?.[0]?.event_data.dwallet_id;
	const sessionIdentifierPreimage = startDKGFirstRoundEvents?.[0]?.session_identifier_preimage;

	if (!dwalletID || !sessionIdentifierPreimage) {
		throw new Error(
			'Failed to extract DWallet ID or session identifier from DKG first round request',
		);
	}

	return {
		dwalletID: dwalletID as string,
		sessionIdentifierPreimage: new Uint8Array(sessionIdentifierPreimage as number[]),
	};
}

/**
 * Register encryption key for testing
 */
export async function registerTestEncryptionKey(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncrytionKeys,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	await ikaTransaction.registerEncryptionKey({
		curve: EncryptionKeyCurve.ED25519,
	});

	const result = await executeTestTransaction(suiClient, transaction, testName);

	const createdEncryptionKeyEvent = result.events?.find((event) => {
		return event.type.includes('CreatedEncryptionKeyEvent');
	});

	if (!createdEncryptionKeyEvent) {
		throw new Error('Failed to find CreatedEncryptionKeyEvent');
	}

	return CoordinatorInnerModule.CreatedEncryptionKeyEvent.fromBase64(
		createdEncryptionKeyEvent.bcs as string,
	);
}

/**
 * Request DKG second round for testing
 */
export async function requestTestDkgSecondRound(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	preparedSecondRound: PreparedSecondRound,
	userShareEncryptionKeys: UserShareEncrytionKeys,
	signerPublicKey: Uint8Array,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.requestDWalletDKGSecondRound({
		dWallet,
		preparedSecondRound,
		signerPublicKey,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);

	const dkgSecondRoundRequestEvent = result.events?.find((event) => {
		return (
			event.type.includes('DWalletDKGSecondRoundRequestEvent') &&
			event.type.includes('DWalletSessionEvent')
		);
	});

	if (!dkgSecondRoundRequestEvent) {
		throw new Error('Failed to find DWalletDKGSecondRoundRequestEvent');
	}

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletDKGSecondRoundRequestEvent,
	).fromBase64(dkgSecondRoundRequestEvent.bcs as string);
}

/**
 * Accept encrypted user share for testing
 */
export async function acceptTestEncryptedUserShare(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	secondRoundMoveResponse: {
		event_data: {
			encrypted_user_secret_key_share_id: string;
		};
	},
	userShareEncryptionKeys: UserShareEncrytionKeys,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	await ikaTransaction.acceptEncryptedUserShare({
		dWallet,
		encryptedUserSecretKeyShareId:
			secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
	});

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Make DWallet user secret key shares public for testing
 */
export async function makeTestDWalletUserSecretKeySharesPublic(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	secretShare: Uint8Array,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.makeDWalletUserSecretKeySharesPublic({
		dWallet,
		secretShare,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Make imported DWallet user secret key shares public for testing
 */
export async function makeTestImportedDWalletUserSecretKeySharesPublic(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	secretShare: Uint8Array,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.makeDWalletUserSecretKeySharesPublic({
		dWallet,
		secretShare,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Presign for testing
 */
export async function testPresign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	signatureAlgorithm: SignatureAlgorithm,
	signerAddress: string,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.presignAndKeep({
		dWallet,
		signatureAlgorithm,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
		receiver: signerAddress,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);

	const presignRequestEvent = result.events?.find((event) => {
		return event.type.includes('PresignRequestEvent') && event.type.includes('DWalletSessionEvent');
	});

	if (!presignRequestEvent) {
		throw new Error('Failed to find PresignRequestEvent');
	}

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.PresignRequestEvent,
	).fromBase64(presignRequestEvent.bcs as string);
}

/**
 * Sign for testing
 */
export async function testSign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	userShareEncryptionKeys: UserShareEncrytionKeys,
	presign: Presign,
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const { messageApproval } = ikaTransaction.approveMessage({
		dWallet,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.sign({
		dWallet,
		messageApproval,
		verifiedPresignCap,
		hashScheme,
		presign,
		encryptedUserSecretKeyShare,
		message,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Sign with public user share for testing
 */
export async function testSignPublicUserShare(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	presign: Presign,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const { messageApproval } = ikaTransaction.approveMessage({
		dWallet,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.signPublic({
		dWallet,
		messageApproval,
		verifiedPresignCap,
		presign,
		message,
		hashScheme,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Request future sign for testing
 */
export async function requestTestFutureSign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	presign: Presign,
	userShareEncryptionKeys: UserShareEncrytionKeys,
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	message: Uint8Array,
	hashScheme: Hash,
	signerAddress: string,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestFutureSignAndKeep({
		dWallet,
		presign,
		verifiedPresignCap,
		encryptedUserSecretKeyShare,
		message,
		hashScheme,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
		receiver: signerAddress,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);

	const futureSignRequestEvent = result.events?.find((event) => {
		return (
			event.type.includes('FutureSignRequestEvent') && event.type.includes('DWalletSessionEvent')
		);
	});

	if (!futureSignRequestEvent) {
		throw new Error('Failed to find FutureSignRequestEvent');
	}

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.FutureSignRequestEvent,
	).fromBase64(futureSignRequestEvent.bcs as string);
}

/**
 * Future sign for testing
 */
export async function testFutureSign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	partialUserSignature: PartialUserSignature,
	userShareEncryptionKeys: UserShareEncrytionKeys,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const { messageApproval } = ikaTransaction.approveMessage({
		dWallet,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.futureSign({
		messageApproval,
		partialUserSignature,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Request imported DWallet verification for testing
 */
export async function requestTestImportedDWalletVerification(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	preparedImportDWalletVerification: PreparedImportDWalletVerification,
	curve: Curve,
	signerPublicKey: Uint8Array,
	sessionIdentifier: string,
	userShareEncryptionKeys: UserShareEncrytionKeys,
	receiver: string,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestImportedDWalletVerificationAndKeep({
		preparedImportDWalletVerification,
		curve,
		signerPublicKey,
		sessionIdentifier,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
		receiver,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);

	const importedKeyDWalletVerificationRequestEvent = result.events?.find((event) => {
		return event.type.includes('DWalletImportedKeyVerificationRequestEvent');
	});

	if (!importedKeyDWalletVerificationRequestEvent) {
		throw new Error('Failed to find DWalletImportedKeyVerificationRequestEvent');
	}

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletImportedKeyVerificationRequestEvent,
	).fromBase64(importedKeyDWalletVerificationRequestEvent.bcs as string);
}

/**
 * Sign with imported DWallet for testing
 */
export async function testSignWithImportedDWallet(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	presign: Presign,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	userShareEncryptionKeys: UserShareEncrytionKeys,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const { importedKeyMessageApproval } = ikaTransaction.approveImportedKeyMessage({
		dWallet,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.signWithImportedDWallet({
		dWallet,
		encryptedUserSecretKeyShare,
		presign,
		hashScheme,
		message,
		importedKeyMessageApproval,
		verifiedPresignCap,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Sign with imported DWallet public for testing
 */
export async function testSignWithImportedDWalletPublic(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	presign: Presign,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const { importedKeyMessageApproval } = ikaTransaction.approveImportedKeyMessage({
		dWallet,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.signWithImportedDWalletPublic({
		dWallet,
		presign,
		hashScheme,
		message,
		importedKeyMessageApproval,
		verifiedPresignCap,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Transfer encrypted user share for testing
 */
export async function testTransferEncryptedUserShare(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	destinationSuiAddress: string,
	sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	userShareEncryptionKeys: UserShareEncrytionKeys,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.transferEncryptedUserShare({
		dWallet,
		destinationSuiAddress,
		sourceEncryptedUserSecretKeyShare,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Create session identifier for testing
 */
export async function createTestSessionIdentifier(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	receiver: string,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction);

	const sessionIdentifier = ikaTransaction.createSessionIdentifier();
	transaction.transferObjects([sessionIdentifier], receiver);

	const result = await executeTestTransaction(suiClient, transaction, testName);

	const sessionIdentifierRegisteredEvent = result.events?.find((event) => {
		return event.type.includes('SessionIdentifierRegisteredEvent');
	});

	if (!sessionIdentifierRegisteredEvent) {
		throw new Error('Failed to find SessionIdentifierRegisteredEvent');
	}

	const sessionIdentifierRegisteredEventParsed =
		SessionsManagerModule.UserSessionIdentifierRegisteredEvent.fromBase64(
			sessionIdentifierRegisteredEvent.bcs as string,
		);

	return {
		sessionIdentifier: sessionIdentifierRegisteredEventParsed.session_object_id,
		sessionIdentifierPreimage: new Uint8Array(
			sessionIdentifierRegisteredEventParsed.session_identifier_preimage,
		),
	};
}
