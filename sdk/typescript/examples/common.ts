// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// @ts-ignore
import { randomBytes } from 'crypto';
import { toHex } from '@mysten/bcs';
import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Secp256k1Keypair } from '@mysten/sui/keypairs/secp256k1';
import type { TransactionObjectArgument } from '@mysten/sui/transactions';
import { Transaction } from '@mysten/sui/transactions';

import type {
	DKGSecondRoundRequestInput,
	ImportDWalletVerificationRequestInput,
} from '../src/client/cryptography.js';
import { IkaClient, IkaTransaction } from '../src/client/index.js';
import { getNetworkConfig } from '../src/client/network-configs.js';
import {
	Curve,
	DWallet,
	EncryptedUserSecretKeyShare,
	EncryptionKey,
	Hash,
	IkaConfig,
	PartialUserSignature,
	Presign,
	SignatureAlgorithm,
} from '../src/client/types.js';
import { UserShareEncrytionKeys } from '../src/client/user-share-encryption-keys.js';
import * as CoordinatorInnerModule from '../src/generated/ika_dwallet_2pc_mpc/coordinator_inner.js';
import * as SessionsManagerModule from '../src/generated/ika_dwallet_2pc_mpc/sessions_manager.js';

export function createSuiClient() {
	return new SuiClient({
		url: 'https://fullnode.testnet.sui.io:443',
	});
}

export function createIkaClient(suiClient: SuiClient) {
	return new IkaClient({
		suiClient,
		network: 'testnet',
		config: getNetworkConfig('testnet'),
	});
}

export async function executeTransaction(suiClient: SuiClient, transaction: Transaction) {
	return suiClient.signAndExecuteTransaction({
		transaction,
		signer: Ed25519Keypair.deriveKeypairFromSeed('0x1'),
		options: {
			showEvents: true,
		},
	});
}

export function generateKeypair() {
	const seed = new Uint8Array(randomBytes(32));
	const userKeypair = Ed25519Keypair.deriveKeypairFromSeed(toHex(new Uint8Array(randomBytes(32))));

	const userShareEncryptionKeys = UserShareEncrytionKeys.fromRootSeedKey(seed);

	return {
		userShareEncryptionKeys,
		signerAddress: userKeypair.getPublicKey().toSuiAddress(),
		signerPublicKey: userKeypair.getPublicKey().toRawBytes(),
	};
}

export function generateKeypairForImportedDWallet() {
	const seed = new Uint8Array(32).fill(8);
	const userKeypair = Ed25519Keypair.deriveKeypairFromSeed('0x1');

	const userShareEncryptionKeys = UserShareEncrytionKeys.fromRootSeedKey(seed);

	const dWalletKeypair = Secp256k1Keypair.deriveKeypair(userKeypair.getSecretKey());

	return {
		userShareEncryptionKeys,
		dWalletKeypair,
		signerAddress: userKeypair.getPublicKey().toSuiAddress(),
		signerPublicKey: userKeypair.getPublicKey().toRawBytes(),
	};
}

export async function requestDKGFirstRound(
	ikaClient: IkaClient,
	suiClient: SuiClient,
): Promise<{
	dwalletID: string;
	sessionIdentifierPreimage: Uint8Array;
}> {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestDWalletDKGFirstRoundAndTransferCapAsync({
		curve: 0,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
		receiver: '0x0',
	});

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTransaction(suiClient, transaction);

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

	return {
		dwalletID: dwalletID as string,
		sessionIdentifierPreimage: new Uint8Array(sessionIdentifierPreimage as number[]),
	};
}

export async function registerEncryptionKey(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncrytionKeys,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys,
	});

	await ikaTransaction.registerEncryptionKey({
		curve: Curve.SECP256K1,
	});

	const result = await executeTransaction(suiClient, transaction);

	const createdEncryptionKeyEvent = result.events?.find((event) => {
		return event.type.includes('CreatedEncryptionKeyEvent');
	});

	return CoordinatorInnerModule.CreatedEncryptionKeyEvent.fromBase64(
		createdEncryptionKeyEvent?.bcs as string,
	);
}

export async function requestDkgSecondRound(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	dkgSecondRoundRequestInput: DKGSecondRoundRequestInput,
	userShareEncryptionKeys: UserShareEncrytionKeys,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.requestDWalletDKGSecondRound({
		dWallet,
		dkgSecondRoundRequestInput,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTransaction(suiClient, transaction);

	const dkgSecondRoundRequestEvent = result.events?.find((event) => {
		return (
			event.type.includes('DWalletDKGSecondRoundRequestEvent') &&
			event.type.includes('DWalletSessionEvent')
		);
	});

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletDKGSecondRoundRequestEvent,
	).fromBase64(dkgSecondRoundRequestEvent?.bcs as string);
}

export async function acceptEncryptedUserShare(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	userPublicOutput: Uint8Array,
	secondRoundMoveResponse: {
		event_data: {
			encrypted_user_secret_key_share_id: string;
		};
	},
	userShareEncryptionKeys: UserShareEncrytionKeys,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys,
	});

	await ikaTransaction.acceptEncryptedUserShare({
		dWallet,
		userPublicOutput,
		encryptedUserSecretKeyShareId:
			secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
	});

	await executeTransaction(suiClient, transaction);
}

export async function acceptEncryptedUserShareForTransferredDWallet(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	destinationUserShareEncryptionKeys: UserShareEncrytionKeys,
	sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	sourceEncryptionKey: EncryptionKey,
	destinationEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys: destinationUserShareEncryptionKeys,
	});

	await ikaTransaction.acceptEncryptedUserShareForTransferredDWallet({
		dWallet,
		sourceEncryptedUserSecretKeyShare,
		sourceEncryptionKey,
		destinationEncryptedUserSecretKeyShare,
	});

	await executeTransaction(suiClient, transaction);
}

export async function makeDWalletUserSecretKeySharesPublic(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	secretShare: Uint8Array,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.makeDWalletUserSecretKeySharesPublic({
		dWallet,
		secretShare,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTransaction(suiClient, transaction);
}

export async function makeImportedDWalletUserSecretKeySharesPublic(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	secretShare: Uint8Array,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.makeDWalletUserSecretKeySharesPublic({
		dWallet,
		secretShare,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTransaction(suiClient, transaction);
}

export async function presign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	signatureAlgorithm: SignatureAlgorithm,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.requestPresignAndTransferCap({
		dWallet,
		signatureAlgorithm,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
		receiver: '0x0',
	});

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTransaction(suiClient, transaction);

	const presignRequestEvent = result.events?.find((event) => {
		return event.type.includes('PresignRequestEvent') && event.type.includes('DWalletSessionEvent');
	});

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.PresignRequestEvent,
	).fromBase64(presignRequestEvent?.bcs as string);
}

export async function sign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	userShareEncryptionKeys: UserShareEncrytionKeys,
	presign: Presign,
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys,
	});

	const { messageApproval } = ikaTransaction.approveMessage({
		dWallet,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

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

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTransaction(suiClient, transaction);
}

export async function signPublicUserShare(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	presign: Presign,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	const { messageApproval } = ikaTransaction.approveMessage({
		dWallet,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

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

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTransaction(suiClient, transaction);
}

export async function requestFutureSign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	presign: Presign,
	userShareEncryptionKeys: UserShareEncrytionKeys,
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	message: Uint8Array,
	hashScheme: Hash,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys,
	});

	const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestFutureSignAndTransferCap({
		dWallet,
		presign,
		verifiedPresignCap,
		encryptedUserSecretKeyShare,
		message,
		hashScheme,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
		receiver: '0x0',
	});

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTransaction(suiClient, transaction);

	const futureSignRequestEvent = result.events?.find((event) => {
		return (
			event.type.includes('FutureSignRequestEvent') && event.type.includes('DWalletSessionEvent')
		);
	});

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.FutureSignRequestEvent,
	).fromBase64(futureSignRequestEvent?.bcs as string);
}

export async function futureSign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	partialUserSignature: PartialUserSignature,
	userShareEncryptionKeys: UserShareEncrytionKeys,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys,
	});

	const { messageApproval } = ikaTransaction.approveMessage({
		dWallet,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.futureSign({
		messageApproval,
		partialUserSignature,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTransaction(suiClient, transaction);
}

export async function requestImportedDWalletVerification(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	importDWalletVerificationRequestInput: ImportDWalletVerificationRequestInput,
	curve: Curve,
	signerPublicKey: Uint8Array,
	sessionIdentifier: string,
	receiver: string,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestImportedDWalletVerificationAndTransferCap({
		importDWalletVerificationRequestInput,
		curve,
		signerPublicKey,
		sessionIdentifier,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
		receiver,
	});

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTransaction(suiClient, transaction);

	const importedKeyDWalletVerificationRequestEvent = result.events?.find((event) => {
		return event.type.includes('ImportedKeyDWalletVerificationRequestEvent');
	});

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletImportedKeyVerificationRequestEvent,
	).fromBase64(importedKeyDWalletVerificationRequestEvent?.bcs as string);
}

export async function signWithImportedDWallet(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	presign: Presign,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	userShareEncryptionKeys: UserShareEncrytionKeys,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys,
	});

	const { importedKeyMessageApproval } = ikaTransaction.approveImportedKeyMessage({
		dWallet,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

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

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTransaction(suiClient, transaction);
}

export async function signWithImportedDWalletPublic(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	presign: Presign,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	const { importedKeyMessageApproval } = ikaTransaction.approveImportedKeyMessage({
		dWallet,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const { verifiedPresignCap } = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

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

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTransaction(suiClient, transaction);
}

export async function transferEncryptedUserShare(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	destinationEncryptionKeyAddress: string,
	sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	userShareEncryptionKeys: UserShareEncrytionKeys,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.transferUserShare({
		dWallet,
		destinationEncryptionKeyAddress,
		sourceEncryptedUserSecretKeyShare,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTransaction(suiClient, transaction);

	const transferUserShareEvent = result.events?.find((event) => {
		return event.type.includes('EncryptedShareVerificationRequestEvent');
	});

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.EncryptedShareVerificationRequestEvent,
	).fromBase64(transferUserShareEvent?.bcs as string);
}

export async function createSessionIdentifier(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	receiver: string,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	const sessionIdentifier = ikaTransaction.createSessionIdentifier();

	transaction.transferObjects([sessionIdentifier], receiver);

	const result = await executeTransaction(suiClient, transaction);

	const sessionIdentifierRegisteredEvent = result.events?.find((event) => {
		return event.type.includes('SessionIdentifierRegisteredEvent');
	});

	const sessionIdentifierRegisteredEventParsed =
		SessionsManagerModule.UserSessionIdentifierRegisteredEvent.fromBase64(
			sessionIdentifierRegisteredEvent?.bcs as string,
		);

	return {
		sessionIdentifier: sessionIdentifierRegisteredEventParsed.session_object_id,
		sessionIdentifierPreimage: new Uint8Array(
			sessionIdentifierRegisteredEventParsed.session_identifier_preimage,
		),
	};
}

export function createEmptyIkaToken(tx: Transaction, ikaConfig: IkaConfig) {
	return tx.moveCall({
		target: `0x2::coin::zero`,
		arguments: [],
		typeArguments: [`${ikaConfig.packages.ikaPackage}::ika::IKA`],
	});
}

export function destroyEmptyIkaToken(
	tx: Transaction,
	ikaConfig: IkaConfig,
	ikaToken: TransactionObjectArgument,
) {
	return tx.moveCall({
		target: `0x2::coin::destroy_zero`,
		arguments: [ikaToken],
		typeArguments: [`${ikaConfig.packages.ikaPackage}::ika::IKA`],
	});
}
