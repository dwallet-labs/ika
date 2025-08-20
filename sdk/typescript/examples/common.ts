// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { toHex } from '@mysten/bcs';
import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Secp256k1Keypair } from '@mysten/sui/keypairs/secp256k1';
import type { TransactionObjectArgument } from '@mysten/sui/transactions';
import { Transaction } from '@mysten/sui/transactions';
import { randomBytes } from '@noble/hashes/utils.js';

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
	ImportedKeyDWallet,
	ImportedSharedDWallet,
	PartialUserSignature,
	Presign,
	SharedDWallet,
	SignatureAlgorithm,
	ZeroTrustDWallet,
} from '../src/client/types.js';
import { UserShareEncryptionKeys } from '../src/client/user-share-encryption-keys.js';
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

	const userShareEncryptionKeys = UserShareEncryptionKeys.fromRootSeedKey(seed);

	return {
		userShareEncryptionKeys,
		signerAddress: userKeypair.getPublicKey().toSuiAddress(),
		signerPublicKey: userKeypair.getPublicKey().toRawBytes(),
	};
}

export function generateKeypairForImportedKeyDWallet() {
	const seed = new Uint8Array(32).fill(8);
	const userKeypair = Ed25519Keypair.deriveKeypairFromSeed('0x1');

	const userShareEncryptionKeys = UserShareEncryptionKeys.fromRootSeedKey(seed);

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

	const dwalletCap = await ikaTransaction.requestDWalletDKGFirstRoundAsync({
		curve: 0,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	transaction.transferObjects([dwalletCap], '0x0');

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
	userShareEncryptionKeys: UserShareEncryptionKeys,
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
	userShareEncryptionKeys: UserShareEncryptionKeys,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.requestDWalletDKGSecondRound({
		dWalletCap: dWallet.dwallet_cap_id,
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
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
	userPublicOutput: Uint8Array,
	secondRoundMoveResponse: {
		event_data: {
			encrypted_user_secret_key_share_id: string;
		};
	},
	userShareEncryptionKeys: UserShareEncryptionKeys,
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
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
	destinationUserShareEncryptionKeys: UserShareEncryptionKeys,
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

	await ikaTransaction.acceptEncryptedUserShare({
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
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
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

export async function makeImportedKeyDWalletUserSecretKeySharesPublic(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: ImportedKeyDWallet,
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

	const unverifiedPresignCap = ikaTransaction.requestPresign({
		dWallet,
		signatureAlgorithm,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	transaction.transferObjects([unverifiedPresignCap], '0x0');

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
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
	userShareEncryptionKeys: UserShareEncryptionKeys,
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

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	// Use appropriate signing method based on DWallet type
	if (dWallet.kind === 'imported-key') {
		const importedKeyMessageApproval = ikaTransaction.approveImportedKeyMessage({
			dWalletCap: dWallet.dwallet_cap_id,
			signatureAlgorithm,
			hashScheme,
			message,
		});

		await ikaTransaction.requestSignWithImportedKey({
			dWallet,
			importedKeyMessageApproval,
			verifiedPresignCap,
			hashScheme,
			presign,
			encryptedUserSecretKeyShare,
			message,
			ikaCoin: emptyIKACoin,
			suiCoin: transaction.gas,
		});
	} else {
		const messageApproval = ikaTransaction.approveMessage({
			dWalletCap: dWallet.dwallet_cap_id,
			signatureAlgorithm,
			hashScheme,
			message,
		});

		await ikaTransaction.requestSign({
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
	}

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTransaction(suiClient, transaction);
}

export async function signPublicUserShare(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: SharedDWallet | ImportedSharedDWallet,
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

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	// Use appropriate signing method based on DWallet type
	if (dWallet.kind === 'imported-key-shared') {
		const importedKeyMessageApproval = ikaTransaction.approveImportedKeyMessage({
			dWalletCap: dWallet.dwallet_cap_id,
			signatureAlgorithm,
			hashScheme,
			message,
		});

		await ikaTransaction.requestSignWithImportedKey({
			dWallet,
			importedKeyMessageApproval,
			verifiedPresignCap,
			presign,
			message,
			hashScheme,
			ikaCoin: emptyIKACoin,
			suiCoin: transaction.gas,
		});
	} else {
		const messageApproval = ikaTransaction.approveMessage({
			dWalletCap: dWallet.dwallet_cap_id,
			signatureAlgorithm,
			hashScheme,
			message,
		});

		await ikaTransaction.requestSign({
			dWallet,
			messageApproval,
			verifiedPresignCap,
			presign,
			message,
			hashScheme,
			ikaCoin: emptyIKACoin,
			suiCoin: transaction.gas,
		});
	}

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTransaction(suiClient, transaction);
}

export async function requestFutureSign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
	presign: Presign,
	userShareEncryptionKeys: UserShareEncryptionKeys,
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

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	let unverifiedPartialUserSignatureCapA: TransactionObjectArgument;

	// Use appropriate future sign method based on DWallet type
	if (dWallet.kind === 'imported-key') {
		const unverifiedPartialUserSignatureCap = await ikaTransaction.requestFutureSignWithImportedKey(
			{
				dWallet,
				presign,
				verifiedPresignCap,
				encryptedUserSecretKeyShare,
				message,
				hashScheme,
				ikaCoin: emptyIKACoin,
				suiCoin: transaction.gas,
			},
		);

		unverifiedPartialUserSignatureCapA = unverifiedPartialUserSignatureCap;
	} else {
		const unverifiedPartialUserSignatureCap = await ikaTransaction.requestFutureSign({
			dWallet,
			presign,
			verifiedPresignCap,
			encryptedUserSecretKeyShare,
			message,
			hashScheme,
			ikaCoin: emptyIKACoin,
			suiCoin: transaction.gas,
		});

		unverifiedPartialUserSignatureCapA = unverifiedPartialUserSignatureCap;
	}

	transaction.transferObjects([unverifiedPartialUserSignatureCapA], '0x0');

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
	userShareEncryptionKeys: UserShareEncryptionKeys,
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

	const messageApproval = ikaTransaction.approveMessage({
		dWalletCap: dWallet.dwallet_cap_id,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.futureSign({
		messageApproval,
		partialUserSignatureCap: partialUserSignature.cap_id,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTransaction(suiClient, transaction);
}

export async function requestImportedKeyDWalletVerification(
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

	const importedKeyDWalletCap = await ikaTransaction.requestImportedKeyDWalletVerification({
		importDWalletVerificationRequestInput,
		curve,
		signerPublicKey,
		sessionIdentifier,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	transaction.transferObjects([importedKeyDWalletCap], '0x0');

	destroyEmptyIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTransaction(suiClient, transaction);

	const importedKeyDWalletVerificationRequestEvent = result.events?.find((event) => {
		return event.type.includes('ImportedKeyDWalletVerificationRequestEvent');
	});

	return SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletImportedKeyVerificationRequestEvent,
	).fromBase64(importedKeyDWalletVerificationRequestEvent?.bcs as string);
}

export async function signWithImportedKeyDWallet(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: ImportedKeyDWallet,
	presign: Presign,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	userShareEncryptionKeys: UserShareEncryptionKeys,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys,
	});

	const importedKeyMessageApproval = ikaTransaction.approveImportedKeyMessage({
		dWalletCap: dWallet.dwallet_cap_id,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestSignWithImportedKey({
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

export async function signWithImportedKeyDWalletPublic(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: ImportedSharedDWallet,
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

	const importedKeyMessageApproval = ikaTransaction.approveImportedKeyMessage({
		dWalletCap: dWallet.dwallet_cap_id,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestSignWithImportedKey({
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
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
	destinationEncryptionKeyAddress: string,
	sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	userShareEncryptionKeys: UserShareEncryptionKeys,
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
