// @ts-ignore
import { bcs } from '@mysten/bcs';
import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';

import { IkaClient, IkaTransaction } from '../client';
import { PreparedSecondRound } from '../client/cryptography';
import {
	DWallet,
	EncryptedUserSecretKeyShare,
	Hash,
	PartialUserSignature,
	Presign,
	SignatureAlgorithm,
} from '../client/types';
import { UserShareEncrytionKeys } from '../client/user-share-encryption-keys';
import * as CoordinatorInnerModule from '../generated/ika_dwallet_2pc_mpc/coordinator_inner.js';
import * as SessionsManagerModule from '../generated/ika_dwallet_2pc_mpc/sessions_manager.js';

export function createSuiClient() {
	return new SuiClient({
		url: 'https://fullnode.testnet.sui.io:443',
	});
}

export function createIkaClient(suiClient: SuiClient) {
	return new IkaClient({
		suiClient,
		config: {
			packages: {
				ikaPackage: '0x9df87437f4f0fb73bffe6fc6291f568da6e59ad4ad0770743b21cd4e1c030914',
				ikaCommonPackage: '0x9df87437f4f0fb73bffe6fc6291f568da6e59ad4ad0770743b21cd4e1c030914',
				ikaSystemPackage: '0x9df87437f4f0fb73bffe6fc6291f568da6e59ad4ad0770743b21cd4e1c030914',
				ikaDwallet2pcMpcPackage:
					'0x9df87437f4f0fb73bffe6fc6291f568da6e59ad4ad0770743b21cd4e1c030914',
			},
			objects: {
				ikaSystemObject: {
					objectID: '0x9df87437f4f0fb73bffe6fc6291f568da6e59ad4ad0770743b21cd4e1c030914',
					initialSharedVersion: 0,
				},
				ikaDWalletCoordinator: {
					objectID: '0x9df87437f4f0fb73bffe6fc6291f568da6e59ad4ad0770743b21cd4e1c030914',
					initialSharedVersion: 0,
				},
			},
		},
		publicParameters: {
			decryptionKeyPublicOutputID: '0x1',
			epoch: 0,
			publicParameters: new Uint8Array(32).fill(8),
		},
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
	const seed = new Uint8Array(32).fill(8);
	const userKeypair = Ed25519Keypair.deriveKeypairFromSeed('0x1');

	const userShareEncryptionKeys = UserShareEncrytionKeys.fromHexString(
		Buffer.from(seed).toString('hex'),
	);

	return {
		userShareEncryptionKeys,
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

	await ikaTransaction.requestDWalletDKGFirstRoundAndKeepAsync({
		curve: 0,
		ikaCoin: coinWithBalance({
			type: '0x2::ika::IKA',
			balance: 0,
		})(transaction),
		suiCoin: coinWithBalance({
			type: '0x2::sui::SUI',
			balance: 0,
		})(transaction),
		receiver: '0x0',
	});

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

	ikaTransaction.registerEncryptionKey({
		curve: 0,
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
	preparedSecondRound: PreparedSecondRound,
	userShareEncryptionKeys: UserShareEncrytionKeys,
	signerPublicKey: Uint8Array,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys,
	});

	ikaTransaction.requestDWalletDKGSecondRound({
		dWallet,
		preparedSecondRound,
		signerPublicKey,
		ikaCoin: coinWithBalance({
			type: '0x2::ika::IKA',
			balance: 0,
		})(transaction),
		suiCoin: coinWithBalance({
			type: '0x2::sui::SUI',
			balance: 0,
		})(transaction),
	});

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

	ikaTransaction.acceptEncryptedUserShare({
		dWallet,
		encryptedUserSecretKeyShareId:
			secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
	});

	await executeTransaction(suiClient, transaction);
}

export async function makeDWalletUserSecretKeySharesPublic(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	preparedSecondRound: PreparedSecondRound,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	ikaTransaction.makeDWalletUserSecretKeySharesPublic({
		dWallet,
		secretShare: preparedSecondRound.centralizedSecretKeyShare,
		ikaCoin: coinWithBalance({
			type: '0x2::ika::IKA',
			balance: 0,
		})(transaction),
		suiCoin: coinWithBalance({
			type: '0x2::sui::SUI',
			balance: 0,
		})(transaction),
	});

	await executeTransaction(suiClient, transaction);
}

export async function presign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dWallet: DWallet,
	signatureAlgorithm: number,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	ikaTransaction.presignAndKeep({
		dWallet,
		signatureAlgorithm,
		ikaCoin: coinWithBalance({
			type: '0x2::ika::IKA',
			balance: 0,
		})(transaction),
		suiCoin: coinWithBalance({
			type: '0x2::sui::SUI',
			balance: 0,
		})(transaction),
		receiver: '0x0',
	});

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

	await ikaTransaction.sign({
		dWallet,
		signatureAlgorithm,
		hashScheme,
		presign,
		encryptedUserSecretKeyShare,
		message,
		ikaCoin: coinWithBalance({
			type: '0x2::ika::IKA',
			balance: 0,
		})(transaction),
		suiCoin: coinWithBalance({
			type: '0x2::sui::SUI',
			balance: 0,
		})(transaction),
	});

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
	hashScheme: number,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys,
	});

	await ikaTransaction.requestFutureSignAndKeep({
		dWallet,
		presign,
		encryptedUserSecretKeyShare,
		message,
		hashScheme,
		ikaCoin: coinWithBalance({
			type: '0x2::ika::IKA',
			balance: 0,
		})(transaction),
		suiCoin: coinWithBalance({
			type: '0x2::sui::SUI',
			balance: 0,
		})(transaction),
		receiver: '0x0',
	});

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
	hashScheme: number,
	signatureAlgorithm: number,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
		userShareEncryptionKeys,
	});

	ikaTransaction.futureSign({
		dWallet,
		partialUserSignature,
		message,
		hashScheme,
		signatureAlgorithm,
		ikaCoin: coinWithBalance({
			type: '0x2::ika::IKA',
			balance: 0,
		})(transaction),
		suiCoin: coinWithBalance({
			type: '0x2::sui::SUI',
			balance: 0,
		})(transaction),
	});

	await executeTransaction(suiClient, transaction);
}
