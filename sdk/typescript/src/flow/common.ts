// @ts-nocheck
import { bcs } from '@mysten/bcs';
import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';

import { IkaClient, IkaTransaction } from '../client';
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

export async function requestDKGFirstRound(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	decryptionKeyID: string,
): Promise<{
	dwalletID: string;
	sessionIdentifierPreimage: Uint8Array;
}> {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	ikaTransaction.requestDWalletDKGFirstRoundAndKeep({
		curve: 0,
		decryptionKeyID,
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
	encryptionKeyAddress: Uint8Array,
	encryptionKey: Uint8Array,
	encryptionKeySignature: Uint8Array,
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	ikaTransaction.registerEncryptionKey({
		curve: 0,
		encryptionKey,
		encryptionKeySignature,
		encryptionKeyAddress,
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
	{
		dWalletCapId,
		centralizedPublicKeyShareAndProof,
		centralizedPublicOutput,
		encryptedUserShareAndProof,
		encryptionKeyAddress,
		signerPublicKey,
		userPublicOutput,
	}: {
		dWalletCapId: string;
		centralizedPublicKeyShareAndProof: Uint8Array;
		centralizedPublicOutput: Uint8Array;
		encryptedUserShareAndProof: Uint8Array;
		encryptionKeyAddress: string;
		signerPublicKey: Uint8Array;
		userPublicOutput: Uint8Array;
	},
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	ikaTransaction.requestDWalletDKGSecondRound({
		dwalletCap: dWalletCapId,
		centralizedPublicKeyShareAndProof,
		centralizedPublicOutput,
		encryptedUserShareAndProof,
		encryptionKeyAddress,
		signerPublicKey,
		userPublicOutput,
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
	{
		dwalletId,
		encryptedUserSecretKeyShareId,
		userOutputSignature,
	}: {
		dwalletId: string;
		encryptedUserSecretKeyShareId: string;
		userOutputSignature: Uint8Array;
	},
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	ikaTransaction.acceptEncryptedUserShare({
		dwalletId,
		encryptedUserSecretKeyShareId,
		userOutputSignature,
	});

	await executeTransaction(suiClient, transaction);
}

export async function makeDWalletUserSecretKeySharesPublic(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	{
		dwalletId,
		secretShare,
	}: {
		dwalletId: string;
		secretShare: Uint8Array;
	},
) {
	const transaction = new Transaction();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction,
	});

	ikaTransaction.makeDWalletUserSecretKeySharesPublic({
		dWalletId: dwalletId,
		secretShare,
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
