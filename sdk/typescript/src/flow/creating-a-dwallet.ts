import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';

import { IkaClient, IkaTransaction } from '../client';
import {
	createClassGroupsKeypair,
	createDKGCentralizedOutput,
	encryptSecretShare,
} from '../client/cryptography';
import * as CoordinatorInnerModule from '../generated/ika_dwallet_2pc_mpc/coordinator_inner.js';
import * as SessionsManagerModule from '../generated/ika_dwallet_2pc_mpc/sessions_manager.js';

const suiClient = new SuiClient({
	url: 'https://fullnode.testnet.sui.io:443',
});

const ikaClient = new IkaClient({
	suiClient,
	config: {
		packages: {
			ikaPackage: '0x9df87437f4f0fb73bffe6fc6291f568da6e59ad4ad0770743b21cd4e1c030914',
			ikaCommonPackage: '0x9df87437f4f0fb73bffe6fc6291f568da6e59ad4ad0770743b21cd4e1c030914',
			ikaSystemPackage: '0x9df87437f4f0fb73bffe6fc6291f568da6e59ad4ad0770743b21cd4e1c030914',
			ikaDwallet2pcMpcPackage: '0x9df87437f4f0fb73bffe6fc6291f568da6e59ad4ad0770743b21cd4e1c030914',
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

async function main() {
	const decryptionKeyID = await ikaClient.getDecryptionKeyID();
	const seed = new Uint8Array(32).fill(8);
	const keypair = Ed25519Keypair.deriveKeypairFromSeed('0x1');
	const encryptedSecretShareSigningKeypair = Ed25519Keypair.deriveKeypairFromSeed(
		Buffer.from(seed).toString('hex'),
	);
	const encryptionKeyAddress = keypair.getPublicKey().toSuiBytes();
	const classGroupsKeypair = createClassGroupsKeypair(seed);
	const encryptionKeySignature = await encryptedSecretShareSigningKeypair.sign(
		new Uint8Array(classGroupsKeypair.encryptionKey),
	);

	const { dwalletID, sessionIdentifierPreimage } = await requestDKGFirstRound(decryptionKeyID);

	await registerEncryptionKey(
		encryptionKeyAddress,
		classGroupsKeypair.encryptionKey,
		encryptionKeySignature,
	);

	const dWallet = await ikaClient.getDWallet(dwalletID);

	const firstRoundOutput = new Uint8Array(
		dWallet.state.AwaitingUserDKGVerificationInitiation?.first_round_output as number[],
	);

	const dWalletCapId = dWallet.dwallet_cap_id;

	const networkDecryptionKeyPublicOutput = await ikaClient.getNetworkPublicParameters();

	const { centralizedPublicKeyShareAndProof, centralizedPublicOutput, centralizedSecretKeyShare } =
		createDKGCentralizedOutput(
			networkDecryptionKeyPublicOutput,
			firstRoundOutput,
			sessionIdentifierPreimage,
		);

	const encryptedUserShareAndProof = encryptSecretShare(
		centralizedSecretKeyShare,
		classGroupsKeypair.encryptionKey,
		networkDecryptionKeyPublicOutput,
	);

	const secondRoundMoveResponse = await requestDkgSecondRound({
		dWalletCapId,
		centralizedPublicKeyShareAndProof,
		centralizedPublicOutput,
		encryptedUserShareAndProof,
		encryptionKeyAddress: keypair.getPublicKey().toSuiAddress(),
		signerPublicKey: keypair.getPublicKey().toRawBytes(),
		userPublicOutput: centralizedPublicOutput,
	});

	const activeDWallet = await ikaClient.getDWallet(dwalletID);

	const publicOutput = new Uint8Array(activeDWallet.state.Active?.public_output as number[]);

	if (!publicOutput) {
		throw new Error('Encrypted user secret key share ID not found');
	}

	await acceptEncryptedUserShare({
		dwalletId: dwalletID,
		encryptedUserSecretKeyShareId:
			secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
		userOutputSignature: await encryptedSecretShareSigningKeypair.sign(publicOutput),
	});
}

async function requestDKGFirstRound(decryptionKeyID: string): Promise<{
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

	const result = await executeTransaction(transaction);

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

async function registerEncryptionKey(
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

	const result = await executeTransaction(transaction);

	const createdEncryptionKeyEvent = result.events?.find((event) => {
		return event.type.includes('CreatedEncryptionKeyEvent');
	});

	return CoordinatorInnerModule.CreatedEncryptionKeyEvent.fromBase64(
		createdEncryptionKeyEvent?.bcs as string,
	);
}

async function requestDkgSecondRound({
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
}) {
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

	const result = await executeTransaction(transaction);

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

async function acceptEncryptedUserShare({
	dwalletId,
	encryptedUserSecretKeyShareId,
	userOutputSignature,
}: {
	dwalletId: string;
	encryptedUserSecretKeyShareId: string;
	userOutputSignature: Uint8Array;
}) {
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

	await executeTransaction(transaction);
}

async function executeTransaction(transaction: Transaction) {
	return suiClient.signAndExecuteTransaction({
		transaction,
		signer: Ed25519Keypair.deriveKeypairFromSeed('0x1'),
		options: {
			showEvents: true,
		},
	});
}
