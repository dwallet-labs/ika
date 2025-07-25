import { create_sign_centralized_output } from '@dwallet-network/dwallet-mpc-wasm';
import { bcs } from '@mysten/bcs';
import type { TransactionResult } from '@mysten/sui/dist/cjs/transactions/Transaction';
import { Transaction } from '@mysten/sui/transactions';

import {
	createSessionIdentifier,
	DWALLET_COORDINATOR_INNER_MOVE_MODULE_NAME,
	DWALLET_COORDINATOR_MOVE_MODULE_NAME,
	getDWalletSecpState,
	getObjectWithType,
	isActiveDWallet,
	isDWalletCap,
	isPresign,
	SUI_PACKAGE_ID,
} from './globals.js';
import type { Config } from './globals.ts';

// noinspection JSUnusedGlobalSymbols
export enum Hash {
	KECCAK256 = 0,
	SHA256 = 1,
}

interface ReadySignObject {
	id: { id: string };
	state: {
		fields: {
			signature: Uint8Array;
		};
	};
}

interface StartSignEvent {
	event_data: {
		sign_id: string;
	};
}

interface StartFutureSignEvent {
	event_data: {
		partial_centralized_signed_message_id: string;
	};
}

interface VerifiedPartialUserSignature {
	state: {
		variant: 'NetworkVerificationCompleted';
	};
	cap_id: string;
}

async function call_mpc_sign_tx(tx: Transaction, emptyIKACoin: TransactionResult, conf: Config) {
	tx.moveCall({
		target: `${SUI_PACKAGE_ID}::coin::destroy_zero`,
		arguments: [emptyIKACoin],
		typeArguments: [`${conf.ikaConfig.packages.ika_package_id}::ika::IKA`],
	});
	const result = await conf.client.signAndExecuteTransaction({
		signer: conf.suiClientKeypair,
		transaction: tx,
		options: {
			showEffects: true,
			showEvents: true,
		},
	});
	const startSessionEvent = result.events?.at(1)?.parsedJson;
	if (!isStartSignEvent(startSessionEvent)) {
		throw new Error('invalid start session event');
	}
	return await getObjectWithType(conf, startSessionEvent.event_data.sign_id, isReadySignObject);
}

function createEmptyIKACoin(tx: Transaction, conf: Config) {
	return tx.moveCall({
		target: `${SUI_PACKAGE_ID}::coin::zero`,
		arguments: [],
		typeArguments: [`${conf.ikaConfig.packages.ika_package_id}::ika::IKA`],
	});
}

async function approveMessageTX(
	conf: Config,
	dwalletCapID: string,
	hash: Hash,
	message: Uint8Array,
	tx: Transaction = new Transaction(),
) {
	const dWalletStateData = await getDWalletSecpState(conf);
	const messageApproval = tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::approve_message`,
		arguments: [
			tx.sharedObjectRef({
				objectId: dWalletStateData.object_id,
				initialSharedVersion: dWalletStateData.initial_shared_version,
				mutable: true,
			}),
			tx.object(dwalletCapID),
			tx.pure.u32(0),
			tx.pure(bcs.u32().serialize(hash.valueOf())),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
	return { dWalletStateData, tx, messageApproval };
}

async function approveImportedDWalletMessageTX(
	conf: Config,
	dwalletCapID: string,
	hash: Hash,
	message: Uint8Array,
	tx: Transaction = new Transaction(),
) {
	const dWalletStateData = await getDWalletSecpState(conf);
	const messageApproval = tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::approve_imported_key_message`,
		arguments: [
			tx.sharedObjectRef({
				objectId: dWalletStateData.object_id,
				initialSharedVersion: dWalletStateData.initial_shared_version,
				mutable: true,
			}),
			tx.object(dwalletCapID),
			tx.pure.u32(0),
			tx.pure(bcs.u32().serialize(hash.valueOf())),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
	return { dWalletStateData, tx, messageApproval };
}

export async function sign(
	conf: Config,
	presignID: string,
	dwalletCapID: string,
	message: Uint8Array,
	secretKey: Uint8Array,
	networkDecryptionKeyPublicOutput: Uint8Array,
	hash = Hash.KECCAK256,
): Promise<ReadySignObject> {
	const dwalletCap = await getObjectWithType(conf, dwalletCapID, isDWalletCap);
	const dwalletID = dwalletCap.dwallet_id;
	const activeDWallet = await getObjectWithType(conf, dwalletID, isActiveDWallet);
	const presign = await getObjectWithType(conf, presignID, isPresign);

	console.time('create_sign_centralized_output');
	const centralizedSignedMessage = create_sign_centralized_output(
		networkDecryptionKeyPublicOutput,
		activeDWallet.state.fields.public_output,
		secretKey,
		presign.state.fields.presign,
		message,
		hash,
	);
	console.timeEnd('create_sign_centralized_output');

	const { dWalletStateData, tx, messageApproval } = await approveMessageTX(
		conf,
		dwalletCapID,
		hash,
		message,
	);
	const emptyIKACoin = createEmptyIKACoin(tx, conf);
	const dwalletStateArg = tx.sharedObjectRef({
		objectId: dWalletStateData.object_id,
		initialSharedVersion: dWalletStateData.initial_shared_version,
		mutable: true,
	});
	const [verifiedPresignCap] = tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::verify_presign_cap`,
		arguments: [dwalletStateArg, tx.object(presign.cap_id)],
	});
	const sessionIdentifier = await createSessionIdentifier(
		tx,
		dwalletStateArg,
		conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id,
	);
	tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::request_sign`,
		arguments: [
			dwalletStateArg,
			verifiedPresignCap,
			messageApproval,
			tx.pure(bcs.vector(bcs.u8()).serialize(centralizedSignedMessage)),
			sessionIdentifier,
			emptyIKACoin,
			tx.gas,
		],
	});
	return await call_mpc_sign_tx(tx, emptyIKACoin, conf);
}

export async function signWithImportedDWallet(
	conf: Config,
	presignID: string,
	dwalletCapID: string,
	message: Uint8Array,
	secretKey: Uint8Array,
	networkDecryptionKeyPublicOutput: Uint8Array,
	hash = Hash.KECCAK256,
): Promise<ReadySignObject> {
	const dwalletCap = await getObjectWithType(conf, dwalletCapID, isDWalletCap);
	const dwalletID = dwalletCap.dwallet_id;
	const activeDWallet = await getObjectWithType(conf, dwalletID, isActiveDWallet);
	const presign = await getObjectWithType(conf, presignID, isPresign);

	const centralizedSignedMessage = create_sign_centralized_output(
		networkDecryptionKeyPublicOutput,
		activeDWallet.state.fields.public_output,
		secretKey,
		presign.state.fields.presign,
		message,
		hash,
	);
	const { dWalletStateData, tx, messageApproval } = await approveImportedDWalletMessageTX(
		conf,
		dwalletCapID,
		hash,
		message,
	);
	const emptyIKACoin = createEmptyIKACoin(tx, conf);

	const [verifiedPresignCap] = tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::verify_presign_cap`,
		arguments: [
			tx.sharedObjectRef({
				objectId: dWalletStateData.object_id,
				initialSharedVersion: dWalletStateData.initial_shared_version,
				mutable: true,
			}),
			tx.object(presign.cap_id),
		],
	});
	const dwalletStateArg = tx.sharedObjectRef({
		objectId: dWalletStateData.object_id,
		initialSharedVersion: dWalletStateData.initial_shared_version,
		mutable: true,
	});
	const sessionIdentifier = await createSessionIdentifier(
		tx,
		dwalletStateArg,
		conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id,
	);
	tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::request_imported_key_sign`,
		arguments: [
			dwalletStateArg,
			verifiedPresignCap,
			messageApproval,
			tx.pure(bcs.vector(bcs.u8()).serialize(centralizedSignedMessage)),
			sessionIdentifier,
			emptyIKACoin,
			tx.gas,
		],
	});
	return await call_mpc_sign_tx(tx, emptyIKACoin, conf);
}

function isReadySignObject(obj: any): obj is ReadySignObject {
	return (
		obj?.state !== undefined &&
		obj.state.fields !== undefined &&
		obj.state.fields.signature !== undefined
	);
}

function isStartSignEvent(event: any): event is StartSignEvent {
	return event.event_data !== undefined && event.event_data.sign_id !== undefined;
}

function isStartFutureSignEvent(event: any): event is StartFutureSignEvent {
	return (
		event.event_data !== undefined &&
		event.event_data.partial_centralized_signed_message_id !== undefined
	);
}

export async function createUnverifiedPartialUserSignatureCap(
	conf: Config,
	presignID: string,
	dwalletCapID: string,
	message: Uint8Array,
	secretKey: Uint8Array,
	networkDecryptionKeyPublicOutput: Uint8Array,
	hash = Hash.KECCAK256,
): Promise<string> {
	const dwalletCap = await getObjectWithType(conf, dwalletCapID, isDWalletCap);
	const dwalletID = dwalletCap.dwallet_id;
	const activeDWallet = await getObjectWithType(conf, dwalletID, isActiveDWallet);
	const presign = await getObjectWithType(conf, presignID, isPresign);
	const dWalletStateData = await getDWalletSecpState(conf);
	const tx = new Transaction();

	const centralizedSignedMessage = create_sign_centralized_output(
		networkDecryptionKeyPublicOutput,
		activeDWallet.state.fields.public_output,
		secretKey,
		presign.state.fields.presign,
		message,
		hash,
	);

	const emptyIKACoin = tx.moveCall({
		target: `${SUI_PACKAGE_ID}::coin::zero`,
		arguments: [],
		typeArguments: [`${conf.ikaConfig.packages.ika_package_id}::ika::IKA`],
	});

	const dwalletStateArg = tx.sharedObjectRef({
		objectId: dWalletStateData.object_id,
		initialSharedVersion: dWalletStateData.initial_shared_version,
		mutable: true,
	});

	const [verifiedPresignCap] = tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::verify_presign_cap`,
		arguments: [dwalletStateArg, tx.object(presign.cap_id)],
	});

	const sessionIdentifier = await createSessionIdentifier(
		tx,
		dwalletStateArg,
		conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id,
	);

	const [unverifiedPartialUserSignatureCap] = tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::request_future_sign`,
		arguments: [
			dwalletStateArg,
			tx.pure.id(dwalletID),
			verifiedPresignCap,
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
			tx.pure(bcs.u32().serialize(hash.valueOf())),
			tx.pure(bcs.vector(bcs.u8()).serialize(centralizedSignedMessage)),
			sessionIdentifier,
			emptyIKACoin,
			tx.gas,
		],
	});
	tx.transferObjects([unverifiedPartialUserSignatureCap], conf.suiClientKeypair.toSuiAddress());
	tx.moveCall({
		target: `${SUI_PACKAGE_ID}::coin::destroy_zero`,
		arguments: [emptyIKACoin],
		typeArguments: [`${conf.ikaConfig.packages.ika_package_id}::ika::IKA`],
	});
	const result = await conf.client.signAndExecuteTransaction({
		signer: conf.suiClientKeypair,
		transaction: tx,
		options: {
			showEffects: true,
			showEvents: true,
			showObjectChanges: true,
		},
	});
	const startSessionEvent = result.events?.at(1)?.parsedJson;
	if (!isStartFutureSignEvent(startSessionEvent)) {
		throw new Error('invalid start session event');
	}

	const partialSignature = await getObjectWithType(
		conf,
		startSessionEvent.event_data.partial_centralized_signed_message_id,
		isVerifiedPartialUserSignature,
	);
	return partialSignature.cap_id;
}

function isVerifiedPartialUserSignature(obj: any): obj is VerifiedPartialUserSignature {
	return (
		obj &&
		'state' in obj &&
		'variant' in obj.state &&
		obj.state.variant === 'NetworkVerificationCompleted'
	);
}

export async function verifySignWithPartialUserSignatures(
	conf: Config,
	unverifiedPartialUserSignatureCapID: string,
): Promise<string> {
	const dWalletStateData = await getDWalletSecpState(conf);
	const tx = new Transaction();

	const [verifiedPartialUserSignatureCap] = tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::verify_partial_user_signature_cap`,
		arguments: [
			tx.sharedObjectRef({
				objectId: dWalletStateData.object_id,
				initialSharedVersion: dWalletStateData.initial_shared_version,
				mutable: true,
			}),
			tx.object(unverifiedPartialUserSignatureCapID),
		],
	});
	tx.transferObjects([verifiedPartialUserSignatureCap], conf.suiClientKeypair.toSuiAddress());

	const result = await conf.client.signAndExecuteTransaction({
		signer: conf.suiClientKeypair,
		transaction: tx,
		options: {
			showEffects: true,
			showEvents: true,
			showObjectChanges: true,
		},
	});
	const objects = result.objectChanges!;
	if (!objects) {
		throw new Error('no objects created during verify_partial_user_signature_cap call');
	}
	for (const obj of objects) {
		if (
			obj &&
			'objectType' in obj &&
			obj.objectType! ===
				`${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_INNER_MOVE_MODULE_NAME}::VerifiedPartialUserSignatureCap`
		) {
			return obj.objectId;
		}
	}
	throw new Error('no verified object created');
}

export async function completeFutureSign(
	conf: Config,
	dwalletCapID: string,
	message: Uint8Array,
	hash = Hash.KECCAK256,
	verifyPartialUserSignatureCapID: string,
): Promise<ReadySignObject> {
	const { dWalletStateData, tx, messageApproval } = await approveMessageTX(
		conf,
		dwalletCapID,
		hash,
		message,
	);
	const emptyIKACoin = createEmptyIKACoin(tx, conf);

	const dwalletStateArg = tx.sharedObjectRef({
		objectId: dWalletStateData.object_id,
		initialSharedVersion: dWalletStateData.initial_shared_version,
		mutable: true,
	});

	const sessionIdentifier = await createSessionIdentifier(
		tx,
		dwalletStateArg,
		conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id,
	);

	tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::request_sign_with_partial_user_signature`,
		arguments: [
			dwalletStateArg,
			tx.object(verifyPartialUserSignatureCapID),
			messageApproval,
			sessionIdentifier,
			emptyIKACoin,
			tx.gas,
		],
	});
	return await call_mpc_sign_tx(tx, emptyIKACoin, conf);
}
