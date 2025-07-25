import {
	create_imported_dwallet_centralized_step,
	encrypt_secret_share,
} from '@dwallet-network/dwallet-mpc-wasm';
import { bcs } from '@mysten/bcs';
import { Transaction } from '@mysten/sui/transactions';

import { acceptEncryptedUserShare } from './dkg.js';
import { getOrCreateClassGroupsKeyPair } from './encrypt-user-share.js';
import type {
	Config,
	DWallet,
	SessionIdentifierRegisteredEvent,
	SharedObjectData,
} from './globals.js';
import {
	createSessionIdentifier,
	DWALLET_COORDINATOR_MOVE_MODULE_NAME,
	getDWalletSecpState,
	getInitialSharedVersion,
	getNetworkDecryptionKeyID,
	getNetworkPublicParameters,
	getObjectWithType,
	isActiveDWallet,
	sessionIdentifierDigest,
	SUI_PACKAGE_ID,
} from './globals.js';

interface DWalletImportedKeyVerificationRequestEvent {
	event_data: {
		dwallet_id: string;
		dwallet_cap_id: string;
		encrypted_user_secret_key_share_id: string;
	};
}

function isSessionIdentifierRegisteredEvent(event: any): event is SessionIdentifierRegisteredEvent {
	return event.session_object_id !== undefined && event.session_identifier_preimage !== undefined;
}

// todo(zeev): refactor for a better API
// https://github.com/dwallet-labs/dwallet-network/pull/1040/files#r2097645823
export async function createImportedDWallet(conf: Config, secretKey: Uint8Array): Promise<DWallet> {
	const networkDecryptionKeyPublicOutput = await getNetworkPublicParameters(conf);
	const sessionIdentifierRegisteredEvent = await createSessionIdentifierMoveCall(conf);

	// The outgoing message and the public output are sent to the network.
	// They include the encrypted network share, encrypted by the network encryption key.
	const [secret_share, public_output, outgoing_message] = create_imported_dwallet_centralized_step(
		networkDecryptionKeyPublicOutput,
		sessionIdentifierDigest(sessionIdentifierRegisteredEvent.session_identifier_preimage),
		secretKey,
	);
	const classGroupsSecpKeyPair = await getOrCreateClassGroupsKeyPair(conf);

	const encryptedUserShareAndProof = encrypt_secret_share(
		secret_share,
		classGroupsSecpKeyPair.encryptionKey,
		networkDecryptionKeyPublicOutput,
	);
	const dwalletState = await getDWalletSecpState(conf);
	const verifyImportedDWalletEvent = await verifyImportedDWalletMoveCall(
		conf,
		dwalletState,
		sessionIdentifierRegisteredEvent.session_object_id,
		outgoing_message,
		encryptedUserShareAndProof,
		public_output,
	);
	const dWalletID = verifyImportedDWalletEvent.event_data.dwallet_id;
	const dWalletCapID = verifyImportedDWalletEvent.event_data.dwallet_cap_id;
	const encryptedSecretShareID =
		verifyImportedDWalletEvent.event_data.encrypted_user_secret_key_share_id;
	const dwallet = await getObjectWithType(conf, dWalletID, isActiveDWallet);
	await acceptEncryptedUserShare(conf, {
		dwallet_id: dwallet.id.id,
		encrypted_user_secret_key_share_id: encryptedSecretShareID,
	});
	return {
		dwalletID: dWalletID,
		dwallet_cap_id: dWalletCapID,
		encrypted_secret_share_id: encryptedSecretShareID,
		secret_share,
		output: dwallet.state.fields.public_output,
	};
}

/**
 * Create a session identifier and return its event.
 */
export async function createSessionIdentifierMoveCall(
	conf: Config,
): Promise<SessionIdentifierRegisteredEvent> {
	const tx = new Transaction();
	const dwalletStateArg = tx.sharedObjectRef({
		objectId: conf.ikaConfig.objects.ika_dwallet_coordinator_object_id,
		initialSharedVersion: await getInitialSharedVersion(
			conf,
			conf.ikaConfig.objects.ika_dwallet_coordinator_object_id,
		),
		mutable: true,
	});
	const sessionIdentifier = await createSessionIdentifier(
		tx,
		dwalletStateArg,
		conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id,
	);
	tx.transferObjects([sessionIdentifier], conf.suiClientKeypair.toSuiAddress());
	const result = await conf.client.signAndExecuteTransaction({
		signer: conf.suiClientKeypair,
		transaction: tx,
		options: {
			showEffects: true,
			showEvents: true,
		},
	});
	const creationEvent = result.events?.at(0)?.parsedJson;
	if (!isSessionIdentifierRegisteredEvent(creationEvent)) {
		throw new Error('Failed to create imported dWallet');
	}
	return creationEvent;
}

export async function verifyImportedDWalletMoveCall(
	conf: Config,
	dWalletStateData: SharedObjectData,
	sessionIdentifierObjectId: string,
	centralized_party_message: Uint8Array,
	encrypted_centralized_secret_share_and_proof: Uint8Array,
	user_public_output: Uint8Array,
): Promise<DWalletImportedKeyVerificationRequestEvent> {
	const tx = new Transaction();
	const dwalletStateArg = tx.sharedObjectRef({
		objectId: dWalletStateData.object_id,
		initialSharedVersion: dWalletStateData.initial_shared_version,
		mutable: true,
	});
	const networkDecryptionKeyID = await getNetworkDecryptionKeyID(conf);
	const centralizedPublicOutputArg = tx.pure(bcs.vector(bcs.u8()).serialize(user_public_output));
	const encryptedCentralizedSecretShareAndProofArg = tx.pure(
		bcs.vector(bcs.u8()).serialize(encrypted_centralized_secret_share_and_proof),
	);
	const encryptionKeyAddressArg = tx.pure.id(
		conf.encryptedSecretShareSigningKeypair.toSuiAddress(),
	);
	const centralizedPartyMessageArg = tx.pure(
		bcs.vector(bcs.u8()).serialize(centralized_party_message),
	);
	const signerPublicKeyArg = tx.pure(
		bcs
			.vector(bcs.u8())
			.serialize(conf.encryptedSecretShareSigningKeypair.getPublicKey().toRawBytes()),
	);

	const emptyIKACoin = tx.moveCall({
		target: `${SUI_PACKAGE_ID}::coin::zero`,
		arguments: [],
		typeArguments: [`${conf.ikaConfig.packages.ika_package_id}::ika::IKA`],
	});
	const cap = tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::request_imported_key_dwallet_verification`,
		arguments: [
			dwalletStateArg,
			tx.pure.id(networkDecryptionKeyID),
			tx.pure.u32(0),
			centralizedPartyMessageArg,
			encryptedCentralizedSecretShareAndProofArg,
			encryptionKeyAddressArg,
			centralizedPublicOutputArg,
			signerPublicKeyArg,
			tx.object(sessionIdentifierObjectId),
			emptyIKACoin,
			tx.gas,
		],
	});
	tx.moveCall({
		target: `${SUI_PACKAGE_ID}::coin::destroy_zero`,
		arguments: [emptyIKACoin],
		typeArguments: [`${conf.ikaConfig.packages.ika_package_id}::ika::IKA`],
	});
	tx.transferObjects([cap], conf.suiClientKeypair.toSuiAddress());
	const result = await conf.client.signAndExecuteTransaction({
		signer: conf.suiClientKeypair,
		transaction: tx,
		options: {
			showEffects: true,
			showEvents: true,
		},
	});
	if (result.errors !== undefined) {
		throw new Error(`DKG second round failed with errors ${result.errors}`);
	}
	const startSessionEvent = result.events?.at(0)?.parsedJson;
	if (!isDWalletImportedKeyVerificationRequestEvent(startSessionEvent)) {
		throw new Error('invalid start session event');
	}
	await getObjectWithType(conf, startSessionEvent.event_data.dwallet_id, isActiveDWallet);
	return startSessionEvent;
}

function isDWalletImportedKeyVerificationRequestEvent(
	event: any,
): event is DWalletImportedKeyVerificationRequestEvent {
	return (
		event.event_data.dwallet_id !== undefined &&
		event.event_data.encrypted_user_secret_key_share_id !== undefined
	);
}
