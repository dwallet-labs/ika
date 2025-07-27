// Copyright (c) dWallet Labs, Ltd..
// SPDX-License-Identifier: BSD-3-Clause-Clear
import {
	create_dkg_centralized_output,
	encrypt_secret_share,
} from '@dwallet-network/dwallet-mpc-wasm';
import { bcs } from '@mysten/bcs';
import { Transaction } from '@mysten/sui/transactions';

import type { ClassGroupsSecpKeyPair } from './encrypt-user-share.js';
import { getOrCreateClassGroupsKeyPair } from './encrypt-user-share.js';
import type { ActiveDWallet, DWallet, EncryptedDWalletData } from './globals.js';
import {
	createSessionIdentifier,
	delay,
	DWALLET_COORDINATOR_MOVE_MODULE_NAME,
	getDWalletSecpState,
	getInitialSharedVersion,
	getNetworkDecryptionKeyID,
	getObjectWithType,
	isActiveDWallet,
	isMoveObject,
	sessionIdentifierDigest,
	SUI_PACKAGE_ID,
} from './globals.js';
import type { Config, SharedObjectData } from './globals.ts';

interface StartDKGFirstRoundEvent {
	event_data: {
		dwallet_id: string;
		dwallet_cap_id: string;
		dwallet_network_encryption_key_id: string;
	};
	session_identifier_preimage: Uint8Array;
}

interface StartDKGSecondRoundEvent {
	event_data: {
		encrypted_user_secret_key_share_id: string;
	};
	session_identifier_preimage: Uint8Array;
}

function isStartDKGSecondRoundEvent(obj: any): obj is StartDKGSecondRoundEvent {
	return (
		!!obj?.event_data?.encrypted_user_secret_key_share_id && !!obj?.session_identifier_preimage
	);
}

interface DKGSecondRoundMoveResponse {
	dwallet: ActiveDWallet;
	encrypted_user_secret_key_share_id: string;
}

interface DKGSecondRoundResponse {
	moveResponse: DKGSecondRoundMoveResponse;
	secretShare: Uint8Array;
}

interface WaitingForUserDWallet {
	state: {
		fields: {
			first_round_output: Uint8Array;
		};
	};
}

function isStartDKGFirstRoundEvent(obj: any): obj is StartDKGFirstRoundEvent {
	return (
		!!obj?.event_data?.dwallet_id &&
		!!obj?.session_identifier_preimage &&
		!!obj?.event_data?.dwallet_cap_id &&
		!!obj?.event_data?.dwallet_network_encryption_key_id
	);
}

export async function createDWallet(
	conf: Config,
	networkDecryptionKeyPublicOutput: Uint8Array,
): Promise<DWallet> {
	console.time('launchDKGFirstRound');
	const firstRoundOutputResult = await launchDKGFirstRound(conf);
	console.timeEnd('launchDKGFirstRound');
	const classGroupsSecpKeyPair = await getOrCreateClassGroupsKeyPair(conf);
	const secondRoundResponse = await launchDKGSecondRound(
		conf,
		firstRoundOutputResult,
		networkDecryptionKeyPublicOutput,
		classGroupsSecpKeyPair,
	);
	await acceptEncryptedUserShare(conf, {
		dwallet_id: secondRoundResponse.moveResponse.dwallet.id.id,
		encrypted_user_secret_key_share_id:
			secondRoundResponse.moveResponse.encrypted_user_secret_key_share_id,
	});
	return {
		dwalletID: firstRoundOutputResult.dwalletID,
		dwallet_cap_id: firstRoundOutputResult.dwalletCapID,
		secret_share: secondRoundResponse.secretShare,
		output: secondRoundResponse.moveResponse.dwallet.state.fields.public_output,
		encrypted_secret_share_id: secondRoundResponse.moveResponse.encrypted_user_secret_key_share_id,
	};
}

export async function launchDKGSecondRound(
	conf: Config,
	firstRoundOutputResult: DKGFirstRoundOutputResult,
	networkDecryptionKeyPublicOutput: Uint8Array,
	classGroupsSecpKeyPair: ClassGroupsSecpKeyPair,
): Promise<DKGSecondRoundResponse> {
	const [centralizedPublicKeyShareAndProof, centralizedPublicOutput, centralizedSecretKeyShare] =
		create_dkg_centralized_output(
			networkDecryptionKeyPublicOutput,
			Uint8Array.from(firstRoundOutputResult.output),
			sessionIdentifierDigest(firstRoundOutputResult.sessionIdentifier),
		);

	const dWalletStateData = await getDWalletSecpState(conf);

	const encryptedUserShareAndProof = encrypt_secret_share(
		centralizedSecretKeyShare,
		classGroupsSecpKeyPair.encryptionKey,
		networkDecryptionKeyPublicOutput,
	);

	const secondRoundMoveResponse = await dkgSecondRoundMoveCall(
		conf,
		dWalletStateData,
		firstRoundOutputResult,
		centralizedPublicKeyShareAndProof,
		encryptedUserShareAndProof,
		centralizedPublicOutput,
	);
	return {
		moveResponse: secondRoundMoveResponse,
		secretShare: centralizedSecretKeyShare,
	};
}

export async function dkgSecondRoundMoveCall(
	conf: Config,
	dWalletStateData: SharedObjectData,
	firstRoundOutputResult: DKGFirstRoundOutputResult,
	centralizedPublicKeyShareAndProof: Uint8Array,
	encryptedUserShareAndProof: Uint8Array,
	centralizedPublicOutput: Uint8Array,
): Promise<DKGSecondRoundMoveResponse> {
	const tx = new Transaction();
	const dwalletStateArg = tx.sharedObjectRef({
		objectId: dWalletStateData.object_id,
		initialSharedVersion: dWalletStateData.initial_shared_version,
		mutable: true,
	});
	const dwalletCapArg = tx.object(firstRoundOutputResult.dwalletCapID);
	const centralizedPublicKeyShareAndProofArg = tx.pure(
		bcs.vector(bcs.u8()).serialize(centralizedPublicKeyShareAndProof),
	);
	const encryptedCentralizedSecretShareAndProofArg = tx.pure(
		bcs.vector(bcs.u8()).serialize(encryptedUserShareAndProof),
	);
	const encryptionKeyAddressArg = tx.pure.id(
		conf.encryptedSecretShareSigningKeypair.toSuiAddress(),
	);
	const userPublicOutputArg = tx.pure(bcs.vector(bcs.u8()).serialize(centralizedPublicOutput));
	const signerPublicKeyArg = tx.pure(
		bcs.vector(bcs.u8()).serialize(conf.suiClientKeypair.getPublicKey().toRawBytes()),
	);

	const emptyIKACoin = tx.moveCall({
		target: `${SUI_PACKAGE_ID}::coin::zero`,
		arguments: [],
		typeArguments: [`${conf.ikaConfig.packages.ika_package_id}::ika::IKA`],
	});
	const sessionIdentifier = await createSessionIdentifier(
		tx,
		dwalletStateArg,
		conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id,
	);
	tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::request_dwallet_dkg_second_round`,
		arguments: [
			dwalletStateArg,
			dwalletCapArg,
			centralizedPublicKeyShareAndProofArg,
			encryptedCentralizedSecretShareAndProofArg,
			encryptionKeyAddressArg,
			userPublicOutputArg,
			signerPublicKeyArg,
			sessionIdentifier,
			emptyIKACoin,
			tx.gas,
		],
	});
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
	if (result.errors !== undefined) {
		throw new Error(`DKG second round failed with errors ${result.errors}`);
	}
	const startSessionEvent = result.events?.at(1)?.parsedJson;
	if (!isStartDKGSecondRoundEvent(startSessionEvent)) {
		throw new Error('invalid start session event');
	}
	const dwallet = await getObjectWithType(conf, firstRoundOutputResult.dwalletID, isActiveDWallet);
	return {
		dwallet,
		encrypted_user_secret_key_share_id:
			startSessionEvent.event_data.encrypted_user_secret_key_share_id,
	};
}

interface DKGFirstRoundOutputResult {
	sessionIdentifier: Uint8Array;
	output: Uint8Array;
	dwalletCapID: string;
	dwalletID: string;
}

/**
 * Starts the first round of the DKG protocol to create a new dWallet.
 * The output of this function is being used to generate the input for the second round,
 * and as input for the centralized party round.
 */
async function launchDKGFirstRound(c: Config): Promise<DKGFirstRoundOutputResult> {
	const tx = new Transaction();
	const emptyIKACoin = tx.moveCall({
		target: `${SUI_PACKAGE_ID}::coin::zero`,
		arguments: [],
		typeArguments: [`${c.ikaConfig.packages.ika_package_id}::ika::IKA`],
	});
	const networkDecryptionKeyID = await getNetworkDecryptionKeyID(c);
	const dwalletStateArg = tx.sharedObjectRef({
		objectId: c.ikaConfig.objects.ika_dwallet_coordinator_object_id,
		initialSharedVersion: await getInitialSharedVersion(
			c,
			c.ikaConfig.objects.ika_dwallet_coordinator_object_id,
		),
		mutable: true,
	});
	const sessionIdentifier = await createSessionIdentifier(
		tx,
		dwalletStateArg,
		c.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id,
	);
	const dwalletCap = tx.moveCall({
		target: `${c.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::request_dwallet_dkg_first_round`,
		arguments: [
			dwalletStateArg,
			tx.pure.id(networkDecryptionKeyID),
			tx.pure.u32(0),
			sessionIdentifier,
			emptyIKACoin,
			tx.gas,
		],
	});
	tx.transferObjects([dwalletCap], c.suiClientKeypair.toSuiAddress());
	tx.moveCall({
		target: `${SUI_PACKAGE_ID}::coin::destroy_zero`,
		arguments: [emptyIKACoin],
		typeArguments: [`${c.ikaConfig.packages.ika_package_id}::ika::IKA`],
	});
	const result = await c.client.signAndExecuteTransaction({
		signer: c.suiClientKeypair,
		transaction: tx,
		options: {
			showEffects: true,
			showEvents: true,
		},
	});
	const startDKGEvent = result.events?.at(1)?.parsedJson;
	if (!isStartDKGFirstRoundEvent(startDKGEvent)) {
		throw new Error('invalid start DKG first round event');
	}
	const dwalletID = startDKGEvent.event_data.dwallet_id;
	const output = await waitForDKGFirstRoundOutput(c, dwalletID);
	return {
		sessionIdentifier: startDKGEvent.session_identifier_preimage,
		output: output,
		dwalletCapID: startDKGEvent.event_data.dwallet_cap_id,
		dwalletID,
	};
}

/**
 * Starts the first round of the DKG protocol to create a new dWallet with given coins.
 *
 * TODO (#1321): Allow running all MPC flows with given coins IDs.
 */
export async function launchDKGFirstRoundWithGivenCoins(
	c: Config,
	sui_coin_id: string,
	ika_coin_id: string = '0x9df87437f4f0fb73bffe6fc6291f568da6e59ad4ad0770743b21cd4e1c030914',
): Promise<DKGFirstRoundOutputResult> {
	const tx = new Transaction();
	const networkDecryptionKeyID = await getNetworkDecryptionKeyID(c);
	const ikaCoinArg = tx.object(ika_coin_id);
	const suiCoinArg = tx.object(sui_coin_id);
	const dwalletStateArg = tx.sharedObjectRef({
		objectId: c.ikaConfig.objects.ika_dwallet_coordinator_object_id,
		initialSharedVersion: await getInitialSharedVersion(
			c,
			c.ikaConfig.objects.ika_dwallet_coordinator_object_id,
		),
		mutable: true,
	});
	const sessionIdentifier = await createSessionIdentifier(
		tx,
		dwalletStateArg,
		c.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id,
	);
	const dwalletCap = tx.moveCall({
		target: `${c.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::request_dwallet_dkg_first_round`,
		arguments: [
			dwalletStateArg,
			tx.pure.id(networkDecryptionKeyID),
			tx.pure.u32(0),
			sessionIdentifier,
			ikaCoinArg,
			suiCoinArg,
		],
	});
	tx.transferObjects([dwalletCap], c.suiClientKeypair.toSuiAddress());
	const result = await c.client.signAndExecuteTransaction({
		signer: c.suiClientKeypair,
		transaction: tx,
		options: {
			showEffects: true,
			showEvents: true,
		},
	});
	const startDKGEvent = result.events?.at(1)?.parsedJson;
	if (!isStartDKGFirstRoundEvent(startDKGEvent)) {
		throw new Error('invalid start DKG first round event');
	}
	const dwalletID = startDKGEvent.event_data.dwallet_id;
	const output = await waitForDKGFirstRoundOutput(c, dwalletID);
	return {
		sessionIdentifier: startDKGEvent.session_identifier_preimage,
		output: output,
		dwalletCapID: startDKGEvent.event_data.dwallet_cap_id,
		dwalletID,
	};
}

function isWaitingForUserDWallet(obj: any): obj is WaitingForUserDWallet {
	return obj?.state?.fields?.first_round_output !== undefined;
}

async function waitForDKGFirstRoundOutput(conf: Config, dwalletID: string): Promise<Uint8Array> {
	const startTime = Date.now();

	while (Date.now() - startTime <= conf.timeout) {
		// Wait for a bit before polling again, objects might not be available immediately.
		await delay(5_000);
		const dwallet = await conf.client.getObject({
			id: dwalletID,
			options: {
				showContent: true,
			},
		});
		if (isMoveObject(dwallet?.data?.content)) {
			const dwalletMoveObject = dwallet?.data?.content?.fields;
			if (isWaitingForUserDWallet(dwalletMoveObject)) {
				return dwalletMoveObject.state.fields.first_round_output;
			}
		}
	}
	const seconds = ((Date.now() - startTime) / 1000).toFixed(2);
	throw new Error(
		`timeout: unable to fetch the DWallet object within ${
			conf.timeout / (60 * 1000)
		} minutes (${seconds} seconds passed).`,
	);
}

export async function acceptEncryptedUserShare(
	conf: Config,
	encryptedDWalletData: EncryptedDWalletData,
): Promise<void> {
	const dwallet = await getObjectWithType(conf, encryptedDWalletData.dwallet_id, isActiveDWallet);
	const dwalletOutput = dwallet.state.fields.public_output;
	const signedPublicOutput = await conf.encryptedSecretShareSigningKeypair.sign(
		new Uint8Array(dwalletOutput),
	);
	const dWalletStateData = await getDWalletSecpState(conf);
	const tx = new Transaction();
	const dwalletStateArg = tx.sharedObjectRef({
		objectId: dWalletStateData.object_id,
		initialSharedVersion: dWalletStateData.initial_shared_version,
		mutable: true,
	});
	const dwalletIDArg = tx.pure.id(encryptedDWalletData.dwallet_id);
	const encryptedUserSecretKeyShareIDArg = tx.pure.id(
		encryptedDWalletData.encrypted_user_secret_key_share_id,
	);
	const userOutputSignatureArg = tx.pure(bcs.vector(bcs.u8()).serialize(signedPublicOutput));
	tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::accept_encrypted_user_share`,
		arguments: [
			dwalletStateArg,
			dwalletIDArg,
			encryptedUserSecretKeyShareIDArg,
			userOutputSignatureArg,
		],
	});
	const result = await conf.client.signAndExecuteTransaction({
		signer: conf.suiClientKeypair,
		transaction: tx,
		options: {
			showEvents: true,
		},
	});
	if (result.events?.length === 0) {
		throw new Error('failed to accept encrypted user share');
	}
}
