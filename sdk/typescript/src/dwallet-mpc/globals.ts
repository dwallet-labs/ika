// Copyright (c) dWallet Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear
import * as fs from 'node:fs';
import { network_dkg_public_output_to_protocol_pp } from '@dwallet-network/dwallet-mpc-wasm';
import type { SuiClient } from '@mysten/sui/client';
import type { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import type { Transaction } from '@mysten/sui/transactions';
import sha3 from 'js-sha3';

export const DWALLET_COORDINATOR_MOVE_MODULE_NAME = 'coordinator';
export const DWALLET_COORDINATOR_INNER_MOVE_MODULE_NAME = 'coordinator_inner';
export const DWALLET_NETWORK_VERSION = 0;

export const SUI_PACKAGE_ID = '0x2';
export const checkpointCreationTime = 2000;

export interface IkaPackageConfig {
	ika_package_id: string;
	ika_common_package_id: string;
	ika_dwallet_2pc_mpc_package_id: string;
	ika_system_package_id: string;
}

export interface IkaObjectsConfig {
	ika_system_object_id: string;
	ika_dwallet_coordinator_object_id: string;
}

export interface IkaConfig {
	packages: IkaPackageConfig;
	objects: IkaObjectsConfig;
}

export interface Config {
	suiClientKeypair: Ed25519Keypair;
	encryptedSecretShareSigningKeypair: Ed25519Keypair;
	client: SuiClient;
	timeout: number;
	ikaConfig: IkaConfig;
	dWalletSeed: Uint8Array;
}

// noinspection JSUnusedGlobalSymbols
export enum MPCKeyScheme {
	Secp256k1 = 0,
	Ristretto = 1,
}

/**
 * Utility function to create a delay.
 */
export function delay(ms: number) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

export interface Presign {
	id: { id: string };
	dwallet_id: string;
	state: {
		fields: {
			presign: Uint8Array;
		};
	};
	cap_id: string;
}

export function isPresign(obj: any): obj is Presign {
	return (
		obj?.id !== undefined &&
		obj?.dwallet_id !== undefined &&
		obj?.state?.fields?.presign !== undefined
	);
}

export async function getObjectWithType<TObject>(
	conf: Config,
	objectID: string,
	isObject: (obj: any) => obj is TObject,
): Promise<TObject> {
	const startTime = Date.now();
	while (Date.now() - startTime <= conf.timeout) {
		// Wait for a bit before polling again, objects might not be available immediately.
		const interval = 500;
		await delay(interval);
		const res = await conf.client.getObject({
			id: objectID,
			options: { showContent: true },
		});

		const objectData =
			res.data?.content?.dataType === 'moveObject' && isObject(res.data.content.fields)
				? (res.data.content.fields as TObject)
				: null;

		if (objectData) {
			return objectData;
		}
	}
	const seconds = ((Date.now() - startTime) / 1000).toFixed(2);
	throw new Error(
		`timeout: unable to fetch an object within ${
			conf.timeout / (60 * 1000)
		} minutes (${seconds} seconds passed).`,
	);
}

/**
 * Represents the Move `coordinatorInner` struct.
 */
interface CoordinatorInner {
	fields: {
		value: {
			fields: {
				dwallet_network_encryption_keys: {
					fields: {
						id: {
							id: string;
						};
						size: number;
					};
				};
				current_epoch: number;
				pricing_and_fee_manager: {
					fields: {
						gas_fee_reimbursement_sui_system_call_value: number;
						/// SUI balance for gas fee reimbursement to fund network tx responses
						gas_fee_reimbursement_sui_system_call_balance: number;
						/// IKA fees charged for consensus validation
						fee_charged_ika: number;
					};
				};
			};
		};
	};
}

export interface SystemInner {
	fields: {
		value: {
			fields: {
				validator_set: {
					fields: {
						validators: {
							fields: {
								id: {
									id: string;
								};
								size: number;
							};
						};
					};
				};
			};
		};
	};
}

export function isSystemInner(obj: any): obj is SystemInner {
	return (
		obj?.fields?.value?.fields?.validator_set?.fields?.validators?.fields?.id?.id !== undefined &&
		obj?.fields?.value?.fields?.validator_set?.fields?.validators?.fields?.size !== undefined
	);
}

export interface Validator {
	operation_cap_id: string;
}

export function isValidator(obj: any): obj is Validator {
	return obj?.operation_cap_id !== undefined;
}

export async function getAllChildObjectsIDs(c: Config, parentID: string): Promise<string[]> {
	let cursor: string | null = null;
	const sessionsIDs: string[] = [];
	do {
		const dynamicFieldPage = await c.client.getDynamicFields({
			parentId: parentID,
			cursor,
		});
		if (dynamicFieldPage.data.length === 0) {
			break;
		}
		for (const field of dynamicFieldPage.data) {
			const session = await c.client.getObject({
				id: field.objectId,
				options: { showContent: true },
			});
			if (!session.data) {
				continue;
			}
			sessionsIDs.push(session?.data?.objectId);
		}
		cursor = dynamicFieldPage.nextCursor;
	} while (cursor);
	return sessionsIDs;
}

interface DWalletNetworkDecryptionKey {
	fields: {
		id: { id: string };
		network_dkg_public_output: Uint8Array;
	};
}

/**
 * Represents a Move shared object owner.
 */
interface SharedObjectOwner {
	Shared: {
		// The object version when it became shared.
		initial_shared_version: number;
	};
}

interface MoveObject {
	fields: any;
}

interface MoveDynamicField {
	fields: {
		name: string;
		value: Uint8Array;
	};
}

// todo(zeev): fix this
export interface SharedObjectData {
	object_id: string;
	initial_shared_version: number;
}

export function isMoveObject(obj: any): obj is MoveObject {
	return obj?.fields !== undefined;
}

export function isMoveDynamicField(obj: any): obj is MoveDynamicField {
	return obj?.fields.name !== undefined || obj?.fields.value !== undefined;
}

export function isCoordinatorInner(obj: any): obj is CoordinatorInner {
	return (
		obj?.fields?.value?.fields?.dwallet_network_encryption_keys !== undefined &&
		obj?.fields?.value?.fields?.current_epoch !== undefined
	);
}

export function isDWalletNetworkDecryptionKey(obj: any): obj is DWalletNetworkDecryptionKey {
	return obj?.fields?.network_dkg_public_output !== undefined;
}

export function isSharedObjectOwner(obj: any): obj is SharedObjectOwner {
	return obj?.Shared?.initial_shared_version !== undefined;
}

export async function getInitialSharedVersion(c: Config, objectID: string): Promise<number> {
	const obj = await c.client.getObject({
		id: objectID,
		options: {
			showOwner: true,
		},
	});
	const owner = obj.data?.owner;
	if (!owner || !isSharedObjectOwner(owner)) {
		throw new Error('Object is not shared');
	}
	return owner.Shared?.initial_shared_version;
}

// todo(zeev): fix naming and fix the types.
export async function getDWalletSecpState(c: Config): Promise<SharedObjectData> {
	const initialSharedVersion = await getInitialSharedVersion(
		c,
		c.ikaConfig.objects.ika_dwallet_coordinator_object_id,
	);
	return {
		object_id: c.ikaConfig.objects.ika_dwallet_coordinator_object_id,
		initial_shared_version: initialSharedVersion,
	};
}

export interface DWalletCap {
	dwallet_id: string;
}

export function isDWalletCap(obj: any): obj is DWalletCap {
	return !!obj?.dwallet_id;
}

export interface ActiveDWallet {
	state: {
		fields: {
			public_output: Uint8Array;
		};
	};
	id: { id: string };
}

export function isActiveDWallet(obj: any): obj is ActiveDWallet {
	return obj?.state?.fields?.public_output !== undefined;
}

export async function getNetworkDecryptionKeyPublicOutputID(
	c: Config,
	networkDecryptionKeyId?: string | null,
): Promise<string> {
	networkDecryptionKeyId = networkDecryptionKeyId ?? (await getNetworkDecryptionKeyID(c));
	const networkDecryptionKey = await c.client.getObject({
		id: networkDecryptionKeyId,
		options: { showContent: true },
	});

	if (
		!networkDecryptionKey ||
		!isMoveObject(networkDecryptionKey?.data?.content) ||
		!isDWalletNetworkDecryptionKey(networkDecryptionKey.data.content) ||
		!isMoveObject(networkDecryptionKey.data.content.fields.network_dkg_public_output)
	) {
		throw new Error(`invalid network decryption key object: ${networkDecryptionKeyId}`);
	}
	return networkDecryptionKey.data.content.fields.network_dkg_public_output.fields.contents.fields
		.id?.id;
}

async function readTableVecAsRawBytes(c: Config, table_id: string): Promise<Uint8Array> {
	let cursor: string | null = null;
	const allTableRows: { objectId: string }[] = [];

	// Fetch all dynamic fields using pagination with cursor
	do {
		const dynamicFieldPage = await c.client.getDynamicFields({
			parentId: table_id,
			cursor,
		});

		if (!dynamicFieldPage?.data?.length) {
			if (allTableRows.length === 0) {
				throw new Error('no dynamic fields found');
			}
			break;
		}

		allTableRows.push(...dynamicFieldPage.data);
		cursor = dynamicFieldPage.nextCursor;
	} while (cursor);

	const data: Uint8Array[] = [];
	for (const tableRowResult of allTableRows) {
		const id = tableRowResult.objectId;

		const dynField = await c.client.getObject({
			id: id,
			options: { showContent: true },
		});
		if (!isMoveObject(dynField.data?.content) || !isMoveDynamicField(dynField.data?.content)) {
			throw new Error('invalid dynamic field object');
		}
		const tableIndex = parseInt(dynField.data.content.fields.name);
		data[tableIndex] = dynField.data.content.fields.value;
	}
	return new Uint8Array(data.flatMap((arr) => Array.from(arr)));
}

export async function getNetworkPublicParameters(c: Config): Promise<Uint8Array> {
	const networkDecryptionKeyPublicOutputID = await getNetworkDecryptionKeyPublicOutputID(c, null);
	const currentEpoch = await getNetworkCurrentEpochNumber(c);
	const cachedPP = getCachedPublicParameters(networkDecryptionKeyPublicOutputID, currentEpoch);
	if (cachedPP) {
		return cachedPP;
	}
	const key = await readTableVecAsRawBytes(c, networkDecryptionKeyPublicOutputID);
	const publicParameters = network_dkg_public_output_to_protocol_pp(key);
	await cachePublicParameters(
		networkDecryptionKeyPublicOutputID,
		currentEpoch,
		new Uint8Array(publicParameters),
	);
	return publicParameters;
}

export async function getNetworkDecryptionKeyID(c: Config): Promise<string> {
	const dynamicFields = await c.client.getDynamicFields({
		parentId: c.ikaConfig.objects.ika_dwallet_coordinator_object_id,
	});
	const coordinatorInner = await c.client.getDynamicFieldObject({
		parentId: c.ikaConfig.objects.ika_dwallet_coordinator_object_id,
		name: dynamicFields.data[DWALLET_NETWORK_VERSION].name,
	});
	if (!isCoordinatorInner(coordinatorInner.data?.content)) {
		throw new Error('Invalid coordinator inner');
	}
	const keysDynamicFields = await c.client.getDynamicFields({
		parentId:
			coordinatorInner.data?.content.fields.value.fields.dwallet_network_encryption_keys.fields.id
				.id,
	});

	const decryptionKeyID = keysDynamicFields.data[keysDynamicFields.data.length - 1].name
		.value as string;
	if (!decryptionKeyID) {
		throw new Error('No network decryption key found');
	}
	return decryptionKeyID;
}

export async function cachePublicParameters(key_id: string, epoch: number, networkKey: Uint8Array) {
	const configDirPath = `${process.env.HOME}/.ika`;
	const keyDirPath = `${configDirPath}/${key_id}`;
	if (!fs.existsSync(keyDirPath)) {
		fs.mkdirSync(keyDirPath, { recursive: true });
	}
	const filePath = `${keyDirPath}/${epoch}.key`;
	if (fs.existsSync(filePath)) {
		fs.unlinkSync(filePath);
	}
	fs.writeFileSync(filePath, networkKey);
}

export function getCachedPublicParameters(key_id: string, epoch: number): Uint8Array | null {
	const configDirPath = `${process.env.HOME}/.ika`;
	const keyDirPath = `${configDirPath}/${key_id}`;
	const filePath = `${keyDirPath}/${epoch}.key`;
	if (fs.existsSync(filePath)) {
		return fs.readFileSync(filePath);
	}
	return null;
}

export async function getNetworkCurrentEpochNumber(c: Config): Promise<number> {
	const dynamicFields = await c.client.getDynamicFields({
		parentId: c.ikaConfig.objects.ika_dwallet_coordinator_object_id,
	});
	const innerSystemState = await c.client.getDynamicFieldObject({
		parentId: c.ikaConfig.objects.ika_dwallet_coordinator_object_id,
		name: dynamicFields.data[DWALLET_NETWORK_VERSION].name,
	});
	if (!isCoordinatorInner(innerSystemState.data?.content)) {
		throw new Error('Invalid inner system state');
	}
	return innerSystemState.data.content.fields.value.fields.current_epoch;
}

export interface DWallet {
	dwalletID: string;
	dwallet_cap_id: string;
	secret_share: Uint8Array;
	output: Uint8Array;
	encrypted_secret_share_id: string;
}

export interface EncryptedDWalletData {
	dwallet_id: string;
	encrypted_user_secret_key_share_id: string;
}

export interface SessionIdentifierRegisteredEvent {
	session_object_id: string;
	session_identifier_preimage: Uint8Array;
}

export async function createSessionIdentifier(
	tx: Transaction,
	dwalletCoordinatorArg: {
		$kind: 'Input';
		Input: number;
		type?: 'object';
	},
	ika_dwallet_2pc_mpc_package_id: string,
) {
	const freshObjectAddress = tx.moveCall({
		target: `${SUI_PACKAGE_ID}::tx_context::fresh_object_address`,
		arguments: [],
		typeArguments: [],
	});
	const freshObjectAddressBytes = tx.moveCall({
		target: `${SUI_PACKAGE_ID}::address::to_bytes`,
		arguments: [freshObjectAddress],
		typeArguments: [],
	});
	return tx.moveCall({
		target: `${ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::register_session_identifier`,
		arguments: [dwalletCoordinatorArg, freshObjectAddressBytes],
		typeArguments: [],
	});
}

function encodeToASCII(input: string): Uint8Array {
	const asciiValues: number[] = [];
	for (let i = 0; i < input.length; i++) {
		asciiValues.push(input.charCodeAt(i));
	}
	return Uint8Array.from(asciiValues);
}

function u64ToBytesBigEndian(value: number | bigint): Uint8Array {
	// Ensure the input is a BigInt for accurate 64-bit operations
	const bigIntValue = BigInt(value);

	// Create an 8-byte (64-bit) ArrayBuffer
	const buffer = new ArrayBuffer(8);
	// Create a DataView to manipulate the buffer with specific endianness
	const view = new DataView(buffer);

	// Write the BigInt value as a BigInt64 (signed 64-bit integer)
	// or BigUint64 (unsigned 64-bit integer) depending on the context.
	// For u64, use setBigUint64.
	view.setBigUint64(0, bigIntValue, false); // false for big-endian

	// Return the Uint8Array representation of the buffer
	return new Uint8Array(buffer);
}

export function sessionIdentifierDigest(sessionIdentifier: Uint8Array): Uint8Array {
	const version = 0; // Version of the session identifier
	// Calculate the user session identifier for digest
	const data = [...u64ToBytesBigEndian(version), ...encodeToASCII('USER'), ...sessionIdentifier];
	// Compute the SHA3-256 digest of the serialized data
	const digest = sha3.keccak256.digest(data);
	return Uint8Array.from(digest);
}
