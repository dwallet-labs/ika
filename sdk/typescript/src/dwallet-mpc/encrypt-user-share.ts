import {
	decrypt_user_share,
	encrypt_secret_share,
	generate_secp_cg_keypair_from_seed,
	verify_user_share,
} from '@dwallet-network/dwallet-mpc-wasm';
import { bcs, toHex } from '@mysten/bcs';
import { Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';

import type { Config, EncryptedDWalletData } from './globals.js';
import {
	createSessionIdentifier,
	delay,
	DWALLET_COORDINATOR_MOVE_MODULE_NAME,
	getDWalletSecpState,
	getObjectWithType,
	isActiveDWallet,
	isMoveObject,
	SUI_PACKAGE_ID,
} from './globals.js';

/**
 * A class groups key pair.
 */
export interface ClassGroupsSecpKeyPair {
	encryptionKey: Uint8Array;
	decryptionKey: Uint8Array;
	objectID: string;
}

/**
 * Event emitted by the blockchain when an
 * `EncryptionKey` Move object is created.
 */
interface CreatedEncryptionKeyEvent {
	session_identifier_preimage: Uint8Array;
	encryption_key_id: string;
}

/**
 * A `class groups` Move encryption key object.
 */
interface EncryptionKey {
	encryption_key: Uint8Array;
	signer_address: string;
	encryption_key_signature: Uint8Array;
	signer_public_key: Uint8Array;
}

interface CreatedEncryptionKeyEvent {
	encryption_key_id: string;
	signer_address: string;
}

interface StartEncryptedShareVerificationEvent {
	event_data: {
		encrypted_user_secret_key_share_id: string;
	};
	session_identifier_preimage: Uint8Array;
}

interface VerifiedEncryptedUserSecretKeyShare {
	state: any;
}

interface EncryptedUserSecretKeyShare {
	id: { id: string };
	dwallet_id: string;
	encrypted_centralized_secret_share_and_proof: Uint8Array;
	encryption_key_id: string;
	encryption_key_address: string;
	source_encrypted_user_secret_key_share_id: string;
	state: {
		fields: {
			user_output_signature: Uint8Array;
		};
	};
}

function isEncryptionKey(obj: any): obj is EncryptionKey {
	return 'encryption_key' in obj && 'signer_address' in obj && 'encryption_key_signature' in obj;
}

export async function getOrCreateClassGroupsKeyPair(conf: Config): Promise<ClassGroupsSecpKeyPair> {
	const [expectedEncryptionKey, decryptionKey] = generate_secp_cg_keypair_from_seed(
		conf.dWalletSeed,
	);
	const activeEncryptionKeyObjID = await getActiveEncryptionKeyObjID(
		conf,
		conf.encryptedSecretShareSigningKeypair.toSuiAddress(),
	);
	if (activeEncryptionKeyObjID) {
		const activeEncryptionKeyObj = await getObjectWithType<EncryptionKey>(
			conf,
			activeEncryptionKeyObjID,
			isEncryptionKey,
		);
		if (isEqual(activeEncryptionKeyObj?.encryption_key, expectedEncryptionKey)) {
			return {
				encryptionKey: expectedEncryptionKey,
				decryptionKey,
				objectID: activeEncryptionKeyObjID,
			};
		}
		throw new Error(
			'the encryption key derived from the key pair does not match the one in the active encryption keys table',
		);
	}

	const encryptionKeyCreationEvent: CreatedEncryptionKeyEvent = await registerEncryptionKey(
		conf,
		expectedEncryptionKey,
	);

	return {
		decryptionKey,
		encryptionKey: expectedEncryptionKey,
		objectID: encryptionKeyCreationEvent.encryption_key_id,
	};
}

function isEqual(arr1: Uint8Array, arr2: Uint8Array): boolean {
	return arr1.length === arr2.length && arr1.every((value, index) => value === arr2[index]);
}

/**
 * Retrieves the active encryption key object ID
 * from the active encryption keys table *activeEncryptionKeysTableID*
 * for the given address — derived from the public key.
 * Throws an error otherwise.
 */
async function getActiveEncryptionKeyObjID(conf: Config, address: string): Promise<string> {
	const tx = new Transaction();
	const dwalletState = await getDWalletSecpState(conf);
	tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::get_active_encryption_key`,
		arguments: [
			tx.sharedObjectRef({
				objectId: dwalletState.object_id,
				initialSharedVersion: dwalletState.initial_shared_version,
				mutable: false,
			}),
			tx.pure.address(address),
		],
	});

	// Safe to use this function as it has been used here:
	// https://github.com/dwallet-labs/dwallet-network/blob/29929ded135f05578b6ce33b52e6ff5e894d0487/sdk/deepbook-v3/src/client.ts#L84
	// in late 2024 (can be seen with git blame).
	// Note that regular `getObject()` is not working because of dynamic fields.
	const res = await conf.client.devInspectTransactionBlock({
		sender: address,
		transactionBlock: tx,
	});

	const objIDArray = new Uint8Array(res.results?.at(0)?.returnValues?.at(0)?.at(0) as number[]);
	return toHex(objIDArray);
}

/**
 * Registers (stores) the given encryption key in the blockchain.
 *
 * This function facilitates the storage of an encryption key as an immutable object
 * on the blockchain.
 * The key is signed with the provided key pair to ensure
 * cryptographic integrity and validate it by the blockchain.
 * Currently, only Class Groups encryption keys are supported.
 *
 * ### Parameters
 * — `keyPair`: A `Keypair` object used to sign the encryption key.
 * — `encryptionKey`: The encryption key to be registered.
 * — `encryptionKeyScheme`: The scheme of the encryption key (e.g., Class Groups).
 */
async function registerEncryptionKey(
	conf: Config,
	encryptionKey: Uint8Array,
): Promise<CreatedEncryptionKeyEvent> {
	// Sign the encryption key with the key pair.
	const encryptionKeySignature = await conf.encryptedSecretShareSigningKeypair.sign(
		new Uint8Array(encryptionKey),
	);
	const tx = new Transaction();

	const dwalletState = await getDWalletSecpState(conf);
	tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::register_encryption_key`,
		arguments: [
			tx.sharedObjectRef({
				objectId: dwalletState.object_id,
				initialSharedVersion: dwalletState.initial_shared_version,
				mutable: true,
			}),
			// TODO: select the correct curve
			tx.pure.u32(0),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptionKey)),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptionKeySignature)),
			tx.pure(
				bcs
					.vector(bcs.u8())
					.serialize(conf.encryptedSecretShareSigningKeypair.getPublicKey().toRawBytes()),
			),
		],
	});
	const res = await conf.client.signAndExecuteTransaction({
		signer: conf.suiClientKeypair,
		transaction: tx,
		options: {
			showEvents: true,
		},
	});
	const createdEncryptionKeyEvent = res.events?.find((event) =>
		isCreatedEncryptionKeyEvent(event.parsedJson),
	);
	if (!createdEncryptionKeyEvent) {
		throw new Error('Encryption key registration failed');
	}
	return createdEncryptionKeyEvent.parsedJson as CreatedEncryptionKeyEvent;
}

function isCreatedEncryptionKeyEvent(obj: any): obj is CreatedEncryptionKeyEvent {
	return 'encryption_key_id' in obj && 'signer_address' in obj;
}

/**
 * Encrypts the given dWallet secret user key share for a given destination public key.
 * This is needed to ensure that the destination entity can
 * later verify and decrypt the encrypted dWallet secret key share.
 *
 * The function ensures that the destination public key has an active encryption key and
 * verifies its authenticity by checking its signature against the public key.
 * If the encryption key is valid,
 * the function encrypts the dWallet secret key share and returns the
 * encrypted key share along with a proof of encryption.
 *
 * @param sourceConf - The key pair that currently owns the sourceDwallet that will
 * be encrypted for the destination.
 * @param destSuiAddress - The sui network address of the destination entity, used to get the encryption key.
 * @param dWalletSecretShare - The secret user key share to encrypt.
 * @param networkDecryptionKeyPublicOutput - The public output of the network decryption key.
 * @returns The encrypted secret user key share.
 * @throws Will throw an error if the destination public key does not have an active encryption key
 *         or if the encryption key is not valid (not signed by the destination's public key).
 */
export async function encryptUserShareForPublicKey(
	sourceConf: Config,
	destSuiAddress: string,
	dWalletSecretShare: Uint8Array,
	networkDecryptionKeyPublicOutput: Uint8Array,
): Promise<Uint8Array> {
	const destActiveEncryptionKeyObjID = await getActiveEncryptionKeyObjID(
		sourceConf,
		destSuiAddress,
	);
	if (!destActiveEncryptionKeyObjID) {
		throw new Error('the dest key pair does not have an active encryption key');
	}
	const destActiveEncryptionKeyObj = await getObjectWithType<EncryptionKey>(
		sourceConf,
		destActiveEncryptionKeyObjID,
		isEncryptionKey,
	);

	const destSuiPubKey = new Ed25519PublicKey(destActiveEncryptionKeyObj.signer_public_key);
	if (!(destSuiPubKey.toSuiAddress() === destSuiAddress)) {
		throw new Error('the destination public key does not match the destination address');
	}
	// Make sure that the active signed encryption key is
	// valid by verifying that the destination public key has signed it.
	const isValidDestEncryptionKey = await destSuiPubKey.verify(
		new Uint8Array(destActiveEncryptionKeyObj.encryption_key),
		new Uint8Array(destActiveEncryptionKeyObj.encryption_key_signature),
	);
	if (!isValidDestEncryptionKey) {
		throw new Error(
			'the destination encryption key has not been signed by the destination public key',
		);
	}

	// Encrypt the centralized secret key share with the destination active encryption key.
	return encrypt_secret_share(
		// Centralized Secret Key Share.
		dWalletSecretShare,
		// Encryption Key.
		new Uint8Array(destActiveEncryptionKeyObj.encryption_key),
		networkDecryptionKeyPublicOutput,
	);
}

async function fetchPublicKeyByAddress(conf: Config, address: string): Promise<Ed25519PublicKey> {
	const destActiveEncryptionKeyObjID = await getActiveEncryptionKeyObjID(conf, address);
	if (!destActiveEncryptionKeyObjID) {
		throw new Error('the dest key pair does not have an active encryption key');
	}
	const destActiveEncryptionKeyObj = await getObjectWithType<EncryptionKey>(
		conf,
		destActiveEncryptionKeyObjID,
		isEncryptionKey,
	);

	const destSuiPubKey = new Ed25519PublicKey(destActiveEncryptionKeyObj.signer_public_key);
	if (!(destSuiPubKey.toSuiAddress() === address)) {
		throw new Error('the destination public key does not match the destination address');
	}
	return destSuiPubKey;
}

/**
 * Transfers an encrypted dWallet user secret key share from a source entity to a destination entity.
 * This function emits an event with the encrypted user secret key share,
 * along with its cryptographic proof, to the blockchain.
 * The chain verifies that the encrypted data matches the expected secret key share
 * associated with the dWallet before creating an `EncryptedUserSecretKeyShare` object.
 */
export async function transferEncryptedSecretShare(
	sourceConf: Config,
	destSuiAddress: string,
	encryptedUserKeyShareAndProofOfEncryption: Uint8Array,
	dwalletID: string,
	source_encrypted_user_secret_key_share_id: string,
): Promise<string> {
	const destSuiPublicKey = await fetchPublicKeyByAddress(sourceConf, destSuiAddress);
	const tx = new Transaction();
	const dwalletSecpState = await getDWalletSecpState(sourceConf);
	const dwalletStateArg = tx.sharedObjectRef({
		objectId: dwalletSecpState.object_id,
		initialSharedVersion: dwalletSecpState.initial_shared_version,
		mutable: true,
	});
	const dwalletIDArg = tx.pure.id(dwalletID);
	const destinationEncryptionKeyAddress = destSuiPublicKey.toSuiAddress();
	const destinationEncryptionKeyAddressArg = tx.pure.address(destinationEncryptionKeyAddress);
	const encryptedCentralizedSecretShareAndProofArg = tx.pure(
		bcs.vector(bcs.u8()).serialize(encryptedUserKeyShareAndProofOfEncryption),
	);
	const sourceEncryptedUserSecretKeyShareIDArg = tx.pure.id(
		source_encrypted_user_secret_key_share_id,
	);
	const emptyIKACoin = tx.moveCall({
		target: `${SUI_PACKAGE_ID}::coin::zero`,
		arguments: [],
		typeArguments: [`${sourceConf.ikaConfig.packages.ika_package_id}::ika::IKA`],
	});
	const sessionIdentifier = await createSessionIdentifier(
		tx,
		dwalletStateArg,
		sourceConf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id,
	);
	tx.moveCall({
		target: `${sourceConf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::request_re_encrypt_user_share_for`,
		arguments: [
			dwalletStateArg,
			dwalletIDArg,
			destinationEncryptionKeyAddressArg,
			encryptedCentralizedSecretShareAndProofArg,
			sourceEncryptedUserSecretKeyShareIDArg,
			sessionIdentifier,
			emptyIKACoin,
			tx.gas,
		],
	});

	tx.moveCall({
		target: `${SUI_PACKAGE_ID}::coin::destroy_zero`,
		arguments: [emptyIKACoin],
		typeArguments: [`${sourceConf.ikaConfig.packages.ika_package_id}::ika::IKA`],
	});

	const result = await sourceConf.client.signAndExecuteTransaction({
		signer: sourceConf.suiClientKeypair,
		transaction: tx,
		options: {
			showEvents: true,
		},
	});
	const startVerificationEvent = result.events?.at(1)?.parsedJson;
	if (!isStartEncryptedShareVerificationEvent(startVerificationEvent)) {
		throw new Error('invalid start DKG first round event');
	}
	await waitForChainVerification(
		sourceConf,
		startVerificationEvent.event_data.encrypted_user_secret_key_share_id,
	);
	return startVerificationEvent.event_data.encrypted_user_secret_key_share_id;
}

function isStartEncryptedShareVerificationEvent(
	obj: any,
): obj is StartEncryptedShareVerificationEvent {
	return (
		!!obj?.session_identifier_preimage && !!obj?.event_data?.encrypted_user_secret_key_share_id
	);
}

function isVerifiedEncryptedUserSecretKeyShare(
	obj: any,
): obj is VerifiedEncryptedUserSecretKeyShare {
	return obj.state.variant === 'NetworkVerificationCompleted';
}

async function waitForChainVerification(conf: Config, encryptedSecretShareObjID: string) {
	const startTime = Date.now();

	while (Date.now() - startTime <= conf.timeout) {
		// Wait for a bit before polling again, objects might not be available immediately.
		await delay(5_000);
		const dwallet = await conf.client.getObject({
			id: encryptedSecretShareObjID,
			options: {
				showContent: true,
			},
		});
		if (isMoveObject(dwallet?.data?.content)) {
			const dwalletMoveObject = dwallet?.data?.content?.fields;
			if (isVerifiedEncryptedUserSecretKeyShare(dwalletMoveObject)) {
				return;
			}
		}
	}
	const seconds = ((Date.now() - startTime) / 1000).toFixed(2);
	throw new Error(
		`timeout: unable to fetch the VerifiedEncryptedUserSecretKeyShare object within ${
			conf.timeout / (60 * 1000)
		} minutes (${seconds} seconds passed).`,
	);
}

function isEncryptedUserSecretKeyShare(objContent: any): objContent is EncryptedUserSecretKeyShare {
	return (
		objContent?.id?.id !== undefined &&
		objContent?.dwallet_id !== undefined &&
		objContent?.encrypted_centralized_secret_share_and_proof !== undefined &&
		objContent?.encryption_key_id !== undefined &&
		objContent?.encryption_key_address !== undefined &&
		objContent?.source_encrypted_user_secret_key_share_id !== undefined
	);
}

export async function decryptAndVerifyReceivedUserShare(
	conf: Config,
	encryptedDWalletData: EncryptedDWalletData,
	sourceSuiAddress: string,
	networkDecryptionKeyPublicOutput: Uint8Array,
) {
	const dwallet = await getObjectWithType(conf, encryptedDWalletData.dwallet_id, isActiveDWallet);
	const dwalletOutput = dwallet.state.fields.public_output;
	const encryptedDWalletSecretShare = await getObjectWithType(
		conf,
		encryptedDWalletData.encrypted_user_secret_key_share_id,
		isEncryptedUserSecretKeyShare,
	);
	const encryptedSecretShareAndProof =
		encryptedDWalletSecretShare.encrypted_centralized_secret_share_and_proof;
	const sourceEncryptedSecretShare = await getObjectWithType(
		conf,
		encryptedDWalletSecretShare.source_encrypted_user_secret_key_share_id,
		isEncryptedUserSecretKeyShare,
	);
	const signedDWalletOutput = sourceEncryptedSecretShare.state.fields.user_output_signature;
	const senderPublicKey = await fetchPublicKeyByAddress(conf, sourceSuiAddress);
	if (
		!(await senderPublicKey.verify(
			new Uint8Array(dwalletOutput),
			new Uint8Array(signedDWalletOutput),
		))
	) {
		throw new Error('the desired address did not sign the dWallet public key share');
	}
	const cgKeyPair = await getOrCreateClassGroupsKeyPair(conf);
	const decryptedSecretShare = decrypt_user_share(
		cgKeyPair.decryptionKey,
		cgKeyPair.encryptionKey,
		dwalletOutput,
		encryptedSecretShareAndProof,
		networkDecryptionKeyPublicOutput,
	);
	// Before validating this centralized output,
	// we are making sure it was signed by us.
	const isValid = verify_user_share(
		new Uint8Array(decryptedSecretShare),
		new Uint8Array(dwalletOutput),
		networkDecryptionKeyPublicOutput,
	);
	if (!isValid) {
		throw new Error('the decrypted key share does not match the dWallet public key share');
	}
	return decryptedSecretShare;
}
