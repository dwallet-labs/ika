// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type {
	Curve,
	DKGRequestInput,
	ImportDWalletVerificationRequestInput,
	UserShareEncryptionKeys,
} from '@ika.xyz/core';
import {
	fromNumberToCurve,
	prepareDKG,
	prepareImportedKeyVerification,
	userAndNetworkDKGOutputMatch,
} from '@ika.xyz/core';
import { bcs } from '@mysten/sui/bcs';
import type { PublicKey } from '@mysten/sui/cryptography';
import { SIGNATURE_FLAG_TO_SCHEME } from '@mysten/sui/cryptography';
import { Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';

import type { IkaClient } from './ika-client.js';
import type { DWallet, EncryptedUserSecretKeyShare, EncryptionKey } from './types.js';

/**
 * Prepare all cryptographic data needed for DKG (async version that fetches protocol parameters).
 *
 * This is the Sui-specific wrapper that converts a Sui address string to bytes
 * and fetches protocol parameters from the network.
 *
 * @param ikaClient - The IkaClient instance to fetch network parameters from
 * @param curve - The curve to use for key generation
 * @param userShareEncryptionKeys - The user's encryption keys for securing the user's share
 * @param bytesToHash - The bytes to hash for session identifier generation
 * @param senderAddress - The Sui sender address string
 * @returns Promise resolving to complete prepared data for DKG
 *
 * SECURITY WARNING: *secret key share must be kept private!*
 */
export async function prepareDKGAsync(
	ikaClient: IkaClient,
	curve: Curve,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	bytesToHash: Uint8Array,
	senderAddress: string,
): Promise<DKGRequestInput> {
	const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(undefined, curve);
	const senderAddressBytes = bcs.Address.serialize(senderAddress).toBytes();

	return prepareDKG(
		protocolPublicParameters,
		curve,
		userShareEncryptionKeys.encryptionKey,
		bytesToHash,
		senderAddressBytes,
	);
}

/**
 * Prepare verification data for importing an existing cryptographic key as a DWallet.
 *
 * @param ikaClient - The IkaClient instance to fetch network parameters from
 * @param curve - The curve to use for key generation
 * @param bytesToHash - The bytes to hash for session identifier generation
 * @param senderAddress - The Sui sender address string
 * @param userShareEncryptionKeys - The user's encryption keys
 * @param privateKey - The existing private key to import
 * @returns Promise resolving to complete verification data for the import process
 */
export async function prepareImportedKeyDWalletVerification(
	ikaClient: IkaClient,
	curve: Curve,
	bytesToHash: Uint8Array,
	senderAddress: string,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	privateKey: Uint8Array,
): Promise<ImportDWalletVerificationRequestInput> {
	const senderAddressBytes = bcs.Address.serialize(senderAddress).toBytes();
	const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(undefined, curve);

	return prepareImportedKeyVerification(
		protocolPublicParameters,
		curve,
		bytesToHash,
		senderAddressBytes,
		userShareEncryptionKeys.encryptionKey,
		privateKey,
	);
}

/**
 * Verify and get the DWallet DKG public output.
 * The `publicKey` is used to verify the user's public output signature.
 *
 * SECURITY WARNING: For withSecrets flows, the public key or public output must be saved by the developer during DKG,
 * NOT fetched from the network, to ensure proper verification.
 */
export async function verifyAndGetDWalletDKGPublicOutput(
	dWallet: DWallet,
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	publicKey: PublicKey,
): Promise<Uint8Array> {
	if (
		SIGNATURE_FLAG_TO_SCHEME[publicKey.flag() as keyof typeof SIGNATURE_FLAG_TO_SCHEME] !==
		'ED25519'
	) {
		throw new Error('Only ED25519 public keys are supported.');
	}

	const activeState = dWallet.state.Active;
	if (!activeState?.public_output) {
		throw new Error('DWallet is not in active state');
	}

	const keyHolderSignedState = encryptedUserSecretKeyShare.state.KeyHolderSigned;
	if (!keyHolderSignedState?.user_output_signature) {
		throw new Error('User output signature is undefined');
	}

	const userPublicOutput = Uint8Array.from(activeState.public_output);

	const userOutputSignature = Uint8Array.from(keyHolderSignedState.user_output_signature);

	if (!(await publicKey.verify(userPublicOutput, userOutputSignature))) {
		throw new Error('Invalid signature');
	}

	if (publicKey.toSuiAddress() !== encryptedUserSecretKeyShare.encryption_key_address) {
		throw new Error(
			'Invalid Sui address. The encryption key address does not match the signing keypair address.',
		);
	}

	return userPublicOutput;
}

/**
 * Get the Sui address derived from UserShareEncryptionKeys' signing public key.
 *
 * @param keys - The UserShareEncryptionKeys instance
 * @returns The Sui address string
 */
export function getSuiAddress(keys: UserShareEncryptionKeys): string {
	const pubKey = new Ed25519PublicKey(keys.getSigningPublicKeyBytes());
	return pubKey.toSuiAddress();
}

/**
 * Sign the dWallet public output to authorize a newly created dWallet.
 *
 * @param keys - The UserShareEncryptionKeys instance
 * @param dWallet - The dWallet object (must be in AwaitingKeyHolderSignature state)
 * @param userPublicOutput - The user's public output from DKG
 * @returns The Ed25519 signature over the dWallet public output
 */
export async function getUserOutputSignature(
	keys: UserShareEncryptionKeys,
	dWallet: DWallet,
	userPublicOutput: Uint8Array,
): Promise<Uint8Array> {
	if (!dWallet.state.AwaitingKeyHolderSignature?.public_output) {
		throw new Error('DWallet is not in awaiting key holder signature state');
	}

	const dWalletPublicOutput = Uint8Array.from(
		dWallet.state.AwaitingKeyHolderSignature?.public_output,
	);

	const isOutputMatch = await userAndNetworkDKGOutputMatch(
		fromNumberToCurve(dWallet.curve),
		userPublicOutput,
		dWalletPublicOutput,
	).catch(() => false);

	if (!isOutputMatch) {
		throw new Error('User public output does not match the DWallet public output');
	}

	return keys.sign(dWalletPublicOutput);
}

/**
 * Sign the dWallet public output for a transferred/shared dWallet.
 *
 * Verifies the source encrypted share against the source encryption key
 * before signing.
 *
 * @param keys - The UserShareEncryptionKeys instance
 * @param dWallet - The dWallet object
 * @param sourceEncryptedUserSecretKeyShare - The source encrypted share
 * @param sourceEncryptionKey - The source encryption key (must be known through trusted channel)
 * @returns The Ed25519 signature over the dWallet public output
 */
export async function getUserOutputSignatureForTransferredDWallet(
	keys: UserShareEncryptionKeys,
	dWallet: DWallet,
	sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	sourceEncryptionKey: EncryptionKey,
): Promise<Uint8Array> {
	const dWalletPublicOutput = await verifyAndGetDWalletDKGPublicOutput(
		dWallet,
		sourceEncryptedUserSecretKeyShare,
		new Ed25519PublicKey(sourceEncryptionKey.signer_public_key),
	);

	return keys.sign(dWalletPublicOutput);
}

/**
 * Decrypt an encrypted user secret key share for a dWallet.
 *
 * Performs verification before decryption using `verifyAndGetDWalletDKGPublicOutput`.
 *
 * @param keys - The UserShareEncryptionKeys instance
 * @param dWallet - The dWallet object
 * @param encryptedUserSecretKeyShare - The encrypted share
 * @param protocolPublicParameters - The protocol public parameters
 * @returns The verified public output and decrypted secret share
 */
export async function decryptUserShare(
	keys: UserShareEncryptionKeys,
	dWallet: DWallet,
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	protocolPublicParameters: Uint8Array,
): Promise<{
	verifiedPublicOutput: Uint8Array;
	secretShare: Uint8Array;
}> {
	const signingPublicKeyBytes = keys.getSigningPublicKeyBytes();
	const dWalletPublicOutput = await verifyAndGetDWalletDKGPublicOutput(
		dWallet,
		encryptedUserSecretKeyShare,
		new Ed25519PublicKey(signingPublicKeyBytes),
	);

	return {
		verifiedPublicOutput: dWalletPublicOutput,
		secretShare: await keys.decryptSecretShare(
			dWalletPublicOutput,
			Uint8Array.from(encryptedUserSecretKeyShare.encrypted_centralized_secret_share_and_proof),
			protocolPublicParameters,
		),
	};
}
