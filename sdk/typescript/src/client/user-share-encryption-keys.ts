// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { bcs, toHex } from '@mysten/bcs';
import { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { keccak_256 } from '@noble/hashes/sha3';

import {
	createClassGroupsKeypair,
	userAndNetworkDKGOutputMatch,
	verifyAndGetDWalletDKGPublicOutput,
} from './cryptography.js';
import { fromCurveToNumber, fromNumberToCurve } from './hash-signature-validation.js';
import type { Curve, DWallet, EncryptedUserSecretKeyShare, EncryptionKey } from './types.js';
import { encodeToASCII } from './utils.js';
import { decrypt_user_share } from './wasm-loader.js';

/**
 * BCS enum for UserShareEncryptionKeys.
 *
 * @see UserShareEncryptionKeys
 */
export const VersionedUserShareEncryptionKeysBcs = bcs.enum('VersionedUserShareEncryptionKeys', {
	V1: bcs.struct('UserShareEncryptionKeysV1', {
		encryptionKey: bcs.vector(bcs.u8()),
		decryptionKey: bcs.vector(bcs.u8()),
		secretShareSigningSecretKey: bcs.string(),
		curve: bcs.u64(),
	}),
});

/**
 * UserShareEncryptionKeys manages encryption/decryption keys and signing keypairs for user shares.
 * This class handles the creation and management of cryptographic keys needed for secure
 * user share operations in the DWallet network.
 */
export class UserShareEncryptionKeys {
	/** The public encryption key used to encrypt secret shares */
	encryptionKey: Uint8Array;
	/** The private decryption key used to decrypt secret shares */
	decryptionKey: Uint8Array;
	/** The Ed25519 keypair used for signing encrypted secret share operations */
	#encryptedSecretShareSigningKeypair: Ed25519Keypair;
	/** The curve used to generate the encryption/decryption keys */
	curve: Curve;

	static domainSeparators = {
		classGroups: 'CLASS_GROUPS_DECRYPTION_KEY_V1',
		encryptionSignerKey: 'ED25519_SIGNING_KEY_V1',
	};

	private constructor(
		encryptionKey: Uint8Array,
		decryptionKey: Uint8Array,
		secretShareSigningSecretKey: Ed25519Keypair,
		curve: Curve,
	) {
		this.encryptionKey = encryptionKey;
		this.decryptionKey = decryptionKey;
		this.#encryptedSecretShareSigningKeypair = secretShareSigningSecretKey;
		this.curve = curve;
	}

	/**
	 * Creates UserShareEncryptionKeys from a root seed key (Uint8Array).
	 *
	 * @param rootSeedKey - The root seed key to generate keys from
	 * @param curve - The curve to use for key generation
	 * @returns A new UserShareEncryptionKeys instance
	 */
	static async fromRootSeedKey(
		rootSeedKey: Uint8Array,
		curve: Curve,
	): Promise<UserShareEncryptionKeys> {
		const classGroupsSeed = UserShareEncryptionKeys.hash(
			UserShareEncryptionKeys.domainSeparators.classGroups,
			rootSeedKey,
			curve,
		);

		const encryptionSignerKeySeed = UserShareEncryptionKeys.hash(
			UserShareEncryptionKeys.domainSeparators.encryptionSignerKey,
			rootSeedKey,
			curve,
		);

		const classGroupsKeypair = await createClassGroupsKeypair(classGroupsSeed, curve);
		const encryptionSignerKey = Ed25519Keypair.deriveKeypairFromSeed(
			toHex(encryptionSignerKeySeed),
		);

		return new UserShareEncryptionKeys(
			new Uint8Array(classGroupsKeypair.encryptionKey),
			new Uint8Array(classGroupsKeypair.decryptionKey),
			encryptionSignerKey,
			curve,
		);
	}

	static fromShareEncryptionKeysBytes(
		shareEncryptionKeysBytes: Uint8Array,
	): UserShareEncryptionKeys {
		const { encryptionKey, decryptionKey, secretShareSigningSecretKey, curve } =
			this.#parseShareEncryptionKeys(shareEncryptionKeysBytes);

		const secretShareSigningKeypair = Ed25519Keypair.fromSecretKey(secretShareSigningSecretKey);

		return new UserShareEncryptionKeys(
			encryptionKey,
			decryptionKey,
			secretShareSigningKeypair,
			curve,
		);
	}

	toShareEncryptionKeysBytes(): Uint8Array {
		return this.#serializeShareEncryptionKeys();
	}

	/**
	 * Gets the public key of the encrypted secret share signing keypair.
	 *
	 * @returns The Ed25519 public key used for signature verification
	 */
	getPublicKey() {
		return this.#encryptedSecretShareSigningKeypair.getPublicKey();
	}

	/**
	 * Gets the Sui address derived from the encrypted secret share signing keypair.
	 *
	 * @returns The Sui address as a string
	 */
	getSuiAddress(): string {
		return this.#encryptedSecretShareSigningKeypair.getPublicKey().toSuiAddress();
	}

	/**
	 * Gets the raw bytes of the public key.
	 *
	 * @returns The raw bytes of the Ed25519 public key
	 */
	getSigningPublicKeyBytes(): Uint8Array {
		return this.#encryptedSecretShareSigningKeypair.getPublicKey().toRawBytes();
	}

	/**
	 * Verifies a signature over a message.
	 *
	 * @param message - The message to verify
	 * @param signature - The signature to verify
	 * @returns Promise resolving to the verification result
	 */
	async verifySignature(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
		return await this.#encryptedSecretShareSigningKeypair.getPublicKey().verify(message, signature);
	}

	/**
	 * Creates a signature over the encryption key using the signing keypair.
	 * This signature proves ownership of the encryption key.
	 *
	 * @returns Promise resolving to the signature bytes
	 */
	async getEncryptionKeySignature(): Promise<Uint8Array> {
		return await this.#encryptedSecretShareSigningKeypair.sign(this.encryptionKey);
	}

	/**
	 * Creates a signature over the DWallet's public output.
	 * This signature proves authorization to use the DWallet's encrypted share.
	 *
	 * @param dWallet - The DWallet to create a signature for
	 * @param userPublicOutput - The user's public output from the DKG process, this is used to verify the user's public output signature.
	 * @returns Promise resolving to the signature bytes
	 * @throws {Error} If the DWallet is not in awaiting key holder signature state or public output is missing or the user public output does not match the DWallet public output
	 */
	async getUserOutputSignature(
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

		return await this.#encryptedSecretShareSigningKeypair.sign(dWalletPublicOutput);
	}

	/**
	 * Creates a signature over the DWallet's public output for a transferred or shared DWallet.
	 * This signature is later used as a fast verification method over the dWallet data (i.e. public output, against which the secret share is also verified.)
	 * We do this at the time of accepting the dWallet, when we know the sender and their public key/address, against which their own signature on the public output is first verified.
	 *
	 * SECURITY WARNING: `sourceEncryptionKey` shouldn't be fetched from the network;
	 * the public key of the sender (or its address) should be known to the receiver,
	 * so that the verification here would be impactful.
	 *
	 * @param dWallet - The DWallet to create a signature for
	 * @param sourceEncryptedUserSecretKeyShare - The encrypted user secret key share.
	 * @param sourceEncryptionKey - The encryption key used to encrypt the user's secret share.
	 * @returns Promise resolving to the signature bytes
	 * @throws {Error} If the DWallet is not in awaiting key holder signature state or public output is missing or the user public output does not match the DWallet public output
	 */
	async getUserOutputSignatureForTransferredDWallet(
		dWallet: DWallet,
		sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
		sourceEncryptionKey: EncryptionKey,
	): Promise<Uint8Array> {
		const dWalletPublicOutput = await verifyAndGetDWalletDKGPublicOutput(
			dWallet,
			sourceEncryptedUserSecretKeyShare,
			new Ed25519PublicKey(sourceEncryptionKey.signer_public_key),
		);

		return await this.#encryptedSecretShareSigningKeypair.sign(dWalletPublicOutput);
	}

	/**
	 * Decrypt an encrypted user secret key share for a specific DWallet.
	 * This method uses the user's decryption key to recover the secret share.
	 *
	 * @param dWallet - The DWallet that the encrypted share belongs to
	 * @param encryptedUserSecretKeyShare - The encrypted secret key share to decrypt
	 * @param protocolPublicParameters - The protocol public parameters for decryption
	 * @returns Promise resolving to the decrypted secret share bytes
	 * @throws {Error} If decryption fails, the DWallet is not active, or verification fails
	 */
	async decryptUserShare(
		dWallet: DWallet,
		encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
		protocolPublicParameters: Uint8Array,
	): Promise<{
		verifiedPublicOutput: Uint8Array;
		secretShare: Uint8Array;
	}> {
		const dWalletPublicOutput = await verifyAndGetDWalletDKGPublicOutput(
			dWallet,
			encryptedUserSecretKeyShare,
			this.#encryptedSecretShareSigningKeypair.getPublicKey(),
		);

		return {
			verifiedPublicOutput: dWalletPublicOutput,
			secretShare: Uint8Array.from(
				await decrypt_user_share(
					fromCurveToNumber(this.curve),
					this.decryptionKey,
					dWalletPublicOutput,
					Uint8Array.from(encryptedUserSecretKeyShare.encrypted_centralized_secret_share_and_proof),
					protocolPublicParameters,
				),
			),
		};
	}

	/**
	 * Hashes a domain separator and root seed to produce a seed for a keypair.
	 *
	 * @param domainSeparator - The domain separator to use
	 * @param rootSeed - The root seed to use
	 * @returns The hashed seed as a Uint8Array
	 */
	static hash(domainSeparator: string, rootSeed: Uint8Array, curve: Curve): Uint8Array {
		return new Uint8Array(
			keccak_256(Uint8Array.from([...encodeToASCII(domainSeparator), curve, ...rootSeed])),
		);
	}

	#serializeShareEncryptionKeys() {
		return VersionedUserShareEncryptionKeysBcs.serialize({
			V1: {
				encryptionKey: this.encryptionKey,
				decryptionKey: this.decryptionKey,
				secretShareSigningSecretKey: this.#encryptedSecretShareSigningKeypair.getSecretKey(),
				curve: fromCurveToNumber(this.curve),
			},
		}).toBytes();
	}

	static #parseShareEncryptionKeys(shareEncryptionKeysBytes: Uint8Array) {
		const {
			V1: { encryptionKey, decryptionKey, secretShareSigningSecretKey, curve },
		} = VersionedUserShareEncryptionKeysBcs.parse(shareEncryptionKeysBytes);

		return {
			encryptionKey: new Uint8Array(encryptionKey),
			decryptionKey: new Uint8Array(decryptionKey),
			secretShareSigningSecretKey,
			curve: fromNumberToCurve(Number(curve)),
		};
	}
}
