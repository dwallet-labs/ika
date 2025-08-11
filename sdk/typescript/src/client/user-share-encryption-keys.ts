// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { decrypt_user_share } from '@ika.xyz/mpc-wasm';
import { bcs, toHex } from '@mysten/bcs';
import { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { keccak_256 } from '@noble/hashes/sha3';

import { createClassGroupsKeypair, userAndNetworkDKGOutputMatch } from './cryptography.js';
import type { DWallet, EncryptedUserSecretKeyShare, EncryptionKey } from './types.js';
import { encodeToASCII } from './utils.js';

/**
 * BCS enum for UserShareEncryptionKeys.
 *
 * @see UserShareEncryptionKeys
 */
export const VersionedUserShareEncryptionKeysBcs = bcs.enum('VersionedUserShareEncryptionKeys', {
	V1: bcs.struct('UserShareEncryptionKeysV1', {
		encryptionKey: bcs.vector(bcs.u8()),
		decryptionKey: bcs.vector(bcs.u8()),
		secretShareSigningSecretKey: bcs.vector(bcs.u8()),
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

	private domainSeperators = {
		classGroups: 'CLASS_GROUPS_DECRYPTION_KEY_V1',
		encryptionSignerKey: 'ED25519_SIGNING_KEY_V1',
	};

	private constructor(rootSeedKey: Uint8Array);
	private constructor(
		encryptionKey: Uint8Array,
		decryptionKey: Uint8Array,
		secretShareSigningSecretKey: Uint8Array,
	);
	private constructor(arg1: Uint8Array, arg2?: Uint8Array, arg3?: Uint8Array) {
		if (arg2 === undefined && arg3 === undefined) {
			const rootSeedKey = arg1;
			const classGroupsSeed = this.#hash(this.domainSeperators.classGroups, rootSeedKey);
			const encryptionSignerKeySeed = this.#hash(
				this.domainSeperators.encryptionSignerKey,
				rootSeedKey,
			);

			const classGroupsKeypair = createClassGroupsKeypair(classGroupsSeed);
			this.encryptionKey = new Uint8Array(classGroupsKeypair.encryptionKey);
			this.decryptionKey = new Uint8Array(classGroupsKeypair.decryptionKey);
			this.#encryptedSecretShareSigningKeypair = Ed25519Keypair.deriveKeypairFromSeed(
				toHex(encryptionSignerKeySeed),
			);
		} else {
			if (arg2 === undefined || arg3 === undefined) {
				throw new Error(
					'encryptionKey, decryptionKey, and secretShareSigningSecretKey must be provided',
				);
			}

			const encryptionKey = arg1;
			const decryptionKey = arg2;
			const secretShareSigningSecretKey = arg3;

			if (
				encryptionKey.length !== 32 ||
				decryptionKey.length !== 32 ||
				secretShareSigningSecretKey.length !== 32
			) {
				throw new Error(
					'encryptionKey, decryptionKey, and secretShareSigningSecretKey must be 32 bytes',
				);
			}

			this.encryptionKey = encryptionKey;
			this.decryptionKey = decryptionKey;
			this.#encryptedSecretShareSigningKeypair = Ed25519Keypair.fromSecretKey(
				secretShareSigningSecretKey,
			);
		}
	}

	/**
	 * Creates UserShareEncryptionKeys from a root seed key (Uint8Array).
	 *
	 * @param rootSeedKey - The root seed key to generate keys from
	 * @returns A new UserShareEncryptionKeys instance
	 */
	static fromRootSeedKey(rootSeedKey: Uint8Array): UserShareEncryptionKeys {
		return new UserShareEncryptionKeys(rootSeedKey);
	}

	static fromShareEncryptionKeysBytes(
		shareEncryptionKeysBytes: Uint8Array,
	): UserShareEncryptionKeys {
		const { encryptionKey, decryptionKey, secretShareSigningSecretKey } =
			this.#parseShareEncryptionKeys(shareEncryptionKeysBytes);

		return new UserShareEncryptionKeys(encryptionKey, decryptionKey, secretShareSigningSecretKey);
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

		if (!userAndNetworkDKGOutputMatch(userPublicOutput, dWalletPublicOutput)) {
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
	 * @param userPublicOutput - The user's public output from the DKG process, this is used to verify the user's public output signature.
	 * @param sourceEncryptedUserSecretKeyShare - The encrypted user secret key share used to encrypt the user's secret share.
	 * @returns Promise resolving to the signature bytes
	 * @throws {Error} If the DWallet is not in awaiting key holder signature state or public output is missing or the user public output does not match the DWallet public output
	 */
	async getUserOutputSignatureForTransferredDWallet(
		dWallet: DWallet,
		sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
		sourceEncryptionKey: EncryptionKey,
	): Promise<Uint8Array> {
		if (!dWallet.state.Active?.public_output) {
			throw new Error('DWallet is not in active state');
		}

		if (!sourceEncryptedUserSecretKeyShare.state.KeyHolderSigned?.user_output_signature) {
			throw new Error('Source encrypted user secret key share is not signed by the key holder');
		}

		const dWalletPublicOutput = Uint8Array.from(dWallet.state.Active?.public_output);

		const sourcePublicKey = new Ed25519PublicKey(sourceEncryptionKey.signer_public_key);

		if (
			sourcePublicKey.toSuiAddress() !== sourceEncryptedUserSecretKeyShare.encryption_key_address
		) {
			throw new Error('Source encryption key address does not match the public key');
		}

		if (
			!(await sourcePublicKey.verify(
				dWalletPublicOutput,
				Uint8Array.from(
					sourceEncryptedUserSecretKeyShare.state.KeyHolderSigned?.user_output_signature,
				),
			))
		) {
			throw new Error(
				'Invalid signature. The user output signature does not match the public output.',
			);
		}

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
	): Promise<Uint8Array> {
		if (!dWallet.state.Active?.public_output) {
			throw new Error('DWallet is not active');
		}

		if (!encryptedUserSecretKeyShare.state.KeyHolderSigned?.user_output_signature) {
			throw new Error('Encrypted user secret key share is not signed by the key holder');
		}

		if (
			!(await this.verifySignature(
				Uint8Array.from(dWallet.state.Active.public_output),
				Uint8Array.from(encryptedUserSecretKeyShare.state.KeyHolderSigned.user_output_signature),
			))
		) {
			throw new Error(
				'Invalid signature. The user output signature does not match the public output.',
			);
		}

		if (
			this.#encryptedSecretShareSigningKeypair.toSuiAddress() !==
			encryptedUserSecretKeyShare.encryption_key_address
		) {
			throw new Error(
				'Invalid Sui address. The encryption key address does not match the signing keypair address.',
			);
		}

		return Uint8Array.from(
			decrypt_user_share(
				this.decryptionKey,
				this.encryptionKey,
				Uint8Array.from(dWallet.state.Active?.public_output),
				Uint8Array.from(encryptedUserSecretKeyShare.encrypted_centralized_secret_share_and_proof),
				protocolPublicParameters,
			),
		);
	}

	/**
	 * Hashes a domain separator and root seed to produce a seed for a keypair.
	 *
	 * @param domainSeparator - The domain separator to use
	 * @param rootSeed - The root seed to use
	 * @returns The hashed seed as a Uint8Array
	 */
	#hash(domainSeparator: string, rootSeed: Uint8Array): Uint8Array {
		return new Uint8Array(
			keccak_256(Uint8Array.from([...encodeToASCII(domainSeparator), ...rootSeed])),
		);
	}

	#serializeShareEncryptionKeys() {
		return VersionedUserShareEncryptionKeysBcs.serialize({
			V1: {
				encryptionKey: this.encryptionKey,
				decryptionKey: this.decryptionKey,
				secretShareSigningSecretKey: Uint8Array.from(
					this.#encryptedSecretShareSigningKeypair.getSecretKey(),
				),
			},
		}).toBytes();
	}

	static #parseShareEncryptionKeys(shareEncryptionKeysBytes: Uint8Array) {
		const {
			V1: { encryptionKey, decryptionKey, secretShareSigningSecretKey },
		} = VersionedUserShareEncryptionKeysBcs.parse(shareEncryptionKeysBytes);

		return {
			encryptionKey: new Uint8Array(encryptionKey),
			decryptionKey: new Uint8Array(decryptionKey),
			secretShareSigningSecretKey: new Uint8Array(secretShareSigningSecretKey),
		};
	}
}
