// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { toHex } from '@mysten/bcs';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { keccak256 } from 'js-sha3';

import { createClassGroupsKeypair, decryptUserShare } from './cryptography.js';
import type { DWallet, EncryptedUserSecretKeyShare } from './types.js';

/**
 * UserShareEncrytionKeys manages encryption/decryption keys and signing keypairs for user shares.
 * This class handles the creation and management of cryptographic keys needed for secure
 * user share operations in the DWallet network.
 */
export class UserShareEncrytionKeys {
	/** The public encryption key used to encrypt secret shares */
	encryptionKey: Uint8Array;
	/** The private decryption key used to decrypt secret shares */
	decryptionKey: Uint8Array;
	/** The Ed25519 keypair used for signing encrypted secret share operations */
	encryptedSecretShareSigningKeypair: Ed25519Keypair;

	private domainSeperators = {
		classGroups: 'CLASS_GROUPS_DECRYPTION_KEY_V1',
		encryptionSignerKey: 'ED25519_SIGNING_KEY_V1',
	};

	/**
	 * Create a new UserShareEncrytionKeys instance from a root seed key.
	 *
	 * @param rootSeedKey - Can be a Uint8Array seed, please keep it secret.
	 */
	constructor(rootSeedKey: Uint8Array) {
		const classGroupsSeed = this.hash(this.domainSeperators.classGroups, rootSeedKey);
		const encryptionSignerKeySeed = this.hash(
			this.domainSeperators.encryptionSignerKey,
			rootSeedKey,
		);

		const classGroupsKeypair = createClassGroupsKeypair(classGroupsSeed);
		this.encryptionKey = new Uint8Array(classGroupsKeypair.encryptionKey);
		this.decryptionKey = new Uint8Array(classGroupsKeypair.decryptionKey);
		this.encryptedSecretShareSigningKeypair = Ed25519Keypair.deriveKeypairFromSeed(
			toHex(encryptionSignerKeySeed),
		);
	}

	/**
	 * Creates UserShareEncrytionKeys from a root seed key (Uint8Array).
	 *
	 * @param rootSeedKey - The root seed key to generate keys from
	 * @returns A new UserShareEncrytionKeys instance
	 */
	static fromRootSeedKey(rootSeedKey: Uint8Array): UserShareEncrytionKeys {
		return new UserShareEncrytionKeys(rootSeedKey);
	}

	/**
	 * Gets the public key of the encrypted secret share signing keypair.
	 *
	 * @returns The Ed25519 public key used for signature verification
	 */
	getPublicKey() {
		return this.encryptedSecretShareSigningKeypair.getPublicKey();
	}

	/**
	 * Gets the Sui address derived from the encrypted secret share signing keypair.
	 *
	 * @returns The Sui address as a string
	 */
	getSuiAddress(): string {
		return this.encryptedSecretShareSigningKeypair.getPublicKey().toSuiAddress();
	}

	/**
	 * Gets the raw bytes of the public key.
	 *
	 * @returns The raw bytes of the Ed25519 public key
	 */
	getSigningPublicKeyBytes(): Uint8Array {
		return this.encryptedSecretShareSigningKeypair.getPublicKey().toRawBytes();
	}

	/**
	 * Creates a signature over the encryption key using the signing keypair.
	 * This signature proves ownership of the encryption key.
	 *
	 * @returns Promise resolving to the signature bytes
	 */
	async getEncryptionKeySignature(): Promise<Uint8Array> {
		return await this.encryptedSecretShareSigningKeypair.sign(this.encryptionKey);
	}

	/**
	 * Creates a signature over the DWallet's public output.
	 * This signature proves authorization to use the DWallet's encrypted share.
	 *
	 * @param dWallet - The DWallet to create a signature for
	 * @returns Promise resolving to the signature bytes
	 * @throws {Error} If the DWallet is not in active state or public output is missing
	 */
	async getUserOutputSignature(dWallet: DWallet): Promise<Uint8Array> {
		if (!dWallet.state.AwaitingKeyHolderSignature?.public_output) {
			throw new Error('DWallet is not in awaiting key holder signature state');
		}

		return await this.encryptedSecretShareSigningKeypair.sign(
			Uint8Array.from(dWallet.state.AwaitingKeyHolderSignature?.public_output),
		);
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

		return decryptUserShare(
			this.decryptionKey,
			this.encryptionKey,
			Uint8Array.from(dWallet.state.Active?.public_output),
			Uint8Array.from(encryptedUserSecretKeyShare.encrypted_centralized_secret_share_and_proof),
			protocolPublicParameters,
		);
	}

	/**
	 * Hashes a domain separator and root seed to produce a seed for a keypair.
	 *
	 * @param domainSeparator - The domain separator to use
	 * @param rootSeed - The root seed to use
	 * @returns The hashed seed as a Uint8Array
	 */
	private hash(domainSeparator: string, rootSeed: Uint8Array): Uint8Array {
		return new Uint8Array(keccak256.digest(domainSeparator + rootSeed));
	}
}
