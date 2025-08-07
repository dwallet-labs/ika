import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';

import { createClassGroupsKeypair, decryptUserShare } from './cryptography';
import { DWallet, EncryptedUserSecretKeyShare } from './types';
import { parseNumbersToBytes, stringToUint8Array } from './utils';

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

	/**
	 * Create a new UserShareEncrytionKeys instance from various input types.
	 *
	 * @param input - Can be a Uint8Array seed, number array, hex string, or Ed25519Keypair
	 */
	constructor(input: Uint8Array | number[] | string | Ed25519Keypair) {
		let seed: Uint8Array;
		let keypair: Ed25519Keypair;

		if (input instanceof Ed25519Keypair) {
			// If input is already a keypair, use it directly
			keypair = input;
			// Generate a seed for class groups keypair (using public key bytes as seed)
			seed = stringToUint8Array(keypair.getSecretKey());
		} else {
			// Convert input to seed
			if (typeof input === 'string') {
				// Handle hex string input
				const hexString = input.startsWith('0x') ? input.slice(2) : input;
				seed = new Uint8Array(Buffer.from(hexString, 'hex'));
			} else if (Array.isArray(input)) {
				// Handle number array input
				seed = new Uint8Array(input);
			} else {
				// Handle Uint8Array input
				seed = input;
			}

			// Create keypair from seed
			keypair = Ed25519Keypair.deriveKeypairFromSeed(Buffer.from(seed).toString('hex'));
		}

		// Create class groups keypair for encryption/decryption
		const classGroupsKeypair = createClassGroupsKeypair(seed);
		this.encryptionKey = classGroupsKeypair.encryptionKey;
		this.decryptionKey = classGroupsKeypair.decryptionKey;
		this.encryptedSecretShareSigningKeypair = keypair;
	}

	/**
	 * Creates UserShareEncrytionKeys from a seed (Uint8Array).
	 *
	 * @param seed - The seed bytes to generate keys from
	 * @returns A new UserShareEncrytionKeys instance
	 */
	static fromSeed(seed: Uint8Array): UserShareEncrytionKeys {
		return new UserShareEncrytionKeys(seed);
	}

	/**
	 * Creates UserShareEncrytionKeys from a number array.
	 *
	 * @param numbers - Array of numbers representing seed bytes
	 * @returns A new UserShareEncrytionKeys instance
	 */
	static fromNumberArray(numbers: number[]): UserShareEncrytionKeys {
		return new UserShareEncrytionKeys(numbers);
	}

	/**
	 * Creates UserShareEncrytionKeys from a hex string.
	 *
	 * @param hexString - Hex string (with or without '0x' prefix) representing seed bytes
	 * @returns A new UserShareEncrytionKeys instance
	 */
	static fromHexString(hexString: string): UserShareEncrytionKeys {
		return new UserShareEncrytionKeys(hexString);
	}

	/**
	 * Creates UserShareEncrytionKeys from an existing Ed25519Keypair.
	 *
	 * @param keypair - An existing Ed25519Keypair to use for signing operations
	 * @returns A new UserShareEncrytionKeys instance
	 */
	static fromKeypair(keypair: Ed25519Keypair): UserShareEncrytionKeys {
		return new UserShareEncrytionKeys(keypair);
	}

	/**
	 * Generates a new random UserShareEncrytionKeys with fresh cryptographic keys.
	 *
	 * @returns A new UserShareEncrytionKeys instance with randomly generated keys
	 */
	static generate(): UserShareEncrytionKeys {
		const keypair = Ed25519Keypair.generate();
		return new UserShareEncrytionKeys(keypair);
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
	getPublicKeyBytes(): Uint8Array {
		return this.encryptedSecretShareSigningKeypair.getPublicKey().toRawBytes();
	}

	/**
	 * Gets the secret key as a string.
	 *
	 * @returns The secret key of the signing keypair as a hex string
	 */
	getSecretKey(): string {
		return this.encryptedSecretShareSigningKeypair.getSecretKey();
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
		return await this.encryptedSecretShareSigningKeypair.sign(
			parseNumbersToBytes(dWallet.state.Active?.public_output),
		);
	}

	/**
	 * Decrypt an encrypted user secret key share for a specific DWallet.
	 * This method uses the user's decryption key to recover the secret share.
	 *
	 * @param dWallet - The DWallet that the encrypted share belongs to
	 * @param encryptedUserSecretKeyShare - The encrypted secret key share to decrypt
	 * @param networkDecryptionKeyPublicOutput - The network's public parameters for decryption
	 * @returns Promise resolving to the decrypted secret share bytes
	 * @throws {Error} If decryption fails, the DWallet is not active, or verification fails
	 */
	async decryptUserShare(
		dWallet: DWallet,
		encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
		networkDecryptionKeyPublicOutput: Uint8Array,
	): Promise<Uint8Array> {
		return decryptUserShare(
			this.decryptionKey,
			this.encryptionKey,
			Uint8Array.from(parseNumbersToBytes(dWallet.state.Active?.public_output)),
			Uint8Array.from(encryptedUserSecretKeyShare.encrypted_centralized_secret_share_and_proof),
			networkDecryptionKeyPublicOutput,
		);
	}
}
