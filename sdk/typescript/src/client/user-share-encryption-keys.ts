import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';

import { createClassGroupsKeypair, stringToUint8Array } from './cryptography';
import { DWallet } from './types';
import { parseNumbersToBytes } from './utils';

export class UserShareEncrytionKeys {
	encryptionKey: Uint8Array;
	decryptionKey: Uint8Array;
	encryptedSecretShareSigningKeypair: Ed25519Keypair;

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
	 * Creates UserShareEncrytionKeys from a seed (Uint8Array)
	 */
	static fromSeed(seed: Uint8Array): UserShareEncrytionKeys {
		return new UserShareEncrytionKeys(seed);
	}

	/**
	 * Creates UserShareEncrytionKeys from a number array
	 */
	static fromNumberArray(numbers: number[]): UserShareEncrytionKeys {
		return new UserShareEncrytionKeys(numbers);
	}

	/**
	 * Creates UserShareEncrytionKeys from a hex string
	 */
	static fromHexString(hexString: string): UserShareEncrytionKeys {
		return new UserShareEncrytionKeys(hexString);
	}

	/**
	 * Creates UserShareEncrytionKeys from an Ed25519Keypair
	 */
	static fromKeypair(keypair: Ed25519Keypair): UserShareEncrytionKeys {
		return new UserShareEncrytionKeys(keypair);
	}

	/**
	 * Generates a new random UserShareEncrytionKeys
	 */
	static generate(): UserShareEncrytionKeys {
		const keypair = Ed25519Keypair.generate();
		return new UserShareEncrytionKeys(keypair);
	}

	/**
	 * Gets the public key of the encrypted secret share signing keypair
	 */
	getPublicKey() {
		return this.encryptedSecretShareSigningKeypair.getPublicKey();
	}

	/**
	 * Gets the Sui address of the encrypted secret share signing keypair
	 */
	getSuiAddress(): string {
		return this.encryptedSecretShareSigningKeypair.getPublicKey().toSuiAddress();
	}

	/**
	 * Gets the raw bytes of the public key
	 */
	getPublicKeyBytes(): Uint8Array {
		return this.encryptedSecretShareSigningKeypair.getPublicKey().toRawBytes();
	}

	/**
	 * Gets the signature of the encrypted secret share signing keypair
	 */
	async getEncryptionKeySignature(): Promise<Uint8Array> {
		return await this.encryptedSecretShareSigningKeypair.sign(this.encryptionKey);
	}

	async getUserOutputSignature(dWallet: DWallet): Promise<Uint8Array> {
		return await this.encryptedSecretShareSigningKeypair.sign(
			parseNumbersToBytes(dWallet.state.Active?.public_output),
		);
	}
}
