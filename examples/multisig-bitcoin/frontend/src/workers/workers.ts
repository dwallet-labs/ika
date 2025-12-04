/**
 * Web Worker for computing cryptographic operations off the main thread
 * Uses comlink to expose a simple API
 */

import ecc from '@bitcoinerlab/secp256k1';
import {
	createUserSignMessageWithPublicOutput,
	Curve,
	Hash,
	prepareDKG as prepareDKGAsync,
	SignatureAlgorithm,
	UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import * as bitcoin from 'bitcoinjs-lib';
import * as Comlink from 'comlink';

// Initialize ECC library for bitcoinjs-lib (required for crypto operations)
// @bitcoinerlab/secp256k1 is pure JavaScript (no WASM) and works well in browsers and workers
// This must be done before any bitcoinjs-lib operations
bitcoin.initEccLib(ecc);

/**
 * Worker API exposed via comlink
 */
const workerApi = {
	async computeKeys(seed: string, curve: Curve): Promise<number[]> {
		const seedBytes = new TextEncoder().encode(seed);
		const keys = await UserShareEncryptionKeys.fromRootSeedKey(seedBytes, curve);
		const serializedBytes = keys.toShareEncryptionKeysBytes();
		return Array.from(serializedBytes);
	},

	async prepareDKG(params: {
		curve: Curve;
		userShareEncryptionKeysBytes: number[];
		sessionIdentifier: number[];
		userAddress: string;
		protocolPublicParameters: number[];
	}): Promise<{
		userPublicOutput: number[];
		userSecretKeyShare: number[];
		userDKGMessage: number[];
	}> {
		// Reconstruct UserShareEncryptionKeys from bytes
		const userShareEncryptionKeys = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(
			new Uint8Array(params.userShareEncryptionKeysBytes),
		);

		// Perform DKG
		const result = await prepareDKGAsync(
			new Uint8Array(params.protocolPublicParameters),
			params.curve,
			userShareEncryptionKeys.encryptionKey,
			new Uint8Array(params.sessionIdentifier),
			params.userAddress,
		);

		// Serialize results to number arrays
		return {
			userPublicOutput: Array.from(result.userPublicOutput),
			userSecretKeyShare: Array.from(result.userSecretKeyShare),
			userDKGMessage: Array.from(result.userDKGMessage),
		};
	},

	async createSignature(params: {
		publicOutput: number[];
		publicUserSecretKeyShare: number[];
		presign: number[];
		preimage: number[];
		hash: Hash;
		signatureAlgorithm: SignatureAlgorithm;
		curve: Curve;
		protocolPublicParameters: number[];
	}): Promise<number[]> {
		// Create signature
		const signature = await createUserSignMessageWithPublicOutput(
			new Uint8Array(params.protocolPublicParameters),
			new Uint8Array(params.publicOutput),
			new Uint8Array(params.publicUserSecretKeyShare),
			new Uint8Array(params.presign),
			new Uint8Array(params.preimage),
			params.hash,
			params.signatureAlgorithm,
			params.curve,
		);

		// Serialize result to number array
		return Array.from(signature);
	},
};

// Expose the API via comlink
Comlink.expose(workerApi);
