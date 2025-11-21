/**
 * Web Worker for computing user share encryption keys off the main thread
 * Uses comlink to expose a simple API
 */

import ecc from '@bitcoinerlab/secp256k1';
import { Curve, UserShareEncryptionKeys } from '@ika.xyz/sdk';
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
};

// Expose the API via comlink
Comlink.expose(workerApi);
