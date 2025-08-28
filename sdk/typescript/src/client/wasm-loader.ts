// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type * as WasmModule from '@ika.xyz/ika-wasm';

let wasmModule: typeof WasmModule | null = null;
let initPromise: Promise<void> | null = null;
const isNode = typeof process !== 'undefined' && !!process.versions?.node;

export async function ensureWasmInitialized() {
	if (wasmModule) return;
	if (!initPromise) initPromise = init();
	await initPromise;
}

async function init() {
	// Always import root; exports pick web vs node for us
	const mod: any = await import('@ika.xyz/ika-wasm');

	if (isNode) {
		// Node glue self-initializes (uses fs internally)
		const normalized = mod && typeof mod === 'object' && 'default' in mod ? mod.default : mod;
		if (typeof normalized.generate_secp_cg_keypair_from_seed !== 'function') {
			throw new Error('ika-wasm node glue not initialized (wrong target?)');
		}
		wasmModule = normalized as typeof WasmModule;
		return;
	}

	// Web glue: explicitly init with NO args so it fetches its own wasm URL
	const initFn: any = mod.default ?? mod.init;
	if (typeof initFn !== 'function') throw new Error('ika-wasm web glue missing init()');
	await initFn(); // <— NO url here
	wasmModule = mod as typeof WasmModule;
}

async function getWasmModule() {
	await ensureWasmInitialized();
	return wasmModule!;
}

// Export wrapped functions that ensure WASM is initialized
export async function encrypt_secret_share(
	userSecretKeyShare: Uint8Array,
	encryptionKey: Uint8Array,
	protocolPublicParameters: Uint8Array,
): Promise<Uint8Array> {
	const wasm = await getWasmModule();
	return wasm.encrypt_secret_share(userSecretKeyShare, encryptionKey, protocolPublicParameters);
}

export async function verify_user_share(
	userSecretKeyShare: Uint8Array,
	userDKGOutput: Uint8Array,
	networkDkgPublicOutput: Uint8Array,
): Promise<boolean> {
	const wasm = await getWasmModule();
	return wasm.verify_user_share(userSecretKeyShare, userDKGOutput, networkDkgPublicOutput);
}

export async function generate_secp_cg_keypair_from_seed(
	seed: Uint8Array,
): Promise<[Uint8Array, Uint8Array]> {
	const wasm = await getWasmModule();
	return wasm.generate_secp_cg_keypair_from_seed(seed);
}

export async function create_dkg_centralized_output(
	protocolPublicParameters: Uint8Array,
	networkFirstRoundOutput: Uint8Array,
	sessionIdentifier: Uint8Array,
): Promise<[Uint8Array, Uint8Array, Uint8Array]> {
	const wasm = await getWasmModule();
	return wasm.create_dkg_centralized_output(
		protocolPublicParameters,
		networkFirstRoundOutput,
		sessionIdentifier,
	);
}

export async function create_sign_centralized_party_message(
	protocolPublicParameters: Uint8Array,
	publicOutput: Uint8Array,
	userSecretKeyShare: Uint8Array,
	presign: Uint8Array,
	message: Uint8Array,
	hash: number,
): Promise<Uint8Array> {
	const wasm = await getWasmModule();
	return wasm.create_sign_centralized_party_message(
		protocolPublicParameters,
		publicOutput,
		userSecretKeyShare,
		presign,
		message,
		hash,
	);
}

export async function network_dkg_public_output_to_protocol_pp(
	networkDkgPublicOutput: Uint8Array,
): Promise<Uint8Array> {
	const wasm = await getWasmModule();
	return wasm.network_dkg_public_output_to_protocol_pp(networkDkgPublicOutput);
}

export async function verify_secp_signature(
	publicKey: Uint8Array,
	signature: Uint8Array,
	message: Uint8Array,
	networkDkgPublicOutput: Uint8Array,
	hash: number,
): Promise<boolean> {
	const wasm = await getWasmModule();
	return wasm.verify_secp_signature(publicKey, signature, message, networkDkgPublicOutput, hash);
}

export async function public_key_from_dwallet_output(
	dWalletOutput: Uint8Array,
): Promise<Uint8Array> {
	const wasm = await getWasmModule();
	return wasm.public_key_from_dwallet_output(dWalletOutput);
}

export async function centralized_and_decentralized_parties_dkg_output_match(
	userPublicOutput: Uint8Array,
	networkDKGOutput: Uint8Array,
): Promise<boolean> {
	const wasm = await getWasmModule();
	return wasm.centralized_and_decentralized_parties_dkg_output_match(
		userPublicOutput,
		networkDKGOutput,
	);
}

export async function create_imported_dwallet_centralized_step(
	protocolPublicParameters: Uint8Array,
	sessionIdentifier: Uint8Array,
	secretKey: Uint8Array,
): Promise<[Uint8Array, Uint8Array, Uint8Array]> {
	const wasm = await getWasmModule();
	return wasm.create_imported_dwallet_centralized_step(
		protocolPublicParameters,
		sessionIdentifier,
		secretKey,
	);
}

export async function decrypt_user_share(
	decryptionKey: Uint8Array,
	encryptionKey: Uint8Array,
	dWalletPublicOutput: Uint8Array,
	encryptedShare: Uint8Array,
	protocolPublicParameters: Uint8Array,
): Promise<Uint8Array> {
	const wasm = await getWasmModule();
	return wasm.decrypt_user_share(
		decryptionKey,
		encryptionKey,
		dWalletPublicOutput,
		encryptedShare,
		protocolPublicParameters,
	);
}

/**
 * Manually initialize the WASM module.
 * This is optional as functions will auto-initialize on first use.
 * Useful for preloading the WASM module during app initialization.
 */
export async function initializeWasm(): Promise<void> {
	await ensureWasmInitialized();
}
