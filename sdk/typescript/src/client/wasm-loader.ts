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
	curve: number,
	userSecretKeyShare: Uint8Array,
	encryptionKey: Uint8Array,
	protocolPublicParameters: Uint8Array,
): Promise<Uint8Array> {
	const wasm = await getWasmModule();
	return wasm.encrypt_secret_share(
		curve,
		userSecretKeyShare,
		encryptionKey,
		protocolPublicParameters,
	);
}

export async function verify_user_share(
	curve: number,
	userSecretKeyShare: Uint8Array,
	userDKGOutput: Uint8Array,
	networkDkgPublicOutput: Uint8Array,
): Promise<boolean> {
	const wasm = await getWasmModule();
	return wasm.verify_user_share(curve, userSecretKeyShare, userDKGOutput, networkDkgPublicOutput);
}

export async function generate_secp_cg_keypair_from_seed(
	curve: number,
	seed: Uint8Array,
): Promise<[Uint8Array, Uint8Array]> {
	const wasm = await getWasmModule();
	return wasm.generate_secp_cg_keypair_from_seed(curve, seed);
}

export async function create_dkg_centralized_output_v1(
	protocolPublicParameters: Uint8Array,
	networkFirstRoundOutput: Uint8Array,
): Promise<[Uint8Array, Uint8Array, Uint8Array]> {
	const wasm = await getWasmModule();
	return wasm.create_dkg_centralized_output_v1(protocolPublicParameters, networkFirstRoundOutput);
}

export async function create_dkg_centralized_output_v2(
	curve: number,
	protocolPublicParameters: Uint8Array,
	session_id: Uint8Array,
): Promise<[Uint8Array, Uint8Array, Uint8Array]> {
	const wasm = await getWasmModule();
	return wasm.create_dkg_centralized_output_v2(curve, protocolPublicParameters, session_id);
}

export async function create_sign_centralized_party_message(
	protocolPublicParameters: Uint8Array,
	publicOutput: Uint8Array,
	userSecretKeyShare: Uint8Array,
	presign: Uint8Array,
	message: Uint8Array,
	hash: number,
	signatureScheme: number,
	curve: number,
): Promise<Uint8Array> {
	const wasm = await getWasmModule();
	return wasm.create_sign_centralized_party_message(
		protocolPublicParameters,
		publicOutput,
		userSecretKeyShare,
		presign,
		message,
		curve,
		signatureScheme,
		hash,
	);
}

export async function create_sign_centralized_party_message_with_centralized_party_dkg_output(
	protocolPublicParameters: Uint8Array,
	centralizedDkgOutput: Uint8Array,
	userSecretKeyShare: Uint8Array,
	presign: Uint8Array,
	message: Uint8Array,
	hash: number,
	signatureScheme: number,
	curve: number,
): Promise<Uint8Array> {
	const wasm = await getWasmModule();
	return wasm.create_sign_centralized_party_message_with_centralized_party_dkg_output(
		protocolPublicParameters,
		centralizedDkgOutput,
		userSecretKeyShare,
		presign,
		message,
		hash,
		signatureScheme,
		curve,
	);
}

export async function network_dkg_public_output_to_protocol_pp(
	curve: number,
	networkDkgPublicOutput: Uint8Array,
): Promise<Uint8Array> {
	const wasm = await getWasmModule();
	return wasm.network_dkg_public_output_to_protocol_pp(curve, networkDkgPublicOutput);
}

export async function verify_secp_signature(
	publicKey: Uint8Array,
	signature: Uint8Array,
	message: Uint8Array,
	networkDkgPublicOutput: Uint8Array,
	hash: number,
	signatureAlgorithm: number,
	curve: number,
): Promise<boolean> {
	const wasm = await getWasmModule();
	return wasm.verify_secp_signature(
		publicKey,
		signature,
		message,
		networkDkgPublicOutput,
		curve,
		signatureAlgorithm,
		hash,
	);
}

export async function public_key_from_dwallet_output(
	curve: number,
	dWalletOutput: Uint8Array,
): Promise<Uint8Array> {
	const wasm = await getWasmModule();
	return wasm.public_key_from_dwallet_output(curve, dWalletOutput);
}

export async function public_key_from_centralized_dkg_output(
	curve: number,
	centralizedDkgOutput: Uint8Array,
): Promise<Uint8Array> {
	const wasm = await getWasmModule();
	return wasm.public_key_from_centralized_dkg_output(curve, centralizedDkgOutput);
}

export async function reconfiguration_public_output_to_protocol_pp(
	curve: number,
	reconfig_public_output: Uint8Array,
	network_dkg_public_output: Uint8Array,
): Promise<Uint8Array> {
	const wasm = await getWasmModule();
	return wasm.reconfiguration_public_output_to_protocol_pp(
		curve,
		reconfig_public_output,
		network_dkg_public_output,
	);
}

export async function centralized_and_decentralized_parties_dkg_output_match(
	curve: number,
	userPublicOutput: Uint8Array,
	networkDKGOutput: Uint8Array,
): Promise<boolean> {
	const wasm = await getWasmModule();
	return wasm.centralized_and_decentralized_parties_dkg_output_match(
		curve,
		userPublicOutput,
		networkDKGOutput,
	);
}

export async function create_imported_dwallet_centralized_step(
	curve: number,
	protocolPublicParameters: Uint8Array,
	sessionIdentifier: Uint8Array,
	secretKey: Uint8Array,
): Promise<[Uint8Array, Uint8Array, Uint8Array]> {
	const wasm = await getWasmModule();
	return wasm.create_imported_dwallet_centralized_step(
		curve,
		protocolPublicParameters,
		sessionIdentifier,
		secretKey,
	);
}

export async function decrypt_user_share(
	curve: number,
	decryptionKey: Uint8Array,
	dWalletPublicOutput: Uint8Array,
	encryptedShare: Uint8Array,
	protocolPublicParameters: Uint8Array,
): Promise<Uint8Array> {
	const wasm = await getWasmModule();
	return wasm.decrypt_user_share(
		curve,
		decryptionKey,
		dWalletPublicOutput,
		encryptedShare,
		protocolPublicParameters,
	);
}

export async function parse_signature_from_sign_output(
	curve: number,
	signatureAlgorithm: number,
	signatureOutput: Uint8Array,
): Promise<Uint8Array> {
	const wasm = await getWasmModule();
	return wasm.parse_signature_from_sign_output(curve, signatureAlgorithm, signatureOutput);
}

/**
 * Manually initialize the WASM module.
 * This is optional as functions will auto-initialize on first use.
 * Useful for preloading the WASM module during app initialization.
 */
export async function initializeWasm(): Promise<void> {
	await ensureWasmInitialized();
}
