// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { keccak_256 } from '@noble/hashes/sha3.js';
import { randomBytes } from '@noble/hashes/utils.js';

import {
	fromCurveAndSignatureAlgorithmAndHashToNumbers,
	fromCurveToNumber,
	fromSignatureAlgorithmToNumber,
} from './hash-signature-validation.js';
import type {
	ValidHashForSignature,
	ValidSignatureAlgorithmForCurve,
} from './hash-signature-validation.js';
import type { Curve } from './types.js';
import { encodeToASCII, u64ToBytesBigEndian } from './utils.js';
import {
	centralized_and_decentralized_parties_dkg_output_match,
	create_dkg_centralized_output_v2,
	create_dkg_centralized_output_v1 as create_dkg_user_output,
	create_sign_centralized_party_message_with_centralized_party_dkg_output,
	create_sign_centralized_party_message as create_sign_user_message,
	encrypt_secret_share,
	generate_secp_cg_keypair_from_seed,
	network_dkg_public_output_to_protocol_pp,
	parse_signature_from_sign_output,
	public_key_from_centralized_dkg_output,
	public_key_from_dwallet_output,
	reconfiguration_public_output_to_protocol_pp,
	verify_secp_signature,
	verify_user_share,
} from './wasm-loader.js';

/**
 * Prepared data for the second round of Distributed Key Generation (DKG).
 * Contains all cryptographic outputs needed to complete the DKG process.
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 */
export interface DKGRequestInput {
	/** The user's public key share along with its zero-knowledge proof */
	userDKGMessage: Uint8Array;
	/** The user's public output from the DKG process */
	userPublicOutput: Uint8Array;
	/** The encrypted user share with its proof of correct encryption */
	encryptedUserShareAndProof: Uint8Array;
	/** The raw secret key share (user share) */
	userSecretKeyShare: Uint8Array;
}

/**
 * Prepared data for importing an existing cryptographic key as a DWallet.
 * Contains verification data needed to prove ownership of the imported key.
 */
export interface ImportDWalletVerificationRequestInput {
	/** The public output that can be verified against the imported key */
	userPublicOutput: Uint8Array;
	/** The outgoing message for the verification protocol */
	userMessage: Uint8Array;
	/** The encrypted user share with proof for the imported key */
	encryptedUserShareAndProof: Uint8Array;
}

/**
 * Create a class groups keypair from a seed for encryption/decryption operations.
 * Uses SECP256k1, SECP256r1, Ristretto, or ED25519 curves with class groups for homomorphic encryption capabilities.
 *
 * @param seed - The seed bytes to generate the keypair from
 * @param curve - The curve to use for key generation
 * @returns Object containing the encryption key (public) and decryption key (private)
 */
export async function createClassGroupsKeypair(
	seed: Uint8Array,
	curve: Curve,
): Promise<{
	encryptionKey: Uint8Array;
	decryptionKey: Uint8Array;
}> {
	if (seed.length !== 32) {
		throw new Error('Seed must be 32 bytes');
	}

	const [encryptionKey, decryptionKey] = await generate_secp_cg_keypair_from_seed(
		fromCurveToNumber(curve),
		seed,
	);

	return {
		encryptionKey: Uint8Array.from(encryptionKey),
		decryptionKey: Uint8Array.from(decryptionKey),
	};
}

/**
 * Create the user's output and message for the Distributed Key Generation (DKG) protocol.
 * This function takes the first round output and produces the user's contribution.
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 *
 * @param protocolPublicParameters - The protocol public parameters for decryption
 * @param networkFirstRoundOutput - The output from the network's first round of DKG
 * @returns Object containing the user's DKG message, public output, and secret key share
 */
export async function createDKGUserOutput(
	protocolPublicParameters: Uint8Array,
	networkFirstRoundOutput: Uint8Array,
): Promise<{
	userDKGMessage: Uint8Array;
	userPublicOutput: Uint8Array;
	userSecretKeyShare: Uint8Array;
}> {
	const [userDKGMessage, userPublicOutput, userSecretKeyShare] = await create_dkg_user_output(
		protocolPublicParameters,
		Uint8Array.from(networkFirstRoundOutput),
	);

	return {
		userDKGMessage: Uint8Array.from(userDKGMessage),
		userPublicOutput: Uint8Array.from(userPublicOutput),
		userSecretKeyShare: Uint8Array.from(userSecretKeyShare),
	};
}

/**
 * Encrypt a secret share using the provided encryption key.
 * This creates an encrypted share that can only be decrypted by the corresponding decryption key.
 *
 * @param curve - The curve to use for encryption
 * @param userSecretKeyShare - The secret key share to encrypt
 * @param encryptionKey - The public encryption key to encrypt with
 * @param protocolPublicParameters - The protocol public parameters for encryption
 * @returns The encrypted secret share with proof of correct encryption
 */
export async function encryptSecretShare(
	curve: Curve,
	userSecretKeyShare: Uint8Array,
	encryptionKey: Uint8Array,
	protocolPublicParameters: Uint8Array,
): Promise<Uint8Array> {
	const encryptedUserShareAndProof = await encrypt_secret_share(
		fromCurveToNumber(curve),
		userSecretKeyShare,
		encryptionKey,
		protocolPublicParameters,
	);

	return Uint8Array.from(encryptedUserShareAndProof);
}

/**
 * Prepare all cryptographic data needed for DKG.
 *
 * @param protocolPublicParameters - The protocol public parameters
 * @param curve - The curve to use for key generation
 * @param encryptionKey - The user's public encryption key
 * @param bytesToHash - The bytes to hash for session identifier generation
 * @param senderAddressBytes - The sender address as raw bytes
 * @returns Complete prepared data for DKG including user message, public output, encrypted share, and secret key share
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 */
export async function prepareDKG(
	protocolPublicParameters: Uint8Array,
	curve: Curve,
	encryptionKey: Uint8Array,
	bytesToHash: Uint8Array,
	senderAddressBytes: Uint8Array,
): Promise<DKGRequestInput> {
	const [userDKGMessage, userPublicOutput, userSecretKeyShare] =
		await create_dkg_centralized_output_v2(
			fromCurveToNumber(curve),
			protocolPublicParameters,
			sessionIdentifierDigest(bytesToHash, senderAddressBytes),
		);

	const encryptedUserShareAndProof = await encryptSecretShare(
		curve,
		userSecretKeyShare,
		encryptionKey,
		protocolPublicParameters,
	);

	return {
		userDKGMessage: Uint8Array.from(userDKGMessage),
		userPublicOutput: Uint8Array.from(userPublicOutput),
		encryptedUserShareAndProof: Uint8Array.from(encryptedUserShareAndProof),
		userSecretKeyShare: Uint8Array.from(userSecretKeyShare),
	};
}

/**
 * Create the user's sign message for the signature generation process.
 * This function combines the user's secret key, presign, and message to create a sign message to be sent to the network.
 *
 * This function is used when developer has access to the user's public output which should be verified before using this method.
 *
 * @param protocolPublicParameters - The protocol public parameters
 * @param publicOutput - The user's public output
 * @param userSecretKeyShare - The user's secret key share
 * @param presign - The presignature data from a completed presign operation
 * @param message - The message bytes to sign
 * @param hash - The hash scheme to use for signing
 * @param signatureAlgorithm - The signature algorithm to use
 * @param curve - The curve to use
 * @returns The user's sign message that will be sent to the network for signature generation
 */
export async function createUserSignMessageWithPublicOutput<
	C extends Curve,
	S extends ValidSignatureAlgorithmForCurve<C>,
	H extends ValidHashForSignature<S>,
>(
	protocolPublicParameters: Uint8Array,
	publicOutput: Uint8Array,
	userSecretKeyShare: Uint8Array,
	presign: Uint8Array,
	message: Uint8Array,
	hash: H,
	signatureAlgorithm: S,
	curve: C,
): Promise<Uint8Array> {
	const { signatureAlgorithmNumber, hashNumber, curveNumber } =
		fromCurveAndSignatureAlgorithmAndHashToNumbers(curve, signatureAlgorithm, hash);

	return Uint8Array.from(
		await create_sign_user_message(
			protocolPublicParameters,
			publicOutput,
			userSecretKeyShare,
			presign,
			message,
			hashNumber,
			signatureAlgorithmNumber,
			curveNumber,
		),
	);
}

/**
 * Create the user's sign message for the signature generation process.
 * This function combines the user's secret key, presign, and message to create a sign message to be sent to the network.
 *
 * This function is used when developer has access to the centralized DKG output which should be verified before using this method.
 *
 * @param protocolPublicParameters - The protocol public parameters
 * @param centralizedDkgOutput - The centralized DKG output
 * @param userSecretKeyShare - The user's secret key share
 * @param presign - The presignature data from a completed presign operation
 * @param message - The message bytes to sign
 * @param hash - The hash scheme to use for signing
 * @param signatureAlgorithm - The signature algorithm to use
 * @param curve - The curve to use
 * @returns The user's sign message that will be sent to the network for signature generation
 */
export async function createUserSignMessageWithCentralizedOutput<
	C extends Curve,
	S extends ValidSignatureAlgorithmForCurve<C>,
	H extends ValidHashForSignature<S>,
>(
	protocolPublicParameters: Uint8Array,
	centralizedDkgOutput: Uint8Array,
	userSecretKeyShare: Uint8Array,
	presign: Uint8Array,
	message: Uint8Array,
	hash: H,
	signatureAlgorithm: S,
	curve: C,
): Promise<Uint8Array> {
	const { signatureAlgorithmNumber, hashNumber, curveNumber } =
		fromCurveAndSignatureAlgorithmAndHashToNumbers(curve, signatureAlgorithm, hash);

	return Uint8Array.from(
		await create_sign_centralized_party_message_with_centralized_party_dkg_output(
			protocolPublicParameters,
			centralizedDkgOutput,
			userSecretKeyShare,
			presign,
			message,
			hashNumber,
			signatureAlgorithmNumber,
			curveNumber,
		),
	);
}

/**
 * Convert a network DKG public output to the protocol public parameters.
 *
 * @param curve - The curve to use for key generation
 * @param network_dkg_public_output - The network DKG public output
 * @returns The protocol public parameters
 */
export async function networkDkgPublicOutputToProtocolPublicParameters(
	curve: Curve,
	network_dkg_public_output: Uint8Array,
): Promise<Uint8Array> {
	return Uint8Array.from(
		await network_dkg_public_output_to_protocol_pp(
			fromCurveToNumber(curve),
			network_dkg_public_output,
		),
	);
}

/**
 * Convert a reconfiguration DKG public output to the protocol public parameters.
 *
 * @param curve - The curve to use for key generation
 * @param reconfiguration_public_output - The reconfiguration DKG public output
 * @param network_dkg_public_output - The network DKG public output
 * @returns The protocol public parameters
 */
export async function reconfigurationPublicOutputToProtocolPublicParameters(
	curve: Curve,
	reconfiguration_public_output: Uint8Array,
	network_dkg_public_output: Uint8Array,
): Promise<Uint8Array> {
	return Uint8Array.from(
		await reconfiguration_public_output_to_protocol_pp(
			fromCurveToNumber(curve),
			reconfiguration_public_output,
			network_dkg_public_output,
		),
	);
}

/**
 * Verify a user's secret key share.
 *
 * @param curve - The curve to use for key generation
 * @param userSecretKeyShare - The user's unencrypted secret key share
 * @param userDKGOutput - The user's DKG output
 * @param networkDkgPublicOutput - The network DKG public output
 * @returns True if the user's secret key share is valid, false otherwise
 */
export async function verifyUserShare(
	curve: Curve,
	userSecretKeyShare: Uint8Array,
	userDKGOutput: Uint8Array,
	networkDkgPublicOutput: Uint8Array,
): Promise<boolean> {
	return await verify_user_share(
		fromCurveToNumber(curve),
		userSecretKeyShare,
		userDKGOutput,
		networkDkgPublicOutput,
	);
}

/**
 * Verify a signature.
 *
 * @param publicKey - The public key bytes
 * @param signature - The signature bytes to verify
 * @param message - The message bytes that was signed
 * @param networkDkgPublicOutput - The network DKG public output
 * @param hash - The hash scheme to use for verification
 * @param signatureAlgorithm - The signature algorithm to use
 * @param curve - The curve to use
 * @returns True if the signature is valid, false otherwise
 */
export async function verifySecpSignature<
	C extends Curve,
	S extends ValidSignatureAlgorithmForCurve<C>,
	H extends ValidHashForSignature<S>,
>(
	publicKey: Uint8Array,
	signature: Uint8Array,
	message: Uint8Array,
	networkDkgPublicOutput: Uint8Array,
	hash: H,
	signatureAlgorithm: S,
	curve: C,
): Promise<boolean> {
	const { signatureAlgorithmNumber, hashNumber, curveNumber } =
		fromCurveAndSignatureAlgorithmAndHashToNumbers(curve, signatureAlgorithm, hash);

	return await verify_secp_signature(
		publicKey,
		signature,
		message,
		networkDkgPublicOutput,
		hashNumber,
		signatureAlgorithmNumber,
		curveNumber,
	);
}

/**
 * Create a public key from a DWallet output.
 *
 * @param curve - The curve to use for key generation
 * @param dWalletOutput - The DWallet output
 * @returns The BCS-encoded public key
 */
export async function publicKeyFromDWalletOutput(
	curve: Curve,
	dWalletOutput: Uint8Array,
): Promise<Uint8Array> {
	return Uint8Array.from(
		await public_key_from_dwallet_output(fromCurveToNumber(curve), dWalletOutput),
	);
}

/**
 * Create a public key from a centralized DKG output.
 *
 * @param curve - The curve to use for key generation
 * @param centralizedDkgOutput - The centralized DKG output
 * @returns The BCS-encoded public key
 */
export async function publicKeyFromCentralizedDKGOutput(
	curve: Curve,
	centralizedDkgOutput: Uint8Array,
): Promise<Uint8Array> {
	return Uint8Array.from(
		await public_key_from_centralized_dkg_output(fromCurveToNumber(curve), centralizedDkgOutput),
	);
}

/**
 * Verify that the user's public output matches the network's public output.
 *
 * @param curve - The curve to use
 * @param userPublicOutput - The user's public output
 * @param networkDKGOutput - The network's public output
 * @returns True if the user's public output matches the network's public output, false otherwise
 */
export async function userAndNetworkDKGOutputMatch(
	curve: Curve,
	userPublicOutput: Uint8Array,
	networkDKGOutput: Uint8Array,
): Promise<boolean> {
	return await centralized_and_decentralized_parties_dkg_output_match(
		fromCurveToNumber(curve),
		userPublicOutput,
		networkDKGOutput,
	);
}

/**
 * Parse a signature from a sign output.
 *
 * @param curve - The curve to use
 * @param signatureAlgorithm - The signature algorithm to use
 * @param signatureOutput - The signature output bytes from the network
 * @returns The parsed signature bytes
 */
export async function parseSignatureFromSignOutput<
	C extends Curve,
	S extends ValidSignatureAlgorithmForCurve<C>,
>(curve: C, signatureAlgorithm: S, signatureOutput: Uint8Array): Promise<Uint8Array> {
	return Uint8Array.from(
		await parse_signature_from_sign_output(
			fromCurveToNumber(curve),
			fromSignatureAlgorithmToNumber(curve, signatureAlgorithm),
			signatureOutput,
		),
	);
}

/**
 * Create a digest of the session identifier for cryptographic operations.
 * This function creates a versioned, domain-separated hash of the session identifier.
 *
 * @param bytesToHash - The bytes to hash for session identifier generation
 * @param senderAddressBytes - The sender address bytes for session identifier generation
 * @returns The KECCAK-256 digest of the versioned and domain-separated session identifier
 */
export function sessionIdentifierDigest(
	bytesToHash: Uint8Array,
	senderAddressBytes: Uint8Array,
): Uint8Array {
	const preimage = keccak_256(Uint8Array.from([...senderAddressBytes, ...bytesToHash]));
	const version = 0; // Version of the session identifier
	// Calculate the user session identifier for digest
	const data = Uint8Array.from([
		...u64ToBytesBigEndian(version),
		...encodeToASCII('USER'),
		...preimage,
	]);
	// Compute the SHA3-256 digest of the serialized data
	const digest = keccak_256(data);
	return Uint8Array.from(digest);
}

/**
 * Create a random session identifier.
 *
 * @returns 32 random bytes for use as a session identifier
 */
export function createRandomSessionIdentifier(): Uint8Array {
	return Uint8Array.from(randomBytes(32));
}
