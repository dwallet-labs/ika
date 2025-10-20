// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { bcs } from '@mysten/sui/bcs';
import { PublicKey, SIGNATURE_FLAG_TO_SCHEME } from '@mysten/sui/cryptography';
import { keccak_256 } from '@noble/hashes/sha3';
import { randomBytes } from '@noble/hashes/utils.js';

import type { IkaClient } from './ika-client.js';
import type { DWallet, EncryptedUserSecretKeyShare } from './types.js';
import { Curve, PublicKeyBCS, SignatureAlgorithm } from './types.js';
import type { UserShareEncryptionKeys } from './user-share-encryption-keys.js';
import { encodeToASCII, u64ToBytesBigEndian } from './utils.js';
import {
	centralized_and_decentralized_parties_dkg_output_match,
	create_dkg_centralized_output_v2,
	create_dkg_centralized_output_v1 as create_dkg_user_output,
	create_imported_dwallet_centralized_step as create_imported_dwallet_user_output,
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

	let encryptionKey: Uint8Array;
	let decryptionKey: Uint8Array;

	if (
		curve === Curve.SECP256K1 ||
		curve === Curve.SECP256R1 ||
		curve === Curve.RISTRETTO ||
		curve === Curve.ED25519
	) {
		[encryptionKey, decryptionKey] = await generate_secp_cg_keypair_from_seed(curve, seed);
	} else {
		throw new Error(
			'Only SECP256K1, SECP256R1, RISTRETTO, and ED25519 curves are supported for now',
		);
	}

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
 * @param sessionIdentifier - Unique identifier for this DKG session
 * @returns Object containing the user's DKG message, public output, and secret key share
 *
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
		curve,
		userSecretKeyShare,
		encryptionKey,
		protocolPublicParameters,
	);

	return Uint8Array.from(encryptedUserShareAndProof);
}

/**
 * @deprecated Use prepareDKG instead
 *
 * @param _protocolPublicParameters - The protocol public parameters
 * @param _dWallet - The DWallet object containing first round output
 * @param _encryptionKey - The user's public encryption key
 * @returns Complete prepared data for the second DKG round
 * @throws {Error} If the first round output is not available in the DWallet
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 */
export async function prepareDKGSecondRound(
	_protocolPublicParameters: Uint8Array,
	_dWallet: DWallet,
	_encryptionKey: Uint8Array,
): Promise<DKGRequestInput> {
	throw new Error('prepareDKGSecondRound is deprecated. Use prepareDKG instead');
}

/**
 * Prepare all cryptographic data needed for DKG.
 *
 * @param protocolPublicParameters - The protocol public parameters
 * @param curve - The curve to use for key generation
 * @param encryptionKey - The user's public encryption key
 * @param bytesToHash - The bytes to hash
 * @param senderAddress - The sender address
 * @returns Complete prepared data for the second DKG round
 * @throws {Error} If the first round output is not available in the DWallet
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 */
export async function prepareDKG(
	protocolPublicParameters: Uint8Array,
	curve: Curve,
	encryptionKey: Uint8Array,
	bytesToHash: Uint8Array,
	senderAddress: string,
): Promise<DKGRequestInput> {
	const senderAddressBytes = bcs.Address.serialize(senderAddress).toBytes();

	const [userDKGMessage, userPublicOutput, userSecretKeyShare] =
		await create_dkg_centralized_output_v2(
			curve,
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
 * @deprecated Use prepareDKGAsync instead
 *
 * @param ikaClient - The IkaClient instance to fetch network parameters from
 * @param dWallet - The DWallet object containing first round output
 * @param userShareEncryptionKeys - The user's encryption keys for securing the user's share
 * @returns Promise resolving to complete prepared data for the second DKG round
 * @throws {Error} If the first round output is not available or network parameters cannot be fetched
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 */
export async function prepareDKGSecondRoundAsync(
	_ikaClient: IkaClient,
	_dWallet: DWallet,
	_userShareEncryptionKeys: UserShareEncryptionKeys,
): Promise<DKGRequestInput> {
	throw new Error('prepareDKGSecondRoundAsync is deprecated. Use prepareDKGAsync instead');
}

/**
 * Prepare all cryptographic data needed for DKG.
 *
 * @param ikaClient - The IkaClient instance to fetch network parameters from
 * @param curve - The curve to use for key generation
 * @param userShareEncryptionKeys - The user's encryption keys for securing the user's share
 * @param bytesToHash - The bytes to hash
 * @param senderAddress - The sender address
 * @returns Promise resolving to complete prepared data for the second DKG round
 * @throws {Error} If the first round output is not available or network parameters cannot be fetched
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 */
export async function prepareDKGAsync(
	ikaClient: IkaClient,
	curve: Curve,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	bytesToHash: Uint8Array,
	senderAddress: string,
): Promise<DKGRequestInput> {
	const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(undefined, curve);

	return prepareDKG(
		protocolPublicParameters,
		curve,
		userShareEncryptionKeys.encryptionKey,
		bytesToHash,
		senderAddress,
	);
}

/**
 * Prepare verification data for importing an existing cryptographic key as a DWallet.
 * This function creates all necessary proofs and encrypted data for the import process.
 *
 * @param ikaClient - The IkaClient instance to fetch network parameters from
 * @param curve - The curve to use for key generation
 * @param sessionIdentifier - Unique identifier for this import session
 * @param userShareEncryptionKeys - The user's encryption keys for securing the imported share
 * @param keypair - The existing keypair to import as a DWallet.
 * @returns Promise resolving to complete verification data for the import process
 * @throws {Error} If network parameters cannot be fetched or key import preparation fails
 */
export async function prepareImportedKeyDWalletVerification(
	ikaClient: IkaClient,
	curve: Curve,
	bytesToHash: Uint8Array,
	senderAddress: string,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	privateKey: Uint8Array,
): Promise<ImportDWalletVerificationRequestInput> {
	const senderAddressBytes = bcs.Address.serialize(senderAddress).toBytes();
	const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(undefined, curve);

	const [userSecretShare, userPublicOutput, userMessage] =
		await create_imported_dwallet_user_output(
			curve,
			protocolPublicParameters,
			sessionIdentifierDigest(bytesToHash, senderAddressBytes),
			bcs.vector(bcs.u8()).serialize(privateKey).toBytes(),
		);

	const encryptedUserShareAndProof = await encryptSecretShare(
		curve,
		userSecretShare,
		userShareEncryptionKeys.encryptionKey,
		protocolPublicParameters,
	);

	return {
		userPublicOutput: Uint8Array.from(userPublicOutput),
		userMessage: Uint8Array.from(userMessage),
		encryptedUserShareAndProof: Uint8Array.from(encryptedUserShareAndProof),
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
 * @param hash - The hash scheme identifier to use for signing
 * @param signatureScheme
 * @returns The user's sign message that will be sent to the network for signature generation
 * @throws {Error} If the DWallet is not in active state or public output is missing
 */
export async function createUserSignMessageWithPublicOutput(
	protocolPublicParameters: Uint8Array,
	publicOutput: Uint8Array,
	userSecretKeyShare: Uint8Array,
	presign: Uint8Array,
	message: Uint8Array,
	hash: number,
	signatureScheme: number,
): Promise<Uint8Array> {
	return Uint8Array.from(
		await create_sign_user_message(
			protocolPublicParameters,
			publicOutput,
			userSecretKeyShare,
			presign,
			message,
			hash,
			signatureScheme,
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
 * @param hash - The hash scheme identifier to use for signing
 * @param signatureScheme
 * @returns The user's sign message that will be sent to the network for signature generation
 * @throws {Error} If the DWallet is not in active state or public output is missing
 */
export async function createUserSignMessageWithCentralizedOutput(
	protocolPublicParameters: Uint8Array,
	centralizedDkgOutput: Uint8Array,
	userSecretKeyShare: Uint8Array,
	presign: Uint8Array,
	message: Uint8Array,
	hash: number,
	signatureScheme: number,
): Promise<Uint8Array> {
	return Uint8Array.from(
		await create_sign_centralized_party_message_with_centralized_party_dkg_output(
			protocolPublicParameters,
			centralizedDkgOutput,
			userSecretKeyShare,
			presign,
			message,
			hash,
			signatureScheme,
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
		await network_dkg_public_output_to_protocol_pp(curve, network_dkg_public_output),
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
			curve,
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
	return await verify_user_share(curve, userSecretKeyShare, userDKGOutput, networkDkgPublicOutput);
}

/**
 * Verify a user's signature.
 *
 * @param publicKey - The user's public key
 * @param signature - The user's signature
 * @param message - The message to verify
 * @param networkDkgPublicOutput - The network DKG public output
 * @param hash - The hash scheme identifier to use for verification
 * @returns True if the signature is valid, false otherwise
 */
export async function verifySecpSignature(
	publicKey: Uint8Array,
	signature: Uint8Array,
	message: Uint8Array,
	networkDkgPublicOutput: Uint8Array,
	hash: number,
): Promise<boolean> {
	return await verify_secp_signature(publicKey, signature, message, networkDkgPublicOutput, hash);
}

/**
 * Create a public key from a DWallet output.
 *
 * @param curve - The curve to use for key generation
 * @param dWalletOutput - The DWallet output
 * @returns The public key
 */
export async function publicKeyFromDWalletOutput(
	curve: Curve,
	dWalletOutput: Uint8Array,
): Promise<Uint8Array> {
	const raw = await public_key_from_dwallet_output(curve, dWalletOutput);
	const encoded = new Uint8Array(raw); // Convert JS array -> Uint8Array

	// If it is Ristretto or ED25519
	// It is not BCS-Encoded since they have fixed size in rust
	if (curve === Curve.RISTRETTO || curve === Curve.ED25519) {
		return new Uint8Array(encoded);
	}

	return new Uint8Array(PublicKeyBCS.parse(encoded)); // Decode BCS bytes -> raw public key
}

/**
 * Create a public key from a centralized DKG output.
 *
 * @param curve - The curve to use for key generation
 * @param centralizedDkgOutput - The centralized DKG output
 * @returns The public key
 */
export async function publicKeyFromCentralizedDKGOutput(
	curve: Curve,
	centralizedDkgOutput: Uint8Array,
): Promise<Uint8Array> {
	const raw = await public_key_from_centralized_dkg_output(curve, centralizedDkgOutput);
	const encoded = new Uint8Array(raw); // Convert JS array -> Uint8Array

	// If it is Ristretto or ED25519
	// It is not BCS-Encoded since they have fixed size in rust
	if (curve === Curve.RISTRETTO || curve === Curve.ED25519) {
		return new Uint8Array(encoded);
	}

	return new Uint8Array(PublicKeyBCS.parse(encoded)); // Decode BCS bytes -> raw public key
}

/**
 * Verify and get the DWallet DKG public output.
 * The `publicKey` is used to verify the user's public output signature.
 *
 * SECURITY WARNING: For withSecrets flows, the public key or public output must be saved by the developer during DKG,
 * NOT fetched from the network, to ensure proper verification.
 *
 * @param dWallet - The DWallet object containing the user's public output
 * @param encryptedUserSecretKeyShare - The encrypted user secret key share
 * @param publicKey - The user share encryption key's public key for verification
 * @returns The DKG public output
 */
export async function verifyAndGetDWalletDKGPublicOutput(
	dWallet: DWallet,
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	publicKey: PublicKey,
): Promise<Uint8Array> {
	if (
		SIGNATURE_FLAG_TO_SCHEME[publicKey.flag() as keyof typeof SIGNATURE_FLAG_TO_SCHEME] !==
		'ED25519'
	) {
		throw new Error('Only ED25519 public keys are supported.');
	}

	if (!dWallet.state.Active?.public_output) {
		throw new Error('DWallet is not in active state');
	}

	if (!encryptedUserSecretKeyShare.state.KeyHolderSigned?.user_output_signature) {
		throw new Error('User output signature is undefined');
	}

	const userPublicOutput = Uint8Array.from(dWallet.state.Active.public_output);

	const userOutputSignature = Uint8Array.from(
		encryptedUserSecretKeyShare.state.KeyHolderSigned?.user_output_signature,
	);

	if (!(await publicKey.verify(userPublicOutput, userOutputSignature))) {
		throw new Error('Invalid signature');
	}

	if (publicKey.toSuiAddress() !== encryptedUserSecretKeyShare.encryption_key_address) {
		throw new Error(
			'Invalid Sui address. The encryption key address does not match the signing keypair address.',
		);
	}

	return Uint8Array.from(dWallet.state.Active.public_output);
}

/**
 * Verify that the user's public output matches the network's public output.
 *
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
		curve,
		userPublicOutput,
		networkDKGOutput,
	);
}

/**
 * Parse a signature from a sign output.
 *
 * @param signatureAlgorithm - The signature algorithm
 * @param signatureOutput - The signature output
 * @returns The parsed signature
 */
export async function parseSignatureFromSignOutput(
	signatureAlgorithm: SignatureAlgorithm,
	signatureOutput: Uint8Array,
): Promise<Uint8Array> {
	return Uint8Array.from(
		await parse_signature_from_sign_output(signatureAlgorithm, signatureOutput),
	);
}

/**
 * Create a digest of the session identifier for cryptographic operations.
 * This function creates a versioned, domain-separated hash of the session identifier.
 *
 * @param sessionIdentifier - The raw session identifier bytes
 * @returns The SHA3-256 digest of the versioned and domain-separated session identifier
 * @private
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
 * @returns The random session identifier
 */
export function createRandomSessionIdentifier(): Uint8Array {
	return Uint8Array.from(randomBytes(32));
}
