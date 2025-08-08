import { bcs } from '@mysten/sui/bcs';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import type { Secp256k1Keypair } from '@mysten/sui/keypairs/secp256k1';
import sha3 from 'js-sha3';

import {
	create_dkg_centralized_output as create_dkg_user_output,
	create_imported_dwallet_centralized_step as create_imported_dwallet_user_output,
	create_sign_centralized_output as create_sign_user_output,
	decrypt_user_share,
	encrypt_secret_share,
	generate_secp_cg_keypair_from_seed,
	network_dkg_public_output_to_protocol_pp,
	public_key_from_dwallet_output,
	verify_secp_signature,
	verify_user_share,
} from '../../../mpc-wasm/dist/node/dwallet_mpc_wasm.js';
import type { IkaClient } from './ika-client.js';
import type { DWallet } from './types.js';
import type { UserShareEncrytionKeys } from './user-share-encryption-keys.js';
import { encodeToASCII, u64ToBytesBigEndian } from './utils.js';

/**
 * Prepared data for the second round of Distributed Key Generation (DKG).
 * Contains all cryptographic outputs needed to complete the DKG process.
 */
export interface PreparedSecondRound {
	/** The user's public key share along with its zero-knowledge proof */
	userDKGMessage: Uint8Array;
	/** The user's public output from the DKG process */
	userPublicOutput: Uint8Array;
	/** The encrypted user share with its proof of correct encryption */
	encryptedUserShareAndProof: Uint8Array;
}

/**
 * Prepared data for importing an existing cryptographic key as a DWallet.
 * Contains verification data needed to prove ownership of the imported key.
 */
export interface PreparedImportDWalletVerification {
	/** The public output that can be verified against the imported key */
	userPublicOutput: Uint8Array;
	/** The outgoing message for the verification protocol */
	userMessage: Uint8Array;
	/** The encrypted user share with proof for the imported key */
	encryptedUserShareAndProof: Uint8Array;
}

/**
 * Create a class groups keypair from a seed for encryption/decryption operations.
 * Uses SECP256k1 curve with class groups for homomorphic encryption capabilities.
 *
 * @param seed - The seed bytes to generate the keypair from
 * @returns Object containing the encryption key (public) and decryption key (private)
 */
export function createClassGroupsKeypair(seed: Uint8Array): {
	encryptionKey: Uint8Array;
	decryptionKey: Uint8Array;
} {
	if (seed.length !== 32) {
		throw new Error('Seed must be 32 bytes');
	}

	const [encryptionKey, decryptionKey] = generate_secp_cg_keypair_from_seed(seed);

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
 * @param firstRoundOutput - The output from the network's first round of DKG
 * @param sessionIdentifier - Unique identifier for this DKG session
 * @returns Object containing the user's DKG message, public output, and secret key share
 *
 */
export function createDKGUserOutput(
	protocolPublicParameters: Uint8Array,
	firstRoundOutput: Uint8Array,
	sessionIdentifier: Uint8Array,
): {
	userDKGMessage: Uint8Array;
	userPublicOutput: Uint8Array;
	userSecretKeyShare: Uint8Array;
} {
	const [userDKGMessage, userPublicOutput, userSecretKeyShare] = create_dkg_user_output(
		protocolPublicParameters,
		Uint8Array.from(firstRoundOutput),
		sessionIdentifierDigest(sessionIdentifier),
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
export function encryptSecretShare(
	userSecretKeyShare: Uint8Array,
	encryptionKey: Uint8Array,
	protocolPublicParameters: Uint8Array,
): Uint8Array {
	const encryptedUserShareAndProof = encrypt_secret_share(
		userSecretKeyShare,
		encryptionKey,
		protocolPublicParameters,
	);

	return Uint8Array.from(encryptedUserShareAndProof);
}

/**
 * Decrypt a user's encrypted secret share.
 * This function verifies the encryption proof and decrypts the share using the private decryption key.
 *
 * SECURITY WARNING: *the user's secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 *
 * @param decryptionKey - The private decryption key
 * @param encryptionKey - The corresponding public encryption key
 * @param dWalletDKGOutput - The DWallet's DKG output for verification
 * @param encryptedUserShareAndProof - The encrypted share with proof to decrypt
 * @param protocolPublicParameters - The protocol public parameters
 * @returns The decrypted secret share
 * @throws {Error} If decryption fails or proof verification fails
 */
export function decryptUserShare(
	decryptionKey: Uint8Array,
	encryptionKey: Uint8Array,
	dWalletDKGOutput: Uint8Array,
	encryptedUserShareAndProof: Uint8Array,
	protocolPublicParameters: Uint8Array,
): Uint8Array {
	const decryptedUserShare = decrypt_user_share(
		decryptionKey,
		encryptionKey,
		dWalletDKGOutput,
		encryptedUserShareAndProof,
		protocolPublicParameters,
	);

	return Uint8Array.from(decryptedUserShare);
}

/**
 * Prepare all cryptographic data needed for the second round of DKG.
 * This function combines the DKG output generation and secret share encryption.
 *
 * @param protocolPublicParameters - The protocol public parameters
 * @param dWallet - The DWallet object containing first round output
 * @param sessionIdentifier - Unique identifier for this DKG session
 * @param encryptionKey - The user's public encryption key
 * @returns Complete prepared data for the second DKG round
 * @throws {Error} If the first round output is not available in the DWallet
 */
export function prepareDKGSecondRound(
	protocolPublicParameters: Uint8Array,
	dWallet: DWallet,
	sessionIdentifier: Uint8Array,
	encryptionKey: Uint8Array,
): PreparedSecondRound {
	const firstRoundOutput = dWallet.state.AwaitingUserDKGVerificationInitiation?.first_round_output;

	if (!firstRoundOutput) {
		throw new Error('First round output is undefined');
	}

	const [userDKGMessage, userPublicOutput, userSecretKeyShare] = create_dkg_user_output(
		protocolPublicParameters,
		Uint8Array.from(firstRoundOutput),
		sessionIdentifierDigest(sessionIdentifier),
	);

	const encryptedUserShareAndProof = encryptSecretShare(
		userSecretKeyShare,
		encryptionKey,
		protocolPublicParameters,
	);

	return {
		userDKGMessage: Uint8Array.from(userDKGMessage),
		userPublicOutput: Uint8Array.from(userPublicOutput),
		encryptedUserShareAndProof: Uint8Array.from(encryptedUserShareAndProof),
	};
}

/**
 * Asynchronously prepare all cryptographic data needed for the second round of DKG.
 * This function fetches network parameters automatically and prepares the second round data.
 *
 * @param ikaClient - The IkaClient instance to fetch network parameters from
 * @param dWallet - The DWallet object containing first round output
 * @param sessionIdentifier - Unique identifier for this DKG session
 * @param classGroupsKeypair - The user's class groups keypair for encryption
 * @returns Promise resolving to complete prepared data for the second DKG round
 * @throws {Error} If the first round output is not available or network parameters cannot be fetched
 */
export async function prepareDKGSecondRoundAsync(
	ikaClient: IkaClient,
	dWallet: DWallet,
	sessionIdentifier: Uint8Array,
	classGroupsKeypair: {
		encryptionKey: Uint8Array;
		decryptionKey: Uint8Array;
	},
): Promise<PreparedSecondRound> {
	const protocolPublicParameters = await ikaClient.getProtocolPublicParameters();
	const firstRoundOutput = dWallet.state.AwaitingUserDKGVerificationInitiation?.first_round_output;

	if (!firstRoundOutput) {
		throw new Error('First round output is undefined');
	}

	const [userDKGMessage, userPublicOutput, userSecretKeyShare] = create_dkg_user_output(
		protocolPublicParameters,
		Uint8Array.from(firstRoundOutput),
		sessionIdentifierDigest(sessionIdentifier),
	);

	const encryptedUserShareAndProof = encryptSecretShare(
		userSecretKeyShare,
		classGroupsKeypair.encryptionKey,
		protocolPublicParameters,
	);

	return {
		userDKGMessage: Uint8Array.from(userDKGMessage),
		userPublicOutput: Uint8Array.from(userPublicOutput),
		encryptedUserShareAndProof: Uint8Array.from(encryptedUserShareAndProof),
	};
}

/**
 * Prepare verification data for importing an existing cryptographic key as a DWallet.
 * This function creates all necessary proofs and encrypted data for the import process.
 *
 * @param ikaClient - The IkaClient instance to fetch network parameters from
 * @param sessionIdentifier - Unique identifier for this import session
 * @param userShareEncryptionKeys - The user's encryption keys for securing the imported share
 * @param keypair - The existing Secp256k1 keypair to import as a DWallet
 * @returns Promise resolving to complete verification data for the import process
 * @throws {Error} If network parameters cannot be fetched or key import preparation fails
 */
export async function prepareImportDWalletVerification(
	ikaClient: IkaClient,
	sessionIdentifier: Uint8Array,
	userShareEncryptionKeys: UserShareEncrytionKeys,
	keypair: Secp256k1Keypair,
): Promise<PreparedImportDWalletVerification> {
	const protocolPublicParameters = await ikaClient.getProtocolPublicParameters();

	const [userSecretShare, userPublicOutput, userMessage] = create_imported_dwallet_user_output(
		protocolPublicParameters,
		sessionIdentifierDigest(sessionIdentifier),
		bcs.vector(bcs.u8()).serialize(decodeSuiPrivateKey(keypair.getSecretKey()).secretKey).toBytes(),
	);

	const encryptedUserShareAndProof = encryptSecretShare(
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
 * @param protocolPublicParameters - The protocol public parameters
 * @param activeDWallet - The active DWallet containing the public output
 * @param secretKey - The user's secret key share
 * @param presign - The presignature data from a completed presign operation
 * @param message - The message bytes to sign
 * @param hash - The hash scheme identifier to use for signing
 * @returns The user's sign message that will be sent to the network for signature generation
 * @throws {Error} If the DWallet is not in active state or public output is missing
 */
export function createUserSignMessage(
	protocolPublicParameters: Uint8Array,
	activeDWallet: DWallet,
	secretKey: Uint8Array,
	presign: Uint8Array,
	message: Uint8Array,
	hash: number,
): Uint8Array {
	if (!activeDWallet.state.Active?.public_output) {
		throw new Error('Active DWallet public output is undefined');
	}

	return Uint8Array.from(
		create_sign_user_output(
			protocolPublicParameters,
			Uint8Array.from(activeDWallet.state.Active?.public_output),
			secretKey,
			presign,
			message,
			hash,
		),
	);
}

/**
 * Convert a network DKG public output to the protocol public parameters.
 *
 * @param network_dkg_public_output - The network DKG public output
 * @returns The protocol public parameters
 */
export function networkDkgPublicOutputToProtocolPp(
	network_dkg_public_output: Uint8Array,
): Uint8Array {
	return Uint8Array.from(network_dkg_public_output_to_protocol_pp(network_dkg_public_output));
}

/**
 * Verify a user's secret key share.
 *
 * @param userSecretKeyShare - The user's unencrypted secret key share
 * @param userDKGOutput - The user's DKG output
 * @param networkDkgPublicOutput - The network DKG public output
 * @returns True if the user's secret key share is valid, false otherwise
 */
export function verifyUserShare(
	userSecretKeyShare: Uint8Array,
	userDKGOutput: Uint8Array,
	networkDkgPublicOutput: Uint8Array,
): boolean {
	return verify_user_share(userSecretKeyShare, userDKGOutput, networkDkgPublicOutput);
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
export function verifySecpSignature(
	publicKey: Uint8Array,
	signature: Uint8Array,
	message: Uint8Array,
	networkDkgPublicOutput: Uint8Array,
	hash: number,
): boolean {
	return verify_secp_signature(publicKey, signature, message, networkDkgPublicOutput, hash);
}

/**
 * Create a public key from a DWallet output.
 *
 * @param dWalletOutput - The DWallet output
 * @returns The public key
 */
export function publicKeyFromDWalletOutput(dWalletOutput: Uint8Array): Uint8Array {
	return Uint8Array.from(public_key_from_dwallet_output(dWalletOutput));
}

/**
 * Create a digest of the session identifier for cryptographic operations.
 * This function creates a versioned, domain-separated hash of the session identifier.
 *
 * @param sessionIdentifier - The raw session identifier bytes
 * @returns The SHA3-256 digest of the versioned and domain-separated session identifier
 * @private
 */
export function sessionIdentifierDigest(sessionIdentifier: Uint8Array): Uint8Array {
	const version = 0; // Version of the session identifier
	// Calculate the user session identifier for digest
	const data = [...u64ToBytesBigEndian(version), ...encodeToASCII('USER'), ...sessionIdentifier];
	// Compute the SHA3-256 digest of the serialized data
	const digest = sha3.keccak256.digest(data);
	return Uint8Array.from(digest);
}
