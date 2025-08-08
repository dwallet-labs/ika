import {
	create_dkg_centralized_output,
	create_imported_dwallet_centralized_step,
	create_sign_centralized_output,
	decrypt_user_share,
	encrypt_secret_share,
	generate_secp_cg_keypair_from_seed,
	network_dkg_public_output_to_protocol_pp,
} from '@dwallet-network/dwallet-mpc-wasm';
import { bcs } from '@mysten/sui/bcs';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import { Secp256k1Keypair } from '@mysten/sui/keypairs/secp256k1';
import sha3 from 'js-sha3';

import { IkaClient } from './ika-client';
import { DWallet } from './types';
import { UserShareEncrytionKeys } from './user-share-encryption-keys';
import { encodeToASCII, u64ToBytesBigEndian } from './utils';

/**
 * Prepared data for the second round of Distributed Key Generation (DKG).
 * Contains all cryptographic outputs needed to complete the DKG process.
 */
export type PreparedSecondRound = {
	/** The centralized public key share along with its zero-knowledge proof */
	centralizedPublicKeyShareAndProof: Uint8Array;
	/** The centralized public output from the DKG process */
	centralizedPublicOutput: Uint8Array;
	/** The centralized secret key share (should be encrypted before storage) */
	centralizedSecretKeyShare: Uint8Array;
	/** The encrypted user share with its proof of correct encryption */
	encryptedUserShareAndProof: Uint8Array;
};

/**
 * Prepared data for importing an existing cryptographic key as a DWallet.
 * Contains verification data needed to prove ownership of the imported key.
 */
export type PreparedImportDWalletVerification = {
	/** The secret share derived from the imported key */
	secret_share: Uint8Array;
	/** The public output that can be verified against the imported key */
	public_output: Uint8Array;
	/** The outgoing message for the verification protocol */
	outgoing_message: Uint8Array;
	/** The encrypted user share with proof for the imported key */
	encryptedUserShareAndProof: Uint8Array;
};

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
	const [expectedEncryptionKey, decryptionKey] = generate_secp_cg_keypair_from_seed(seed);

	return {
		encryptionKey: Uint8Array.from(expectedEncryptionKey),
		decryptionKey: Uint8Array.from(decryptionKey),
	};
}

/**
 * Create the centralized output for the Distributed Key Generation (DKG) process.
 * This function takes the first round output and produces the centralized party's contribution.
 *
 * @param networkDecryptionKeyPublicOutput - The network's public parameters for decryption
 * @param firstRoundOutput - The output from the first round of DKG
 * @param sessionIdentifier - Unique identifier for this DKG session
 * @returns Object containing the centralized public key share with proof, public output, and secret key share
 */
export function createDKGCentralizedOutput(
	networkDecryptionKeyPublicOutput: Uint8Array,
	firstRoundOutput: Uint8Array,
	sessionIdentifier: Uint8Array,
): {
	centralizedPublicKeyShareAndProof: Uint8Array;
	centralizedPublicOutput: Uint8Array;
	centralizedSecretKeyShare: Uint8Array;
} {
	const [centralizedPublicKeyShareAndProof, centralizedPublicOutput, centralizedSecretKeyShare] =
		create_dkg_centralized_output(
			networkDecryptionKeyPublicOutput,
			Uint8Array.from(firstRoundOutput),
			sessionIdentifierDigest(sessionIdentifier),
		);

	return {
		centralizedPublicKeyShareAndProof: Uint8Array.from(centralizedPublicKeyShareAndProof),
		centralizedPublicOutput: Uint8Array.from(centralizedPublicOutput),
		centralizedSecretKeyShare: Uint8Array.from(centralizedSecretKeyShare),
	};
}

/**
 * Encrypt a secret share using the provided encryption key.
 * This creates an encrypted share that can only be decrypted by the corresponding decryption key.
 *
 * @param centralizedSecretKeyShare - The secret key share to encrypt
 * @param encryptionKey - The public encryption key to encrypt with
 * @param networkDecryptionKeyPublicOutput - The network's public parameters for encryption
 * @returns The encrypted secret share with proof of correct encryption
 */
export function encryptSecretShare(
	centralizedSecretKeyShare: Uint8Array,
	encryptionKey: Uint8Array,
	networkDecryptionKeyPublicOutput: Uint8Array,
): Uint8Array {
	const encryptedUserShareAndProof = encrypt_secret_share(
		centralizedSecretKeyShare,
		encryptionKey,
		networkDecryptionKeyPublicOutput,
	);

	return Uint8Array.from(encryptedUserShareAndProof);
}

/**
 * Decrypt a user's encrypted secret share.
 * This function verifies the encryption proof and decrypts the share using the private decryption key.
 *
 * @param decryptionKey - The private decryption key
 * @param encryptionKey - The corresponding public encryption key
 * @param dWalletOutput - The DWallet's public output for verification
 * @param encryptedUserShareAndProof - The encrypted share with proof to decrypt
 * @param networkDecryptionKeyPublicOutput - The network's public parameters
 * @returns The decrypted secret share
 * @throws {Error} If decryption fails or proof verification fails
 */
export function decryptUserShare(
	decryptionKey: Uint8Array,
	encryptionKey: Uint8Array,
	dWalletOutput: Uint8Array,
	encryptedUserShareAndProof: Uint8Array,
	networkDecryptionKeyPublicOutput: Uint8Array,
): Uint8Array {
	const decryptedUserShare = decrypt_user_share(
		decryptionKey,
		encryptionKey,
		dWalletOutput,
		encryptedUserShareAndProof,
		networkDecryptionKeyPublicOutput,
	);

	return Uint8Array.from(decryptedUserShare);
}

/**
 * Prepare all cryptographic data needed for the second round of DKG.
 * This function combines the DKG output generation and secret share encryption.
 *
 * @param networkDecryptionKeyPublicOutput - The network's public parameters
 * @param dWallet - The DWallet object containing first round output
 * @param sessionIdentifier - Unique identifier for this DKG session
 * @param encryptionKey - The user's public encryption key
 * @returns Complete prepared data for the second DKG round
 * @throws {Error} If the first round output is not available in the DWallet
 */
export function prepareDKGSecondRound(
	networkDecryptionKeyPublicOutput: Uint8Array,
	dWallet: DWallet,
	sessionIdentifier: Uint8Array,
	encryptionKey: Uint8Array,
): PreparedSecondRound {
	const firstRoundOutput = dWallet.state.AwaitingUserDKGVerificationInitiation?.first_round_output;

	if (!firstRoundOutput) {
		throw new Error('First round output is undefined');
	}

	const [centralizedPublicKeyShareAndProof, centralizedPublicOutput, centralizedSecretKeyShare] =
		create_dkg_centralized_output(
			networkDecryptionKeyPublicOutput,
			Uint8Array.from(firstRoundOutput),
			sessionIdentifierDigest(sessionIdentifier),
		);

	const encryptedUserShareAndProof = encryptSecretShare(
		centralizedSecretKeyShare,
		encryptionKey,
		networkDecryptionKeyPublicOutput,
	);

	return {
		centralizedPublicKeyShareAndProof: Uint8Array.from(centralizedPublicKeyShareAndProof),
		centralizedPublicOutput: Uint8Array.from(centralizedPublicOutput),
		centralizedSecretKeyShare: Uint8Array.from(centralizedSecretKeyShare),
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
	const networkDecryptionKeyPublicOutput = await ikaClient.getNetworkPublicParameters();
	const firstRoundOutput = dWallet.state.AwaitingUserDKGVerificationInitiation?.first_round_output;

	if (!firstRoundOutput) {
		throw new Error('First round output is undefined');
	}

	const [centralizedPublicKeyShareAndProof, centralizedPublicOutput, centralizedSecretKeyShare] =
		create_dkg_centralized_output(
			networkDecryptionKeyPublicOutput,
			Uint8Array.from(firstRoundOutput),
			sessionIdentifierDigest(sessionIdentifier),
		);

	const encryptedUserShareAndProof = encryptSecretShare(
		centralizedSecretKeyShare,
		classGroupsKeypair.encryptionKey,
		networkDecryptionKeyPublicOutput,
	);

	return {
		centralizedPublicKeyShareAndProof: Uint8Array.from(centralizedPublicKeyShareAndProof),
		centralizedPublicOutput: Uint8Array.from(centralizedPublicOutput),
		centralizedSecretKeyShare: Uint8Array.from(centralizedSecretKeyShare),
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
	const networkDecryptionKeyPublicOutput = await ikaClient.getNetworkPublicParameters();

	const [secret_share, public_output, outgoing_message] = create_imported_dwallet_centralized_step(
		networkDecryptionKeyPublicOutput,
		sessionIdentifierDigest(sessionIdentifier),
		bcs.vector(bcs.u8()).serialize(decodeSuiPrivateKey(keypair.getSecretKey()).secretKey).toBytes(),
	);

	const encryptedUserShareAndProof = encryptSecretShare(
		secret_share,
		userShareEncryptionKeys.encryptionKey,
		networkDecryptionKeyPublicOutput,
	);

	return {
		secret_share: Uint8Array.from(secret_share),
		public_output: Uint8Array.from(public_output),
		outgoing_message: Uint8Array.from(outgoing_message),
		encryptedUserShareAndProof: Uint8Array.from(encryptedUserShareAndProof),
	};
}

/**
 * Create the centralized output for a signature generation process.
 * This function combines the user's secret key, presign, and message to create a signature component.
 *
 * @param networkDecryptionKeyPublicOutput - The network's public parameters
 * @param activeDWallet - The active DWallet containing the public output
 * @param secretKey - The user's secret key share
 * @param presign - The presignature data from a completed presign operation
 * @param message - The message bytes to sign
 * @param hash - The hash scheme identifier to use for signing
 * @returns The centralized signature output that can be combined with other signature components
 * @throws {Error} If the DWallet is not in active state or public output is missing
 */
export function createSignCentralizedOutput(
	networkDecryptionKeyPublicOutput: Uint8Array,
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
		create_sign_centralized_output(
			networkDecryptionKeyPublicOutput,
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
 * Create a digest of the session identifier for cryptographic operations.
 * This function creates a versioned, domain-separated hash of the session identifier.
 *
 * @param sessionIdentifier - The raw session identifier bytes
 * @returns The SHA3-256 digest of the versioned and domain-separated session identifier
 * @private
 */
function sessionIdentifierDigest(sessionIdentifier: Uint8Array): Uint8Array {
	const version = 0; // Version of the session identifier
	// Calculate the user session identifier for digest
	const data = [...u64ToBytesBigEndian(version), ...encodeToASCII('USER'), ...sessionIdentifier];
	// Compute the SHA3-256 digest of the serialized data
	const digest = sha3.keccak256.digest(data);
	return Uint8Array.from(digest);
}
