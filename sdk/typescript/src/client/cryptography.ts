import {
	create_dkg_centralized_output,
	encrypt_secret_share,
	generate_secp_cg_keypair_from_seed,
} from '@dwallet-network/dwallet-mpc-wasm';
import sha3 from 'js-sha3';

import { IkaClient } from './ika-client';
import { DWallet } from './types';
import { encodeToASCII, u64ToBytesBigEndian } from './utils';

export type PreparedSecondRound = {
	centralizedPublicKeyShareAndProof: Uint8Array;
	centralizedPublicOutput: Uint8Array;
	centralizedSecretKeyShare: Uint8Array;
	encryptedUserShareAndProof: Uint8Array;
};

export function createClassGroupsKeypair(seed: Uint8Array): {
	encryptionKey: Uint8Array;
	decryptionKey: Uint8Array;
} {
	const [expectedEncryptionKey, decryptionKey] = generate_secp_cg_keypair_from_seed(seed);

	return {
		encryptionKey: expectedEncryptionKey,
		decryptionKey,
	};
}

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
		centralizedPublicKeyShareAndProof,
		centralizedPublicOutput,
		centralizedSecretKeyShare,
	};
}

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

	return encryptedUserShareAndProof;
}

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
		centralizedPublicKeyShareAndProof,
		centralizedPublicOutput,
		centralizedSecretKeyShare,
		encryptedUserShareAndProof,
	};
}

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
		centralizedPublicKeyShareAndProof,
		centralizedPublicOutput,
		centralizedSecretKeyShare,
		encryptedUserShareAndProof,
	};
}

function sessionIdentifierDigest(sessionIdentifier: Uint8Array): Uint8Array {
	const version = 0; // Version of the session identifier
	// Calculate the user session identifier for digest
	const data = [...u64ToBytesBigEndian(version), ...encodeToASCII('USER'), ...sessionIdentifier];
	// Compute the SHA3-256 digest of the serialized data
	const digest = sha3.keccak256.digest(data);
	return Uint8Array.from(digest);
}
