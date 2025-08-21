// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { prepareImportedKeyDWalletVerification } from '../../src/client/cryptography.js';
import { Curve, Hash, ImportedKeyDWallet, SignatureAlgorithm } from '../../src/client/types.js';
import {
	acceptEncryptedUserShare,
	createIkaClient,
	createSessionIdentifier,
	createSuiClient,
	generateKeypairForImportedKeyDWallet,
	presign,
	requestImportedKeyDWalletVerification,
	signWithImportedKeyDWallet,
} from '../common.js';

const suiClient = createSuiClient();
const ikaClient = createIkaClient(suiClient);

async function main() {
	await ikaClient.initialize();

	const { userShareEncryptionKeys, signerPublicKey, dWalletKeypair, signerAddress } =
		generateKeypairForImportedKeyDWallet();

	const { sessionIdentifier, sessionIdentifierPreimage } = await createSessionIdentifier(
		ikaClient,
		suiClient,
		signerAddress,
	);

	const importDWalletVerificationRequestInput = await prepareImportedKeyDWalletVerification(
		ikaClient,
		sessionIdentifierPreimage,
		userShareEncryptionKeys,
		dWalletKeypair,
	);

	const importedKeyDWalletVerificationRequestEvent = await requestImportedKeyDWalletVerification(
		ikaClient,
		suiClient,
		importDWalletVerificationRequestInput,
		Curve.SECP256K1,
		signerPublicKey,
		sessionIdentifier,
		signerAddress,
	);

	const importedKeyDWallet = await ikaClient.getDWalletInParticularState(
		importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
		'Active',
	);

	await acceptEncryptedUserShare(
		ikaClient,
		suiClient,
		importedKeyDWallet as ImportedKeyDWallet,
		importDWalletVerificationRequestInput.userPublicOutput,
		importedKeyDWalletVerificationRequestEvent,
		userShareEncryptionKeys,
	);

	const activeDWallet = await ikaClient.getDWalletInParticularState(
		importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
		'Active',
	);

	const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		importedKeyDWalletVerificationRequestEvent.event_data.encrypted_user_secret_key_share_id,
	);

	const presignRequestEvent = await presign(
		ikaClient,
		suiClient,
		importedKeyDWallet,
		SignatureAlgorithm.ECDSA,
	);

	const presignObject = await ikaClient.getPresignInParticularState(
		presignRequestEvent.event_data.presign_id,
		'Completed',
	);

	await signWithImportedKeyDWallet(
		ikaClient,
		suiClient,
		activeDWallet as ImportedKeyDWallet,
		presignObject,
		// eslint-disable-next-line @typescript-eslint/no-unsafe-argument
		new TextEncoder().encode('hello world'),
		Hash.KECCAK256,
		SignatureAlgorithm.ECDSA,
		encryptedUserSecretKeyShare,
		userShareEncryptionKeys,
	);
}

export { main };
