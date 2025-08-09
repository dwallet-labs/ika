// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { prepareImportDWalletVerification } from '../../src/client/cryptography.js';
import { Curve, Hash, SignatureAlgorithm } from '../../src/client/types.js';
import {
	acceptEncryptedUserShare,
	createIkaClient,
	createSessionIdentifier,
	createSuiClient,
	generateKeypairForImportedDWallet,
	makeImportedDWalletUserSecretKeySharesPublic,
	presign,
	requestImportedDWalletVerification,
	signWithImportedDWalletPublic,
} from '../common.js';

const suiClient = createSuiClient();
const ikaClient = createIkaClient(suiClient);

async function main() {
	await ikaClient.initialize();

	const { userShareEncryptionKeys, signerPublicKey, dWalletKeypair, signerAddress } =
		generateKeypairForImportedDWallet();

	const { sessionIdentifier, sessionIdentifierPreimage } = await createSessionIdentifier(
		ikaClient,
		suiClient,
		signerAddress,
	);

	const importDWalletVerificationRequestInput = await prepareImportDWalletVerification(
		ikaClient,
		sessionIdentifierPreimage,
		userShareEncryptionKeys,
		dWalletKeypair,
	);

	const importedKeyDWalletVerificationRequestEvent = await requestImportedDWalletVerification(
		ikaClient,
		suiClient,
		importDWalletVerificationRequestInput,
		Curve.SECP256K1,
		signerPublicKey,
		sessionIdentifier,
		signerAddress,
	);

	const awaitingKeyHolderSignatureDWallet = await ikaClient.getDWalletInParticularState(
		importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
		'AwaitingKeyHolderSignature',
	);

	await acceptEncryptedUserShare(
		ikaClient,
		suiClient,
		awaitingKeyHolderSignatureDWallet,
		importedKeyDWalletVerificationRequestEvent,
		userShareEncryptionKeys,
	);

	const activeDWallet = await ikaClient.getDWalletInParticularState(
		importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
		'Active',
	);

	const secretShare = await ikaClient.getEncryptedUserSecretKeyShare(
		importedKeyDWalletVerificationRequestEvent.event_data.encrypted_user_secret_key_share_id,
	);

	await makeImportedDWalletUserSecretKeySharesPublic(
		ikaClient,
		suiClient,
		activeDWallet,
		await userShareEncryptionKeys.decryptUserShare(
			activeDWallet,
			secretShare,
			await ikaClient.getProtocolPublicParameters(),
		),
	);

	const presignRequestEvent = await presign(
		ikaClient,
		suiClient,
		activeDWallet,
		SignatureAlgorithm.ECDSA,
	);

	const presignObject = await ikaClient.getPresignInParticularState(
		presignRequestEvent.event_data.presign_id,
		'Completed',
	);

	await signWithImportedDWalletPublic(
		ikaClient,
		suiClient,
		activeDWallet,
		presignObject,
		new TextEncoder().encode('hello world'),
		Hash.KECCAK256,
		SignatureAlgorithm.ECDSA,
	);
}

export { main };
