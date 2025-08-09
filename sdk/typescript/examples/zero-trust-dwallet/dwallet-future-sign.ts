// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { prepareDKGSecondRoundAsync } from '../../src/client/cryptography.js';
import { Hash, SignatureAlgorithm } from '../../src/client/types.js';
import {
	acceptEncryptedUserShare,
	createIkaClient,
	createSuiClient,
	futureSign,
	generateKeypair,
	presign,
	registerEncryptionKey,
	requestDKGFirstRound,
	requestDkgSecondRound,
	requestFutureSign,
} from '../common.js';

const suiClient = createSuiClient();
const ikaClient = createIkaClient(suiClient);

async function main() {
	await ikaClient.initialize();
	const { userShareEncryptionKeys, signerPublicKey } = generateKeypair();

	const { dwalletID, sessionIdentifierPreimage } = await requestDKGFirstRound(ikaClient, suiClient);

	await registerEncryptionKey(ikaClient, suiClient, userShareEncryptionKeys);

	const dWallet = await ikaClient.getDWalletInParticularState(
		dwalletID,
		'AwaitingUserDKGVerificationInitiation',
	);

	const dkgSecondRoundRequestInput = await prepareDKGSecondRoundAsync(
		ikaClient,
		dWallet,
		sessionIdentifierPreimage,
		userShareEncryptionKeys,
	);

	const secondRoundMoveResponse = await requestDkgSecondRound(
		ikaClient,
		suiClient,
		dWallet,
		dkgSecondRoundRequestInput,
		userShareEncryptionKeys,
		signerPublicKey,
	);

	const awaitingKeyHolderSignatureDWallet = await ikaClient.getDWalletInParticularState(
		dwalletID,
		'AwaitingKeyHolderSignature',
	);

	await acceptEncryptedUserShare(
		ikaClient,
		suiClient,
		awaitingKeyHolderSignatureDWallet,
		secondRoundMoveResponse,
		userShareEncryptionKeys,
	);

	const activeDWallet = await ikaClient.getDWalletInParticularState(dwalletID, 'Active');

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

	const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
	);

	const futureSignRequest = await requestFutureSign(
		ikaClient,
		suiClient,
		activeDWallet,
		presignObject,
		userShareEncryptionKeys,
		encryptedUserSecretKeyShare,
		new TextEncoder().encode('hello world'),
		Hash.KECCAK256,
	);

	const partialUserSignature = await ikaClient.getPartialUserSignatureInParticularState(
		futureSignRequest.event_data.partial_centralized_signed_message_id,
		'NetworkVerificationCompleted',
	);

	await futureSign(
		ikaClient,
		suiClient,
		activeDWallet,
		partialUserSignature,
		userShareEncryptionKeys,
		new TextEncoder().encode('hello world'),
		Hash.KECCAK256,
		SignatureAlgorithm.ECDSA,
	);
}

export { main };
