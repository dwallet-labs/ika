// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';

import { prepareDKGSecondRoundAsync } from '../../src/client/cryptography.js';
import { ZeroTrustDWallet } from '../../src/client/types.js';
import {
	acceptEncryptedUserShare,
	acceptEncryptedUserShareForTransferredDWallet,
	createIkaClient,
	createSuiClient,
	generateKeypair,
	registerEncryptionKey,
	requestDKGFirstRound,
	requestDkgSecondRound,
	transferEncryptedUserShare,
} from '../common.js';

const suiClient = createSuiClient();
const ikaClient = createIkaClient(suiClient);

async function main() {
	await ikaClient.initialize();

	const { userShareEncryptionKeys: sourceUserShareEncryptionKeys } = generateKeypair();

	// THIS IS NOT SOMETHING THAT YOU SHOULD DO, DESTINATION HAS IT'S OWN KEYS.
	const { userShareEncryptionKeys: destinationUserShareEncryptionKeys } = generateKeypair();

	const { dwalletID, sessionIdentifierPreimage } = await requestDKGFirstRound(ikaClient, suiClient);

	await registerEncryptionKey(ikaClient, suiClient, sourceUserShareEncryptionKeys);

	// THIS IS NOT SOMETHING THAT YOU SHOULD DO, DESTINATION HAS IT'S OWN KEYS AND SHOULD REGISTER IT'S OWN ENCRYPTION KEY.
	await registerEncryptionKey(ikaClient, suiClient, destinationUserShareEncryptionKeys);

	const dWallet = await ikaClient.getDWalletInParticularState(
		dwalletID,
		'AwaitingUserDKGVerificationInitiation',
	);

	const dkgSecondRoundRequestInput = await prepareDKGSecondRoundAsync(
		ikaClient,
		dWallet,
		sessionIdentifierPreimage,
		sourceUserShareEncryptionKeys,
	);

	const secondRoundMoveResponse = await requestDkgSecondRound(
		ikaClient,
		suiClient,
		dWallet,
		dkgSecondRoundRequestInput,
		sourceUserShareEncryptionKeys,
	);

	const awaitingKeyHolderSignatureDWallet = await ikaClient.getDWalletInParticularState(
		dwalletID,
		'AwaitingKeyHolderSignature',
	);

	await acceptEncryptedUserShare(
		ikaClient,
		suiClient,
		awaitingKeyHolderSignatureDWallet as ZeroTrustDWallet,
		dkgSecondRoundRequestInput.userPublicOutput,
		secondRoundMoveResponse,
		sourceUserShareEncryptionKeys,
	);

	const activeDWallet = await ikaClient.getDWalletInParticularState(dwalletID, 'Active');

	const sourceEncryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
	);

	const transferUserShareEvent = await transferEncryptedUserShare(
		ikaClient,
		suiClient,
		activeDWallet as ZeroTrustDWallet,
		destinationUserShareEncryptionKeys.getSuiAddress(),
		sourceEncryptedUserSecretKeyShare,
		sourceUserShareEncryptionKeys,
	);

	const sourceEncryptionKey = await ikaClient.getActiveEncryptionKey(
		sourceUserShareEncryptionKeys.getSuiAddress(),
	);

	const destinationEncryptedUserSecretKeyShare =
		await ikaClient.getEncryptedUserSecretKeyShareInParticularState(
			transferUserShareEvent.event_data.encrypted_user_secret_key_share_id,
			'NetworkVerificationCompleted',
		);

	await acceptEncryptedUserShareForTransferredDWallet(
		ikaClient,
		suiClient,
		activeDWallet as ZeroTrustDWallet,
		destinationUserShareEncryptionKeys,
		sourceEncryptedUserSecretKeyShare,
		sourceEncryptionKey,
		destinationEncryptedUserSecretKeyShare,
	);
}

export { main };
