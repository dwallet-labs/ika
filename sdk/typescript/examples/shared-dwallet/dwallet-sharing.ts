// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { prepareDKGSecondRoundAsync } from '../../src/client/cryptography.js';
import {
	acceptEncryptedUserShare,
	createIkaClient,
	createSuiClient,
	generateKeypair,
	makeDWalletUserSecretKeySharesPublic,
	registerEncryptionKey,
	requestDKGFirstRound,
	requestDkgSecondRound,
} from '../common.js';

const suiClient = createSuiClient();
const ikaClient = createIkaClient(suiClient);

async function main() {
	await ikaClient.initialize();

	const { userShareEncryptionKeys } = generateKeypair();

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
	);

	const awaitingKeyHolderSignatureDWallet = await ikaClient.getDWalletInParticularState(
		dwalletID,
		'AwaitingKeyHolderSignature',
	);

	await acceptEncryptedUserShare(
		ikaClient,
		suiClient,
		awaitingKeyHolderSignatureDWallet,
		dkgSecondRoundRequestInput.userPublicOutput,
		secondRoundMoveResponse,
		userShareEncryptionKeys,
	);

	const activeDWallet = await ikaClient.getDWalletInParticularState(dwalletID, 'Active');

	const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
	);

	const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
		activeDWallet,
		encryptedUserSecretKeyShare,
		await ikaClient.getProtocolPublicParameters(activeDWallet),
	);

	await makeDWalletUserSecretKeySharesPublic(ikaClient, suiClient, activeDWallet, secretShare);
}

export { main };
