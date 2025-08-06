import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';

import { prepareDKGSecondRoundAsync } from '../../client/cryptography';
import {
	acceptEncryptedUserShare,
	createIkaClient,
	createSuiClient,
	generateKeypair,
	registerEncryptionKey,
	requestDKGFirstRound,
	requestDkgSecondRound,
	transferEncryptedUserShare,
} from '../common';

const suiClient = createSuiClient();
const ikaClient = createIkaClient(suiClient);

async function main() {
	const { userShareEncryptionKeys, signerPublicKey } = generateKeypair();

	const { dwalletID, sessionIdentifierPreimage } = await requestDKGFirstRound(ikaClient, suiClient);

	await registerEncryptionKey(ikaClient, suiClient, userShareEncryptionKeys);

	const dWallet = await ikaClient.getDWallet(dwalletID);

	const preparedSecondRound = await prepareDKGSecondRoundAsync(
		ikaClient,
		dWallet,
		sessionIdentifierPreimage,
		userShareEncryptionKeys,
	);

	const secondRoundMoveResponse = await requestDkgSecondRound(
		ikaClient,
		suiClient,
		dWallet,
		preparedSecondRound,
		userShareEncryptionKeys,
		signerPublicKey,
	);

	const activeDWallet = await ikaClient.getDWallet(dwalletID);

	await acceptEncryptedUserShare(
		ikaClient,
		suiClient,
		activeDWallet,
		secondRoundMoveResponse,
		userShareEncryptionKeys,
	);

	const sourceEncryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
	);

	// WARNING: THIS ADDRESS NEEDS TO HAVE AN ACTIVE ENCRYPTION KEY.
	const destinationSuiAddress = Ed25519Keypair.generate().toSuiAddress();

	await transferEncryptedUserShare(
		ikaClient,
		suiClient,
		activeDWallet,
		destinationSuiAddress,
		sourceEncryptedUserSecretKeyShare,
		userShareEncryptionKeys,
	);
}

export { main };
