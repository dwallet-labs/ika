import { prepareDKGSecondRoundAsync } from '../client/cryptography';
import {
	acceptEncryptedUserShare,
	createIkaClient,
	createSuiClient,
	generateKeypair,
	registerEncryptionKey,
	requestDKGFirstRound,
	requestDkgSecondRound,
} from './common';

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
}

export { main };
