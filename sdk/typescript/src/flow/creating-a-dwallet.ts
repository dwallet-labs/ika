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
	const {
		encryptedSecretShareSigningKeypair,
		encryptionKeyPublicKey,
		encryptionKeyAddress,
		signerPublicKey,
		classGroupsKeypair,
	} = generateKeypair();

	const { dwalletID, sessionIdentifierPreimage } = await requestDKGFirstRound(ikaClient, suiClient);

	await registerEncryptionKey(
		ikaClient,
		suiClient,
		encryptionKeyPublicKey,
		classGroupsKeypair,
		encryptedSecretShareSigningKeypair,
	);

	const dWallet = await ikaClient.getDWallet(dwalletID);

	const preparedSecondRound = await prepareDKGSecondRoundAsync(
		ikaClient,
		dWallet,
		sessionIdentifierPreimage,
		classGroupsKeypair,
	);

	const secondRoundMoveResponse = await requestDkgSecondRound(ikaClient, suiClient, {
		preparedSecondRound,
		encryptionKeyAddress,
		signerPublicKey,
	});

	const activeDWallet = await ikaClient.getDWallet(dwalletID);

	await acceptEncryptedUserShare(
		ikaClient,
		suiClient,
		activeDWallet,
		secondRoundMoveResponse,
		encryptedSecretShareSigningKeypair,
	);
}

export { main };
