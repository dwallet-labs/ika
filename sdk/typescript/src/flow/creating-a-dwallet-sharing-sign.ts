import { Hash, SignatureAlgorithm } from '../client';
import { prepareDKGSecondRoundAsync } from '../client/cryptography';
import {
	acceptEncryptedUserShare,
	createIkaClient,
	createSuiClient,
	generateKeypair,
	makeDWalletUserSecretKeySharesPublic,
	presign,
	registerEncryptionKey,
	requestDKGFirstRound,
	requestDkgSecondRound,
	signPublicUserShare,
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

	await makeDWalletUserSecretKeySharesPublic(
		ikaClient,
		suiClient,
		activeDWallet,
		preparedSecondRound,
	);

	const presignRequestEvent = await presign(
		ikaClient,
		suiClient,
		activeDWallet,
		SignatureAlgorithm.ECDSA,
	);

	const presignObject = await ikaClient.getPresign(presignRequestEvent.event_data.presign_id);

	const publicDWallet = await ikaClient.getDWallet(dwalletID);

	await signPublicUserShare(
		ikaClient,
		suiClient,
		publicDWallet,
		presignObject,
		Buffer.from('hello world'),
		Hash.KECCAK256,
		SignatureAlgorithm.ECDSA,
	);
}

export { main };
