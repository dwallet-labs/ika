import { Hash, SignatureAlgorithm } from '../../client';
import { prepareDKGSecondRoundAsync } from '../../client/cryptography';
import {
	acceptEncryptedUserShare,
	createIkaClient,
	createSuiClient,
	generateKeypair,
	presign,
	registerEncryptionKey,
	requestDKGFirstRound,
	requestDkgSecondRound,
	sign,
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

	const presignRequestEvent = await presign(
		ikaClient,
		suiClient,
		activeDWallet,
		SignatureAlgorithm.ECDSA,
	);

	const presignObject = await ikaClient.getPresign(presignRequestEvent.event_data.presign_id);

	const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
	);

	await sign(
		ikaClient,
		suiClient,
		activeDWallet,
		userShareEncryptionKeys,
		presignObject,
		encryptedUserSecretKeyShare,
		Buffer.from('hello world'),
		Hash.KECCAK256,
		SignatureAlgorithm.ECDSA,
	);
}

export { main };
