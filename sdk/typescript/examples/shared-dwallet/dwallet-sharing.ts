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

	const { userShareEncryptionKeys, signerPublicKey } = generateKeypair();

	const { dwalletID, sessionIdentifierPreimage } = await requestDKGFirstRound(ikaClient, suiClient);

	await registerEncryptionKey(ikaClient, suiClient, userShareEncryptionKeys);

	const dWallet = await ikaClient.getDWalletInParticularState(
		dwalletID,
		'AwaitingUserDKGVerificationInitiation',
	);

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

	const secretShare = await ikaClient.getEncryptedUserSecretKeyShare(
		secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
	);

	await makeDWalletUserSecretKeySharesPublic(
		ikaClient,
		suiClient,
		activeDWallet,
		await userShareEncryptionKeys.decryptUserShare(
			activeDWallet,
			secretShare,
			await ikaClient.getProtocolPublicParameters(),
		),
	);
}

export { main };
