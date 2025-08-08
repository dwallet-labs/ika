import { Hash, SignatureAlgorithm } from '../../src/client';
import { prepareDKGSecondRoundAsync } from '../../src/client/cryptography';
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
} from '../common';

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
			await ikaClient.getNetworkPublicParameters(),
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

	const publicDWallet = await ikaClient.getDWalletInParticularState(dwalletID, 'Active');

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
