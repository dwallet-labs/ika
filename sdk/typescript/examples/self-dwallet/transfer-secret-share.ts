import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';

import { prepareDKGSecondRoundAsync } from '../../src/client/cryptography.js';
import {
	acceptEncryptedUserShare,
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

	// AFTER TRANSFER, DESTINATION NEEDS TO ACCEPT ENCRYPTED USER SECRET KEY SHARE.
}

export { main };
