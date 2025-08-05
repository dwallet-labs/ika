import { createClassGroupsKeypair, prepareDKGSecondRoundAsync } from '../client/cryptography';
import { parseNumbersToBytes } from '../client/utils';
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
		seed,
		encryptionKeyPublicKey,
		encryptionKeyAddress,
		signerPublicKey,
	} = generateKeypair();

	const classGroupsKeypair = createClassGroupsKeypair(seed);

	const encryptionKeySignature = await encryptedSecretShareSigningKeypair.sign(
		new Uint8Array(classGroupsKeypair.encryptionKey),
	);

	const { dwalletID, sessionIdentifierPreimage } = await requestDKGFirstRound(ikaClient, suiClient);

	await registerEncryptionKey(
		ikaClient,
		suiClient,
		encryptionKeyPublicKey,
		classGroupsKeypair.encryptionKey,
		encryptionKeySignature,
	);

	const dWallet = await ikaClient.getDWallet(dwalletID);

	const preparedSecondRound = await prepareDKGSecondRoundAsync(
		ikaClient,
		dWallet.state.AwaitingUserDKGVerificationInitiation?.first_round_output,
		sessionIdentifierPreimage,
		classGroupsKeypair.encryptionKey,
		dWallet.dwallet_cap_id,
	);

	const secondRoundMoveResponse = await requestDkgSecondRound(ikaClient, suiClient, {
		preparedSecondRound,
		encryptionKeyAddress,
		signerPublicKey,
	});

	const activeDWallet = await ikaClient.getDWallet(dwalletID);

	await acceptEncryptedUserShare(ikaClient, suiClient, {
		dwalletId: dwalletID,
		encryptedUserSecretKeyShareId:
			secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
		userOutputSignature: await encryptedSecretShareSigningKeypair.sign(
			parseNumbersToBytes(activeDWallet.state.Active?.public_output),
		),
	});
}

export { main };
