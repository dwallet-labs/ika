import { Curve } from '../../src/client';
import { prepareImportDWalletVerification } from '../../src/client/cryptography';
import {
	acceptEncryptedUserShare,
	createIkaClient,
	createSessionIdentifier,
	createSuiClient,
	generateKeypairForImportedDWallet,
	makeImportedDWalletUserSecretKeySharesPublic,
	requestImportedDWalletVerification,
} from '../common';

const suiClient = createSuiClient();
const ikaClient = createIkaClient(suiClient);

async function main() {
	await ikaClient.initialize();

	const { userShareEncryptionKeys, signerPublicKey, dWalletKeypair, signerAddress } =
		generateKeypairForImportedDWallet();

	const { sessionIdentifier, sessionIdentifierPreimage } = await createSessionIdentifier(
		ikaClient,
		suiClient,
		signerAddress,
	);

	const preparedImportDWalletVerification = await prepareImportDWalletVerification(
		ikaClient,
		sessionIdentifierPreimage,
		userShareEncryptionKeys,
		dWalletKeypair,
	);

	const importedKeyDWalletVerificationRequestEvent = await requestImportedDWalletVerification(
		ikaClient,
		suiClient,
		preparedImportDWalletVerification,
		Curve.SECP256K1,
		signerPublicKey,
		sessionIdentifier,
		signerAddress,
	);

	const awaitingKeyHolderSignatureDWallet = await ikaClient.getDWalletInParticularState(
		importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
		'AwaitingKeyHolderSignature',
	);

	await acceptEncryptedUserShare(
		ikaClient,
		suiClient,
		awaitingKeyHolderSignatureDWallet,
		importedKeyDWalletVerificationRequestEvent,
		userShareEncryptionKeys,
	);

	const activeDWallet = await ikaClient.getDWalletInParticularState(
		importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
		'Active',
	);

	await makeImportedDWalletUserSecretKeySharesPublic(
		ikaClient,
		suiClient,
		activeDWallet,
		preparedImportDWalletVerification,
	);
}

export { main };
