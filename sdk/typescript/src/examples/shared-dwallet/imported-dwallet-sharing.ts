import { Curve } from '../../client';
import { prepareImportDWalletVerification } from '../../client/cryptography';
import {
	acceptEncryptedUserShare,
	createIkaClient,
	createSessionIdentifier,
	createSuiClient,
	generateKeyparForImportedDWallet,
	makeImportedDWalletUserSecretKeySharesPublic,
	requestImportedDWalletVerification,
} from '../common';

const suiClient = createSuiClient();
const ikaClient = createIkaClient(suiClient);

async function main() {
	await ikaClient.initialize();

	const { userShareEncryptionKeys, signerPublicKey, dWalletKeypair, signerAddress } =
		generateKeyparForImportedDWallet();

	const sessionIdentifier = await createSessionIdentifier(ikaClient, suiClient, signerAddress);

	const preparedImportDWalletVerification = await prepareImportDWalletVerification(
		ikaClient,
		sessionIdentifier,
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
