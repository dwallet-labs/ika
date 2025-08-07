import { Curve, Hash, SignatureAlgorithm } from '../../client';
import { prepareImportDWalletVerification } from '../../client/cryptography';
import {
	acceptEncryptedUserShare,
	createIkaClient,
	createSessionIdentifier,
	createSuiClient,
	generateKeyparForImportedDWallet,
	makeImportedDWalletUserSecretKeySharesPublic,
	presign,
	requestImportedDWalletVerification,
	signWithImportedDWalletPublic,
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

	await signWithImportedDWalletPublic(
		ikaClient,
		suiClient,
		activeDWallet,
		presignObject,
		Buffer.from('hello world'),
		Hash.KECCAK256,
		SignatureAlgorithm.ECDSA,
	);
}

export { main };
