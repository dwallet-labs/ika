import { Curve, Hash, SignatureAlgorithm } from '../../client';
import { prepareImportDWalletVerification } from '../../client/cryptography';
import {
	acceptEncryptedUserShare,
	createIkaClient,
	createSessionIdentifier,
	createSuiClient,
	generateKeyparForImportedDWallet,
	presign,
	requestImportedDWalletVerification,
	signWithImportedDWallet,
} from '../common';

const suiClient = createSuiClient();
const ikaClient = createIkaClient(suiClient);

async function main() {
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

	const importedKeyDWallet = await ikaClient.getDWallet(
		importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
	);

	await acceptEncryptedUserShare(
		ikaClient,
		suiClient,
		importedKeyDWallet,
		importedKeyDWalletVerificationRequestEvent,
		userShareEncryptionKeys,
	);

	const activeDWallet = await ikaClient.getDWallet(
		importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
	);

	const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		importedKeyDWalletVerificationRequestEvent.event_data.encrypted_user_secret_key_share_id,
	);

	const presignRequestEvent = await presign(
		ikaClient,
		suiClient,
		importedKeyDWallet,
		SignatureAlgorithm.ECDSA,
	);

	const presignObject = await ikaClient.getPresign(presignRequestEvent.event_data.presign_id);

	await signWithImportedDWallet(
		ikaClient,
		suiClient,
		activeDWallet,
		presignObject,
		Buffer.from('hello world'),
		Hash.KECCAK256,
		SignatureAlgorithm.ECDSA,
		encryptedUserSecretKeyShare,
	);
}

export { main };
