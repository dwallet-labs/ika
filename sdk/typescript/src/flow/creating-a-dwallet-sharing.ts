import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';

import {
	createClassGroupsKeypair,
	createDKGCentralizedOutput,
	encryptSecretShare,
} from '../client/cryptography';
import {
	acceptEncryptedUserShare,
	createIkaClient,
	createSuiClient,
	makeDWalletUserSecretKeySharesPublic,
	registerEncryptionKey,
	requestDKGFirstRound,
	requestDkgSecondRound,
} from './common';

const suiClient = createSuiClient();
const ikaClient = createIkaClient(suiClient);

async function main() {
	const decryptionKeyID = await ikaClient.getDecryptionKeyID();
	const seed = new Uint8Array(32).fill(8);
	const keypair = Ed25519Keypair.deriveKeypairFromSeed('0x1');
	const encryptedSecretShareSigningKeypair = Ed25519Keypair.deriveKeypairFromSeed(
		Buffer.from(seed).toString('hex'),
	);
	const encryptionKeyAddress = keypair.getPublicKey().toSuiBytes();

	const classGroupsKeypair = createClassGroupsKeypair(seed);
	const encryptionKeySignature = await encryptedSecretShareSigningKeypair.sign(
		new Uint8Array(classGroupsKeypair.encryptionKey),
	);

	const { dwalletID, sessionIdentifierPreimage } = await requestDKGFirstRound(
		ikaClient,
		suiClient,
		decryptionKeyID,
	);

	await registerEncryptionKey(
		ikaClient,
		suiClient,
		encryptionKeyAddress,
		classGroupsKeypair.encryptionKey,
		encryptionKeySignature,
	);

	const dWallet = await ikaClient.getDWallet(dwalletID);

	const firstRoundOutput = new Uint8Array(
		dWallet.state.AwaitingUserDKGVerificationInitiation?.first_round_output as number[],
	);

	const dWalletCapId = dWallet.dwallet_cap_id;

	const networkDecryptionKeyPublicOutput = await ikaClient.getNetworkPublicParameters();

	const { centralizedPublicKeyShareAndProof, centralizedPublicOutput, centralizedSecretKeyShare } =
		createDKGCentralizedOutput(
			networkDecryptionKeyPublicOutput,
			firstRoundOutput,
			sessionIdentifierPreimage,
		);

	const encryptedUserShareAndProof = encryptSecretShare(
		centralizedSecretKeyShare,
		classGroupsKeypair.encryptionKey,
		networkDecryptionKeyPublicOutput,
	);

	const secondRoundMoveResponse = await requestDkgSecondRound(ikaClient, suiClient, {
		dWalletCapId,
		centralizedPublicKeyShareAndProof,
		centralizedPublicOutput,
		encryptedUserShareAndProof,
		encryptionKeyAddress: keypair.getPublicKey().toSuiAddress(),
		signerPublicKey: keypair.getPublicKey().toRawBytes(),
		userPublicOutput: centralizedPublicOutput,
	});

	const activeDWallet = await ikaClient.getDWallet(dwalletID);

	const publicOutput = new Uint8Array(activeDWallet.state.Active?.public_output as number[]);

	if (!publicOutput) {
		throw new Error('Encrypted user secret key share ID not found');
	}

	await acceptEncryptedUserShare(ikaClient, suiClient, {
		dwalletId: dwalletID,
		encryptedUserSecretKeyShareId:
			secondRoundMoveResponse.event_data.encrypted_user_secret_key_share_id,
		userOutputSignature: await encryptedSecretShareSigningKeypair.sign(publicOutput),
	});

	await makeDWalletUserSecretKeySharesPublic(ikaClient, suiClient, {
		dwalletId: dwalletID,
		secretShare: centralizedSecretKeyShare,
	});
}

export { main };
