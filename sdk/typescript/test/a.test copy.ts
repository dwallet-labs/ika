import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';

import {
	createRandomSessionIdentifier,
	Curve,
	getNetworkConfig,
	Hash,
	IkaClient,
	IkaTransaction,
	prepareDKGAsync,
	SignatureAlgorithm,
	UserShareEncryptionKeys,
	ZeroTrustDWallet,
} from '../src/client/index.js';

const suiClient = new SuiClient({
	url: getFullnodeUrl('testnet'),
});

const ikaClient = new IkaClient({
	suiClient,
	config: getNetworkConfig('testnet'),
});

await ikaClient.initialize();

const curve = Curve.SECP256R1; // or Curve.SECP256K1, Curve.ED25519, Curve.RISTRETTO
const presign = await ikaClient.getPresignInParticularState(
	'global presign id that you requested before hand',
	'Completed',
);
const dWallet = await ikaClient.getDWalletInParticularState(
	'dWallet id that you requested before hand',
	'Active',
);

const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
	'encrypted user secret key share id',
);

const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
	new TextEncoder().encode('test seed'),
	curve,
);

const transaction = new Transaction();
const ikaTransaction = new IkaTransaction({
	ikaClient,
	transaction,
	userShareEncryptionKeys,
});

const signId = await ikaTransaction.futureSign({
	suiCoin,
	ikaCoin,
	messageApproval,
	partialUserSignatureCap,
});

const message = new TextEncoder().encode('test message');

const messageApproval = ikaTransaction.approveMessage({
	message,
	curve,
	dWalletCap: dWallet.dwallet_cap_id,
	signatureAlgorithm: SignatureAlgorithm.ECDSASecp256r1,
	hashScheme: Hash.SHA256,
});

const optionSignId = await ikaTransaction.requestSign({
	dWallet: dWallet as ZeroTrustDWallet,
	hashScheme: Hash.SHA256,
	verifiedPresignCap: ikaTransaction.verifyPresignCap({
		presign,
	}),
	presign,
	encryptedUserSecretKeyShare: encryptedUserSecretKeyShare,
	message,
	signatureScheme: SignatureAlgorithm.ECDSASecp256r1,
	ikaCoin,
	suiCoin,
	messageApproval,
	publicOutput, // <-- You can also use this optional parameter to pass the public output of the dWallet, but check it before using it, if you use it, you wouldn't need to fetch the dWallet
	secretShare, // <-- You can also use this optional parameter to pass the secret share of the dWallet, but check it before using it, if you use it, you wouldn't need to fetch the dWallet
});

await executeTransaction(suiClient, transaction);

// You can later on fetch the signature from the sign id you got from events, returns or how you want to get it
const signature = await ikaClient.getSignInParticularState(
	'the sign id you got from event',
	curve,
	SignatureAlgorithm.ECDSASecp256r1,
	'Completed',
);

const rawSignature = Uint8Array.from(signature.state.Completed.signature);
