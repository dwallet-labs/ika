// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { prepareImportDWalletVerification } from '../../src/client/cryptography.js';
import { Curve } from '../../src/client/types.js';
import {
	acceptEncryptedUserShare,
	createIkaClient,
	createSessionIdentifier,
	createSuiClient,
	generateKeypairForImportedDWallet,
	requestImportedDWalletVerification,
} from '../common.js';

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

	const importDWalletVerificationRequestInput = await prepareImportDWalletVerification(
		ikaClient,
		sessionIdentifierPreimage,
		userShareEncryptionKeys,
		dWalletKeypair,
	);

	const importedKeyDWalletVerificationRequestEvent = await requestImportedDWalletVerification(
		ikaClient,
		suiClient,
		importDWalletVerificationRequestInput,
		Curve.SECP256K1,
		signerPublicKey,
		sessionIdentifier,
		signerAddress,
	);

	const importedKeyDWallet = await ikaClient.getDWalletInParticularState(
		importedKeyDWalletVerificationRequestEvent.event_data.dwallet_id,
		'Active',
	);

	await acceptEncryptedUserShare(
		ikaClient,
		suiClient,
		importedKeyDWallet,
		importDWalletVerificationRequestInput.userPublicOutput,
		importedKeyDWalletVerificationRequestEvent,
		userShareEncryptionKeys,
	);
}

export { main };
