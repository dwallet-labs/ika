// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Transaction } from '@mysten/sui/transactions';
import { beforeAll, describe, expect, it } from 'vitest';

import { prepareDKGSecondRoundAsync } from '../../src/client/cryptography';
import { Curve, SignatureAlgorithm } from '../../src/client/types';
import {
	acceptTestEncryptedUserShare,
	createCompleteDWallet,
	registerTestEncryptionKey,
	requestTestDKGFirstRound,
	requestTestDkgSecondRound,
} from '../helpers/dwallet-test-helpers';
import { createIndividualTestSetup, getSharedTestSetup } from '../helpers/shared-test-setup';
import {
	createEmptyTestIkaToken,
	createTestIkaTransaction,
	delay,
	destroyEmptyTestIkaToken,
	executeTestTransaction,
	generateTestKeypair,
	requestTestFaucetFunds,
	retryUntil,
} from '../helpers/test-utils';

// Setup shared resources before all tests
beforeAll(async () => {
	await getSharedTestSetup();
}, 60000);

describe('IkaTransaction Non-Transfer Methods', () => {
	it('should use requestDWalletDKGFirstRound without transferring capability', async () => {
		const testName = 'non-transfer-dkg-first-round-test';
		const { suiClient, ikaClient } = await createIndividualTestSetup(testName);

		const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName);
		await requestTestFaucetFunds(signerAddress);

		// Get the latest network encryption key for manual specification
		const networkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

		const tx = new Transaction();
		const ikaTransaction = createTestIkaTransaction(ikaClient, tx);

		const emptyIKACoin = createEmptyTestIkaToken(tx, ikaClient.ikaConfig);

		// Use the non-transfer version - should return dwalletCap instead of transferring it
		const dwalletCap = ikaTransaction.requestDWalletDKGFirstRound({
			curve: Curve.SECP256K1,
			networkEncryptionKeyID: networkEncryptionKey.id,
			ikaCoin: emptyIKACoin,
			suiCoin: tx.gas,
		});

		// Transfer the dwalletCap to the signer address to avoid UnusedValueWithoutDrop error
		tx.transferObjects([dwalletCap], signerAddress);

		destroyEmptyTestIkaToken(tx, ikaClient.ikaConfig, emptyIKACoin);

		// The dwalletCap should be defined (not transferred automatically)
		expect(dwalletCap).toBeDefined();

		const result = await executeTestTransaction(suiClient, tx, testName);

		// Should have DKG first round event
		const dkgEvent = result.events?.find((event) =>
			event.type.includes('DWalletDKGFirstRoundRequestEvent'),
		);
		expect(dkgEvent).toBeDefined();
	});

	it('should use requestPresign without transferring capability', async () => {
		const testName = 'non-transfer-presign-test';
		const { suiClient, ikaClient } = await createIndividualTestSetup(testName);

		// Create a complete dWallet using the helper function
		const { dWallet: activeDWallet } = await createCompleteDWallet(ikaClient, suiClient, testName);

		// Now test requestPresign without transfer
		const tx = new Transaction();
		const ikaTransaction = createTestIkaTransaction(ikaClient, tx);

		const emptyIKACoin = createEmptyTestIkaToken(tx, ikaClient.ikaConfig);

		// Use the non-transfer version - should return unverifiedPresignCap instead of transferring it
		const unverifiedPresignCap = ikaTransaction.requestPresign({
			dWallet: activeDWallet,
			signatureAlgorithm: SignatureAlgorithm.ECDSA,
			ikaCoin: emptyIKACoin,
			suiCoin: tx.gas,
		});

		// Get the signer address from the dWallet creation
		const { signerAddress } = await generateTestKeypair(testName);

		// Transfer the unverifiedPresignCap to the signer address to avoid UnusedValueWithoutDrop error
		tx.transferObjects([unverifiedPresignCap], signerAddress);

		destroyEmptyTestIkaToken(tx, ikaClient.ikaConfig, emptyIKACoin);

		// The unverifiedPresignCap should be defined (not transferred automatically)
		expect(unverifiedPresignCap).toBeDefined();

		const result = await executeTestTransaction(suiClient, tx, testName);

		// Should have presign request event
		const presignEvent = result.events?.find((event) => event.type.includes('PresignRequestEvent'));
		expect(presignEvent).toBeDefined();
	});
});
