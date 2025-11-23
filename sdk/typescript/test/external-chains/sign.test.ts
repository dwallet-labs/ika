// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
import { bitcoin_address_from_dwallet_output } from '@ika.xyz/ika-wasm';
import { public_key_from_dwallet_output } from '@ika.xyz/mpc-wasm';
import { Transaction } from '@mysten/sui/transactions';
import * as bitcoin from 'z';
import { networks, payments, Psbt } from 'bitcoinjs-lib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { Curve, Hash, SignatureAlgorithm } from '../../src/client/types';
import {
	createCompleteDWallet,
	createCompleteDWalletV2,
	testPresign,
} from '../helpers/dwallet-test-helpers';
import { createIndividualTestSetup, getSharedTestSetup } from '../helpers/shared-test-setup';
import {
	createEmptyTestIkaToken,
	createTestIkaTransaction,
	createTestMessage,
	destroyEmptyTestIkaToken,
	executeTestTransaction,
	retryUntil,
} from '../helpers/test-utils';
import { curve } from '../../src/generated/ika_dwallet_2pc_mpc/coordinator_inner';
import { setupDKGFlow } from '../v2/all-combinations.test';

// Setup shared resources before all tests
beforeAll(async () => {
	await getSharedTestSetup();
}, 60000); // 1 minute timeout for setup

// Cleanup shared resources after all tests
afterAll(async () => {
	const sharedSetup = await getSharedTestSetup();
	sharedSetup.cleanup();

	// Force garbage collection if available
	if (global.gc) {
		global.gc();
	}
});

/**
 * Enhanced test sign function that returns transaction results for validation
 */
async function testSignWithResult(
	ikaClient: any,
	suiClient: any,
	dWallet: any,
	userShareEncryptionKeys: any,
	presign: any,
	encryptedUserSecretKeyShare: any,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	testName: string,
) {
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const messageApproval = ikaTransaction.approveMessage({
		dWalletCap: dWallet.dwallet_cap_id,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestSign({
		dWallet,
		messageApproval,
		verifiedPresignCap,
		hashScheme,
		presign,
		encryptedUserSecretKeyShare,
		message,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);

	return result;
}

async function getUTXO(
	address: string,
): Promise<{ utxo: any; txid: string; vout: number; satoshis: number }> {
	const utxoUrl = `https://blockstream.info/testnet/api/address/${address}/utxo`;
	const { data: utxos } = await axios.get(utxoUrl);

	if (utxos.length === 0) {
		throw new Error('No UTXOs found for this address');
	}

	// Taking the first unspent transaction.
	// You can change and return them all and to choose or to use more than one input.
	const utxo = utxos[0];
	const txid = utxo.txid;
	const vout = utxo.vout;
	const satoshis = utxo.value;

	return { utxo: utxo, txid: txid, vout: vout, satoshis: satoshis };
}

function toBase64<T>(data: T): string {
	if (data instanceof Uint8Array || data instanceof ArrayBuffer) {
		return Buffer.from(data as Uint8Array).toString("base64");
	}
	return Buffer.from(JSON.stringify(data)).toString("base64");
}

function fromBase64<T>(encoded: string): T {
	const json = Buffer.from(encoded, "base64").toString("utf8");
	return JSON.parse(json) as T;
}

describe('DWallet Signing', () => {
	it('should create a DWallet and print its address', async () => {
		const testName = 'dwallet-sign-test';

		const {
			ikaClient,
			activeDWallet,
			encryptedUserSecretKeyShareId,
			userShareEncryptionKeys,
			signerAddress,
		} = await setupDKGFlow(testName, Curve.SECP256K1);
		console.log('DWallet created successfully.');
		const dwalletBitcoinAddress = bitcoin_address_from_dwallet_output(
			Uint8Array.from(activeDWallet.state.Active.public_output),
		);
		console.log("DWallet's Bitcoin address:", dwalletBitcoinAddress);

		// log all the dwallet components as base 64
		console.log(
			'DWallet Components:',
			{
				activeDWallet: toBase64(activeDWallet),
				encryptedUserSecretKeyShare: toBase64(encryptedUserSecretKeyShareId),
				userShareEncryptionKeys: toBase64(userShareEncryptionKeys),
				signerAddress: toBase64(signerAddress),
			}
		)

		return;
	});

	it('should create a DWallet and sign a message', async () => {
		const testName = 'dwallet-sign-test';

		// Use shared clients but create individual DWallet to avoid gas conflicts
		const { suiClient, ikaClient } = await createIndividualTestSetup(testName);
		const {
			dWallet: activeDWallet,
			encryptedUserSecretKeyShare,
			userShareEncryptionKeys,
			signerAddress,
		} = await createCompleteDWallet(ikaClient, suiClient, testName);

		expect(activeDWallet).toBeDefined();
		expect(activeDWallet.state.$kind).toBe('Active');
		expect(activeDWallet.id.id).toMatch(/^0x[a-f0-9]+$/);

		// Create presign
		const presignRequestEvent = await testPresign(
			ikaClient,
			suiClient,
			activeDWallet,
			SignatureAlgorithm.ECDSA,
			signerAddress,
			testName,
		);

		expect(presignRequestEvent).toBeDefined();
		expect(presignRequestEvent.event_data.presign_id).toBeDefined();

		// Wait for presign to complete
		const presignObject = await retryUntil(
			() =>
				ikaClient.getPresignInParticularState(
					presignRequestEvent.event_data.presign_id,
					'Completed',
				),
			(presign) => presign !== null,
			30,
			2000,
		);

		expect(presignObject).toBeDefined();
		expect((presignObject as any).state.$kind).toBe('Completed');

		const network = networks.testnet;
		const psbt = new Psbt({ network });
		psbt.addInput({
			hash: 'prev_txid_hex',
			index: 0,
			witnessUtxo: {
				script: payments.p2wpkh({ address: 'bc1qYourFromAddr...' }).output!,
				value: 120_000, // sats
			},
		});

		// Sign a message and validate result
		const message = createTestMessage(testName);
		const signingResult = await testSignWithResult(
			ikaClient,
			suiClient,
			activeDWallet,
			userShareEncryptionKeys,
			presignObject,
			encryptedUserSecretKeyShare,
			message,
			Hash.KECCAK256,
			SignatureAlgorithm.ECDSA,
			testName,
		);

		// Validate transaction succeeded
		expect(signingResult).toBeDefined();
		expect(signingResult.digest).toBeDefined();
		expect(signingResult.digest).toMatch(/^[a-zA-Z0-9]+$/); // Base58-like transaction digest
		expect(signingResult.digest.length).toBeGreaterThan(20); // Transaction digest should be substantial
		expect(signingResult.digest.length).toBeLessThan(100); // But not unreasonably long

		// Validate transaction execution metadata
		expect(signingResult.confirmedLocalExecution).toBe(false);

		// Validate events were emitted - signing should generate multiple events
		expect(signingResult.events).toBeDefined();
		expect(signingResult.events!.length).toBeGreaterThan(0);

		// Check for specific signing-related events
		const hasSigningEvents = signingResult.events!.some(
			(event) =>
				event.type.includes('Sign') ||
				event.type.includes('Message') ||
				event.type.includes('Signature'),
		);
		expect(hasSigningEvents).toBe(true);

		// Validate BCS data is present (indicates proper encoding)
		const hasBcsData = signingResult.events!.some((event) => event.bcs && event.bcs.length > 0);
		expect(hasBcsData).toBe(true);

		// Verify DWallet is still active after signing
		const dWalletAfterSigning = await ikaClient.getDWalletInParticularState(
			activeDWallet.id.id,
			'Active',
		);
		expect(dWalletAfterSigning).toBeDefined();
		expect(dWalletAfterSigning.state.$kind).toBe('Active');
	});
});
