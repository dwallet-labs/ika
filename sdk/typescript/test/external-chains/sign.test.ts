// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
import { bitcoin_address_from_dwallet_output } from '@ika.xyz/ika-wasm';
import { public_key_from_dwallet_output } from '@ika.xyz/mpc-wasm';
import { toHex } from '@mysten/bcs';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { sha256 } from '@noble/hashes/sha256';
import axios from 'axios';
import { Transaction as BtcTransaction, networks, payments, Psbt } from 'bitcoinjs-lib';
import * as bitcoin from 'bitcoinjs-lib';
import { BufferWriter, varuint } from 'bitcoinjs-lib/src/cjs/bufferutils';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
	CoordinatorInnerModule,
	createRandomSessionIdentifier,
	getNetworkConfig,
	IkaClient,
	IkaTransaction,
	prepareDKGAsync,
	SessionsManagerModule,
	UserShareEncryptionKeys,
} from '../../src';
import { Curve, Hash, SignatureAlgorithm } from '../../src/client/types';
import { curve } from '../../src/generated/ika_dwallet_2pc_mpc/coordinator_inner';
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
	executeTestTransactionWithKeypair,
	generateTestKeypair,
	retryUntil,
} from '../helpers/test-utils';
import { setupDKGFlow } from '../v2/all-combinations.test';

function varSliceSize(someScript: Uint8Array): number {
	const length = someScript.length;

	return varuint.encodingLength(length) + length;
}

function txBytesToSign(
	tx: BtcTransaction,
	inIndex: number,
	prevOutScript: Uint8Array,
	value: number,
	hashType: number,
): Buffer {
	const ZERO: Buffer = Buffer.from(
		'0000000000000000000000000000000000000000000000000000000000000000',
		'hex',
	);

	let tbuffer: Buffer = Buffer.from([]);
	let bufferWriter: BufferWriter;

	let hashOutputs = ZERO;
	let hashPrevious = ZERO;
	let hashSequence = ZERO;

	if (!(hashType & bitcoin.Transaction.SIGHASH_ANYONECANPAY)) {
		tbuffer = Buffer.allocUnsafe(36 * tx.ins.length);
		bufferWriter = new BufferWriter(tbuffer, 0);

		tx.ins.forEach((txIn) => {
			bufferWriter.writeSlice(txIn.hash);
			bufferWriter.writeUInt32(txIn.index);
		});

		hashPrevious = Buffer.from(sha256(sha256(tbuffer)));
	}

	if (
		!(hashType & bitcoin.Transaction.SIGHASH_ANYONECANPAY) &&
		(hashType & 0x1f) !== bitcoin.Transaction.SIGHASH_SINGLE &&
		(hashType & 0x1f) !== bitcoin.Transaction.SIGHASH_NONE
	) {
		tbuffer = Buffer.allocUnsafe(4 * tx.ins.length);
		bufferWriter = new BufferWriter(tbuffer, 0);

		tx.ins.forEach((txIn) => {
			bufferWriter.writeUInt32(txIn.sequence);
		});

		hashSequence = Buffer.from(sha256(sha256(tbuffer)));
	}

	if (
		(hashType & 0x1f) !== bitcoin.Transaction.SIGHASH_SINGLE &&
		(hashType & 0x1f) !== bitcoin.Transaction.SIGHASH_NONE
	) {
		const txOutsSize = tx.outs.reduce((sum, output) => {
			return sum + 8 + varSliceSize(output.script);
		}, 0);

		tbuffer = Buffer.allocUnsafe(txOutsSize);
		bufferWriter = new BufferWriter(tbuffer, 0);

		tx.outs.forEach((out) => {
			bufferWriter.writeUInt64(out.value);
			bufferWriter.writeVarSlice(out.script);
		});

		hashOutputs = Buffer.from(sha256(sha256(tbuffer)));
	} else if ((hashType & 0x1f) === bitcoin.Transaction.SIGHASH_SINGLE && inIndex < tx.outs.length) {
		const output = tx.outs[inIndex];

		tbuffer = Buffer.allocUnsafe(8 + varSliceSize(output.script));
		bufferWriter = new BufferWriter(tbuffer, 0);
		bufferWriter.writeUInt64(output.value);
		bufferWriter.writeVarSlice(output.script);

		hashOutputs = Buffer.from(sha256(sha256(tbuffer)));
	}

	tbuffer = Buffer.allocUnsafe(156 + varSliceSize(prevOutScript));
	bufferWriter = new BufferWriter(tbuffer, 0);

	const input = tx.ins[inIndex];
	bufferWriter.writeInt32(tx.version);
	bufferWriter.writeSlice(hashPrevious);
	bufferWriter.writeSlice(hashSequence);
	bufferWriter.writeSlice(input.hash);
	bufferWriter.writeUInt32(input.index);
	bufferWriter.writeVarSlice(prevOutScript);
	bufferWriter.writeUInt64(value);
	bufferWriter.writeUInt32(input.sequence);
	bufferWriter.writeSlice(hashOutputs);
	bufferWriter.writeUInt32(tx.locktime);
	bufferWriter.writeUInt32(hashType);

	return tbuffer;
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
		return Buffer.from(data as Uint8Array).toString('base64');
	}
	return Buffer.from(JSON.stringify(data)).toString('base64');
}

function fromBase64<T>(encoded: string): T {
	const json = Buffer.from(encoded, 'base64').toString('utf8');
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
		console.log('DWallet Components:', {
			activeDWallet: toBase64(activeDWallet),
			encryptedUserSecretKeyShare: toBase64(encryptedUserSecretKeyShareId),
			userShareEncryptionKeys: toBase64(userShareEncryptionKeys),
			signerAddress: toBase64(signerAddress),
		});

		return;
	});

	it('should create a raw tx to send bitcoin from given address A to given address B, output the raw tx', async () => {
		const address = 'tb1pjlwh6hymv4ljfstu84nv27aq6f3dfpkev4qjyqrqq8xqv49exneq7d82z0';
		const recipientAddress = 'tb1q0snqvzf2wr3290wq5elgmzfq8jektkrgl3ang0';

		// Put any number you want to send in Satoshi.
		const amount = 500;

		// Get the UTXO for the sender address.
		const { utxo, txid, vout, satoshis } = await getUTXO(address);

		const psbt = new bitcoin.Psbt({ network: networks.testnet });

		let output;

		// Add the input UTXO.
		psbt.addInput({
			hash: txid,
			index: vout,
			witnessUtxo: {
				script: output,
				// @ts-ignore
				value: satoshis,
			},
		});

		// Add the recipient output.
		psbt.addOutput({
			address: recipientAddress,
			// @ts-ignore
			value: amount,
		});

		// Calculate change and add change output if necessary,
		// 150 Satoshi is a simple fee. Choose the value you want to spend.
		const fee = 150;
		const change = satoshis - amount - fee;

		// Sending the rest to the back to the sender.
		if (change > 0) {
			psbt.addOutput({
				address,
				// @ts-ignore
				value: change,
			});
		}

		const tx = bitcoin.Transaction.fromBuffer(psbt.data.getTransaction());
		const signingScript = bitcoin.payments.p2pkh({
			hash: output.slice(2),
		}).output!
		console.log('Signing script:', signingScript.toString())

		const bytesToSign = txBytesToSign(
			tx,
			0,
			signingScript,
			satoshis,
			bitcoin.Transaction.SIGHASH_ALL,
		);
		console.log('Raw transaction bytes to sign (hex):', bytesToSign.toString('hex'));
	});

	it('should create a testnet dWallet and print its address', async () => {
		const client = new SuiClient({ url: getFullnodeUrl('devnet') }); // mainnet / testnet

		const ikaClient = new IkaClient({
			suiClient: client,
			config: getNetworkConfig('testnet'), // mainnet / testnet
		});

		await ikaClient.initialize();

		const curve = Curve.SECP256R1; // or Curve.SECP256K1, Curve.ED25519, Curve.RISTRETTO

		// Note: You still need UserShareEncryptionKeys for the DKG protocol itself,
		// but not for the encrypted user share storage
		let seed = new TextEncoder().encode('seed');
		const userKeypair = Ed25519Keypair.deriveKeypairFromSeed(toHex(seed));
		const signerAddress = userKeypair.toSuiAddress();

		const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(seed, curve);

		const transaction = new Transaction();
		const ikaTransaction = new IkaTransaction({
			ikaClient,
			transaction,
			userShareEncryptionKeys, // <-- Needed for DKG protocol, not for storage
		});

		const identifier = createRandomSessionIdentifier();

		// Prepare DKG - this generates the necessary cryptographic materials
		const dkgRequestInput = await prepareDKGAsync(
			ikaClient,
			curve,
			userShareEncryptionKeys,
			identifier,
			signerAddress,
		);

		const dWalletEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

		const ikaCoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

		// Create a shared dWallet using requestDWalletDKGWithPublicUserShare
		// The key difference: we pass publicUserSecretKeyShare instead of encrypted share
		const [dWalletCap] = await ikaTransaction.requestDWalletDKGWithPublicUserShare({
			publicKeyShareAndProof: dkgRequestInput.userDKGMessage,
			publicUserSecretKeyShare: dkgRequestInput.userSecretKeyShare, // <-- Public, not encrypted
			userPublicOutput: dkgRequestInput.userPublicOutput,
			curve,
			dwalletNetworkEncryptionKeyId: dWalletEncryptionKey.id,
			ikaCoin,
			suiCoin: transaction.gas,
			sessionIdentifier: ikaTransaction.registerSessionIdentifier(identifier),
		});

		transaction.transferObjects([dWalletCap], signerAddress);

		const result = await executeTestTransactionWithKeypair(client, transaction, userKeypair);

		const dkgEvent = result.events?.find((event) => {
			return (
				event.type.includes('DWalletDKGRequestEvent') && event.type.includes('DWalletSessionEvent')
			);
		});

		const parsedDkgEvent = SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.DWalletDKGRequestEvent,
		).fromBase64(dkgEvent?.bcs as string);

		const dWalletID = parsedDkgEvent.event_data.dwallet_id;

		// Wait for the dWallet to become active (no user confirmation needed)
		const activeDWallet = await ikaClient.getDWalletInParticularState(dWalletID, 'Active', {
			timeout: 30000,
			interval: 1000,
		});

		// Verify it's a shared dWallet
		expect(activeDWallet.public_user_secret_key_share).toBeDefined();
	});
});
