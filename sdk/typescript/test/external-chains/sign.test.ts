// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
import { bitcoin_pubkey_from_dwallet_output } from '@ika.xyz/ika-wasm';
import { sha256 } from '@noble/hashes/sha256';
import axios from 'axios';
import * as bitcoin from 'bitcoinjs-lib';
import { Transaction as BtcTransaction, networks } from 'bitcoinjs-lib';
import { BufferWriter, varuint } from 'bitcoinjs-lib/src/bufferutils';
import * as bscript from 'bitcoinjs-lib/src/script';
import ECPairFactory from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import { describe, expect, it } from 'vitest';

import { Curve } from '../../src/client/types';
import { setupDKGFlow } from '../v2/all-combinations.test';

describe('DWallet Signing', () => {
	it('should create a DWallet and print its bitcoin public key', async () => {
		const testName = 'dwallet-sign-test';

		const {
			ikaClient,
			activeDWallet,
			encryptedUserSecretKeyShareId,
			userShareEncryptionKeys,
			signerAddress,
		} = await setupDKGFlow(testName, Curve.SECP256K1);
		const dwalletBitcoinPubkey = bitcoin_pubkey_from_dwallet_output(
			Uint8Array.from(activeDWallet.state.Active.public_output),
		);
		console.log("DWallet's Bitcoin public key:", dwalletBitcoinPubkey);
	});

	it('should generate a bitcoin pubkey and address from a fixed privkey', () => {
		// 32-byte fixed private key (test-only). Choose any constant you like.
		const privKeyHex = 'da889368578dc91e6cb152f1dfb46808ab0f8cde6124b8c4de21975d5342f0c8';
		const privKey = Buffer.from(privKeyHex, 'hex');

		const keyPair = ECPair.fromPrivateKey(privKey, { network: networks.testnet });

		const { address } = bitcoin.payments.p2wpkh({
			pubkey: keyPair.publicKey,
			network: networks.testnet,
		});

		expect(address).toBeDefined();

		console.log('pubkey:', keyPair.publicKey.toString());
		console.log('address:', address);
	});

	it('should create a raw tx to send bitcoin from given address A to given address B, output the raw tx & the TX bytes that needed to be signed', async () => {
		let dwalletBTCPubkey = Uint8Array.from([]);
		const recipientAddress = 'tb1q0snqvzf2wr3290wq5elgmzfq8jektkrgl3ang0';
		const amount = 500;

		const { address } = bitcoin.payments.p2wpkh({
			pubkey: dwalletBTCPubkey,
			network: networks.testnet,
		});

		// Get the UTXO for the sender address.
		const { utxo, txid, vout, satoshis } = await getUTXO(address);

		const psbt = new bitcoin.Psbt({ network: networks.testnet });

		const output = bitcoin.payments.p2wpkh({
			pubkey: dwalletBTCPubkey,
			network: networks.testnet,
		}).output!;

		// Add the input UTXO.
		psbt.addInput({
			hash: txid,
			index: vout,
			witnessUtxo: {
				script: output,
				value: BigInt(satoshis),
			},
		});

		// Add the recipient output.
		psbt.addOutput({
			address: recipientAddress,
			// @ts-ignore
			value: BigInt(amount),
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
				value: BigInt(change),
			});
		}

		console.log('txHex', Buffer.from(psbt.data.getTransaction()).toString('hex'));

		const tx = bitcoin.Transaction.fromBuffer(psbt.data.getTransaction());
		const signingScript = bitcoin.payments.p2pkh({
			hash: output.slice(2),
		}).output!;
		console.log('Signing script:', signingScript.toString());

		const bytesToSign = txBytesToSign(
			tx,
			0,
			signingScript,
			satoshis,
			bitcoin.Transaction.SIGHASH_ALL,
		);
		console.log(
			'Raw transaction hash bytes to sign (hex):',
			Buffer.from(bytesToSign).toString('hex'),
		);
	});

	it('should submit a signed transaction to the bitcoin blockchain', async () => {
		const txHex =
			'0200000001001d1ceeeaf170eb960ac13451d0974a6ab39e8fb905e5c19278be45aeae7be20100000000ffffffff02f4010000000000001600147c2606092a70e2a2bdc0a67e8d89203cb365d868880a020000000000160014ca951aace9377759dea4a8c9b8e6cecd6740a54900000000';
		const dwalletBitcoinPubkey = Uint8Array.from([]);
		const signature = Uint8Array.from([]);

		const tx = bitcoin.Transaction.fromHex(txHex);

		console.log('Signature (hex):', Buffer.from(signature).toString('hex'));
		const broadcastUrl = `https://blockstream.info/testnet/api/tx`;

		const output = bitcoin.payments.p2wpkh({
			pubkey: dwalletBitcoinPubkey,
			network: networks.testnet,
		}).output!;

		// To put the signature in the transaction, we get the calculated witness and set it as the input witness.
		const witness = bitcoin.payments.p2wpkh({
			output: output,
			pubkey: dwalletBitcoinPubkey,
			signature: bscript.signature.encode(signature, bitcoin.Transaction.SIGHASH_ALL),
		}).witness!;

		// Set the witness of the first input (in our case, we only have one).
		tx.setWitness(0, witness);

		try {
			const response = await axios.post(broadcastUrl, tx.toHex());
			console.log('Transaction Broadcast:', response.data);
		} catch (error) {
			console.error('Error broadcasting transaction:', error);
		}
	});
});

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

const ECPair = ECPairFactory(ecc);

function createDeterministicBTCKeypair() {
	const privKeyHex = 'da889368578dc91e6cb152f1dfb46808ab0f8cde6124b8c4de21975d5342f0c8';
	const privKey = Buffer.from(privKeyHex, 'hex');
	const keyPair = ECPair.fromPrivateKey(privKey, { network: networks.testnet });
	return keyPair;
}
