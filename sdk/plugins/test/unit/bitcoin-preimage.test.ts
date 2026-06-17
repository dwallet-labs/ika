// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Validates the Bitcoin sighash preimage builders against bitcoinjs-lib's
// reference digest functions. If `hash(preimage)` matches the reference
// digest for every mode, the MPC will sign the right thing.

import { sha256 } from '@noble/hashes/sha2.js';
import * as bitcoin from 'bitcoinjs-lib';
import { describe, expect, it } from 'vitest';

import {
	buildBip143Preimage,
	p2wpkhScriptCode,
} from '../../src/bitcoin/destination/preimage/bip143.js';
import {
	buildBip341Preimage,
	computeTapLeafHash,
} from '../../src/bitcoin/destination/preimage/bip341.js';
import { buildLegacyPreimage, p2pkhScript } from '../../src/bitcoin/destination/preimage/legacy.js';

function dsha256(b: Uint8Array): Uint8Array {
	return new Uint8Array(sha256(sha256(b)));
}

function toHex(b: Uint8Array): string {
	return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function makeTx(opts: {
	inputs: Array<{ hash: Uint8Array; index: number; sequence?: number }>;
	outputs: Array<{ script: Uint8Array; value: bigint }>;
	version?: number;
	locktime?: number;
}): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = opts.version ?? 2;
	tx.locktime = opts.locktime ?? 0;
	for (const i of opts.inputs) {
		tx.addInput(i.hash, i.index, i.sequence);
	}
	for (const o of opts.outputs) {
		tx.addOutput(o.script, o.value);
	}
	return tx;
}

const TXID_A = new Uint8Array(32).fill(0xaa);
const TXID_B = new Uint8Array(32).fill(0xbb);
const PKH = new Uint8Array(20).fill(0x11);
const RECIPIENT_SCRIPT = (() => {
	const out = new Uint8Array(25);
	out[0] = 0x76;
	out[1] = 0xa9;
	out[2] = 0x14;
	out.set(new Uint8Array(20).fill(0x22), 3);
	out[23] = 0x88;
	out[24] = 0xac;
	return out;
})();

describe('legacy P2PKH sighash preimage', () => {
	it('hash256(preimage) matches bitcoinjs-lib hashForSignature (SIGHASH_ALL, single input)', () => {
		const tx = makeTx({
			inputs: [{ hash: TXID_A, index: 0 }],
			outputs: [{ script: RECIPIENT_SCRIPT, value: 100_000n }],
		});
		const script = p2pkhScript(PKH);
		const ref = tx.hashForSignature(0, script, bitcoin.Transaction.SIGHASH_ALL);
		const out = buildLegacyPreimage({
			tx,
			inputIndex: 0,
			prevOutScript: script,
			hashType: bitcoin.Transaction.SIGHASH_ALL,
		});
		expect(out.preimage).toBeTruthy();
		expect(toHex(dsha256(out.preimage!))).toBe(toHex(ref));
	});

	it('matches reference for two-input tx (SIGHASH_ALL)', () => {
		const tx = makeTx({
			inputs: [
				{ hash: TXID_A, index: 0 },
				{ hash: TXID_B, index: 1 },
			],
			outputs: [{ script: RECIPIENT_SCRIPT, value: 50_000n }],
		});
		const script = p2pkhScript(PKH);
		for (const idx of [0, 1] as const) {
			const ref = tx.hashForSignature(idx, script, bitcoin.Transaction.SIGHASH_ALL);
			const out = buildLegacyPreimage({
				tx,
				inputIndex: idx,
				prevOutScript: script,
				hashType: bitcoin.Transaction.SIGHASH_ALL,
			});
			expect(out.preimage).toBeTruthy();
			expect(toHex(dsha256(out.preimage!))).toBe(toHex(ref));
		}
	});

	it('matches reference for SIGHASH_ANYONECANPAY', () => {
		const tx = makeTx({
			inputs: [
				{ hash: TXID_A, index: 0 },
				{ hash: TXID_B, index: 1 },
			],
			outputs: [{ script: RECIPIENT_SCRIPT, value: 50_000n }],
		});
		const script = p2pkhScript(PKH);
		const hashType = bitcoin.Transaction.SIGHASH_ALL | bitcoin.Transaction.SIGHASH_ANYONECANPAY;
		const ref = tx.hashForSignature(0, script, hashType);
		const out = buildLegacyPreimage({ tx, inputIndex: 0, prevOutScript: script, hashType });
		expect(out.preimage).toBeTruthy();
		expect(toHex(dsha256(out.preimage!))).toBe(toHex(ref));
	});
});

describe('BIP-143 P2WPKH sighash preimage', () => {
	it('hash256(preimage) matches hashForWitnessV0 (single input, SIGHASH_ALL)', () => {
		const tx = makeTx({
			inputs: [{ hash: TXID_A, index: 0 }],
			outputs: [{ script: RECIPIENT_SCRIPT, value: 100_000n }],
		});
		const scriptCode = p2wpkhScriptCode(PKH);
		const value = 200_000n;
		const ref = tx.hashForWitnessV0(0, scriptCode, value, bitcoin.Transaction.SIGHASH_ALL);
		const preimage = buildBip143Preimage({
			tx,
			inputIndex: 0,
			scriptCode,
			value,
			hashType: bitcoin.Transaction.SIGHASH_ALL,
		});
		expect(toHex(dsha256(preimage))).toBe(toHex(ref));
	});

	it('matches reference for two-input tx (SIGHASH_ALL)', () => {
		const tx = makeTx({
			inputs: [
				{ hash: TXID_A, index: 0 },
				{ hash: TXID_B, index: 1 },
			],
			outputs: [
				{ script: RECIPIENT_SCRIPT, value: 50_000n },
				{ script: RECIPIENT_SCRIPT, value: 25_000n },
			],
		});
		const scriptCode = p2wpkhScriptCode(PKH);
		for (const idx of [0, 1] as const) {
			const value = 200_000n + BigInt(idx);
			const ref = tx.hashForWitnessV0(idx, scriptCode, value, bitcoin.Transaction.SIGHASH_ALL);
			const preimage = buildBip143Preimage({
				tx,
				inputIndex: idx,
				scriptCode,
				value,
				hashType: bitcoin.Transaction.SIGHASH_ALL,
			});
			expect(toHex(dsha256(preimage))).toBe(toHex(ref));
		}
	});

	it('matches reference for SIGHASH_ANYONECANPAY', () => {
		const tx = makeTx({
			inputs: [
				{ hash: TXID_A, index: 0 },
				{ hash: TXID_B, index: 1 },
			],
			outputs: [{ script: RECIPIENT_SCRIPT, value: 50_000n }],
		});
		const scriptCode = p2wpkhScriptCode(PKH);
		const value = 200_000n;
		const hashType = bitcoin.Transaction.SIGHASH_ALL | bitcoin.Transaction.SIGHASH_ANYONECANPAY;
		const ref = tx.hashForWitnessV0(0, scriptCode, value, hashType);
		const preimage = buildBip143Preimage({
			tx,
			inputIndex: 0,
			scriptCode,
			value,
			hashType,
		});
		expect(toHex(dsha256(preimage))).toBe(toHex(ref));
	});
});

describe('BIP-341 Taproot sighash preimage', () => {
	it('sha256(preimage) matches hashForWitnessV1 — key path, SIGHASH_DEFAULT', () => {
		const tx = makeTx({
			inputs: [{ hash: TXID_A, index: 0 }],
			outputs: [{ script: RECIPIENT_SCRIPT, value: 100_000n }],
		});
		// 32-byte arbitrary P2TR scriptPubKey: OP_1 OP_PUSHBYTES_32 <xOnly>
		const xOnly = new Uint8Array(32).fill(0x33);
		const spk = new Uint8Array(34);
		spk[0] = 0x51; // OP_1
		spk[1] = 0x20;
		spk.set(xOnly, 2);
		const values = [123_456n];
		const prevOutScripts = [spk];

		const ref = tx.hashForWitnessV1(0, prevOutScripts, values, bitcoin.Transaction.SIGHASH_DEFAULT);
		const preimage = buildBip341Preimage({
			tx,
			inputIndex: 0,
			prevOutScripts,
			values,
			hashType: bitcoin.Transaction.SIGHASH_DEFAULT,
		});
		expect(toHex(new Uint8Array(sha256(preimage)))).toBe(toHex(ref));
	});

	it('sha256(preimage) matches hashForWitnessV1 — script path with leaf hash', () => {
		const tx = makeTx({
			inputs: [{ hash: TXID_A, index: 0 }],
			outputs: [{ script: RECIPIENT_SCRIPT, value: 100_000n }],
		});
		const xOnly = new Uint8Array(32).fill(0x33);
		const spk = new Uint8Array(34);
		spk[0] = 0x51;
		spk[1] = 0x20;
		spk.set(xOnly, 2);
		const values = [123_456n];
		const prevOutScripts = [spk];

		// Tapscript: OP_PUSHBYTES_32 <xOnly> OP_CHECKSIG (BIP-342 v0)
		const script = new Uint8Array(34);
		script[0] = 0x20;
		script.set(xOnly, 1);
		script[33] = 0xac;
		const leafHash = computeTapLeafHash(script);

		const ref = tx.hashForWitnessV1(
			0,
			prevOutScripts,
			values,
			bitcoin.Transaction.SIGHASH_DEFAULT,
			leafHash,
		);
		const preimage = buildBip341Preimage({
			tx,
			inputIndex: 0,
			prevOutScripts,
			values,
			hashType: bitcoin.Transaction.SIGHASH_DEFAULT,
			leafHash,
		});
		expect(toHex(new Uint8Array(sha256(preimage)))).toBe(toHex(ref));
	});

	it('sha256(preimage) matches hashForWitnessV1 — SIGHASH_ANYONECANPAY | SIGHASH_ALL', () => {
		const tx = makeTx({
			inputs: [
				{ hash: TXID_A, index: 0 },
				{ hash: TXID_B, index: 1 },
			],
			outputs: [{ script: RECIPIENT_SCRIPT, value: 100_000n }],
		});
		const xOnly = new Uint8Array(32).fill(0x33);
		const spk = new Uint8Array(34);
		spk[0] = 0x51;
		spk[1] = 0x20;
		spk.set(xOnly, 2);
		const values = [123_456n, 50_000n];
		const prevOutScripts = [spk, spk];
		const hashType = bitcoin.Transaction.SIGHASH_ALL | bitcoin.Transaction.SIGHASH_ANYONECANPAY;
		const ref = tx.hashForWitnessV1(0, prevOutScripts, values, hashType);
		const preimage = buildBip341Preimage({
			tx,
			inputIndex: 0,
			prevOutScripts,
			values,
			hashType,
		});
		expect(toHex(new Uint8Array(sha256(preimage)))).toBe(toHex(ref));
	});
});
