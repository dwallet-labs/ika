// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Legacy (pre-BIP-143) sighash preimage construction for P2PKH. Builds a
 * stripped-and-modified copy of the transaction whose serialization plus
 * `nHashType` is what ECDSA signs over (after DoubleSHA256). The MPC
 * computes the hash from the preimage via `Hash.DoubleSHA256`.
 *
 * Spec: https://en.bitcoin.it/wiki/OP_CHECKSIG
 *       https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp
 *
 * For SIGHASH_SINGLE with `inputIndex >= outs.length`, Bitcoin Core returns
 * the constant `0x010000...00` (one followed by 31 zeros) as the digest.
 * That edge case is observable to callers but rare; we surface it as an
 * explicit return value rather than panic.
 */

import * as bitcoin from 'bitcoinjs-lib';

import { BufferWriter } from './writer.js';
import {
	SIGHASH_ANYONECANPAY,
	SIGHASH_NONE,
	SIGHASH_SINGLE,
} from './bip143.js';

const { OPS, decompile, compile } = bitcoin.script;

const ONE_DIGEST = (() => {
	const out = new Uint8Array(32);
	out[0] = 1;
	return out;
})();

export interface LegacyPreimageArgs {
	readonly tx: bitcoin.Transaction;
	readonly inputIndex: number;
	readonly prevOutScript: Uint8Array;
	readonly hashType: number;
}

/**
 * Build the legacy sighash preimage. Returns `{ preimage }` if the standard
 * path applies, or `{ digest: ONE_DIGEST }` for the SIGHASH_SINGLE
 * out-of-range corner case where the spec hardcodes a digest of `1`.
 *
 * Callers MUST handle the `digest` branch — when it fires, the MPC should
 * be fed `digest` directly (with whatever hash maps to identity), or the
 * callsite should refuse to sign the input.
 */
export function buildLegacyPreimage(
	args: LegacyPreimageArgs,
): { readonly preimage: Uint8Array; readonly digest?: undefined }
	| { readonly preimage?: undefined; readonly digest: Uint8Array } {
	const { tx, inputIndex, prevOutScript, hashType } = args;
	if (inputIndex >= tx.ins.length) {
		// Same `ONE` sentinel Bitcoin Core returns; documented Bitcoin quirk.
		return { digest: ONE_DIGEST };
	}

	// Strip OP_CODESEPARATOR from the prev script — matches bitcoinjs-lib
	// and Bitcoin Core's `SignatureHash`.
	const filteredScript = compile(
		decompile(prevOutScript)?.filter((x) => x !== OPS.OP_CODESEPARATOR) ?? [],
	);
	const ourScript = filteredScript;

	// Clone the tx by serializing + re-parsing. cheaper than implementing a
	// manual deep-copy here.
	const txTmp = bitcoin.Transaction.fromBuffer(tx.toBuffer());

	const sigType = hashType & 0x1f;

	if (sigType === SIGHASH_NONE) {
		txTmp.outs = [];
		txTmp.ins.forEach((input, i) => {
			if (i !== inputIndex) input.sequence = 0;
		});
	} else if (sigType === SIGHASH_SINGLE) {
		if (inputIndex >= tx.outs.length) {
			return { digest: ONE_DIGEST };
		}
		txTmp.outs.length = inputIndex + 1;
		// Bitcoin's `BLANK_OUTPUT` sentinel: empty script + value bytes
		// FFFFFFFFFFFFFFFF. Stored here as `-1n` because bitcoinjs-lib
		// serializes `out.value` as int64-LE; `-1n` is the int64 form of
		// the same 8 bytes that Bitcoin Core writes.
		for (let i = 0; i < inputIndex; i++) {
			txTmp.outs[i] = { script: new Uint8Array(0), value: -1n };
		}
		txTmp.ins.forEach((input, i) => {
			if (i !== inputIndex) input.sequence = 0;
		});
	}

	if (hashType & SIGHASH_ANYONECANPAY) {
		txTmp.ins = [txTmp.ins[inputIndex]];
		txTmp.ins[0].script = ourScript;
	} else {
		txTmp.ins.forEach((input) => {
			input.script = new Uint8Array(0);
		});
		txTmp.ins[inputIndex].script = ourScript;
	}

	// Serialize the modified tx (non-witness format) + append the 4-byte
	// hashType. That's the preimage. v7 `toBuffer()` defaults to the
	// non-witness serialization which matches what `hashForSignature`
	// hashes internally.
	const txBytes = txTmp.toBuffer();
	const buf = new Uint8Array(txBytes.length + 4);
	buf.set(txBytes, 0);
	const w = new BufferWriter(buf.subarray(txBytes.length));
	w.writeUInt32LE(hashType);
	return { preimage: buf };
}

/**
 * The standard P2PKH script (matches what's in the UTXO's scriptPubKey):
 *   `OP_DUP OP_HASH160 OP_PUSHBYTES_20 <pkh> OP_EQUALVERIFY OP_CHECKSIG`.
 * Used as the `prevOutScript` for legacy sighashing of a P2PKH input.
 */
export function p2pkhScript(pubkeyHash160: Uint8Array): Uint8Array {
	if (pubkeyHash160.length !== 20) {
		throw new Error(`p2pkhScript requires a 20-byte hash160 (got ${pubkeyHash160.length})`);
	}
	const out = new Uint8Array(25);
	out[0] = 0x76;
	out[1] = 0xa9;
	out[2] = 0x14;
	out.set(pubkeyHash160, 3);
	out[23] = 0x88;
	out[24] = 0xac;
	return out;
}

