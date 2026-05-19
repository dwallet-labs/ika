// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * BIP-143 sighash preimage construction (SegWit v0). The MPC signs
 * `dsha256(preimage)` via `(Hash.DoubleSHA256, message: preimage)`. We
 * build the preimage here so the chain hash stays under the MPC's
 * control — this avoids exposing the raw digest on the wire.
 *
 * Spec: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
 *
 * Layout:
 *   nVersion (4)            LE
 *   hashPrevouts (32)
 *   hashSequence (32)
 *   outpoint (36)           input.hash || input.index
 *   scriptCode (varSlice)   script being executed
 *   value (8)               LE
 *   nSequence (4)           LE
 *   hashOutputs (32)
 *   nLocktime (4)           LE
 *   nHashType (4)           LE
 */

import { sha256 } from '@noble/hashes/sha2.js';
import * as bitcoin from 'bitcoinjs-lib';

import { BufferWriter, varSliceSize } from './writer.js';

const ZERO32: Uint8Array = new Uint8Array(32);

function dsha256(bytes: Uint8Array): Uint8Array {
	return new Uint8Array(sha256(sha256(bytes)));
}

/** Constants from bitcoinjs-lib's `Transaction.SIGHASH_*` mirrored here. */
export const SIGHASH_ALL = 0x01;
export const SIGHASH_NONE = 0x02;
export const SIGHASH_SINGLE = 0x03;
export const SIGHASH_ANYONECANPAY = 0x80;

export interface Bip143Args {
	readonly tx: bitcoin.Transaction;
	readonly inputIndex: number;
	readonly scriptCode: Uint8Array;
	readonly value: bigint;
	readonly hashType: number;
}

/**
 * Build the BIP-143 sighash preimage. Returns the bytes to feed to MPC with
 * `Hash.DoubleSHA256`; the MPC computes `dsha256(preimage)` and ECDSA-signs
 * the resulting digest.
 *
 * `scriptCode` for P2WPKH is the implicit P2PKH script:
 *   `OP_DUP OP_HASH160 OP_PUSHBYTES_20 <pkh> OP_EQUALVERIFY OP_CHECKSIG`.
 * For P2SH-P2WPKH the same scriptCode is used; the only difference is the
 * outer P2SH wrapping which the witness program already encodes.
 */
export function buildBip143Preimage(args: Bip143Args): Uint8Array {
	const { tx, inputIndex, scriptCode, value, hashType } = args;
	if (inputIndex >= tx.ins.length) {
		throw new Error(
			`buildBip143Preimage: inputIndex ${inputIndex} out of bounds (${tx.ins.length} inputs)`,
		);
	}

	let hashPrevouts = ZERO32;
	let hashSequence = ZERO32;
	let hashOutputs = ZERO32;

	if (!(hashType & SIGHASH_ANYONECANPAY)) {
		const buf = new Uint8Array(36 * tx.ins.length);
		const w = new BufferWriter(buf);
		for (const input of tx.ins) {
			w.writeSlice(input.hash);
			w.writeUInt32LE(input.index);
		}
		hashPrevouts = dsha256(buf);
	}

	if (
		!(hashType & SIGHASH_ANYONECANPAY) &&
		(hashType & 0x1f) !== SIGHASH_SINGLE &&
		(hashType & 0x1f) !== SIGHASH_NONE
	) {
		const buf = new Uint8Array(4 * tx.ins.length);
		const w = new BufferWriter(buf);
		for (const input of tx.ins) {
			w.writeUInt32LE(input.sequence);
		}
		hashSequence = dsha256(buf);
	}

	if ((hashType & 0x1f) !== SIGHASH_SINGLE && (hashType & 0x1f) !== SIGHASH_NONE) {
		const txOutsSize = tx.outs.reduce((sum, out) => sum + 8 + varSliceSize(out.script), 0);
		const buf = new Uint8Array(txOutsSize);
		const w = new BufferWriter(buf);
		for (const out of tx.outs) {
			w.writeInt64LE(BigInt(out.value));
			w.writeVarSlice(out.script);
		}
		hashOutputs = dsha256(buf);
	} else if ((hashType & 0x1f) === SIGHASH_SINGLE && inputIndex < tx.outs.length) {
		const out = tx.outs[inputIndex];
		const buf = new Uint8Array(8 + varSliceSize(out.script));
		const w = new BufferWriter(buf);
		w.writeInt64LE(BigInt(out.value));
		w.writeVarSlice(out.script);
		hashOutputs = dsha256(buf);
	}

	const input = tx.ins[inputIndex];
	const buf = new Uint8Array(156 + varSliceSize(scriptCode));
	const w = new BufferWriter(buf);
	w.writeUInt32LE(tx.version);
	w.writeSlice(hashPrevouts);
	w.writeSlice(hashSequence);
	w.writeSlice(input.hash);
	w.writeUInt32LE(input.index);
	w.writeVarSlice(scriptCode);
	w.writeInt64LE(value);
	w.writeUInt32LE(input.sequence);
	w.writeSlice(hashOutputs);
	w.writeUInt32LE(tx.locktime);
	w.writeUInt32LE(hashType);
	return buf;
}

/**
 * The implicit P2WPKH scriptCode used in BIP-143 sighashing. It's NOT what's
 * in the UTXO's scriptPubKey (which is `OP_0 OP_PUSHBYTES_20 <pkh>`) — for
 * sighashing it gets expanded to the legacy P2PKH script as per BIP-143.
 */
export function p2wpkhScriptCode(pubkeyHash160: Uint8Array): Uint8Array {
	if (pubkeyHash160.length !== 20) {
		throw new Error(`p2wpkhScriptCode requires a 20-byte hash160 (got ${pubkeyHash160.length})`);
	}
	const out = new Uint8Array(25);
	out[0] = 0x76; // OP_DUP
	out[1] = 0xa9; // OP_HASH160
	out[2] = 0x14; // push 20
	out.set(pubkeyHash160, 3);
	out[23] = 0x88; // OP_EQUALVERIFY
	out[24] = 0xac; // OP_CHECKSIG
	return out;
}
