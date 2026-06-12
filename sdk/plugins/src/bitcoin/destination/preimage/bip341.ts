// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * BIP-341 / BIP-342 Taproot sighash preimage construction.
 *
 *   tag = SHA256("TapSighash")
 *   preimage = tag || tag || 0x00 || sigMsg
 *   TapSighash = SHA256(preimage)
 *
 * The MPC signs with `signatureAlgorithm: Taproot, hash: SHA256, message:
 * preimage`. The MPC hashes the preimage to get the TapSighash and produces
 * a BIP-340 Schnorr signature over it.
 *
 * The full `sigMsg` layout is defined in BIP-341 §Common signature message
 * and BIP-342 §Common signature message extension (the leaf-hash tail).
 *
 * Ported from the multisig-bitcoin demo to keep behaviour identical; the
 * structure mirrors bitcoinjs-lib's `Transaction.hashForWitnessV1` minus the
 * final `taggedHash` reduction (we need to expose the unhashed preimage).
 */

import { sha256 } from '@noble/hashes/sha2.js';
import type * as bitcoin from 'bitcoinjs-lib';

import { SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE } from './bip143.js';
import { BufferWriter, varSliceSize } from './writer.js';

const SIGHASH_DEFAULT = 0x00;
const SIGHASH_OUTPUT_MASK = 0x03;
const SIGHASH_INPUT_MASK = 0x80;

// Pre-computed tagHash = SHA256("TapSighash"). Spelled out so the preimage
// can be assembled without re-hashing the tag every call.
const TAP_SIGHASH_TAG = (() => {
	const tag = sha256(new TextEncoder().encode('TapSighash'));
	return new Uint8Array(tag);
})();

const TAP_LEAF_TAG = (() => {
	const tag = sha256(new TextEncoder().encode('TapLeaf'));
	return new Uint8Array(tag);
})();

export interface Bip341Args {
	readonly tx: bitcoin.Transaction;
	readonly inputIndex: number;
	/** Previous-output scriptPubKeys for ALL inputs (BIP-341 commits to all). */
	readonly prevOutScripts: ReadonlyArray<Uint8Array>;
	/** Previous-output values (satoshis) for ALL inputs. */
	readonly values: ReadonlyArray<bigint>;
	/** Sighash type. Pass `0x00` (SIGHASH_DEFAULT) for the modern Taproot default. */
	readonly hashType: number;
	/** Optional TapLeaf hash; required for script-path spending (BIP-342). */
	readonly leafHash?: Uint8Array;
	/** Optional annex bytes (BIP-341 spend type bit 0). */
	readonly annex?: Uint8Array;
}

/**
 * Build the BIP-341 Taproot sighash preimage. Returns the bytes to feed to
 * MPC with `Hash.SHA256`; the MPC computes `sha256(preimage)` to obtain the
 * TapSighash and BIP-340 Schnorr-signs it.
 */
export function buildBip341Preimage(args: Bip341Args): Uint8Array {
	const { tx, inputIndex, prevOutScripts, values, hashType, leafHash, annex } = args;
	if (values.length !== tx.ins.length || prevOutScripts.length !== tx.ins.length) {
		throw new Error(
			`buildBip341Preimage: must supply prevOutScript + value for all ${tx.ins.length} inputs`,
		);
	}
	if (inputIndex >= tx.ins.length) {
		throw new Error(
			`buildBip341Preimage: inputIndex ${inputIndex} out of bounds (${tx.ins.length} inputs)`,
		);
	}

	const outputType =
		hashType === SIGHASH_DEFAULT ? 0x01 /* SIGHASH_ALL */ : hashType & SIGHASH_OUTPUT_MASK;
	const inputType = hashType & SIGHASH_INPUT_MASK;
	const isAnyoneCanPay = inputType === SIGHASH_ANYONECANPAY;
	const isNone = outputType === SIGHASH_NONE;
	const isSingle = outputType === SIGHASH_SINGLE;

	const EMPTY = new Uint8Array(0);
	let hashPrevouts: Uint8Array = EMPTY;
	let hashAmounts: Uint8Array = EMPTY;
	let hashScriptPubKeys: Uint8Array = EMPTY;
	let hashSequences: Uint8Array = EMPTY;
	let hashOutputs: Uint8Array = EMPTY;

	if (!isAnyoneCanPay) {
		const buf = new Uint8Array(36 * tx.ins.length);
		const w = new BufferWriter(buf);
		for (const input of tx.ins) {
			w.writeSlice(input.hash);
			w.writeUInt32LE(input.index);
		}
		hashPrevouts = new Uint8Array(sha256(buf));

		const amountsBuf = new Uint8Array(8 * values.length);
		const aw = new BufferWriter(amountsBuf);
		for (const v of values) aw.writeInt64LE(v);
		hashAmounts = new Uint8Array(sha256(amountsBuf));

		const spkBufferSize = prevOutScripts.reduce((sum, s) => sum + varSliceSize(s), 0);
		const spkBuf = new Uint8Array(spkBufferSize);
		const sw = new BufferWriter(spkBuf);
		for (const s of prevOutScripts) sw.writeVarSlice(s);
		hashScriptPubKeys = new Uint8Array(sha256(spkBuf));

		const seqBuf = new Uint8Array(4 * tx.ins.length);
		const qw = new BufferWriter(seqBuf);
		for (const input of tx.ins) qw.writeUInt32LE(input.sequence);
		hashSequences = new Uint8Array(sha256(seqBuf));
	}

	if (!(isNone || isSingle)) {
		if (tx.outs.length === 0) {
			throw new Error('buildBip341Preimage: SIGHASH_ALL needs at least one output');
		}
		const outsSize = tx.outs.reduce((sum, out) => sum + 8 + varSliceSize(out.script), 0);
		const outBuf = new Uint8Array(outsSize);
		const ow = new BufferWriter(outBuf);
		for (const out of tx.outs) {
			ow.writeInt64LE(out.value);
			ow.writeVarSlice(out.script);
		}
		hashOutputs = new Uint8Array(sha256(outBuf));
	} else if (isSingle && inputIndex < tx.outs.length) {
		const out = tx.outs[inputIndex];
		const buf = new Uint8Array(8 + varSliceSize(out.script));
		const w = new BufferWriter(buf);
		w.writeInt64LE(out.value);
		w.writeVarSlice(out.script);
		hashOutputs = new Uint8Array(sha256(buf));
	}

	const spendType = (leafHash ? 2 : 0) + (annex ? 1 : 0);

	// Size pre-computation per BIP-341.
	const sigMsgSize =
		174 - (isAnyoneCanPay ? 49 : 0) - (isNone ? 32 : 0) + (annex ? 32 : 0) + (leafHash ? 37 : 0);

	const sigMsg = new Uint8Array(sigMsgSize);
	const w = new BufferWriter(sigMsg);

	w.writeUInt8(hashType);
	w.writeInt32LE(tx.version);
	w.writeUInt32LE(tx.locktime);
	if (!isAnyoneCanPay) {
		w.writeSlice(hashPrevouts);
		w.writeSlice(hashAmounts);
		w.writeSlice(hashScriptPubKeys);
		w.writeSlice(hashSequences);
	}
	if (!(isNone || isSingle)) {
		w.writeSlice(hashOutputs);
	}
	w.writeUInt8(spendType);
	if (isAnyoneCanPay) {
		const input = tx.ins[inputIndex];
		w.writeSlice(input.hash);
		w.writeUInt32LE(input.index);
		w.writeInt64LE(values[inputIndex]);
		w.writeVarSlice(prevOutScripts[inputIndex]);
		w.writeUInt32LE(input.sequence);
	} else {
		w.writeUInt32LE(inputIndex);
	}
	if (annex) {
		const annexBuf = new Uint8Array(varSliceSize(annex));
		const aw = new BufferWriter(annexBuf);
		aw.writeVarSlice(annex);
		w.writeSlice(new Uint8Array(sha256(annexBuf)));
	}
	if (isSingle) {
		w.writeSlice(hashOutputs);
	}
	// BIP-342 leaf-hash extension.
	if (leafHash) {
		w.writeSlice(leafHash);
		w.writeUInt8(0); // key version
		w.writeUInt32LE(0xffffffff); // codeseparator position
	}

	// Compose preimage = tag || tag || 0x00 || sigMsg
	const out = new Uint8Array(32 + 32 + 1 + sigMsg.length);
	out.set(TAP_SIGHASH_TAG, 0);
	out.set(TAP_SIGHASH_TAG, 32);
	out[64] = 0x00;
	out.set(sigMsg, 65);
	return out;
}

/**
 * Compute the TapLeaf hash for a script-path leaf:
 *   `taggedHash("TapLeaf", leafVersion || varSlice(script))`.
 * Used both for the control block reveal and inside `buildBip341Preimage`.
 */
export function computeTapLeafHash(script: Uint8Array, leafVersion = 0xc0): Uint8Array {
	const inner = new Uint8Array(1 + varSliceSize(script));
	const w = new BufferWriter(inner);
	w.writeUInt8(leafVersion);
	w.writeVarSlice(script);
	const full = new Uint8Array(32 + 32 + inner.length);
	full.set(TAP_LEAF_TAG, 0);
	full.set(TAP_LEAF_TAG, 32);
	full.set(inner, 64);
	return new Uint8Array(sha256(full));
}
