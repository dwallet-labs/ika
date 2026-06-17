// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Mode handlers. One per Bitcoin spending mode. Each handler knows:
 *
 *   - The `(signatureAlgorithm, hash)` pair the MPC expects.
 *   - How to build the sighash preimage for a PSBT input.
 *   - How to apply the resulting MPC signature back into the PSBT.
 *
 * The handlers are pure functions; they don't talk to the source — the
 * source-signing call is owned by `signCore`, which dispatches to the right
 * handler for the mode the caller asked for.
 */

import { Hash, SignatureAlgorithm } from '@ika.xyz/sdk';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import * as bitcoin from 'bitcoinjs-lib';

import { buildCheckSigScript, hash160, toXOnlyPubkey } from './address.js';
import type { BitcoinMode, P2trBundle } from './address.js';
import { buildBip143Preimage, p2wpkhScriptCode } from './preimage/bip143.js';
import { buildBip341Preimage, computeTapLeafHash } from './preimage/bip341.js';
import { buildLegacyPreimage } from './preimage/legacy.js';

const SECP256K1_N = secp256k1.Point.Fn.ORDER;
const SECP256K1_N_HALF = SECP256K1_N >> 1n;

/**
 * Normalize an ECDSA (r||s) signature to low-S form. Required by Bitcoin
 * Core's BIP-146 / standard relay policy — high-S signatures are valid
 * under consensus but won't propagate through default-policy nodes, so
 * the tx silently fails to confirm.
 */
function normalizeLowS(rs: Uint8Array): Uint8Array {
	if (rs.length !== 64) return rs;
	let sBig = 0n;
	for (let i = 32; i < 64; i++) sBig = (sBig << 8n) | BigInt(rs[i]);
	if (sBig <= SECP256K1_N_HALF) return rs;
	let flipped = SECP256K1_N - sBig;
	const out = new Uint8Array(64);
	out.set(rs.subarray(0, 32), 0);
	for (let i = 31; i >= 0; i--) {
		out[32 + i] = Number(flipped & 0xffn);
		flipped = flipped >> 8n;
	}
	return out;
}

export interface ModeSignaturePlan {
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly hash: Hash;
}

export interface BuildPreimageArgs {
	readonly psbt: bitcoin.Psbt;
	readonly inputIndex: number;
	readonly compressedPubkey: Uint8Array;
	readonly p2trBundle?: P2trBundle;
	/** Override hashType. Defaults to SIGHASH_ALL (ECDSA modes) or SIGHASH_DEFAULT (Taproot). */
	readonly hashType?: number;
}

export interface ApplySignatureArgs {
	readonly psbt: bitcoin.Psbt;
	readonly inputIndex: number;
	readonly compressedPubkey: Uint8Array;
	readonly signature: Uint8Array;
	readonly hashType: number;
	readonly p2trBundle?: P2trBundle;
}

export interface BitcoinModeHandler {
	readonly mode: BitcoinMode;
	readonly plan: ModeSignaturePlan;
	/** Default sighash type when the caller doesn't override it. */
	readonly defaultHashType: number;
	/**
	 * Build the bytes to feed to MPC. The MPC will apply `plan.hash` and
	 * sign the resulting digest.
	 */
	buildPreimage(args: BuildPreimageArgs): Uint8Array;
	/**
	 * Apply the MPC's signature back onto the PSBT input. After this, the
	 * caller can call `psbt.finalizeInput(inputIndex)` to produce the final
	 * witness/scriptSig.
	 */
	applySignature(args: ApplySignatureArgs): void;
}

/**
 * Read the previous-output value for an input. Source-of-truth differs by
 * mode: segwit inputs MUST have `witnessUtxo`; legacy inputs use
 * `nonWitnessUtxo` (the full previous transaction).
 */
function readPrevOutputValue(psbt: bitcoin.Psbt, inputIndex: number): bigint {
	const dataInput = psbt.data.inputs[inputIndex];
	if (dataInput.witnessUtxo) {
		return BigInt(dataInput.witnessUtxo.value);
	}
	if (dataInput.nonWitnessUtxo) {
		const prev = bitcoin.Transaction.fromBuffer(dataInput.nonWitnessUtxo);
		const txIn = psbt.txInputs[inputIndex];
		return BigInt(prev.outs[txIn.index].value);
	}
	throw new Error(
		`bitcoin destination: input ${inputIndex} has neither witnessUtxo nor nonWitnessUtxo`,
	);
}

function readPrevOutScript(psbt: bitcoin.Psbt, inputIndex: number): Uint8Array {
	const dataInput = psbt.data.inputs[inputIndex];
	if (dataInput.witnessUtxo) {
		return new Uint8Array(dataInput.witnessUtxo.script);
	}
	if (dataInput.nonWitnessUtxo) {
		const prev = bitcoin.Transaction.fromBuffer(dataInput.nonWitnessUtxo);
		const txIn = psbt.txInputs[inputIndex];
		return new Uint8Array(prev.outs[txIn.index].script);
	}
	throw new Error(
		`bitcoin destination: input ${inputIndex} has neither witnessUtxo nor nonWitnessUtxo`,
	);
}

function psbtTransaction(psbt: bitcoin.Psbt): bitcoin.Transaction {
	return bitcoin.Transaction.fromBuffer(psbt.data.getTransaction());
}

// ---------------------------------------------------------------------------
// P2PKH
// ---------------------------------------------------------------------------

const p2pkhHandler: BitcoinModeHandler = {
	mode: 'p2pkh',
	plan: { signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1, hash: Hash.DoubleSHA256 },
	defaultHashType: bitcoin.Transaction.SIGHASH_ALL,
	buildPreimage(args) {
		const tx = psbtTransaction(args.psbt);
		const prevOutScript = readPrevOutScript(args.psbt, args.inputIndex);
		const result = buildLegacyPreimage({
			tx,
			inputIndex: args.inputIndex,
			prevOutScript,
			hashType: args.hashType ?? this.defaultHashType,
		});
		if (!result.preimage) {
			// SIGHASH_SINGLE out-of-range corner case. Bitcoin Core returns a
			// hardcoded digest of `0x010000...`. Refuse to sign rather than
			// silently let the MPC produce a signature over a sentinel.
			throw new Error(
				'bitcoin destination: legacy SIGHASH_SINGLE out-of-range — sighash returns the protocol sentinel digest. Refusing to sign.',
			);
		}
		return result.preimage;
	},
	applySignature(args) {
		// PSBT carries the signature as DER-encoded ECDSA in `partialSig` with
		// the pubkey + 1-byte hashType suffix. bitcoinjs-lib's PSBT will
		// produce the right scriptSig at `finalizeInput` time.
		args.psbt.updateInput(args.inputIndex, {
			partialSig: [
				{
					pubkey: args.compressedPubkey,
					signature: encodeDerEcdsaWithHashType(args.signature, args.hashType),
				},
			],
		});
	},
};

// ---------------------------------------------------------------------------
// P2WPKH (native segwit v0)
// ---------------------------------------------------------------------------

const p2wpkhHandler: BitcoinModeHandler = {
	mode: 'p2wpkh',
	plan: { signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1, hash: Hash.DoubleSHA256 },
	defaultHashType: bitcoin.Transaction.SIGHASH_ALL,
	buildPreimage(args) {
		const tx = psbtTransaction(args.psbt);
		const value = readPrevOutputValue(args.psbt, args.inputIndex);
		const pkh = hash160(args.compressedPubkey);
		const scriptCode = p2wpkhScriptCode(pkh);
		return buildBip143Preimage({
			tx,
			inputIndex: args.inputIndex,
			scriptCode,
			value,
			hashType: args.hashType ?? this.defaultHashType,
		});
	},
	applySignature(args) {
		args.psbt.updateInput(args.inputIndex, {
			partialSig: [
				{
					pubkey: args.compressedPubkey,
					signature: encodeDerEcdsaWithHashType(args.signature, args.hashType),
				},
			],
		});
	},
};

// ---------------------------------------------------------------------------
// P2SH-P2WPKH (nested segwit)
// ---------------------------------------------------------------------------
//
// Same sighash as P2WPKH (BIP-143 with the implicit P2PKH-style scriptCode
// over the inner witness program's hash). Only the OUTER scriptSig wraps
// the P2WPKH; finalize handles that. So the handler is identical to P2WPKH
// at the preimage and signature-application level — bitcoinjs-lib's PSBT
// finalizer reads `redeemScript` from the input to produce the correct
// outer scriptSig.
// ---------------------------------------------------------------------------

const p2shP2wpkhHandler: BitcoinModeHandler = {
	mode: 'p2sh-p2wpkh',
	plan: { signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1, hash: Hash.DoubleSHA256 },
	defaultHashType: bitcoin.Transaction.SIGHASH_ALL,
	buildPreimage(args) {
		// Same as P2WPKH. The redeem script (`OP_0 OP_PUSHBYTES_20 <pkh>`) is
		// what's revealed in the outer scriptSig at finalize time; the inner
		// sighash uses the BIP-143 implicit P2PKH-style scriptCode.
		return p2wpkhHandler.buildPreimage(args);
	},
	applySignature(args) {
		p2wpkhHandler.applySignature(args);
	},
};

// ---------------------------------------------------------------------------
// P2TR script-path (taproot)
// ---------------------------------------------------------------------------

const p2trScriptHandler: BitcoinModeHandler = {
	mode: 'p2tr-script',
	plan: { signatureAlgorithm: SignatureAlgorithm.Taproot, hash: Hash.SHA256 },
	defaultHashType: bitcoin.Transaction.SIGHASH_DEFAULT,
	buildPreimage(args) {
		if (!args.p2trBundle) {
			throw new Error('bitcoin destination: p2tr-script requires `p2trBundle`');
		}
		const tx = psbtTransaction(args.psbt);
		// BIP-341 commits to ALL inputs' prev-out scripts and values.
		const prevOutScripts: Uint8Array[] = [];
		const values: bigint[] = [];
		for (let i = 0; i < tx.ins.length; i++) {
			prevOutScripts.push(readPrevOutScript(args.psbt, i));
			values.push(readPrevOutputValue(args.psbt, i));
		}
		const xOnly = toXOnlyPubkey(args.compressedPubkey);
		const leafScript = buildCheckSigScript(xOnly);
		const leafHash = computeTapLeafHash(leafScript);
		return buildBip341Preimage({
			tx,
			inputIndex: args.inputIndex,
			prevOutScripts,
			values,
			hashType: args.hashType ?? this.defaultHashType,
			leafHash,
		});
	},
	applySignature(args) {
		if (!args.p2trBundle) {
			throw new Error('bitcoin destination: p2tr-script requires `p2trBundle`');
		}
		if (args.signature.length !== 64) {
			throw new Error(
				`bitcoin destination: p2tr-script expects 64-byte schnorr signature, got ${args.signature.length}`,
			);
		}
		const xOnly = toXOnlyPubkey(args.compressedPubkey);
		const leafScript = buildCheckSigScript(xOnly);
		const leafHash = computeTapLeafHash(leafScript);
		// BIP-341 §Signature serialization: a 64-byte schnorr sig means
		// SIGHASH_DEFAULT; any other hashType appends one byte.
		const sigWithHashType =
			args.hashType === bitcoin.Transaction.SIGHASH_DEFAULT
				? args.signature
				: concatBytes(args.signature, Uint8Array.from([args.hashType]));
		args.psbt.updateInput(args.inputIndex, {
			tapScriptSig: [
				{
					pubkey: xOnly,
					signature: sigWithHashType,
					leafHash,
				},
			],
		});
	},
};

const HANDLERS: Record<BitcoinMode, BitcoinModeHandler> = {
	p2pkh: p2pkhHandler,
	p2wpkh: p2wpkhHandler,
	'p2sh-p2wpkh': p2shP2wpkhHandler,
	'p2tr-script': p2trScriptHandler,
};

export function modeHandlerFor(mode: BitcoinMode): BitcoinModeHandler {
	const h = HANDLERS[mode];
	if (!h) throw new Error(`bitcoin destination: unknown mode ${mode}`);
	return h;
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
	const out = new Uint8Array(a.length + b.length);
	out.set(a, 0);
	out.set(b, a.length);
	return out;
}

/**
 * Encode a raw 64-byte (r||s) ECDSA signature as DER + 1-byte hashType
 * suffix, which is the exact wire format Bitcoin PSBT's `partialSig` expects.
 *
 * The DER encoding follows BIP-66's strict rules: positive integers with no
 * leading zeros (except a 0x00 padding byte when the high bit is set). We
 * also re-normalize to low-S so default-policy mempools (BIP-146) accept
 * the resulting tx regardless of whether the MPC emitted canonical s.
 */
function encodeDerEcdsaWithHashType(rs: Uint8Array, hashType: number): Uint8Array {
	if (rs.length !== 64) {
		throw new Error(`encodeDerEcdsaWithHashType: expected 64-byte (r||s), got ${rs.length}`);
	}
	const normalized = normalizeLowS(rs);
	const r = stripLeadingZeros(normalized.subarray(0, 32));
	const s = stripLeadingZeros(normalized.subarray(32, 64));
	const der = derEncode(r, s);
	const out = new Uint8Array(der.length + 1);
	out.set(der, 0);
	out[der.length] = hashType;
	return out;
}

function stripLeadingZeros(n: Uint8Array): Uint8Array {
	let i = 0;
	while (i < n.length - 1 && n[i] === 0) i++;
	// BIP-66: prepend 0x00 if the high bit is set so the value is interpreted as positive.
	if (n[i] & 0x80) {
		const out = new Uint8Array(n.length - i + 1);
		out[0] = 0;
		out.set(n.subarray(i), 1);
		return out;
	}
	return n.subarray(i);
}

function derEncode(r: Uint8Array, s: Uint8Array): Uint8Array {
	const rLen = r.length;
	const sLen = s.length;
	const totalLen = 2 + rLen + 2 + sLen;
	const out = new Uint8Array(2 + totalLen);
	out[0] = 0x30; // SEQUENCE
	out[1] = totalLen;
	out[2] = 0x02; // INTEGER
	out[3] = rLen;
	out.set(r, 4);
	out[4 + rLen] = 0x02;
	out[5 + rLen] = sLen;
	out.set(s, 6 + rLen);
	return out;
}
