// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import * as ecc from '@bitcoinerlab/secp256k1';
import { Curve, publicKeyFromDWalletOutput } from '@ika.xyz/sdk';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as bitcoin from 'bitcoinjs-lib';

import { bytesToHexLower, createCoalescingCache } from '../../internal/cache.js';
import type { CoalescingCache } from '../../internal/cache.js';

/**
 * bitcoinjs-lib's P2TR payment requires an ECC backend for the BIP-341
 * internal-key tweak. Registering once is idempotent; doing it lazily here
 * keeps the dependency out of every Bitcoin code path that doesn't need
 * Taproot (P2PKH / P2WPKH / P2SH-P2WPKH all skip it).
 */
let eccInitialized = false;
function ensureEccLib(): void {
	if (eccInitialized) return;
	bitcoin.initEccLib(ecc as Parameters<typeof bitcoin.initEccLib>[0]);
	eccInitialized = true;
}

/**
 * Bitcoin spending mode. Each mode pairs a specific address derivation with
 * a specific sighash flow and signature algorithm:
 *
 *   - `p2pkh`         legacy `1...` address. ECDSA + legacy sighash (dsha256).
 *   - `p2wpkh`        native segwit `bc1q...`. ECDSA + BIP-143 sighash (dsha256).
 *   - `p2sh-p2wpkh`   nested segwit `3...`. ECDSA + BIP-143 sighash (the
 *                     witness is the same as `p2wpkh`; only the scriptSig
 *                     wrapping differs).
 *   - `p2tr-script`   taproot `bc1p...` SCRIPT PATH only. Schnorr +
 *                     BIP-341/342 sighash (sha256). Ika MPC cannot tweak
 *                     keys, so key-path spending is structurally unsupported.
 */
export type BitcoinMode = 'p2pkh' | 'p2wpkh' | 'p2sh-p2wpkh' | 'p2tr-script';

export type BitcoinNetwork = 'mainnet' | 'testnet' | 'signet' | 'regtest';

export type BitcoinSupportedCurve = 'SECP256K1';

/**
 * BIP-340 "Nothing Up My Sleeve" point. Used as the P2TR internal pubkey for
 * script-path-only spending; nobody knows its discrete log so the key path
 * is provably unspendable.
 */
const NUMS_PUBKEY = new Uint8Array([
	0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
	0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
]);

/** Tapscript leaf version (BIP-342 v0). */
export const TAPSCRIPT_LEAF_VERSION = 0xc0;

function assertSecp256k1(curve: Curve): void {
	if (curve !== Curve.SECP256K1) {
		throw new Error(`bitcoin destination does not support curve ${curve}. Use SECP256K1.`);
	}
}

export function networkParams(network: BitcoinNetwork): bitcoin.Network {
	switch (network) {
		case 'mainnet':
			return bitcoin.networks.bitcoin;
		case 'testnet':
		case 'signet':
			return bitcoin.networks.testnet;
		case 'regtest':
			return bitcoin.networks.regtest;
	}
}

/** Strip the parity byte from a 33-byte compressed pubkey to get the 32-byte x-only form. */
export function toXOnlyPubkey(pubkey: Uint8Array): Uint8Array {
	if (pubkey.length === 32) return pubkey;
	if (pubkey.length === 33 && (pubkey[0] === 0x02 || pubkey[0] === 0x03)) {
		return pubkey.subarray(1);
	}
	throw new Error(
		`bitcoin destination: expected 32B x-only or 33B compressed pubkey, got ${pubkey.length}`,
	);
}

function assertCompressed(pubkey: Uint8Array): void {
	if (pubkey.length !== 33 || (pubkey[0] !== 0x02 && pubkey[0] !== 0x03)) {
		throw new Error(
			`bitcoin destination: expected 33B compressed pubkey, got ${pubkey.length} bytes`,
		);
	}
}

/** `hash160(pubkey) = ripemd160(sha256(pubkey))`. The 20-byte hash used in P2PKH/P2WPKH. */
export function hash160(bytes: Uint8Array): Uint8Array {
	return new Uint8Array(ripemd160(new Uint8Array(sha256(bytes))));
}

/** Build the single-leaf `OP_PUSHBYTES_32 <xOnly> OP_CHECKSIG` Tapscript. */
export function buildCheckSigScript(xOnlyPubkey: Uint8Array): Uint8Array {
	if (xOnlyPubkey.length !== 32) {
		throw new Error('buildCheckSigScript requires a 32-byte x-only pubkey');
	}
	const out = new Uint8Array(34);
	out[0] = 0x20;
	out.set(xOnlyPubkey, 1);
	out[33] = 0xac;
	return out;
}

export interface P2trBundle {
	readonly kind: 'p2tr-script';
	readonly address: string;
	readonly redeem: { readonly output: Uint8Array; readonly redeemVersion: number };
	readonly scriptTree: { readonly output: Uint8Array };
	readonly payment: bitcoin.payments.Payment;
	readonly internalPubkey: Uint8Array;
}

/** Build the P2TR script-path payment bundle for one dWallet on one network. */
export function buildP2trScriptPath(xOnlyPubkey: Uint8Array, network: BitcoinNetwork): P2trBundle {
	ensureEccLib();
	const script = buildCheckSigScript(xOnlyPubkey);
	const redeem = {
		output: script,
		redeemVersion: TAPSCRIPT_LEAF_VERSION,
	};
	const scriptTree = { output: script };
	const payment = bitcoin.payments.p2tr(
		{
			internalPubkey: NUMS_PUBKEY,
			scriptTree,
			redeem,
			network: networkParams(network),
		},
		{ validate: true },
	);
	if (!payment.address) {
		throw new Error('bitcoin destination: failed to derive P2TR address');
	}
	return {
		kind: 'p2tr-script',
		address: payment.address,
		redeem,
		scriptTree,
		payment,
		internalPubkey: NUMS_PUBKEY,
	};
}

/**
 * Build an address for a given mode. The plugin uses this directly for
 * `getAddress` and indirectly when validating that a PSBT input's
 * `witnessUtxo`/`nonWitnessUtxo` script matches the requested mode.
 */
export function deriveAddressByMode(
	compressedPubkey: Uint8Array,
	mode: BitcoinMode,
	network: BitcoinNetwork,
): string {
	assertCompressed(compressedPubkey);
	const net = networkParams(network);
	switch (mode) {
		case 'p2pkh': {
			const payment = bitcoin.payments.p2pkh({
				pubkey: compressedPubkey,
				network: net,
			});
			if (!payment.address) throw new Error('failed to derive P2PKH address');
			return payment.address;
		}
		case 'p2wpkh': {
			const payment = bitcoin.payments.p2wpkh({
				pubkey: compressedPubkey,
				network: net,
			});
			if (!payment.address) throw new Error('failed to derive P2WPKH address');
			return payment.address;
		}
		case 'p2sh-p2wpkh': {
			const inner = bitcoin.payments.p2wpkh({
				pubkey: compressedPubkey,
				network: net,
			});
			const payment = bitcoin.payments.p2sh({ redeem: inner, network: net });
			if (!payment.address) throw new Error('failed to derive P2SH-P2WPKH address');
			return payment.address;
		}
		case 'p2tr-script': {
			const xOnly = toXOnlyPubkey(compressedPubkey);
			return buildP2trScriptPath(xOnly, network).address;
		}
	}
}

/** One-shot, unmemoized derivation. Prefer `createBitcoinAddressCache()` on hot paths. */
export async function deriveBitcoinAddress(
	curve: Curve,
	publicOutput: Uint8Array,
	mode: BitcoinMode,
	network: BitcoinNetwork,
): Promise<string> {
	assertSecp256k1(curve);
	const pubkey = await publicKeyFromDWalletOutput(curve, publicOutput);
	return deriveAddressByMode(pubkey, mode, network);
}

export interface BitcoinAddressCache {
	/** Compressed (33B) secp256k1 pubkey for this dWallet. */
	compressedPubkey(curve: Curve, publicOutput: Uint8Array): Promise<Uint8Array>;
	address(
		curve: Curve,
		publicOutput: Uint8Array,
		mode: BitcoinMode,
		network: BitcoinNetwork,
	): Promise<string>;
	p2trBundle(curve: Curve, publicOutput: Uint8Array, network: BitcoinNetwork): Promise<P2trBundle>;
}

export function createBitcoinAddressCache(): BitcoinAddressCache {
	const pkCache: CoalescingCache<Uint8Array> = createCoalescingCache({
		clone: (v) => new Uint8Array(v),
	});
	const addrCache: CoalescingCache<string> = createCoalescingCache();
	const p2trCache: CoalescingCache<P2trBundle> = createCoalescingCache();

	const pkKey = (curve: Curve, bytes: Uint8Array): string => curve + ':' + bytesToHexLower(bytes);
	const addrKey = (
		curve: Curve,
		bytes: Uint8Array,
		mode: BitcoinMode,
		network: BitcoinNetwork,
	): string => curve + ':' + bytesToHexLower(bytes) + ':' + mode + ':' + network;
	const p2trKey = (curve: Curve, bytes: Uint8Array, network: BitcoinNetwork): string =>
		curve + ':' + bytesToHexLower(bytes) + ':' + network;

	const compressedPubkey = (curve: Curve, publicOutput: Uint8Array): Promise<Uint8Array> => {
		assertSecp256k1(curve);
		return pkCache.get(pkKey(curve, publicOutput), async () => {
			const pk = await publicKeyFromDWalletOutput(curve, publicOutput);
			assertCompressed(pk);
			return pk;
		});
	};

	const address = (
		curve: Curve,
		publicOutput: Uint8Array,
		mode: BitcoinMode,
		network: BitcoinNetwork,
	): Promise<string> =>
		addrCache.get(addrKey(curve, publicOutput, mode, network), async () => {
			const pk = await compressedPubkey(curve, publicOutput);
			return deriveAddressByMode(pk, mode, network);
		});

	const p2trBundle = (
		curve: Curve,
		publicOutput: Uint8Array,
		network: BitcoinNetwork,
	): Promise<P2trBundle> =>
		p2trCache.get(p2trKey(curve, publicOutput, network), async () => {
			const pk = await compressedPubkey(curve, publicOutput);
			return buildP2trScriptPath(toXOnlyPubkey(pk), network);
		});

	return { compressedPubkey, address, p2trBundle };
}
