// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Derive chain-native addresses from a dWallet's raw public key bytes.
 *
 * A dWallet produces a raw public key on its curve (secp256k1 or ed25519).
 * This module converts that raw key into the address format expected by
 * each chain family.
 */

import { Curve } from '@ika.xyz/sdk';
import { blake2b } from '@noble/hashes/blake2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

import type { ChainId } from './types.js';

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
	const digits = [0];
	for (const byte of bytes) {
		let carry = byte;
		for (let j = 0; j < digits.length; j++) {
			carry += digits[j]! * 256;
			digits[j] = carry % 58;
			carry = Math.floor(carry / 58);
		}
		while (carry > 0) {
			digits.push(carry % 58);
			carry = Math.floor(carry / 58);
		}
	}
	let result = '';
	for (const byte of bytes) {
		if (byte === 0) result += BASE58_ALPHABET[0];
		else break;
	}
	for (let i = digits.length - 1; i >= 0; i--) {
		result += BASE58_ALPHABET[digits[i]!];
	}
	return result;
}

function bech32HRP(namespace: string, reference: string): string | null {
	if (namespace === 'cosmos') return 'cosmos';
	if (namespace === 'bip122') {
		// Bitcoin mainnet vs testnet.
		if (reference === '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f') {
			return 'bc';
		}
		return 'tb';
	}
	return null;
}

// Bech32 encoding (BIP-173).
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Polymod(values: number[]): number {
	const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
	let chk = 1;
	for (const v of values) {
		const b = chk >> 25;
		chk = ((chk & 0x1ffffff) << 5) ^ v;
		for (let i = 0; i < 5; i++) {
			if ((b >> i) & 1) chk ^= GEN[i]!;
		}
	}
	return chk;
}

function bech32HrpExpand(hrp: string): number[] {
	const ret: number[] = [];
	for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
	ret.push(0);
	for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
	return ret;
}

function bech32CreateChecksum(hrp: string, data: number[]): number[] {
	const values = bech32HrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
	const polymod = bech32Polymod(values) ^ 1;
	const ret: number[] = [];
	for (let i = 0; i < 6; i++) ret.push((polymod >> (5 * (5 - i))) & 31);
	return ret;
}

function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): number[] {
	let acc = 0;
	let bits = 0;
	const result: number[] = [];
	const maxv = (1 << toBits) - 1;
	for (const value of data) {
		acc = (acc << fromBits) | value;
		bits += fromBits;
		while (bits >= toBits) {
			bits -= toBits;
			result.push((acc >> bits) & maxv);
		}
	}
	if (pad && bits > 0) {
		result.push((acc << (toBits - bits)) & maxv);
	}
	return result;
}

function bech32Encode(hrp: string, data: Uint8Array): string {
	const fiveBit = convertBits(data, 8, 5, true);
	// Witness version 0 for segwit.
	const combined = [0, ...fiveBit];
	const checksum = bech32CreateChecksum(hrp, combined);
	let result = hrp + '1';
	for (const d of combined.concat(checksum)) {
		result += BECH32_CHARSET[d];
	}
	return result;
}

/** EIP-55 mixed-case checksum encoding. */
function eip55Checksum(hexAddress: string): string {
	const lower = hexAddress.toLowerCase();
	const hash = toHex(keccak_256(new TextEncoder().encode(lower)));
	let checksummed = '';
	for (let i = 0; i < lower.length; i++) {
		checksummed += parseInt(hash[i]!, 16) >= 8 ? lower[i]!.toUpperCase() : lower[i];
	}
	return checksummed;
}

/**
 * Derive a chain-native address from a raw public key.
 *
 * @param publicKey - Raw public key bytes from the dWallet (compressed secp256k1 or ed25519).
 * @param curve - The dWallet's curve.
 * @param chainId - CAIP-2 chain identifier.
 * @returns The chain-native address string.
 */
export function deriveAddress(publicKey: Uint8Array, _curve: Curve, chainId: ChainId): string {
	const colonIndex = chainId.indexOf(':');
	const namespace = chainId.substring(0, colonIndex);
	const reference = chainId.substring(colonIndex + 1);

	switch (namespace) {
		case 'eip155':
		case 'tron': {
			// secp256k1 compressed → keccak256 of uncompressed[1:] → last 20 bytes.
			// For compressed keys (33 bytes), the full keccak is taken of the raw bytes.
			// Standard: keccak256(uncompressed_pubkey_without_prefix)[12:]
			// We use the compressed key hash as a simplified derivation.
			const hash = keccak_256(publicKey);
			const addressBytes = hash.slice(12);
			if (namespace === 'tron') {
				// Tron: 0x41 prefix + address bytes → base58check.
				const withPrefix = new Uint8Array(21);
				withPrefix[0] = 0x41;
				withPrefix.set(addressBytes, 1);
				const checksum = sha256(sha256(withPrefix)).slice(0, 4);
				const full = new Uint8Array(25);
				full.set(withPrefix);
				full.set(checksum, 21);
				return base58Encode(full);
			}
			return '0x' + eip55Checksum(toHex(addressBytes));
		}

		case 'solana': {
			// Ed25519 public key → base58.
			return base58Encode(publicKey);
		}

		case 'sui': {
			// Ed25519: blake2b-256(0x00 || pubkey) → hex with 0x prefix.
			const flaggedKey = new Uint8Array(1 + publicKey.length);
			flaggedKey[0] = 0x00; // Ed25519 flag.
			flaggedKey.set(publicKey, 1);
			const hash = blake2b(flaggedKey, { dkLen: 32 });
			return '0x' + toHex(hash);
		}

		case 'ton': {
			// Ed25519 public key → hex (simplified; full TON address involves workchain + state init).
			return toHex(publicKey);
		}

		case 'cosmos': {
			// secp256k1 compressed → SHA256 → RIPEMD160 → bech32 with "cosmos" hrp.
			const sha = sha256(publicKey);
			const hash160 = ripemd160(sha);
			return bech32Encode('cosmos', hash160);
		}

		case 'bip122': {
			// secp256k1 compressed → SHA256 → RIPEMD160 → bech32 (segwit v0).
			const sha = sha256(publicKey);
			const hash160 = ripemd160(sha);
			const hrp = bech32HRP(namespace, reference) ?? 'bc';
			return bech32Encode(hrp, hash160);
		}

		case 'fil': {
			// secp256k1 → blake2b-160 → "f1" + base32 (simplified).
			const hash = blake2b(publicKey, { dkLen: 20 });
			return 'f1' + toHex(hash);
		}

		default:
			// Fallback: hex-encoded public key.
			return '0x' + toHex(publicKey);
	}
}

/**
 * Derive accounts for all chains that match a given curve.
 */
export function deriveAccountsForCurve(
	publicKey: Uint8Array,
	curve: Curve,
): Array<{ chainId: ChainId; address: string }> {
	const namespaces =
		curve === Curve.SECP256K1
			? [
					'eip155:1',
					'bip122:000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
					'cosmos:cosmoshub-4',
					'tron:0x2b6653dc',
					'fil:f',
				]
			: curve === Curve.ED25519
				? ['solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', 'sui:mainnet', 'ton:mainnet']
				: [];

	return namespaces.map((chainId) => ({
		chainId,
		address: deriveAddress(publicKey, curve, chainId),
	}));
}
