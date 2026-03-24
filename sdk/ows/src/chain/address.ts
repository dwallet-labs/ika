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
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

import type { ChainId } from '../types.js';

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

function base32Encode(bytes: Uint8Array): string {
	let result = '';
	let buffer = 0;
	let bits = 0;
	for (const byte of bytes) {
		buffer = (buffer << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			result += BASE32_ALPHABET[(buffer >> bits) & 0x1f];
		}
	}
	if (bits > 0) {
		result += BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1f];
	}
	return result;
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
			// secp256k1: decompress → keccak256(uncompressed[1:]) → last 20 bytes.
			// The uncompressed key is 65 bytes (0x04 || x || y), skip the 0x04 prefix.
			const uncompressed = publicKey.length === 33
				? secp256k1.Point.fromHex(toHex(publicKey)).toBytes(false)
				: publicKey;
			const hash = keccak_256(uncompressed.slice(1));
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
			// TON wallet v5r1 address: pubkey → data cell hash → state init hash → base64url.
			return tonWalletV5R1Address(publicKey);
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
			// Filecoin secp256k1: uncompressed pubkey → blake2b-160 → base32 + blake2b-4 checksum.
			const uncompressedFil = publicKey.length === 33
				? secp256k1.Point.fromHex(toHex(publicKey)).toBytes(false)
				: publicKey;
			const payload = blake2b(uncompressedFil, { dkLen: 20 });
			// Checksum: blake2b-4(protocol_byte || payload)
			const checksumInput = new Uint8Array(1 + payload.length);
			checksumInput[0] = 1; // secp256k1 protocol
			checksumInput.set(payload, 1);
			const checksum = blake2b(checksumInput, { dkLen: 4 });
			// base32 lower-case encode (payload || checksum)
			const addrBytes = new Uint8Array(payload.length + checksum.length);
			addrBytes.set(payload, 0);
			addrBytes.set(checksum, payload.length);
			return 'f1' + base32Encode(addrBytes);
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

// ─── TON Wallet v5r1 Address ─────────────────────────────────────────────

/** Wallet v5r1 code cell hash (SHA256 of the cell representation). */
const WALLET_V5R1_CODE_HASH = new Uint8Array([
	0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14, 0x7e, 0x1b, 0x2f, 0xb4,
	0x57, 0xb8, 0x4e, 0x74, 0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6,
	0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f,
]);

const WALLET_V5R1_CODE_DEPTH = 6;

/** Default walletId: networkGlobalId(-239) XOR context(0x80000000). */
const DEFAULT_WALLET_ID = 0x7fffff11;

/**
 * Derive a TON wallet v5r1 address from an ed25519 public key.
 * Non-bounceable, workchain 0.
 */
function tonWalletV5R1Address(publicKey: Uint8Array): string {
	const dataHash = tonDataCellHash(publicKey);
	const stateHash = tonStateInitHash(WALLET_V5R1_CODE_HASH, WALLET_V5R1_CODE_DEPTH, dataHash);
	return tonEncodeAddress(0, stateHash, false);
}

/**
 * Compute data cell hash for wallet v5r1 initial state.
 * Data: is_sig_allowed(1b) + seqno(0, 32b) + walletId(32b) + pubkey(256b) + extensions(0, 1b)
 * = 322 bits, 0 refs.
 */
function tonDataCellHash(publicKey: Uint8Array): Uint8Array {
	const bits: number[] = [];

	// is_signature_allowed = 1
	bits.push(1);
	// seqno = 0 (32 bits)
	for (let i = 0; i < 32; i++) bits.push(0);
	// walletId (32 bits, big-endian)
	for (let shift = 31; shift >= 0; shift--) {
		bits.push((DEFAULT_WALLET_ID >>> shift) & 1);
	}
	// public key (256 bits)
	for (const byte of publicKey) {
		for (let shift = 7; shift >= 0; shift--) {
			bits.push((byte >> shift) & 1);
		}
	}
	// extensions = 0
	bits.push(0);
	// Completion tag
	bits.push(1);
	while (bits.length % 8 !== 0) bits.push(0);

	// Convert bits to bytes
	const dataBytes: number[] = [];
	for (let i = 0; i < bits.length; i += 8) {
		let byte = 0;
		for (let j = 0; j < 8; j++) byte |= (bits[i + j]! << (7 - j));
		dataBytes.push(byte);
	}

	// Cell repr: d1(0 refs) + d2(ceil(322/8)+floor(322/8)) + data
	const d1 = 0;
	const d2 = 81; // 41 + 40
	const repr = new Uint8Array(2 + dataBytes.length);
	repr[0] = d1;
	repr[1] = d2;
	repr.set(dataBytes, 2);

	return sha256(repr);
}

/**
 * Compute StateInit cell hash.
 * StateInit: 5 bits (00110) = split_depth(0) special(0) code(1) data(1) library(0), 2 refs.
 */
function tonStateInitHash(
	codeHash: Uint8Array,
	codeDepth: number,
	dataHash: Uint8Array,
): Uint8Array {
	const repr = new Uint8Array(2 + 1 + 4 + 32 + 32);
	repr[0] = 2;    // d1: 2 refs
	repr[1] = 1;    // d2: ceil(5/8) + floor(5/8)
	repr[2] = 0x34; // 00110 + completion tag '100'
	// Code depth (big-endian u16)
	repr[3] = (codeDepth >> 8) & 0xff;
	repr[4] = codeDepth & 0xff;
	// Data depth = 0
	repr[5] = 0;
	repr[6] = 0;
	// Code hash + data hash
	repr.set(codeHash, 7);
	repr.set(dataHash, 39);

	return sha256(repr);
}

/** Encode a TON user-friendly address (base64url with CRC16). */
function tonEncodeAddress(workchain: number, hash: Uint8Array, bounceable: boolean): string {
	const tag = bounceable ? 0x11 : 0x51;
	const addr = new Uint8Array(36);
	addr[0] = tag;
	addr[1] = workchain & 0xff;
	addr.set(hash, 2);

	const crc = crc16ccitt(addr.subarray(0, 34));
	addr[34] = (crc >> 8) & 0xff;
	addr[35] = crc & 0xff;

	return base64urlEncode(addr);
}

function crc16ccitt(data: Uint8Array): number {
	let crc = 0;
	for (const byte of data) {
		crc ^= byte << 8;
		for (let j = 0; j < 8; j++) {
			if (crc & 0x8000) {
				crc = ((crc << 1) ^ 0x1021) & 0xffff;
			} else {
				crc = (crc << 1) & 0xffff;
			}
		}
	}
	return crc;
}

function base64urlEncode(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString('base64url');
}
