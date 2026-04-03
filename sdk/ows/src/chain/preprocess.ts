// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Chain-specific message and transaction pre-processing.
 *
 * Ika MPC applies the hash scheme internally (keccak256, SHA256, doubleSHA256,
 * SHA512), but each chain has its own envelope/prefix format that must be
 * applied BEFORE hashing. This module handles that.
 */

import { blake2b } from '@noble/hashes/blake2.js';

/**
 * Pre-process a message or transaction for chain-specific signing standards.
 *
 * For transactions, most chains expect the raw serialized tx bytes — the Ika
 * protocol hashes them according to the chain's hash scheme.
 *
 * For messages, each chain has its own prefix convention.
 */
export function preProcessForChain(
	chain: string,
	bytes: Uint8Array,
	kind: 'transaction' | 'message',
): Uint8Array {
	const namespace = chain.split(':')[0]!;

	switch (namespace) {
		case 'eip155': {
			if (kind === 'message') {
				// EIP-191 personal_sign: "\x19Ethereum Signed Message:\n{len}{msg}"
				return prefixMessage(`\x19Ethereum Signed Message:\n${bytes.length}`, bytes);
			}
			return bytes;
		}

		case 'tron': {
			if (kind === 'message') {
				// Tron personal message: "\x19TRON Signed Message:\n{len}{msg}"
				return prefixMessage(`\x19TRON Signed Message:\n${bytes.length}`, bytes);
			}
			return bytes;
		}

		case 'bip122': {
			if (kind === 'message') {
				// Bitcoin message signing: "\x18Bitcoin Signed Message:\n" + CompactSize(len) + msg
				const header = new TextEncoder().encode('\x18Bitcoin Signed Message:\n');
				const lenBytes = compactSizeEncode(bytes.length);
				const wrapped = new Uint8Array(header.length + lenBytes.length + bytes.length);
				wrapped.set(header, 0);
				wrapped.set(lenBytes, header.length);
				wrapped.set(bytes, header.length + lenBytes.length);
				return wrapped;
			}
			return bytes;
		}

		case 'sui': {
			if (kind === 'message') {
				// Sui personal message: BCS ULEB128 length prefix + msg,
				// then intent scope 3 + blake2b-256.
				const lenBytes = uleb128Encode(bytes.length);
				const bcsMsg = new Uint8Array(lenBytes.length + bytes.length);
				bcsMsg.set(lenBytes, 0);
				bcsMsg.set(bytes, lenBytes.length);
				const intentMessage = new Uint8Array(3 + bcsMsg.length);
				intentMessage.set([3, 0, 0], 0); // scope=3 (PersonalMessage)
				intentMessage.set(bcsMsg, 3);
				return blake2b(intentMessage, { dkLen: 32 });
			}
			// Transaction: intent scope 0 + blake2b-256
			const intentMessage = new Uint8Array(3 + bytes.length);
			intentMessage.set([0, 0, 0], 0);
			intentMessage.set(bytes, 3);
			return blake2b(intentMessage, { dkLen: 32 });
		}

		case 'fil': {
			// Filecoin: blake2b-256 of tx/message bytes.
			return blake2b(bytes, { dkLen: 32 });
		}

		// solana, cosmos, ton: raw bytes, no pre-processing.
		default:
			return bytes;
	}
}

/** Prefix a message with a string header. */
function prefixMessage(header: string, msg: Uint8Array): Uint8Array {
	const prefix = new TextEncoder().encode(header);
	const result = new Uint8Array(prefix.length + msg.length);
	result.set(prefix, 0);
	result.set(msg, prefix.length);
	return result;
}

/** Bitcoin CompactSize encoding. */
function compactSizeEncode(n: number): Uint8Array {
	if (n < 0xfd) return new Uint8Array([n]);
	if (n <= 0xffff) {
		const buf = new Uint8Array(3);
		buf[0] = 0xfd;
		buf[1] = n & 0xff;
		buf[2] = (n >> 8) & 0xff;
		return buf;
	}
	const buf = new Uint8Array(5);
	buf[0] = 0xfe;
	buf[1] = n & 0xff;
	buf[2] = (n >> 8) & 0xff;
	buf[3] = (n >> 16) & 0xff;
	buf[4] = (n >> 24) & 0xff;
	return buf;
}

/** ULEB128 encoding for BCS. */
function uleb128Encode(n: number): Uint8Array {
	const bytes: number[] = [];
	let val = n;
	do {
		let byte = val & 0x7f;
		val >>= 7;
		if (val > 0) byte |= 0x80;
		bytes.push(byte);
	} while (val > 0);
	return new Uint8Array(bytes);
}
