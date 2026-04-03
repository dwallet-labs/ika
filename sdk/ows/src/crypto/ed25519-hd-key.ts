// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Adapted from https://github.com/alepop/ed25519-hd-key
// Uses @noble/hashes for browser compatibility.

import { hmac } from '@noble/hashes/hmac.js';
import { sha512 } from '@noble/hashes/sha2.js';

type Keys = {
	key: Uint8Array;
	chainCode: Uint8Array;
};

const ED25519_CURVE = new TextEncoder().encode('ed25519 seed');
const HARDENED_OFFSET = 0x80000000;
const PATH_REGEX = /^m(\/[0-9]+')+$/;

function getMasterKeyFromSeed(seed: Uint8Array): Keys {
	const I = hmac(sha512, ED25519_CURVE, seed);
	return {
		key: I.slice(0, 32),
		chainCode: I.slice(32),
	};
}

function deriveChild({ key, chainCode }: Keys, index: number): Keys {
	const data = new Uint8Array(37);
	data[0] = 0x00;
	data.set(key, 1);
	const view = new DataView(data.buffer, data.byteOffset + 33, 4);
	view.setUint32(0, index);

	const I = hmac(sha512, chainCode, data);
	return {
		key: I.slice(0, 32),
		chainCode: I.slice(32),
	};
}

/**
 * SLIP-0010 ed25519 HD key derivation.
 *
 * @param path - Derivation path (e.g., "m/44'/501'/0'/0'"). All levels must be hardened.
 * @param seed - BIP-39 seed as hex string.
 * @returns The derived key and chain code.
 */
export function derivePath(path: string, seed: string): Keys {
	if (!PATH_REGEX.test(path)) {
		throw new Error('Invalid derivation path');
	}

	const seedBytes = hexToBytes(seed);
	const { key, chainCode } = getMasterKeyFromSeed(seedBytes);

	const segments = path
		.split('/')
		.slice(1)
		.map((s) => parseInt(s.replace("'", ''), 10));

	return segments.reduce(
		(parent, segment) => deriveChild(parent, segment + HARDENED_OFFSET),
		{ key, chainCode },
	);
}

function hexToBytes(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
	}
	return bytes;
}
