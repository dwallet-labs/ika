// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Encode a string to ASCII bytes.
 * Converts each character to its ASCII character code and returns as a Uint8Array.
 *
 * @param input - The string to encode to ASCII
 * @returns The ASCII-encoded bytes of the string
 */
export function encodeToASCII(input: string): Uint8Array {
	const asciiValues: number[] = [];
	for (let i = 0; i < input.length; i++) {
		asciiValues.push(input.charCodeAt(i));
	}
	return Uint8Array.from(asciiValues);
}

/**
 * Convert a 64-bit unsigned integer to bytes in big-endian format.
 * This function handles both number and bigint inputs and ensures proper 64-bit representation.
 *
 * @param value - The 64-bit unsigned integer value to convert (number or bigint)
 * @returns The value as an 8-byte Uint8Array in big-endian format
 */
export function u64ToBytesBigEndian(value: number | bigint): Uint8Array {
	// Ensure the input is a BigInt for accurate 64-bit operations
	const bigIntValue = BigInt(value);

	// Create an 8-byte (64-bit) ArrayBuffer
	const buffer = new ArrayBuffer(8);
	// Create a DataView to manipulate the buffer with specific endianness
	const view = new DataView(buffer);

	// Write the BigInt value as a BigUint64 (unsigned 64-bit integer)
	// For u64, use setBigUint64.
	view.setBigUint64(0, bigIntValue, false); // false for big-endian

	// Return the Uint8Array representation of the buffer
	return new Uint8Array(buffer);
}

/**
 * Converts a string to a Uint8Array by encoding each character as its ASCII value.
 *
 * @param input - The string to convert
 * @returns The Uint8Array representation of the string's ASCII values
 */
export function stringToUint8Array(input: string): Uint8Array {
	const asciiValues: number[] = [];

	for (let i = 0; i < input.length; i++) {
		asciiValues.push(input.charCodeAt(i));
	}

	return Uint8Array.from(asciiValues);
}

/**
 * Convert a Uint8Array to a hex string.
 *
 * @param bytes - The bytes to convert
 * @returns The hex string representation (without 0x prefix)
 */
export function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

/**
 * Convert a hex string to a Uint8Array.
 *
 * @param hex - The hex string to convert (with or without 0x prefix)
 * @returns The Uint8Array representation
 * @throws {Error} If the string contains non-hex characters or has odd length
 */
export function hexToBytes(hex: string): Uint8Array {
	const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
	if (cleanHex.length % 2 !== 0) {
		throw new Error(`Invalid hex string: odd length (${cleanHex.length})`);
	}
	if (cleanHex.length > 0 && !/^[0-9a-fA-F]+$/.test(cleanHex)) {
		throw new Error('Invalid hex string: contains non-hex characters');
	}
	const bytes = new Uint8Array(cleanHex.length / 2);
	for (let i = 0; i < cleanHex.length; i += 2) {
		bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
	}
	return bytes;
}
