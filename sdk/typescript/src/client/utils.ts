import type { SuiObjectResponse } from '@mysten/sui/client';

import { InvalidObjectError } from './errors.js';

/**
 * Extract BCS (Binary Canonical Serialization) bytes from a Sui object response.
 * This function validates the response and extracts the serialized object data.
 *
 * @param resp - The Sui object response from a blockchain query
 * @returns The BCS-encoded bytes of the object
 * @throws {InvalidObjectError} If the response doesn't contain valid BCS data
 */
export function objResToBcs(resp: SuiObjectResponse): string {
	if (resp.data?.bcs?.dataType !== 'moveObject') {
		throw new InvalidObjectError(
			`Response bcs missing: ${JSON.stringify(resp.data?.type, null, 2)}`,
		);
	}

	return resp.data.bcs.bcsBytes;
}

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

	// Write the BigInt value as a BigInt64 (signed 64-bit integer)
	// or BigUint64 (unsigned 64-bit integer) depending on the context.
	// For u64, use setBigUint64.
	view.setBigUint64(0, bigIntValue, false); // false for big-endian

	// Return the Uint8Array representation of the buffer
	return new Uint8Array(buffer);
}

/**
 * Converts a string to a Uint8Array by encoding each character as its ASCII value.
 * This function is similar to encodeToASCII but with a more descriptive name.
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
