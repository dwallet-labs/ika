import { SuiObjectResponse } from '@mysten/sui/client';

import { InvalidObjectError } from './errors';

export function objResToBcs(resp: SuiObjectResponse): string {
	if (resp.data?.bcs?.dataType !== 'moveObject') {
		throw new InvalidObjectError(`Response bcs missing: ${JSON.stringify(resp, null, 2)}`);
	}

	return resp.data.bcs.bcsBytes;
}

export function parseNumbersToBytes(numbers: number[] | undefined): Uint8Array {
	if (!numbers) {
		throw new Error('Numbers are undefined');
	}

	return new Uint8Array(numbers);
}

export function encodeToASCII(input: string): Uint8Array {
	const asciiValues: number[] = [];
	for (let i = 0; i < input.length; i++) {
		asciiValues.push(input.charCodeAt(i));
	}
	return Uint8Array.from(asciiValues);
}

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
 * Converts a string to a Uint8Array
 * @param input - The string to convert
 * @returns The Uint8Array representation of the string
 */
export function stringToUint8Array(input: string): Uint8Array {
	const asciiValues: number[] = [];

	for (let i = 0; i < input.length; i++) {
		asciiValues.push(input.charCodeAt(i));
	}

	return Uint8Array.from(asciiValues);
}
