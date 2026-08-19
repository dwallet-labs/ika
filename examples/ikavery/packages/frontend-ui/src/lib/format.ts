/** Truncate a long string in the middle: `0xabc…1234`. */
export function truncateAddress(address: string, head = 6, tail = 4): string {
	if (address.length <= head + tail + 1) return address;
	return `${address.slice(0, head)}…${address.slice(-tail)}`;
}

export function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
	const stripped = hex.startsWith('0x') ? hex.slice(2) : hex;
	if (stripped.length % 2 !== 0) {
		throw new Error('hex string must have even length');
	}
	const out = new Uint8Array(stripped.length / 2);
	for (let i = 0; i < out.length; i++) {
		const byte = stripped.slice(i * 2, i * 2 + 2);
		const parsed = Number.parseInt(byte, 16);
		if (Number.isNaN(parsed)) {
			throw new Error(`bad hex byte at offset ${i * 2}: ${byte}`);
		}
		out[i] = parsed;
	}
	return out;
}
