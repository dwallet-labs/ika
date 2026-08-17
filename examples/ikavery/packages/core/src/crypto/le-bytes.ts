// Re-export audited utilities from `@noble/hashes/utils` so the rest of the
// SDK has a single import surface, plus our one Move-mirroring helper.
export { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';

/** Encode a u64 as little-endian 8 bytes. Mirrors Move-side `challenges::u64_to_le_bytes`. */
export function u64ToLeBytes(v: bigint | number): Uint8Array {
	const out = new Uint8Array(8);
	new DataView(out.buffer).setBigUint64(0, BigInt(v), true);
	return out;
}
