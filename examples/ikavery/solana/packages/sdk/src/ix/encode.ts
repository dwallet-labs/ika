/**
 * Wire-format encoders for ikavery instructions.
 *
 * The on-chain handler reads ix args via Quasar's `#[instruction]` macro,
 * which pointer-casts a `repr(C)` zeropod struct over the data buffer.
 * Primitives are stored little-endian, fixed arrays inline. There's no
 * length prefix on `[u8; N]` — sizes are baked into the schema.
 */

export function writeU8(out: Uint8Array, off: number, v: number): number {
	out[off] = v & 0xff;
	return off + 1;
}

export function writeU16le(out: Uint8Array, off: number, v: number): number {
	out[off] = v & 0xff;
	out[off + 1] = (v >>> 8) & 0xff;
	return off + 2;
}

export function writeU32le(out: Uint8Array, off: number, v: number): number {
	out[off] = v & 0xff;
	out[off + 1] = (v >>> 8) & 0xff;
	out[off + 2] = (v >>> 16) & 0xff;
	out[off + 3] = (v >>> 24) & 0xff;
	return off + 4;
}

/** Write a fixed-length byte array verbatim, asserting exact length. */
export function writeBytes(
	out: Uint8Array,
	off: number,
	bytes: Uint8Array,
	expectedLen: number,
): number {
	if (bytes.length !== expectedLen) {
		throw new Error(`expected ${expectedLen}b, got ${bytes.length}b`);
	}
	out.set(bytes, off);
	return off + expectedLen;
}

/** Pad a variable-length payload into a fixed-length buffer (zero-fill tail). */
export function padInto(out: Uint8Array, off: number, payload: Uint8Array, bufLen: number): number {
	if (payload.length > bufLen) {
		throw new Error(`payload ${payload.length}b exceeds ${bufLen}b buffer`);
	}
	out.set(payload, off);
	return off + bufLen;
}

/** Concatenate byte chunks into one buffer. */
export function concat(...chunks: Uint8Array[]): Uint8Array {
	const total = chunks.reduce((acc, c) => acc + c.length, 0);
	const out = new Uint8Array(total);
	let off = 0;
	for (const c of chunks) {
		out.set(c, off);
		off += c.length;
	}
	return out;
}
