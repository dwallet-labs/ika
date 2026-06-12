// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Minimal Bitcoin serialization helpers. bitcoinjs-lib's `BufferWriter` is
 * internal, so we recreate the small surface the preimage builders need.
 * All multi-byte writes are little-endian.
 */
export class BufferWriter {
	private offset = 0;
	constructor(public readonly buffer: Uint8Array) {}

	writeUInt8(n: number): void {
		this.buffer[this.offset] = n & 0xff;
		this.offset += 1;
	}

	writeUInt32LE(n: number): void {
		const v = new DataView(this.buffer.buffer, this.buffer.byteOffset + this.offset, 4);
		v.setUint32(0, n >>> 0, true);
		this.offset += 4;
	}

	writeInt32LE(n: number): void {
		const v = new DataView(this.buffer.buffer, this.buffer.byteOffset + this.offset, 4);
		v.setInt32(0, n | 0, true);
		this.offset += 4;
	}

	writeInt64LE(n: bigint): void {
		const v = new DataView(this.buffer.buffer, this.buffer.byteOffset + this.offset, 8);
		v.setBigInt64(0, BigInt(n), true);
		this.offset += 8;
	}

	writeUInt64LE(n: bigint): void {
		const v = new DataView(this.buffer.buffer, this.buffer.byteOffset + this.offset, 8);
		v.setBigUint64(0, BigInt(n), true);
		this.offset += 8;
	}

	writeSlice(bytes: Uint8Array): void {
		this.buffer.set(bytes, this.offset);
		this.offset += bytes.length;
	}

	writeVarInt(n: number): void {
		if (n < 0xfd) {
			this.writeUInt8(n);
		} else if (n <= 0xffff) {
			this.writeUInt8(0xfd);
			const v = new DataView(this.buffer.buffer, this.buffer.byteOffset + this.offset, 2);
			v.setUint16(0, n, true);
			this.offset += 2;
		} else if (n <= 0xffffffff) {
			this.writeUInt8(0xfe);
			this.writeUInt32LE(n);
		} else {
			this.writeUInt8(0xff);
			this.writeUInt64LE(BigInt(n));
		}
	}

	writeVarSlice(bytes: Uint8Array): void {
		this.writeVarInt(bytes.length);
		this.writeSlice(bytes);
	}
}

export function varIntSize(n: number): number {
	if (n < 0xfd) return 1;
	if (n <= 0xffff) return 3;
	if (n <= 0xffffffff) return 5;
	return 9;
}

export function varSliceSize(bytes: Uint8Array): number {
	return varIntSize(bytes.length) + bytes.length;
}

/** Lowercase hex; tiny, dependency-free. */
export function bytesToHex(b: Uint8Array): string {
	return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}
