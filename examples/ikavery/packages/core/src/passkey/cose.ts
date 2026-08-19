import { p256 } from '@noble/curves/nist.js';

/**
 * Fallback path for browsers/authenticators that don't expose
 * `AuthenticatorAttestationResponse.getPublicKey()` (notably Firefox + 1Password
 * for ES256 credentials, where `getPublicKey()` returns null even though the
 * algorithm is supported).
 *
 * The attestationObject is always present and CBOR-encoded as
 *   { fmt: text, attStmt: map, authData: bytes }.
 * authData has a fixed binary header followed by — when the AT flag is set —
 * the AAGUID, the credentialId, and a CBOR-encoded COSE_Key. For ES256
 * (alg=-7, kty=EC2, crv=P-256) the COSE_Key carries the X / Y coords directly.
 *
 * Returns the same 33-byte compressed P-256 point that `spkiToCompressedP256`
 * produces, so callers can use either path interchangeably.
 */
export function extractEs256PubkeyFromAttestationObject(attestationObject: Uint8Array): Uint8Array {
	const reader = new CborReader(attestationObject);
	const top = reader.next();
	if (top.major !== 5) {
		throw new Error('attestationObject: expected top-level CBOR map');
	}
	const map = top.value as Map<unknown, unknown>;
	const authData = map.get('authData');
	if (!(authData instanceof Uint8Array)) {
		throw new Error('attestationObject: missing or non-bytes `authData` field');
	}

	// authData layout per WebAuthn:
	//   0..32   rpIdHash
	//   32      flags
	//   33..37  signCount (big-endian u32)
	//   37+     attestedCredentialData (only when AT flag (0x40) is set):
	//             aaguid(16) + credIdLen(2 BE) + credId(N) + COSE_Key (CBOR)
	if (authData.length < 37) {
		throw new Error(`authData: too short (${authData.length} bytes)`);
	}
	const flags = authData[32]!;
	if (!(flags & 0x40)) {
		throw new Error('authData: AT flag not set, no attestedCredentialData present');
	}
	const aaguidEnd = 37 + 16;
	if (authData.length < aaguidEnd + 2) {
		throw new Error('authData: truncated before credIdLen');
	}
	const credIdLen = (authData[aaguidEnd]! << 8) | authData[aaguidEnd + 1]!;
	const credIdEnd = aaguidEnd + 2 + credIdLen;
	if (authData.length < credIdEnd) {
		throw new Error('authData: truncated credentialId');
	}
	const cose = authData.subarray(credIdEnd);
	return cosePubkeyToCompressedP256(cose);
}

/**
 * Parse an ES256 COSE_Key (kty=EC2, alg=-7, crv=P-256) and return the 33-byte
 * compressed P-256 point. The point is validated by `@noble/curves`.
 */
export function cosePubkeyToCompressedP256(cose: Uint8Array): Uint8Array {
	const reader = new CborReader(cose);
	const top = reader.next();
	if (top.major !== 5) {
		throw new Error('COSE_Key: expected CBOR map');
	}
	const m = top.value as Map<unknown, unknown>;
	const kty = m.get(1);
	const alg = m.get(3);
	const crv = m.get(-1);
	const x = m.get(-2);
	const y = m.get(-3);
	if (kty !== 2) {
		throw new Error(`COSE_Key: expected kty=EC2 (2), got ${String(kty)}`);
	}
	if (alg !== -7) {
		throw new Error(`COSE_Key: expected alg=ES256 (-7), got ${String(alg)}`);
	}
	if (crv !== 1) {
		throw new Error(`COSE_Key: expected crv=P-256 (1), got ${String(crv)}`);
	}
	if (!(x instanceof Uint8Array) || x.length !== 32) {
		throw new Error('COSE_Key: bad X coordinate');
	}
	if (!(y instanceof Uint8Array) || y.length !== 32) {
		throw new Error('COSE_Key: bad Y coordinate');
	}
	const uncompressed = new Uint8Array(65);
	uncompressed[0] = 0x04;
	uncompressed.set(x, 1);
	uncompressed.set(y, 33);
	return p256.Point.fromBytes(uncompressed).toBytes(true);
}

/**
 * Minimal CBOR reader covering only the major types we encounter in WebAuthn
 * attestation objects and COSE_Keys: unsigned int, negative int, byte string,
 * text string, array, map. Floats, tags, and indefinite-length items are not
 * supported and would throw.
 */
class CborReader {
	constructor(
		private buf: Uint8Array,
		private pos = 0,
	) {}

	next(): { major: number; value: unknown } {
		if (this.pos >= this.buf.length) {
			throw new Error('CBOR: unexpected end of input');
		}
		const head = this.buf[this.pos]!;
		this.pos += 1;
		const major = head >> 5;
		const ai = head & 0x1f;
		switch (major) {
			case 0:
				return { major, value: this.readUint(ai) };
			case 1:
				return { major, value: -1 - this.readUint(ai) };
			case 2: {
				const len = this.readUint(ai);
				const v = this.buf.subarray(this.pos, this.pos + len);
				this.pos += len;
				return { major, value: v };
			}
			case 3: {
				const len = this.readUint(ai);
				const bytes = this.buf.subarray(this.pos, this.pos + len);
				this.pos += len;
				return { major, value: new TextDecoder().decode(bytes) };
			}
			case 4: {
				const n = this.readUint(ai);
				const arr: unknown[] = [];
				for (let i = 0; i < n; i++) arr.push(this.next().value);
				return { major, value: arr };
			}
			case 5: {
				const n = this.readUint(ai);
				const m = new Map<unknown, unknown>();
				for (let i = 0; i < n; i++) {
					const k = this.next().value;
					const v = this.next().value;
					m.set(k, v);
				}
				return { major, value: m };
			}
			default:
				throw new Error(`CBOR: unsupported major type ${major}`);
		}
	}

	private readUint(ai: number): number {
		if (ai < 24) return ai;
		if (ai === 24) {
			const v = this.buf[this.pos]!;
			this.pos += 1;
			return v;
		}
		if (ai === 25) {
			const v = (this.buf[this.pos]! << 8) | this.buf[this.pos + 1]!;
			this.pos += 2;
			return v;
		}
		if (ai === 26) {
			const v =
				this.buf[this.pos]! * 0x1000000 +
				((this.buf[this.pos + 1]! << 16) |
					(this.buf[this.pos + 2]! << 8) |
					this.buf[this.pos + 3]!);
			this.pos += 4;
			return v;
		}
		throw new Error(`CBOR: unsupported additional info ${ai}`);
	}
}
