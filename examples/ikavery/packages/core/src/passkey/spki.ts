import { p256 } from '@noble/curves/nist.js';

/**
 * For ES256 (alg=-7) the WebAuthn `response.publicKey` is a 91-byte ASN.1
 * SubjectPublicKeyInfo with this exact prefix:
 *
 *   SEQUENCE(89) {
 *     SEQUENCE(19) {
 *       OID id-ecPublicKey   // 1.2.840.10045.2.1
 *       OID prime256v1       // 1.2.840.10045.3.1.7
 *     }
 *     BIT STRING(66) { 0x00, 0x04, X(32), Y(32) }   // 0x00 = no unused bits
 *   }
 *
 * Bytes 0..25 are the prefix; bytes 26..90 are the uncompressed point.
 */
const ES256_SPKI_PREFIX = new Uint8Array([
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
	0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
]);

/**
 * Parse a P-256 SubjectPublicKeyInfo (as returned by `getPublicKey()` /
 * `RegistrationResponseJSON.response.publicKey`) and return the 33-byte
 * compressed point form expected by Sui's `ecdsa_r1::secp256r1_verify`.
 *
 * Validation is done by `@noble/curves`'s point parser, so any non–on-curve
 * input is rejected.
 */
export function spkiToCompressedP256(spki: Uint8Array): Uint8Array {
	if (spki.length !== 91) {
		throw new Error(`SPKI: expected 91 bytes for ES256 P-256, got ${spki.length}`);
	}
	for (let i = 0; i < ES256_SPKI_PREFIX.length; i++) {
		if (spki[i] !== ES256_SPKI_PREFIX[i]) {
			throw new Error(`SPKI: ES256 prefix mismatch at byte ${i}`);
		}
	}
	const uncompressed = spki.subarray(26, 91);
	return p256.Point.fromBytes(uncompressed).toBytes(true);
}

/**
 * Convert an ASN.1 DER ECDSA signature to the 64-byte `r || s` form expected
 * by Sui's `ecdsa_r1::secp256r1_verify`. Delegates to `@noble/curves`.
 *
 * Normalizes to low-S form. Sui's `secp256r1_verify` is backed by fastcrypto
 * → RustCrypto's `p256` crate, which rejects high-S signatures (BIP-62 style)
 * as invalid. WebAuthn authenticators (notably Apple's) routinely emit
 * high-S signatures; without this normalization, ~half of all signatures
 * would fail on-chain `assertion::verify_signature` with EAssertionInvalid.
 */
export function derSigToCompactRaw64(der: Uint8Array): Uint8Array {
	const sig = p256.Signature.fromBytes(der, 'der');
	// @noble/curves v2 removed `normalizeS()`, so flip high-S by hand: s -> n - s.
	const normalized = sig.hasHighS() ? new p256.Signature(sig.r, p256.Point.CURVE().n - sig.s) : sig;
	return normalized.toBytes('compact');
}
