import { sha512 } from '@noble/hashes/sha2.js';

const L = 2n ** 252n + 27742317777372353535851937790883648493n;

/**
 * Convert a Solana ed25519 32-byte secret-key SEED into the canonical 32-byte
 * Ed25519 SCALAR (little-endian, < L) that Ika's `prepareImportedKeyDWalletVerification`
 * expects.
 *
 * RFC 8032 derives the signing scalar as `clamp(SHA512(seed)[0..32])`. That
 * value is in `[2^254 + 8, 2^255 - 8]`, well above the group order L. Reducing
 * mod L gives the canonical scalar that produces the same public key under
 * scalar*G.
 */
export function solanaSeedToCanonicalScalar(seed: Uint8Array): Uint8Array {
	if (seed.length !== 32) {
		throw new Error(`solanaSeedToCanonicalScalar: expected 32-byte seed, got ${seed.length}`);
	}
	const h = sha512(seed).slice(0, 32);
	// RFC 8032 clamping
	h[0] = h[0]! & 248;
	h[31] = (h[31]! & 127) | 64;
	// little-endian decode
	let val = 0n;
	for (let i = 31; i >= 0; i--) {
		val = (val << 8n) | BigInt(h[i]!);
	}
	val %= L;
	const out = new Uint8Array(32);
	for (let i = 0; i < 32; i++) {
		out[i] = Number(val & 0xffn);
		val >>= 8n;
	}
	return out;
}
