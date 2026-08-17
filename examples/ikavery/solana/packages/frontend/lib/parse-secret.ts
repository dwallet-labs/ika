import bs58 from 'bs58';

export type ParsedSecret =
	{ ok: true; bytes: Uint8Array; publicKey: string } | { ok: false; error: string };

/**
 * Accepts the three formats devs realistically paste:
 *   - JSON array (Solana CLI keypair: `[1, 2, 3, …]`)
 *   - Hex string (with or without 0x prefix; 32 or 64 bytes)
 *   - Base58 string (Phantom export, 64 bytes; or 32-byte seed)
 *
 * 64-byte expanded form: the last 32 bytes ARE the public key — surface
 * directly. 32-byte seed: skip ed25519 derivation here (avoids loading
 * `@noble/ed25519` on this page) and surface a placeholder. The actual
 * derivation runs server-side at seal time anyway.
 */
export function parseSolanaSecret(input: string): ParsedSecret {
	const trimmed = input.trim();
	if (!trimmed) return { ok: false, error: 'Empty input.' };

	if (trimmed.startsWith('[')) {
		try {
			const arr = JSON.parse(trimmed) as number[];
			if (!Array.isArray(arr) || !arr.every((n) => typeof n === 'number' && n >= 0 && n <= 255)) {
				return {
					ok: false,
					error: 'JSON array must contain only 0-255 integers.',
				};
			}
			if (arr.length !== 32 && arr.length !== 64) {
				return {
					ok: false,
					error: `JSON array must be 32 or 64 bytes, got ${arr.length}.`,
				};
			}
			const bytes = new Uint8Array(arr);
			return { ok: true, bytes, publicKey: derivePublicKey(bytes) };
		} catch {
			return {
				ok: false,
				error: 'Invalid JSON. Use the Solana CLI keypair format.',
			};
		}
	}

	if (/^(0x)?[0-9a-fA-F]+$/.test(trimmed)) {
		const clean = trimmed.startsWith('0x') ? trimmed.slice(2) : trimmed;
		if (clean.length === 64 || clean.length === 128) {
			const bytes = new Uint8Array(clean.length / 2);
			for (let i = 0; i < bytes.length; i++) {
				bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
			}
			return { ok: true, bytes, publicKey: derivePublicKey(bytes) };
		}
	}

	// base58 — Phantom-exported secrets are 64-byte base58.
	try {
		const bytes = bs58.decode(trimmed);
		if (bytes.length !== 32 && bytes.length !== 64) {
			return {
				ok: false,
				error: `Decoded ${bytes.length} bytes; need 32 or 64.`,
			};
		}
		return { ok: true, bytes, publicKey: derivePublicKey(bytes) };
	} catch (e) {
		return {
			ok: false,
			error:
				e instanceof Error ? `Could not decode as base58: ${e.message}` : 'Could not decode input.',
		};
	}
}

function derivePublicKey(bytes: Uint8Array): string {
	if (bytes.length === 64) return bs58.encode(bytes.slice(32));
	return '(seed only — public key derived at import)';
}

/**
 * Generate a fresh ed25519 keypair (random 32-byte seed concatenated with
 * its derived public key). Used by /setup/key's "Generate a demo key" CTA;
 * never call this with anything you'd want to keep.
 */
export async function generateDemoSecret(): Promise<string> {
	// Lazy-load curves so the page bundle stays lean if the user pastes a key.
	const { ed25519 } = await import('@noble/curves/ed25519');
	const seed = crypto.getRandomValues(new Uint8Array(32));
	const pub = ed25519.getPublicKey(seed);
	const expanded = new Uint8Array(64);
	expanded.set(seed, 0);
	expanded.set(pub, 32);
	return bs58.encode(expanded);
}
