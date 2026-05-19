// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { blake2b } from '@noble/hashes/blake2.js';
import { Curve, publicKeyFromDWalletOutput } from '@ika.xyz/sdk';
import type { SignatureScheme } from '@mysten/sui/cryptography';

import {
	bytesToHexLower,
	createCoalescingCache,
	type CoalescingCache,
} from '../../internal/cache.js';

/** Sui signature-scheme flag byte per curve. Used in address derivation and serialized-signature framing. */
export const SUI_SCHEME_FLAG: Record<Curve, number> = {
	[Curve.ED25519]: 0x00,
	[Curve.SECP256K1]: 0x01,
	[Curve.SECP256R1]: 0x02,
	[Curve.RISTRETTO]: 0xff, // Sentinel for unsupported curve; checked at the cache and derivation boundaries.
};

export const SUI_SCHEME_NAME: Record<Curve, SignatureScheme | undefined> = {
	[Curve.ED25519]: 'ED25519',
	[Curve.SECP256K1]: 'Secp256k1',
	[Curve.SECP256R1]: 'Secp256r1',
	[Curve.RISTRETTO]: undefined,
};

export interface SuiAddressCache {
	suiAddress(curve: Curve, publicOutput: Uint8Array): Promise<string>;
	publicKey(curve: Curve, publicOutput: Uint8Array): Promise<Uint8Array>;
}

/**
 * Per-instance derivation cache. Each destination plugin owns its own; nothing
 * is shared across IkaClient instances, so multi-tenant processes are isolated.
 *
 * Bounded LRU with first-miss coalescing via the shared
 * {@link createCoalescingCache} helper.
 */
export function createAddressCache(): SuiAddressCache {
	const publicKeyCache: CoalescingCache<Uint8Array> = createCoalescingCache({
		clone: (v) => new Uint8Array(v),
	});
	const addressCache: CoalescingCache<string> = createCoalescingCache();
	const cacheKey = (curve: Curve, bytes: Uint8Array): string =>
		curve + ':' + bytesToHexLower(bytes);

	const publicKey = (curve: Curve, publicOutput: Uint8Array): Promise<Uint8Array> =>
		publicKeyCache.get(cacheKey(curve, publicOutput), () =>
			publicKeyFromDWalletOutput(curve, publicOutput),
		);

	const suiAddress = (curve: Curve, publicOutput: Uint8Array): Promise<string> => {
		const flag = SUI_SCHEME_FLAG[curve];
		if (flag === undefined || flag === 0xff) {
			throw new Error(`curve ${curve} is not supported by Sui signing`);
		}
		return addressCache.get(cacheKey(curve, publicOutput), async () => {
			const pk = await publicKey(curve, publicOutput);
			const input = new Uint8Array(1 + pk.length);
			input[0] = flag;
			input.set(pk, 1);
			return `0x${bytesToHexLower(blake2b(input, { dkLen: 32 }))}`;
		});
	};

	return { suiAddress, publicKey };
}

/** One-shot, unmemoized Sui address derivation. Prefer `createAddressCache()` on hot paths. */
export async function deriveSuiAddress(curve: Curve, publicOutput: Uint8Array): Promise<string> {
	const flag = SUI_SCHEME_FLAG[curve];
	if (flag === undefined || flag === 0xff) {
		throw new Error(`curve ${curve} is not supported by Sui signing`);
	}
	const pk = await publicKeyFromDWalletOutput(curve, publicOutput);
	const input = new Uint8Array(1 + pk.length);
	input[0] = flag;
	input.set(pk, 1);
	return `0x${bytesToHexLower(blake2b(input, { dkLen: 32 }))}`;
}
