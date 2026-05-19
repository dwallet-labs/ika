// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { Curve, publicKeyFromDWalletOutput } from '@ika.xyz/sdk';
import type { Hex } from 'viem';
import { publicKeyToAddress } from 'viem/accounts';

import {
	bytesToHexLower,
	createCoalescingCache,
	type CoalescingCache,
} from '../../internal/cache.js';

/**
 * Ethereum addresses come from secp256k1 only. Ed25519/RISTRETTO dWallets are
 * not addressable on Ethereum — type-level narrowing keeps them out of the
 * destination's surface, this is the runtime guard.
 */
function assertSecp256k1(curve: Curve): void {
	if (curve !== Curve.SECP256K1) {
		throw new Error(`ethereum destination does not support curve ${curve}. Use SECP256K1.`);
	}
}

/**
 * Take whatever secp256k1 pubkey shape `publicKeyFromDWalletOutput` returns
 * (33-byte compressed today) and yield the 65-byte uncompressed form viem's
 * `publicKeyToAddress` expects.
 */
function toUncompressed(pubkey: Uint8Array): Uint8Array {
	if (pubkey.length === 65 && pubkey[0] === 0x04) return pubkey;
	return secp256k1.Point.fromBytes(pubkey).toBytes(false);
}

/**
 * One-shot, unmemoized Ethereum address derivation. Prefer
 * `createEthereumAddressCache()` on hot paths.
 */
export async function deriveEthereumAddress(
	curve: Curve,
	publicOutput: Uint8Array,
): Promise<Hex> {
	assertSecp256k1(curve);
	const pubkey = await publicKeyFromDWalletOutput(curve, publicOutput);
	const uncompressed = toUncompressed(pubkey);
	return publicKeyToAddress(('0x' + bytesToHexLower(uncompressed)) as Hex);
}

/** Cached uncompressed pubkey + address per dWallet. */
export interface EthereumAddressCache {
	address(curve: Curve, publicOutput: Uint8Array): Promise<Hex>;
	uncompressedPubkey(curve: Curve, publicOutput: Uint8Array): Promise<Uint8Array>;
}

/**
 * Per-destination derivation cache. Bounded LRU with first-miss coalescing
 * via the shared {@link createCoalescingCache} helper. Each destination
 * instance owns its own cache — nothing is shared across IkaClient
 * instances, so multi-tenant processes remain isolated.
 */
export function createEthereumAddressCache(): EthereumAddressCache {
	const pkCache: CoalescingCache<Uint8Array> = createCoalescingCache({
		clone: (v) => new Uint8Array(v),
	});
	const addrCache: CoalescingCache<Hex> = createCoalescingCache();
	const keyOf = (curve: Curve, bytes: Uint8Array): string =>
		curve + ':' + bytesToHexLower(bytes);

	const uncompressedPubkey = (curve: Curve, publicOutput: Uint8Array): Promise<Uint8Array> => {
		assertSecp256k1(curve);
		return pkCache.get(keyOf(curve, publicOutput), async () => {
			const pk = await publicKeyFromDWalletOutput(curve, publicOutput);
			return toUncompressed(pk);
		});
	};

	const address = (curve: Curve, publicOutput: Uint8Array): Promise<Hex> =>
		addrCache.get(keyOf(curve, publicOutput), async () => {
			const pk = await uncompressedPubkey(curve, publicOutput);
			return publicKeyToAddress(('0x' + bytesToHexLower(pk)) as Hex);
		});

	return { address, uncompressedPubkey };
}
