// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { PublicKey } from '@solana/web3.js';
import { Curve, publicKeyFromDWalletOutput } from '@ika.xyz/sdk';

import {
	bytesToHexLower,
	createCoalescingCache,
	type CoalescingCache,
} from '../../internal/cache.js';

/**
 * Length check on the dWallet `publicOutput` before WASM derivation. Catches
 * obviously-wrong inputs with an actionable error instead of producing a
 * 32-byte Solana address from garbage. The length check is necessary but not
 * sufficient; the WASM output is re-validated below.
 */
function assertValidEd25519PublicOutput(publicOutput: Uint8Array): void {
	if (publicOutput.byteLength < 32) {
		throw new Error(
			`solana destination: dWallet publicOutput must be at least 32 bytes for Ed25519 ` +
				`(got ${publicOutput.byteLength}). This dWallet was not created for ED25519, ` +
				`or its data is corrupted.`,
		);
	}
}

function assertEd25519RawKey(raw: Uint8Array): void {
	if (raw.byteLength !== 32) {
		throw new Error(
			`solana destination: derived Ed25519 raw key has ${raw.byteLength} bytes, expected 32. ` +
				`This usually means the dWallet's curve does not actually decode as Ed25519.`,
		);
	}
}

export interface SolanaAddressCache {
	publicKey(publicOutput: Uint8Array): Promise<PublicKey>;
}

/**
 * Per-instance derivation cache. Bounded LRU with first-miss coalescing via
 * the shared {@link createCoalescingCache} helper. Each destination plugin
 * owns its own — nothing is shared across IkaClient instances.
 */
export function createSolanaAddressCache(): SolanaAddressCache {
	const cache: CoalescingCache<PublicKey> = createCoalescingCache();
	return {
		publicKey: (publicOutput: Uint8Array): Promise<PublicKey> => {
			assertValidEd25519PublicOutput(publicOutput);
			return cache.get(bytesToHexLower(publicOutput), async () => {
				const raw = await publicKeyFromDWalletOutput(Curve.ED25519, publicOutput);
				assertEd25519RawKey(raw);
				return new PublicKey(raw);
			});
		},
	};
}

/** One-shot, unmemoized Solana public-key derivation. Prefer `createSolanaAddressCache()` on hot paths. */
export async function deriveSolanaPublicKey(publicOutput: Uint8Array): Promise<PublicKey> {
	assertValidEd25519PublicOutput(publicOutput);
	const raw = await publicKeyFromDWalletOutput(Curve.ED25519, publicOutput);
	assertEd25519RawKey(raw);
	return new PublicKey(raw);
}
