// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Curve } from '@ika.xyz/sdk';
import type { DestinationPlugin, DWallet, IkaContext } from '@ika.xyz/sdk/plugin';

import { createSolanaAddressCache } from './address.js';
import { signCore } from './sign.js';
import type {
	SolanaSignArgs,
	SolanaSignedTx,
	SolanaSignInput,
	SolanaSupportedCurve,
} from './types.js';

/**
 * Client-extension shape on `ika.solana.*`. Both methods narrow `dWallet` to
 * Ed25519 at the type level.
 */
export interface SolanaDestinationClientExtend {
	readonly solana: {
		sign(args: SolanaSignArgs): Promise<SolanaSignedTx>;
		getAddress(dWallet: DWallet<SolanaSupportedCurve>): Promise<string>;
	};
}

/**
 * Per-dWallet decoration shape. Installed by `client.decorate(dWallet)`; never
 * present on a naked DWallet (no global declaration merging).
 */
export interface SolanaDestinationDWalletExtend {
	readonly solana: {
		getAddress(): Promise<string>;
		sign(input: SolanaSignInput): Promise<SolanaSignedTx>;
	};
}

/**
 * Solana destination plugin. Adds `ika.solana.sign` and `ika.solana.getAddress`
 * to the client surface, and contributes `solana.sign` / `solana.getAddress` to
 * the typed dWallet decoration shape for Ed25519 dWallets. Non-Ed25519 dWallets
 * are filtered out at decoration time.
 */
export function solana(): DestinationPlugin<
	'solana',
	SolanaSupportedCurve,
	SolanaDestinationClientExtend,
	SolanaDestinationDWalletExtend
> {
	let ctx: IkaContext | null = null;
	// Per-destination-instance cache; module-level singletons would leak
	// derived-address state across IkaClient instances.
	const cache = createSolanaAddressCache();

	const extend: SolanaDestinationClientExtend = {
		solana: {
			sign: async ({ dWallet, ...input }) =>
				signCore(requireCtx(ctx), dWallet, input as SolanaSignInput, cache),
			getAddress: async (dWallet: DWallet<SolanaSupportedCurve>) =>
				(await cache.publicKey(dWallet.publicOutput)).toBase58(),
		},
	};

	return {
		kind: 'destination',
		name: 'solana',
		supportedCurves: [Curve.ED25519],
		extend,
		dWalletExtend: (dWallet) => ({
			solana: {
				getAddress: async () => (await cache.publicKey(dWallet.publicOutput)).toBase58(),
				sign: (input) => signCore(requireCtx(ctx), dWallet, input, cache),
			},
		}),
		install(installCtx) {
			ctx = installCtx;
		},
	};
}

function requireCtx(ctx: IkaContext | null): IkaContext {
	if (!ctx) throw new Error("solana destination: install hasn't run yet");
	return ctx;
}
