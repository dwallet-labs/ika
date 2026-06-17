// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Curve } from '@ika.xyz/sdk';
import type { DestinationPlugin, DWallet, IkaContext } from '@ika.xyz/sdk/plugin';

import { createSolanaAddressCache } from './address.js';
import { assembleSign, prepareSign, signCore } from './sign.js';
import type {
	SolanaPrepareSignArgs,
	SolanaPrepareSignResult,
	SolanaSignArgs,
	SolanaSignedTx,
	SolanaSignInput,
	SolanaSignPrep,
	SolanaSupportedCurve,
} from './types.js';

/**
 * Chain-led `createDWallet` sugar for Solana. Binds curve to ED25519.
 *
 * Note: Ed25519 is not compatible with the SECP256K1 chains (Bitcoin,
 * Ethereum). A Solana dWallet is single-chain in practice.
 */
export interface SolanaCreateDWalletInput {
	readonly kind: 'zero-trust' | 'shared' | 'imported-key' | 'imported-key-shared';
	readonly importedKey?: Uint8Array;
	readonly sessionIdentifier?: Uint8Array;
	readonly networkEncryptionKeyId?: string;
	readonly capRecipient?: string;
	readonly acknowledge?: 'i-understand-this-is-irreversible';
}

/**
 * Client-extension shape on `ika.solana.*`. Both methods narrow `dWallet` to
 * Ed25519 at the type level.
 */
export interface SolanaDestinationClientExtend {
	readonly solana: {
		/**
		 * Chain-led `createDWallet` sugar. Equivalent to the active source's
		 * `createDWallet({ curve: ED25519, ...input })`.
		 */
		createDWallet(input: SolanaCreateDWalletInput): Promise<DWallet<SolanaSupportedCurve>>;
		sign(args: SolanaSignArgs): Promise<SolanaSignedTx>;
		getAddress(dWallet: DWallet<SolanaSupportedCurve>): Promise<string>;
		/**
		 * Build the bytes-to-sign for a Solana payload WITHOUT submitting
		 * anything on chain. Pair with `assembleSign(prep, signature)` once a
		 * network signature is in hand. See the bitcoin destination's docs
		 * for the typical "hand-off to custom Move contract" flow.
		 */
		prepareSign(args: SolanaPrepareSignArgs): Promise<SolanaPrepareSignResult>;
		/** Apply a 64-byte Ed25519 network signature to a prepared payload. */
		assembleSign(prep: SolanaSignPrep, signature: Uint8Array): Promise<SolanaSignedTx>;
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
		/** See {@link SolanaDestinationClientExtend.solana.prepareSign}. */
		prepareSign(input: SolanaSignInput): Promise<SolanaPrepareSignResult>;
		/** See {@link SolanaDestinationClientExtend.solana.assembleSign}. */
		assembleSign(prep: SolanaSignPrep, signature: Uint8Array): Promise<SolanaSignedTx>;
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
			createDWallet: async (input) => {
				const c = requireCtx(ctx);
				const src = c.source;
				if (!src || !src.createDWallet) {
					throw new Error(
						'solana.createDWallet: no source plugin with createDWallet is registered. ' +
							'Register a source (e.g. `suiSource(...)`) before calling this.',
					);
				}
				const dWallet = await src.createDWallet({ curve: Curve.ED25519, ...input });
				return c.client.decorate(dWallet) as Promise<DWallet<SolanaSupportedCurve>>;
			},
			sign: async ({ dWallet, ...input }) =>
				signCore(requireCtx(ctx), dWallet, input as SolanaSignInput, cache),
			getAddress: async (dWallet: DWallet<SolanaSupportedCurve>) =>
				(await cache.publicKey(dWallet.publicOutput)).toBase58(),
			prepareSign: async ({ dWallet, ...input }) =>
				prepareSign(dWallet, input as SolanaSignInput, cache),
			assembleSign: assembleSign,
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
				prepareSign: (input) => prepareSign(dWallet, input, cache),
				assembleSign: assembleSign,
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
