// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Curve } from '@ika.xyz/sdk';
import type { DestinationPlugin, DWallet, IkaContext } from '@ika.xyz/sdk/plugin';
import type { Hex } from 'viem';

import { createEthereumAddressCache } from './address.js';
import { assembleSign, prepareSign, signCore } from './sign.js';
import type {
	EthereumPrepareSignArgs,
	EthereumPrepareSignResult,
	EthereumSignArgs,
	EthereumSignedTx,
	EthereumSignInput,
	EthereumSignPrep,
	EthereumSupportedCurve,
} from './types.js';

/**
 * Chain-led `createDWallet` sugar for Ethereum. Binds curve to SECP256K1.
 *
 * The resulting MPC key also signs for Bitcoin and any other SECP256K1
 * chain. One key, many destinations.
 */
export interface EthereumCreateDWalletInput {
	readonly kind: 'zero-trust' | 'shared' | 'imported-key' | 'imported-key-shared';
	readonly importedKey?: Uint8Array;
	readonly sessionIdentifier?: Uint8Array;
	readonly networkEncryptionKeyId?: string;
	readonly capRecipient?: string;
	readonly acknowledge?: 'i-understand-this-is-irreversible';
}

/**
 * Client-extension shape on `ika.ethereum.*` after `.use(eth())`. Curve is
 * narrowed to secp256k1; passing ED25519/SECP256R1/RISTRETTO is a
 * compile-time error.
 */
export interface EthereumDestinationClientExtend {
	readonly ethereum: {
		/**
		 * Chain-led `createDWallet` sugar. Equivalent to the active source's
		 * `createDWallet({ curve: SECP256K1, ...input })`. Returned dWallet
		 * is already decorated, so `dWallet.ethereum.getAddress()` works on
		 * the result.
		 */
		createDWallet(input: EthereumCreateDWalletInput): Promise<DWallet<EthereumSupportedCurve>>;
		/** Flat-args sign: `ika.ethereum.sign({ dWallet, kind: 'transaction', tx })`. */
		sign(args: EthereumSignArgs): Promise<EthereumSignedTx>;
		getAddress(dWallet: DWallet<EthereumSupportedCurve>): Promise<Hex>;
		/**
		 * Build the pre-keccak bytes + digest WITHOUT submitting anything on
		 * chain. Pair with `assembleSign` once a network signature is in hand.
		 * See the bitcoin destination's docs for the typical "hand-off to a
		 * custom Move contract" flow — the shape is the same across destinations.
		 */
		prepareSign(args: EthereumPrepareSignArgs): Promise<EthereumPrepareSignResult>;
		/** Apply a 64-byte (r||s) network signature to a previously prepared payload. */
		assembleSign(prep: EthereumSignPrep, signature: Uint8Array): Promise<EthereumSignedTx>;
	};
}

/**
 * Per-dWallet decoration shape. Installed on the handle returned from
 * `client.decorate(...)` (or auto-installed by surface methods that return a
 * dWallet).
 */
export interface EthereumDestinationDWalletExtend {
	readonly ethereum: {
		getAddress(): Promise<Hex>;
		sign(input: EthereumSignInput): Promise<EthereumSignedTx>;
		/** See {@link EthereumDestinationClientExtend.ethereum.prepareSign}. */
		prepareSign(input: EthereumSignInput): Promise<EthereumPrepareSignResult>;
		/** See {@link EthereumDestinationClientExtend.ethereum.assembleSign}. */
		assembleSign(prep: EthereumSignPrep, signature: Uint8Array): Promise<EthereumSignedTx>;
	};
}

/**
 * Ethereum destination plugin. Adds `ika.ethereum.sign` and
 * `ika.ethereum.getAddress` to the client surface, plus
 * `ethereum.sign` / `ethereum.getAddress` to decorated dWallet handles.
 *
 * `transaction` mode produces a serialized signed tx ready for
 * `eth_sendRawTransaction`; `message` mode produces an EIP-191 personal_sign
 * signature; `typedData` mode produces an EIP-712 signature.
 *
 * Signed transactions can be passed to `ika.publish({ chain: 'ethereum', ... })`
 * when `ethPublisher` is also installed. `message` / `typedData` payloads are
 * not broadcastable — the publisher refuses them at compile time.
 */
export function eth(): DestinationPlugin<
	'ethereum',
	EthereumSupportedCurve,
	EthereumDestinationClientExtend,
	EthereumDestinationDWalletExtend
> {
	let ctx: IkaContext | null = null;
	const cache = createEthereumAddressCache();

	const extend: EthereumDestinationClientExtend = {
		ethereum: {
			createDWallet: async (input) => {
				const c = requireCtx(ctx);
				const src = c.source;
				if (!src || !src.createDWallet) {
					throw new Error(
						'ethereum.createDWallet: no source plugin with createDWallet is registered. ' +
							'Register a source (e.g. `suiSource(...)`) before calling this.',
					);
				}
				const dWallet = await src.createDWallet({ curve: Curve.SECP256K1, ...input });
				return c.client.decorate(dWallet) as Promise<DWallet<EthereumSupportedCurve>>;
			},
			sign: async ({ dWallet, ...input }) =>
				signCore(requireCtx(ctx), dWallet, input as EthereumSignInput, cache),
			getAddress: async (dWallet) => cache.address(dWallet.curve, dWallet.publicOutput),
			prepareSign: async ({ dWallet, ...input }) =>
				prepareSign(dWallet, input as EthereumSignInput, cache),
			assembleSign: assembleSign,
		},
	};

	return {
		kind: 'destination',
		name: 'ethereum',
		supportedCurves: [Curve.SECP256K1],
		extend,
		dWalletExtend: (dWallet) => ({
			ethereum: {
				getAddress: () => cache.address(dWallet.curve, dWallet.publicOutput),
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
	if (!ctx) throw new Error("ethereum destination: install hasn't run yet");
	return ctx;
}
