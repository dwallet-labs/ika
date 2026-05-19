// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { Hex } from 'viem';
import { Curve } from '@ika.xyz/sdk';
import type { DestinationPlugin, DWallet, IkaContext } from '@ika.xyz/sdk/plugin';

import { createEthereumAddressCache } from './address.js';
import { signCore } from './sign.js';
import type {
	EthereumSignArgs,
	EthereumSignedTx,
	EthereumSignInput,
	EthereumSupportedCurve,
} from './types.js';

/**
 * Client-extension shape on `ika.ethereum.*` after `.use(eth())`. Curve is
 * narrowed to secp256k1; passing ED25519/SECP256R1/RISTRETTO is a
 * compile-time error.
 */
export interface EthereumDestinationClientExtend {
	readonly ethereum: {
		/** Flat-args sign: `ika.ethereum.sign({ dWallet, kind: 'transaction', tx })`. */
		sign(args: EthereumSignArgs): Promise<EthereumSignedTx>;
		getAddress(dWallet: DWallet<EthereumSupportedCurve>): Promise<Hex>;
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
			sign: async ({ dWallet, ...input }) =>
				signCore(requireCtx(ctx), dWallet, input as EthereumSignInput, cache),
			getAddress: async (dWallet) => cache.address(dWallet.curve, dWallet.publicOutput),
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
