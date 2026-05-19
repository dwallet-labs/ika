// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Curve } from '@ika.xyz/sdk';
import type { DestinationPlugin, DWallet, IkaContext } from '@ika.xyz/sdk/plugin';

import { createAddressCache } from './address.js';
import { signCore } from './sign.js';
import type { SuiSignArgs, SuiSignedTx, SuiSignInput, SuiSupportedCurve } from './types.js';

/**
 * Client-extension shape on `ika.sui.*` after `.use(sui())`. The `sign`
 * method narrows `dWallet` to a Sui-supported curve at the type level, so
 * passing RISTRETTO is a compile-time error.
 */
export interface SuiDestinationClientExtend {
	readonly sui: {
		/** Flat-args sign: `ika.sui.sign({ dWallet, kind: 'message', message })`. */
		sign(args: SuiSignArgs): Promise<SuiSignedTx>;
		getAddress(dWallet: DWallet<SuiSupportedCurve>): Promise<string>;
	};
}

/**
 * Per-dWallet decoration shape. Installed on a dWallet handle by
 * `ika.decorate(dWallet)` or by extend-surface methods that auto-decorate.
 * There is no global declaration merging; the merged shape lives only on
 * decorated handles.
 */
export interface SuiDestinationDWalletExtend {
	readonly sui: {
		/** Derive this dWallet's Sui address. Cached per destination instance. */
		getAddress(): Promise<string>;
		sign(input: SuiSignInput): Promise<SuiSignedTx>;
	};
}

/**
 * Sui destination plugin. Adds `ika.sui.sign` and `ika.sui.getAddress` to the
 * client surface and contributes `sui.sign` / `sui.getAddress` to the typed
 * dWallet decoration shape.
 */
export function sui(): DestinationPlugin<
	'sui',
	SuiSupportedCurve,
	SuiDestinationClientExtend,
	SuiDestinationDWalletExtend
> {
	// `ctx` is captured at install time. The `IkaContext` is stable and
	// `ctx.source` is a getter, so capturing once does not freeze the source
	// reference.
	let ctx: IkaContext | null = null;
	// Per-destination-instance cache; a module-level singleton would leak
	// derived-address state across IkaClient instances.
	const cache = createAddressCache();

	const extend: SuiDestinationClientExtend = {
		sui: {
			sign: async ({ dWallet, ...input }) =>
				signCore(requireCtx(ctx), dWallet, input as SuiSignInput, cache),
			getAddress: async (dWallet: DWallet<SuiSupportedCurve>) =>
				cache.suiAddress(dWallet.curve, dWallet.publicOutput),
		},
	};

	return {
		kind: 'destination',
		name: 'sui',
		supportedCurves: [Curve.ED25519, Curve.SECP256K1, Curve.SECP256R1],
		extend,
		dWalletExtend: (dWallet) => ({
			sui: {
				getAddress: () => cache.suiAddress(dWallet.curve, dWallet.publicOutput),
				sign: (input) => signCore(requireCtx(ctx), dWallet, input, cache),
			},
		}),
		install(installCtx) {
			ctx = installCtx;
		},
	};
}

function requireCtx(ctx: IkaContext | null): IkaContext {
	if (!ctx) throw new Error("sui destination: install hasn't run yet");
	return ctx;
}
