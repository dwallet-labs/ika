// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Curve } from '@ika.xyz/sdk';
import type { DestinationPlugin, DWallet, IkaContext } from '@ika.xyz/sdk/plugin';

import { createBitcoinAddressCache } from './address.js';
import { signCore } from './sign.js';
import type {
	BitcoinAddressOptions,
	BitcoinSignArgs,
	BitcoinSignedTx,
	BitcoinSignInput,
	BitcoinSupportedCurve,
} from './types.js';

/**
 * Client-extension shape on `ika.bitcoin.*` after `.use(btc())`. The `mode`
 * is required at sign and getAddress time — a dWallet can spend from any of
 * the four mode addresses (`p2pkh`, `p2wpkh`, `p2sh-p2wpkh`, `p2tr-script`),
 * so callers must say which one matches the UTXO being spent.
 *
 * Key-path Taproot is structurally unsupported because the Ika MPC cannot
 * tweak the dWallet's internal key (BIP-341); `p2tr-script` uses a NUMS
 * internal pubkey and signs the script-path leaf.
 */
export interface BitcoinDestinationClientExtend {
	readonly bitcoin: {
		sign(args: BitcoinSignArgs): Promise<BitcoinSignedTx>;
		getAddress(
			dWallet: DWallet<BitcoinSupportedCurve>,
			opts: BitcoinAddressOptions,
		): Promise<string>;
	};
}

export interface BitcoinDestinationDWalletExtend {
	readonly bitcoin: {
		getAddress(opts: BitcoinAddressOptions): Promise<string>;
		sign(input: BitcoinSignInput): Promise<BitcoinSignedTx>;
	};
}

/**
 * Bitcoin destination plugin. Supports four spending modes:
 *
 *   - `p2pkh`         legacy `1...` (ECDSA, legacy sighash, dsha256)
 *   - `p2wpkh`        native segwit `bc1q...` (ECDSA, BIP-143, dsha256)
 *   - `p2sh-p2wpkh`   nested segwit `3...` (ECDSA, BIP-143, dsha256)
 *   - `p2tr-script`   taproot `bc1p...` script path (Schnorr, BIP-341, sha256)
 *
 * Signed PSBT payloads can be passed to `ika.publish({ chain: 'bitcoin', ... })`
 * when `bitcoinPublisher` is also installed. `preimage`-mode payloads are
 * not broadcastable — the publisher refuses them at compile time.
 */
export function btc(): DestinationPlugin<
	'bitcoin',
	BitcoinSupportedCurve,
	BitcoinDestinationClientExtend,
	BitcoinDestinationDWalletExtend
> {
	let ctx: IkaContext | null = null;
	const cache = createBitcoinAddressCache();

	const extend: BitcoinDestinationClientExtend = {
		bitcoin: {
			sign: async ({ dWallet, ...input }) =>
				signCore(requireCtx(ctx), dWallet, input as BitcoinSignInput, cache),
			getAddress: async (dWallet, opts) =>
				cache.address(dWallet.curve, dWallet.publicOutput, opts.mode, opts.network),
		},
	};

	return {
		kind: 'destination',
		name: 'bitcoin',
		supportedCurves: [Curve.SECP256K1],
		extend,
		dWalletExtend: (dWallet) => ({
			bitcoin: {
				getAddress: (opts) =>
					cache.address(dWallet.curve, dWallet.publicOutput, opts.mode, opts.network),
				sign: (input) => signCore(requireCtx(ctx), dWallet, input, cache),
			},
		}),
		install(installCtx) {
			ctx = installCtx;
		},
	};
}

function requireCtx(ctx: IkaContext | null): IkaContext {
	if (!ctx) throw new Error("bitcoin destination: install hasn't run yet");
	return ctx;
}
