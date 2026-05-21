// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Curve } from '@ika.xyz/sdk';
import type { DestinationPlugin, DWallet, IkaContext } from '@ika.xyz/sdk/plugin';

import { createBitcoinAddressCache } from './address.js';
import { assembleSign, prepareSign, signCore } from './sign.js';
import type {
	BitcoinAddressOptions,
	BitcoinPrepareSignArgs,
	BitcoinPrepareSignResult,
	BitcoinSignArgs,
	BitcoinSignedTx,
	BitcoinSignInput,
	BitcoinSignPrep,
	BitcoinSupportedCurve,
} from './types.js';

/**
 * Chain-led convenience over the source's `createDWallet`. The Bitcoin
 * destination binds the curve to SECP256K1 since that's the only curve
 * Bitcoin supports.
 *
 * The resulting key can also sign for Ethereum (same curve). This is a
 * feature of the underlying protocol, not a bug — both chains use
 * SECP256K1, so one MPC key serves both.
 */
export interface BitcoinCreateDWalletInput {
	readonly kind: 'zero-trust' | 'shared' | 'imported-key' | 'imported-key-shared';
	readonly importedKey?: Uint8Array;
	readonly sessionIdentifier?: Uint8Array;
	readonly networkEncryptionKeyId?: string;
	readonly capRecipient?: string;
	readonly acknowledge?: 'i-understand-this-is-irreversible';
}

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
		/**
		 * Chain-led `createDWallet` sugar. Equivalent to calling the active
		 * source's `createDWallet({ curve: SECP256K1, ...input })`. Returns
		 * a `DWallet` already decorated with the bitcoin namespace, so
		 * `dWallet.bitcoin.getAddress(...)` works on the return value.
		 *
		 * Important: the resulting MPC key also signs for Ethereum and any
		 * other SECP256K1 chain. One key, many destinations.
		 */
		createDWallet(input: BitcoinCreateDWalletInput): Promise<DWallet<BitcoinSupportedCurve>>;
		sign(args: BitcoinSignArgs): Promise<BitcoinSignedTx>;
		getAddress(
			dWallet: DWallet<BitcoinSupportedCurve>,
			opts: BitcoinAddressOptions,
		): Promise<string>;
		/**
		 * Build the bytes-to-sign for a Bitcoin spend without submitting
		 * anything on chain. Returns `{ prep, preimage, plan }`: `prep` for
		 * `assembleSign`, `preimage` + `plan` for the custom Move flow that
		 * gates the actual `request_sign`. See {@link prepareSign}.
		 */
		prepareSign(args: BitcoinPrepareSignArgs): Promise<BitcoinPrepareSignResult>;
		/** Apply a network signature to a previously prepared payload. */
		assembleSign(prep: BitcoinSignPrep, signature: Uint8Array): Promise<BitcoinSignedTx>;
	};
}

export interface BitcoinDestinationDWalletExtend {
	readonly bitcoin: {
		getAddress(opts: BitcoinAddressOptions): Promise<string>;
		sign(input: BitcoinSignInput): Promise<BitcoinSignedTx>;
		/** See {@link BitcoinDestinationClientExtend.bitcoin.prepareSign}. */
		prepareSign(input: BitcoinSignInput): Promise<BitcoinPrepareSignResult>;
		/** See {@link BitcoinDestinationClientExtend.bitcoin.assembleSign}. */
		assembleSign(prep: BitcoinSignPrep, signature: Uint8Array): Promise<BitcoinSignedTx>;
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
			createDWallet: async (input) => {
				const c = requireCtx(ctx);
				const src = c.source;
				if (!src || !src.createDWallet) {
					throw new Error(
						'bitcoin.createDWallet: no source plugin with createDWallet is registered. ' +
							'Register a source (e.g. `suiSource(...)`) before calling this.',
					);
				}
				const dWallet = await src.createDWallet({ curve: Curve.SECP256K1, ...input });
				return c.client.decorate(dWallet) as Promise<DWallet<BitcoinSupportedCurve>>;
			},
			sign: async ({ dWallet, ...input }) =>
				signCore(requireCtx(ctx), dWallet, input as BitcoinSignInput, cache),
			getAddress: async (dWallet, opts) =>
				cache.address(dWallet.curve, dWallet.publicOutput, opts.mode, opts.network),
			prepareSign: async ({ dWallet, ...input }) =>
				prepareSign(dWallet, input as BitcoinSignInput, cache),
			assembleSign: assembleSign,
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
	if (!ctx) throw new Error("bitcoin destination: install hasn't run yet");
	return ctx;
}
