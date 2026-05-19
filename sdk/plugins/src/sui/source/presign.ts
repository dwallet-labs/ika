// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Transaction } from '@mysten/sui/transactions';
import {
	type IkaClient as CoreIkaClient,
	IkaTransaction,
	type Presign,
} from '@ika.xyz/sdk';

import { findEvent, parsePresignEvent } from './events.js';
import type { makeExec, makePay } from './execute.js';
import type {
	RequestGlobalPresignInput,
	RequestPresignInput,
	SuiSourceDefaults,
} from './types.js';

export interface PresignCtx {
	readonly defaults: SuiSourceDefaults;
	readonly ikaClient: CoreIkaClient;
	readonly pay: ReturnType<typeof makePay>;
	readonly exec: ReturnType<typeof makeExec>;
}

/** Per-dWallet presign. Required for imported-key ECDSA; otherwise prefer `requestGlobalPresign`. */
export async function requestPresign(ctx: PresignCtx, input: RequestPresignInput): Promise<Presign> {
	const tx = new Transaction();
	tx.setSender(ctx.defaults.signerAddress);
	const p = ctx.pay(tx);
	const ikaTx = new IkaTransaction({ ikaClient: ctx.ikaClient, transaction: tx });
	const cap = ikaTx.requestPresign({
		dWallet: input.dWallet.raw,
		signatureAlgorithm: input.signatureAlgorithm,
		ikaCoin: p.ika,
		suiCoin: p.sui,
	});
	p.finalize(cap);
	const result = await ctx.exec(tx);
	const presignId = parsePresignEvent(findEvent(result, 'PresignRequestEvent')).event_data
		.presign_id;
	return ctx.ikaClient.getPresignInParticularState(presignId, 'Completed', {
		timeout: ctx.defaults.timeouts.presign,
		interval: 2000,
		signal: input.signal,
	});
}

/**
 * Global presign keyed by (curve, signatureAlgorithm). Faster for most use
 * cases. Cannot be used for imported-key ECDSA; use `requestPresign` there.
 */
export async function requestGlobalPresign(
	ctx: PresignCtx,
	input: RequestGlobalPresignInput,
): Promise<Presign> {
	const netKeyId =
		input.networkEncryptionKeyId ??
		(await ctx.ikaClient.getLatestNetworkEncryptionKey()).id;

	const tx = new Transaction();
	tx.setSender(ctx.defaults.signerAddress);
	const p = ctx.pay(tx);
	const ikaTx = new IkaTransaction({ ikaClient: ctx.ikaClient, transaction: tx });
	const cap = ikaTx.requestGlobalPresign({
		dwalletNetworkEncryptionKeyId: netKeyId,
		curve: input.curve,
		signatureAlgorithm: input.signatureAlgorithm,
		ikaCoin: p.ika,
		suiCoin: p.sui,
	});
	p.finalize(cap);
	const result = await ctx.exec(tx);
	const presignId = parsePresignEvent(findEvent(result, 'PresignRequestEvent')).event_data
		.presign_id;
	return ctx.ikaClient.getPresignInParticularState(presignId, 'Completed', {
		timeout: ctx.defaults.timeouts.presign,
		interval: 2000,
		signal: input.signal,
	});
}

/**
 * Picks the right presign flavour for a (dWallet, algo) pair. Used by the
 * high-level signMessage; surfaces it as the default so callers do not have
 * to think about presign type.
 */
export async function presignForSign(
	ctx: PresignCtx,
	args: {
		dWallet: RequestPresignInput['dWallet'];
		signatureAlgorithm: RequestPresignInput['signatureAlgorithm'];
		curve: RequestGlobalPresignInput['curve'];
		networkEncryptionKeyId?: string;
		signal?: AbortSignal;
	},
): Promise<Presign> {
	// Branches on the plugin-owned `dWallet.kind` (set by `wrap.ts`) rather
	// than the raw Move shape's `is_imported_key_dwallet` flag. The raw shape
	// is owned by the upstream Move struct and may rename fields.
	const isImported =
		args.dWallet.kind === 'imported-key' || args.dWallet.kind === 'imported-key-shared';
	const needsPerDWallet =
		isImported &&
		(args.signatureAlgorithm === 'ECDSASecp256k1' ||
			args.signatureAlgorithm === 'ECDSASecp256r1');
	if (needsPerDWallet) {
		return requestPresign(ctx, {
			dWallet: args.dWallet,
			signatureAlgorithm: args.signatureAlgorithm,
			signal: args.signal,
		});
	}
	return requestGlobalPresign(ctx, {
		curve: args.curve,
		signatureAlgorithm: args.signatureAlgorithm,
		networkEncryptionKeyId: args.networkEncryptionKeyId,
		signal: args.signal,
	});
}
