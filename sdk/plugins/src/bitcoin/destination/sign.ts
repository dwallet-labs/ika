// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Curve } from '@ika.xyz/sdk';
import type { BaseSignResult, DWallet, IkaContext } from '@ika.xyz/sdk/plugin';

import type { BitcoinAddressCache } from './address.js';
import { modeHandlerFor, type BitcoinModeHandler } from './modes.js';
import type { BitcoinSignedPayload, BitcoinSignedTx, BitcoinSignInput } from './types.js';

/**
 * Sign-flow dispatcher. Selects the mode handler, builds the preimage,
 * forwards it through the active source's `signMessage`, and either:
 *
 *   - For `kind: 'psbt'` — applies the signature back into the PSBT, calls
 *     `finalizeInput`, and returns the signed tx hex + txid.
 *   - For `kind: 'preimage'` — returns the raw signature for the caller to
 *     do whatever they want with it (multisig contract submission, etc.).
 *
 * The actual MPC call goes through `ctx.source.signMessage`, so any source
 * plugin that satisfies the contract works. Overrides (`presign`,
 * `encryptedShareId`, `dWalletCap`, ...) are forwarded verbatim.
 */
export async function signCore(
	ctx: IkaContext,
	dWallet: DWallet,
	input: BitcoinSignInput,
	cache: BitcoinAddressCache,
): Promise<BitcoinSignedTx> {
	if (!ctx.source) {
		throw new Error('bitcoin destination: no source plugin registered');
	}
	if (dWallet.curve !== Curve.SECP256K1) {
		throw new Error(
			`bitcoin destination does not support curve ${dWallet.curve}. Use SECP256K1.`,
		);
	}

	const handler = modeHandlerFor(input.mode);
	const compressedPubkey = await cache.compressedPubkey(dWallet.curve, dWallet.publicOutput);

	if (input.kind === 'preimage') {
		const signature = await signWithSource(ctx, dWallet, handler, input.preimage, input);
		return {
			chain: 'bitcoin',
			payload: { kind: 'preimage', signature, mode: input.mode },
		};
	}

	const p2trBundle =
		input.mode === 'p2tr-script'
			? await cache.p2trBundle(dWallet.curve, dWallet.publicOutput, input.network)
			: undefined;
	const hashType = input.hashType ?? handler.defaultHashType;

	const preimage = handler.buildPreimage({
		psbt: input.psbt,
		inputIndex: input.inputIndex,
		compressedPubkey,
		p2trBundle,
		hashType,
	});

	const signature = await signWithSource(ctx, dWallet, handler, preimage, input);

	handler.applySignature({
		psbt: input.psbt,
		inputIndex: input.inputIndex,
		compressedPubkey,
		signature,
		hashType,
		p2trBundle,
	});

	input.psbt.finalizeInput(input.inputIndex);
	const tx = input.psbt.extractTransaction();
	const sender = await cache.address(
		dWallet.curve,
		dWallet.publicOutput,
		input.mode,
		input.network,
	);

	const payload: BitcoinSignedPayload = {
		kind: 'psbt',
		psbt: input.psbt,
		signedTxHex: tx.toHex(),
		txid: tx.getId(),
		network: input.network,
		mode: input.mode,
		sender,
	};
	return { chain: 'bitcoin', payload };
}

async function signWithSource(
	ctx: IkaContext,
	dWallet: DWallet,
	handler: BitcoinModeHandler,
	message: Uint8Array,
	input: BitcoinSignInput,
): Promise<Uint8Array> {
	const overrides = pickOverrides(input);
	const result: BaseSignResult = await ctx.source!.signMessage({
		dWallet,
		message,
		curve: Curve.SECP256K1,
		signatureAlgorithm: handler.plan.signatureAlgorithm,
		hash: handler.plan.hash,
		...overrides,
	} as Parameters<NonNullable<IkaContext['source']>['signMessage']>[0]);
	return new Uint8Array(result.signature);
}

function pickOverrides(input: BitcoinSignInput): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	if (input.userShareEncryptionKeys) out.userShareEncryptionKeys = input.userShareEncryptionKeys;
	if (input.presign) out.presign = input.presign;
	if (input.encryptedShareId) out.encryptedShareId = input.encryptedShareId;
	if (input.dWalletCap) out.dWalletCap = input.dWalletCap;
	if (input.buildApproval) out.buildApproval = input.buildApproval;
	if (input.buildVerifiedPresignCap) out.buildVerifiedPresignCap = input.buildVerifiedPresignCap;
	return out;
}
