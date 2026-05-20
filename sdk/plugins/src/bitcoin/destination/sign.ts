// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Curve } from '@ika.xyz/sdk';
import type { BaseSignResult, DWallet, IkaContext } from '@ika.xyz/sdk/plugin';

import type { BitcoinAddressCache } from './address.js';
import { modeHandlerFor } from './modes.js';
import type { BitcoinModeHandler } from './modes.js';
import type {
	BitcoinPrepareSignResult,
	BitcoinSignedPayload,
	BitcoinSignedTx,
	BitcoinSignInput,
	BitcoinSignPrep,
} from './types.js';

/**
 * Build the bytes-to-sign for a Bitcoin spend WITHOUT submitting anything on
 * chain. Returns `{ prep, preimage, plan }`:
 *
 *   - `preimage` is what the MPC hashes-then-signs. Hand it to the Move
 *     flow that gates the actual `request_sign` call (multisig vote,
 *     future-sign release, sponsored relay, ...).
 *   - `plan` is the `(curve, signatureAlgorithm, hash)` the MPC will use.
 *     Pair with `ika.sui.prepareSign({ message: preimage, ...plan, ... })`
 *     to compute the user-side `userSignMessage`.
 *   - `prep` is the assemble context — pass it back to `assembleSign(prep,
 *     networkSignature)` once the network has produced a signature.
 *
 * `prep` does NOT carry `preimage` or `plan`. That keeps the assemble
 * context minimal and lets you reconstruct `prep` at execute-time from
 * persisted state (PSBT, dWallet pubkey, mode, network) without re-running
 * `prepareSign` and re-deriving the preimage.
 *
 * `sign(input)` is the one-shot wrapper: `prepareSign` → source
 * `signMessage` → `assembleSign`. Use prepare/assemble directly when the
 * sign request doesn't flow through the source's default `signMessage`
 * (e.g. the multisig pattern in `examples/multisig-bitcoin`).
 */
export async function prepareSign(
	dWallet: DWallet,
	input: BitcoinSignInput,
	cache: BitcoinAddressCache,
): Promise<BitcoinPrepareSignResult> {
	if (dWallet.curve !== Curve.SECP256K1) {
		throw new Error(`bitcoin destination does not support curve ${dWallet.curve}. Use SECP256K1.`);
	}
	const handler = modeHandlerFor(input.mode);
	const plan = {
		curve: Curve.SECP256K1 as Curve,
		signatureAlgorithm: handler.plan.signatureAlgorithm,
		hash: handler.plan.hash,
	};

	if (input.kind === 'preimage') {
		return {
			prep: { kind: 'preimage', mode: input.mode },
			preimage: input.preimage,
			plan,
		};
	}

	const compressedPubkey = await cache.compressedPubkey(dWallet.curve, dWallet.publicOutput);
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
	const sender = await cache.address(
		dWallet.curve,
		dWallet.publicOutput,
		input.mode,
		input.network,
	);

	return {
		prep: {
			kind: 'psbt',
			mode: input.mode,
			network: input.network,
			sender,
			psbt: input.psbt,
			inputIndex: input.inputIndex,
			hashType,
			compressedPubkey,
			p2trBundle,
		},
		preimage,
		plan,
	};
}

/**
 * Apply the network's signature to the prepared PSBT (or wrap it for
 * preimage-mode) and return the broadcast-ready payload. The signature
 * MUST be the raw bytes Ika returns (64B `r||s` for ECDSA modes, 64B
 * Schnorr for Taproot) — DER encoding, sighash-flag appending, and witness
 * packing all happen here.
 *
 * The `prep.psbt` reference is mutated in place: after `assembleSign` the
 * PSBT carries the signature, the input is finalized, and the tx is
 * extractable via `prep.psbt.extractTransaction()`. The returned payload's
 * `signedTxHex` is what you'd typically pass to `ika.publish(...)`.
 */
export async function assembleSign(
	prep: BitcoinSignPrep,
	signature: Uint8Array,
): Promise<BitcoinSignedTx> {
	if (prep.kind === 'preimage') {
		return {
			chain: 'bitcoin',
			payload: { kind: 'preimage', signature, mode: prep.mode },
		};
	}

	const handler = modeHandlerFor(prep.mode);
	handler.applySignature({
		psbt: prep.psbt,
		inputIndex: prep.inputIndex,
		compressedPubkey: prep.compressedPubkey,
		signature,
		hashType: prep.hashType,
		p2trBundle: prep.p2trBundle,
	});
	prep.psbt.finalizeInput(prep.inputIndex);
	const tx = prep.psbt.extractTransaction();
	const payload: BitcoinSignedPayload = {
		kind: 'psbt',
		psbt: prep.psbt,
		signedTxHex: tx.toHex(),
		txid: tx.getId(),
		network: prep.network,
		mode: prep.mode,
		sender: prep.sender,
	};
	return { chain: 'bitcoin', payload };
}

/**
 * One-shot sign: builds the preimage, asks the active source to produce a
 * signature, applies the signature back into the PSBT (or returns it raw
 * for preimage-mode). Equivalent to `prepareSign` → `ctx.source.signMessage`
 * → `assembleSign` and that's exactly the composition used here. Drop down
 * to the explicit prepare/assemble pair when the sign request doesn't go
 * through `ctx.source.signMessage` directly.
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
	const { prep, preimage } = await prepareSign(dWallet, input, cache);
	const handler = modeHandlerFor(input.mode);
	const signature = await signWithSource(ctx, dWallet, handler, preimage, input);
	return assembleSign(prep, signature);
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
