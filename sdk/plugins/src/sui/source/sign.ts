// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { IkaTransaction } from '@ika.xyz/sdk';
import type {
	IkaClient as CoreIkaClient,
	Curve,
	Hash,
	ImportedKeyDWallet,
	ImportedSharedDWallet,
	Presign,
	SharedDWallet,
	SignatureAlgorithm,
	ZeroTrustDWallet,
} from '@ika.xyz/sdk';
import { Transaction } from '@mysten/sui/transactions';
import type { TransactionObjectArgument } from '@mysten/sui/transactions';

import type { SuiDWallet } from './dwallet.js';
import { findEvent, parseSignEvent } from './events.js';
import type { makeExec, makePay } from './execute.js';
import { presignForSign } from './presign.js';
import type { PresignCtx } from './presign.js';
import type {
	RequestSignInput,
	SuiSignMessageInput,
	SuiSignResult,
	SuiSourceDefaults,
} from './types.js';
import { resolveUsek } from './usek.js';

export interface SignCtx extends PresignCtx {
	readonly defaults: SuiSourceDefaults;
	readonly ikaClient: CoreIkaClient;
	readonly pay: ReturnType<typeof makePay>;
	readonly exec: ReturnType<typeof makeExec>;
}

/**
 * Args for `composeSign`, which adds a sign Move call to an existing
 * `IkaTransaction` without executing.
 *
 * Use this to compose the sign step with custom approval logic (multisig cap,
 * sponsored approval from a separate Move module) or with a pre-verified
 * presign cap from an upstream flow.
 *
 *   - `messageApproval` (optional): pre-built approval `TransactionObjectArgument`.
 *     If omitted, `composeSign` builds the standard approval internally using
 *     `dWalletCap` (or `dWallet.dWalletCapId`).
 *   - `verifiedPresignCap` (optional): pre-verified cap from
 *     `ikaTx.verifyPresignCap(...)`. If omitted, `composeSign` verifies internally.
 *   - `ikaCoin` / `suiCoin`: required.
 *
 * Returns a promise because zero-trust and imported-key paths fetch the
 * encrypted user share from chain before the Move call.
 */
export interface ComposeSignArgs {
	readonly ikaTx: IkaTransaction;
	readonly dWallet: SuiDWallet;
	readonly message: Uint8Array;
	readonly curve: Curve;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly hash: Hash;
	readonly presign: Presign;
	readonly ikaCoin: TransactionObjectArgument;
	readonly suiCoin: TransactionObjectArgument;
	/** Pre-built approval. Takes precedence over `buildApproval`. */
	readonly messageApproval?: TransactionObjectArgument;
	/** Pre-verified presign cap. Takes precedence over `buildVerifiedPresignCap`. */
	readonly verifiedPresignCap?: TransactionObjectArgument;
	/** Approval builder. Invoked only when `messageApproval` is omitted. */
	readonly buildApproval?: (ikaTx: IkaTransaction, defaultCap: string) => TransactionObjectArgument;
	/** Presign-cap builder. Invoked only when `verifiedPresignCap` is omitted. */
	readonly buildVerifiedPresignCap?: (
		ikaTx: IkaTransaction,
		presign: Presign,
	) => TransactionObjectArgument;
	readonly dWalletCap?: string;
	readonly encryptedShareId?: string;
}

/**
 * Add the sign Move call to an existing `IkaTransaction`. Use when composing
 * sign with other ops in a single tx, or when supplying a pre-built approval
 * or verified presign cap from a custom flow.
 *
 * Does not execute the tx; the caller submits it (typically via
 * `ika.sui.transaction(...)`).
 */
export async function composeSign(ikaClient: CoreIkaClient, args: ComposeSignArgs): Promise<void> {
	const dWallet = args.dWallet;
	const raw = dWallet.raw;
	const kind = dWallet.kind;
	const isImported = kind === 'imported-key' || kind === 'imported-key-shared';
	const capRef = args.dWalletCap ?? dWallet.dWalletCapId;

	const verifiedPresignCap =
		args.verifiedPresignCap ??
		(args.buildVerifiedPresignCap
			? args.buildVerifiedPresignCap(args.ikaTx, args.presign)
			: args.ikaTx.verifyPresignCap({ presign: args.presign }));

	if (isImported) {
		const approval =
			args.messageApproval ??
			(args.buildApproval
				? args.buildApproval(args.ikaTx, capRef)
				: args.ikaTx.approveImportedKeyMessage({
						dWalletCap: capRef,
						curve: args.curve,
						signatureAlgorithm: args.signatureAlgorithm,
						hashScheme: args.hash,
						message: args.message,
					}));
		if (kind === 'imported-key-shared') {
			await args.ikaTx.requestSignWithImportedKey({
				dWallet: raw as ImportedSharedDWallet,
				importedKeyMessageApproval: approval,
				verifiedPresignCap,
				hashScheme: args.hash,
				presign: args.presign,
				message: args.message,
				signatureScheme: args.signatureAlgorithm,
				ikaCoin: args.ikaCoin,
				suiCoin: args.suiCoin,
			});
		} else {
			const encShareId = args.encryptedShareId ?? dWallet.encryptedShareId;
			if (!encShareId) {
				throw new Error(
					'imported-key sign requires `encryptedShareId`. Pass it explicitly or use a dWallet handle that carries it.',
				);
			}
			const encShare = await ikaClient.getEncryptedUserSecretKeyShare(encShareId);
			await args.ikaTx.requestSignWithImportedKey({
				dWallet: raw as ImportedKeyDWallet,
				importedKeyMessageApproval: approval,
				verifiedPresignCap,
				hashScheme: args.hash,
				presign: args.presign,
				encryptedUserSecretKeyShare: encShare,
				message: args.message,
				signatureScheme: args.signatureAlgorithm,
				ikaCoin: args.ikaCoin,
				suiCoin: args.suiCoin,
			});
		}
	} else {
		const approval =
			args.messageApproval ??
			(args.buildApproval
				? args.buildApproval(args.ikaTx, capRef)
				: args.ikaTx.approveMessage({
						dWalletCap: capRef,
						curve: args.curve,
						signatureAlgorithm: args.signatureAlgorithm,
						hashScheme: args.hash,
						message: args.message,
					}));
		if (kind === 'shared') {
			await args.ikaTx.requestSign({
				dWallet: raw as SharedDWallet,
				messageApproval: approval,
				verifiedPresignCap,
				hashScheme: args.hash,
				presign: args.presign,
				message: args.message,
				signatureScheme: args.signatureAlgorithm,
				ikaCoin: args.ikaCoin,
				suiCoin: args.suiCoin,
			});
		} else {
			const encShareId = args.encryptedShareId ?? dWallet.encryptedShareId;
			if (!encShareId) {
				throw new Error(
					'zero-trust sign requires `encryptedShareId`. Pass it explicitly or use a dWallet handle that carries it.',
				);
			}
			const encShare = await ikaClient.getEncryptedUserSecretKeyShare(encShareId);
			await args.ikaTx.requestSign({
				dWallet: raw as ZeroTrustDWallet,
				messageApproval: approval,
				verifiedPresignCap,
				hashScheme: args.hash,
				presign: args.presign,
				encryptedUserSecretKeyShare: encShare,
				message: args.message,
				signatureScheme: args.signatureAlgorithm,
				ikaCoin: args.ikaCoin,
				suiCoin: args.suiCoin,
			});
		}
	}
}

/**
 * Builds its own tx, requests a sign, waits for completion, returns the
 * `SuiSignResult`. The caller supplies everything except (optionally) the
 * presign, which is auto-fetched if omitted.
 *
 * For custom approval flows or pre-verified presign caps, use
 * `ika.sui.transaction(...)` with `composeSign` instead: `requestSign` owns
 * its tx and cannot accept tx-internal `TransactionObjectArgument` overrides.
 *
 * For zero-trust and imported-key dWallets, the encrypted user-share id is
 * required; it defaults to `dWallet.encryptedShareId` and may be overridden
 * via the `encryptedShareId` field.
 */
export async function requestSign(ctx: SignCtx, input: RequestSignInput): Promise<SuiSignResult> {
	const dWallet = input.dWallet;
	const kind = dWallet.kind;
	const needsUsek = kind === 'zero-trust' || kind === 'imported-key';

	// Auto-fetch a presign if not supplied. `presignForSign` picks the flavour
	// (per-dWallet vs global) per dWallet kind and signature algorithm.
	const presign =
		input.presign ??
		(await presignForSign(ctx, {
			dWallet,
			signatureAlgorithm: input.signatureAlgorithm,
			curve: input.curve,
			signal: input.signal,
		}));

	const tx = new Transaction();
	tx.setSender(ctx.defaults.signerAddress);
	const p = ctx.pay(tx);

	const usek = needsUsek
		? resolveUsek(ctx.defaults, input.userShareEncryptionKeys, `sign with ${kind} dWallet`)
		: undefined;

	const ikaTx = new IkaTransaction({
		ikaClient: ctx.ikaClient,
		transaction: tx,
		...(usek ? { userShareEncryptionKeys: usek } : {}),
	});

	await composeSign(ctx.ikaClient, {
		ikaTx,
		dWallet,
		message: input.message,
		curve: input.curve,
		signatureAlgorithm: input.signatureAlgorithm,
		hash: input.hash,
		presign,
		ikaCoin: p.ika,
		suiCoin: p.sui,
		dWalletCap: input.dWalletCap,
		encryptedShareId: input.encryptedShareId,
		buildApproval: input.buildApproval,
		buildVerifiedPresignCap: input.buildVerifiedPresignCap,
	});

	p.finalize();
	const result = await ctx.exec(tx);
	const signEv = parseSignEvent(findEvent(result, 'SignRequestEvent'));
	const signId = signEv.event_data.sign_id as string;
	const sign = await ctx.ikaClient.getSignInParticularState(
		signId,
		input.curve,
		input.signatureAlgorithm,
		'Completed',
		{ timeout: ctx.defaults.timeouts.sign, interval: 2000, signal: input.signal },
	);
	const completed = sign.state.Completed;
	if (!completed?.signature || completed.signature.length === 0) {
		// An empty signature flowing downstream would produce a transaction
		// the chain rejects with a misleading "invalid signature length"
		// error. Surface a clearer message at the source boundary.
		throw new Error(
			`Ika sign ${signId}: protocol returned a Completed state with no signature payload. ` +
				`This indicates a network/SDK mismatch.`,
		);
	}
	return {
		signature: Uint8Array.from(completed.signature),
		curve: input.curve,
		signatureAlgorithm: input.signatureAlgorithm,
		hash: input.hash,
		signId,
	};
}

/**
 * Source-surface entry point that destination plugins call into. Forwards
 * every override on `SuiSignMessageInput` to `requestSign` so destinations
 * pass through user-supplied customization (presign, USEK, approval hook,
 * etc.) without re-implementing it.
 */
export async function signMessage(
	ctx: SignCtx,
	input: SuiSignMessageInput,
): Promise<SuiSignResult> {
	return requestSign(ctx, {
		dWallet: input.dWallet,
		message: input.message,
		curve: input.curve,
		signatureAlgorithm: input.signatureAlgorithm,
		hash: input.hash,
		presign: input.presign,
		encryptedShareId: input.encryptedShareId,
		userShareEncryptionKeys: input.userShareEncryptionKeys,
		dWalletCap: input.dWalletCap,
		buildApproval: input.buildApproval,
		buildVerifiedPresignCap: input.buildVerifiedPresignCap,
		signal: input.signal,
	});
}
