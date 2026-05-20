// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { IkaTransaction } from '@ika.xyz/sdk';
import type {
	IkaClient as CoreIkaClient,
	Curve,
	Hash,
	ImportedKeyDWallet,
	ImportedSharedDWallet,
	PartialUserSignatureWithState,
	Presign,
	SharedDWallet,
	SignatureAlgorithm,
	UserShareEncryptionKeys,
	ZeroTrustDWallet,
} from '@ika.xyz/sdk';
import { Transaction } from '@mysten/sui/transactions';
import type { TransactionObjectArgument } from '@mysten/sui/transactions';

import type { SuiDWallet } from './dwallet.js';
import { findEvent, parseFutureSignEvent, parseSignEvent } from './events.js';
import type { SignCtx } from './sign.js';
import type { BuildApprovalHook, BuildVerifiedPresignCapHook } from './types.js';
import { resolveUsek } from './usek.js';

/**
 * Phase-1 input for the future-sign flow: capture the commitment now,
 * release later. The MPC network validates the
 * `(message, presign, userSignMessage)` triple and produces a
 * `PartialUserSignature` whose `cap_id` can be transferred to anyone —
 * a Move contract that gates release on a vote / time-lock / oracle,
 * the user's wallet, an escrow, etc.
 *
 * The user-sign-message is built inside `ikaTx.requestFutureSign(...)`
 * (the SDK auto-detects shared / zero-trust / imported-key from the
 * dWallet handle) — no separate `prepareSign` call needed here.
 */
export interface RequestFutureSignInput {
	readonly dWallet: SuiDWallet;
	/** Bytes the MPC will hash-and-sign — typically a destination's `prepareSign().preimage`. */
	readonly message: Uint8Array;
	readonly curve: Curve;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly hash: Hash;
	readonly presign: Presign;
	/** Required for zero-trust / imported-key when not on the dWallet handle. */
	readonly encryptedShareId?: string;
	/** Per-call USEK override for zero-trust / imported-key dWallets. */
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	/**
	 * Where the validated `PartialUserSignatureCap` lands. Defaults to the
	 * source's signer address. Set this when a custom Move flow should hold
	 * the cap (e.g. a multisig package, an escrow object).
	 */
	readonly capRecipient?: string;
	readonly signal?: AbortSignal;
}

export interface RequestFutureSignOutput {
	/**
	 * The `PartialUserSignature` object ID. Use this to poll state via
	 * `ika.sui.client.getPartialUserSignatureInParticularState(...)`.
	 */
	readonly partialSignatureId: string;
	/**
	 * The validated cap object ID — passed to `completeFutureSign` (or
	 * `ikaTx.futureSign({ partialUserSignatureCap: ... })` for a custom
	 * Move flow) once release conditions are met.
	 */
	readonly capId: string;
	/** Full partial-signature state, in `NetworkVerificationCompleted`. */
	readonly partialSignature: PartialUserSignatureWithState<'NetworkVerificationCompleted'>;
}

/**
 * Phase-2 input: release the captured commitment. Consumes the validated
 * cap from Phase 1 plus a fresh message approval and triggers the MPC
 * sign. The signature lands on chain the same way as a normal sign;
 * fetch via `ika.sui.client.getSignInParticularState(signId, ...,
 * 'Completed')` and pass to your destination's `assembleSign(prep, sig)`.
 */
export interface CompleteFutureSignInput {
	readonly dWallet: SuiDWallet;
	/** Validated cap id from `requestFutureSign`. */
	readonly partialCapId: string;
	/** Same bytes as Phase 1. Used to build the message approval. */
	readonly message: Uint8Array;
	readonly curve: Curve;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly hash: Hash;
	/** Override the dWalletCap used to build the approval. */
	readonly dWalletCap?: string;
	/** Custom approval builder (sponsored / multisig / etc.). */
	readonly buildApproval?: BuildApprovalHook;
	readonly signal?: AbortSignal;
}

export interface CompleteFutureSignOutput {
	/** Sign session ID. Poll via `ika.sui.client.getSignInParticularState(...)`. */
	readonly signId: string;
}

/**
 * Submit a `request_future_sign` PTB and wait for the network to validate
 * the partial signature. Returns the validated cap id along with the
 * partial-signature object id so callers can either:
 *
 *   - immediately call `completeFutureSign({ partialCapId, ... })` when
 *     the release condition is already met; or
 *   - persist the cap id and let a Move contract / off-chain orchestrator
 *     gate the release.
 *
 * For shared / imported-shared dWallets the user-sign-message is built
 * from the public share on chain. For zero-trust / imported-key, the
 * encrypted share is fetched + decrypted via the source's (or per-call)
 * USEK.
 */
export async function requestFutureSign(
	ctx: SignCtx,
	input: RequestFutureSignInput,
): Promise<RequestFutureSignOutput> {
	const dWallet = input.dWallet;
	const kind = dWallet.kind;
	const recipient = input.capRecipient ?? ctx.defaults.signerAddress;

	const tx = new Transaction();
	tx.setSender(ctx.defaults.signerAddress);
	const p = ctx.pay(tx);

	const needsUsek = kind === 'zero-trust' || kind === 'imported-key';
	const usek = needsUsek
		? resolveUsek(ctx.defaults, input.userShareEncryptionKeys, 'requestFutureSign')
		: undefined;
	const ikaTx = new IkaTransaction({
		ikaClient: ctx.ikaClient,
		transaction: tx,
		...(usek ? { userShareEncryptionKeys: usek } : {}),
	});

	const verifiedPresignCap = ikaTx.verifyPresignCap({ presign: input.presign });

	let unverifiedCap: TransactionObjectArgument;
	if (kind === 'imported-key' || kind === 'imported-key-shared') {
		const args = {
			verifiedPresignCap,
			presign: input.presign,
			message: input.message,
			hashScheme: input.hash,
			signatureScheme: input.signatureAlgorithm,
			ikaCoin: p.ika,
			suiCoin: p.sui,
		};
		if (kind === 'imported-key-shared') {
			unverifiedCap = await ikaTx.requestFutureSignWithImportedKey({
				dWallet: dWallet.raw as unknown as ImportedSharedDWallet,
				...args,
			} as unknown as Parameters<typeof ikaTx.requestFutureSignWithImportedKey>[0]);
		} else {
			const encShareId = input.encryptedShareId ?? dWallet.encryptedShareId;
			if (!encShareId) {
				throw new Error(
					'imported-key requestFutureSign requires `encryptedShareId`. ' +
						'Pass it explicitly or use a dWallet handle that carries it.',
				);
			}
			const encShare = await ctx.ikaClient.getEncryptedUserSecretKeyShare(encShareId);
			unverifiedCap = await ikaTx.requestFutureSignWithImportedKey({
				dWallet: dWallet.raw as unknown as ImportedKeyDWallet,
				encryptedUserSecretKeyShare: encShare,
				...args,
			} as unknown as Parameters<typeof ikaTx.requestFutureSignWithImportedKey>[0]);
		}
	} else {
		const args = {
			verifiedPresignCap,
			presign: input.presign,
			message: input.message,
			hashScheme: input.hash,
			signatureScheme: input.signatureAlgorithm,
			ikaCoin: p.ika,
			suiCoin: p.sui,
		};
		if (kind === 'shared') {
			unverifiedCap = await ikaTx.requestFutureSign({
				dWallet: dWallet.raw as unknown as SharedDWallet,
				...args,
			} as unknown as Parameters<typeof ikaTx.requestFutureSign>[0]);
		} else {
			const encShareId = input.encryptedShareId ?? dWallet.encryptedShareId;
			if (!encShareId) {
				throw new Error(
					'zero-trust requestFutureSign requires `encryptedShareId`. ' +
						'Pass it explicitly or use a dWallet handle that carries it.',
				);
			}
			const encShare = await ctx.ikaClient.getEncryptedUserSecretKeyShare(encShareId);
			unverifiedCap = await ikaTx.requestFutureSign({
				dWallet: dWallet.raw as unknown as ZeroTrustDWallet,
				encryptedUserSecretKeyShare: encShare,
				...args,
			} as unknown as Parameters<typeof ikaTx.requestFutureSign>[0]);
		}
	}

	// The unverified cap MUST be transferred (PTB validation rejects
	// dropped objects). Route it to `capRecipient` so a backend can spawn
	// a future-sign whose validated cap lands at a Move contract / the
	// end-user / an escrow directly.
	tx.transferObjects([unverifiedCap], recipient);
	p.finalize();

	const result = await ctx.exec(tx);
	const ev = parseFutureSignEvent(findEvent(result, 'FutureSignRequestEvent'));
	const partialSignatureId = ev.event_data.partial_centralized_signed_message_id as string;

	const partialSignature = await ctx.ikaClient.getPartialUserSignatureInParticularState(
		partialSignatureId,
		'NetworkVerificationCompleted',
		{
			timeout: ctx.defaults.timeouts.sign,
			interval: 2000,
			signal: input.signal,
		},
	);

	return {
		partialSignatureId,
		capId: partialSignature.cap_id,
		partialSignature,
	};
}

/**
 * Submit `request_sign_with_partial_user_signature` consuming a validated
 * cap. The MPC sign runs the same way as a normal sign — fetch via
 * `getSignInParticularState(signId, ..., 'Completed')` and assemble the
 * broadcast payload with your destination's `assembleSign(prep, sig)`.
 */
export async function completeFutureSign(
	ctx: SignCtx,
	input: CompleteFutureSignInput,
): Promise<CompleteFutureSignOutput> {
	const dWallet = input.dWallet;
	const isImported = dWallet.kind === 'imported-key' || dWallet.kind === 'imported-key-shared';

	const tx = new Transaction();
	tx.setSender(ctx.defaults.signerAddress);
	const p = ctx.pay(tx);
	const ikaTx = new IkaTransaction({ ikaClient: ctx.ikaClient, transaction: tx });

	const capRef = input.dWalletCap ?? dWallet.dWalletCapId;
	if (isImported) {
		const importedApproval =
			input.buildApproval?.(ikaTx, capRef) ??
			ikaTx.approveImportedKeyMessage({
				dWalletCap: capRef,
				curve: input.curve,
				signatureAlgorithm: input.signatureAlgorithm,
				hashScheme: input.hash,
				message: input.message,
			});
		ikaTx.futureSignWithImportedKey({
			partialUserSignatureCap: input.partialCapId,
			importedKeyMessageApproval: importedApproval,
			ikaCoin: p.ika,
			suiCoin: p.sui,
		});
	} else {
		const approval =
			input.buildApproval?.(ikaTx, capRef) ??
			ikaTx.approveMessage({
				dWalletCap: capRef,
				curve: input.curve,
				signatureAlgorithm: input.signatureAlgorithm,
				hashScheme: input.hash,
				message: input.message,
			});
		ikaTx.futureSign({
			partialUserSignatureCap: input.partialCapId,
			messageApproval: approval,
			ikaCoin: p.ika,
			suiCoin: p.sui,
		});
	}
	p.finalize();

	const result = await ctx.exec(tx);
	const signEv = parseSignEvent(findEvent(result, 'SignRequestEvent'));
	return { signId: signEv.event_data.sign_id as string };
}

/**
 * Args for the compose-mode `requestFutureSign` (used inside
 * `ika.sui.transaction(...)`). Same shape as the standalone version
 * minus the `signal` / capRecipient (caller handles the cap inline) and
 * with explicit `ikaCoin` / `suiCoin` arguments (caller allocates them
 * via the builder's `pay()`).
 */
export interface ComposeFutureSignArgs {
	readonly ikaTx: IkaTransaction;
	readonly dWallet: SuiDWallet;
	readonly message: Uint8Array;
	readonly curve: Curve;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly hash: Hash;
	readonly presign: Presign;
	readonly ikaCoin: TransactionObjectArgument;
	readonly suiCoin: TransactionObjectArgument;
	readonly encryptedShareId?: string;
	readonly verifiedPresignCap?: TransactionObjectArgument;
	readonly buildVerifiedPresignCap?: BuildVerifiedPresignCapHook;
}

/**
 * Compose a `request_future_sign` Move call into an in-flight
 * `IkaTransaction`. Returns the `unverifiedPartialUserSignatureCap` Move
 * argument so the caller can transfer it inline (to a contract, to a
 * user, etc.) before the PTB executes.
 *
 * Mirrors `composeSign(...)`: it does NOT execute the tx and does NOT
 * fetch any partial signature state. Use the standalone `requestFutureSign`
 * when you want the one-shot "submit + wait for verification" flow.
 */
export async function composeRequestFutureSign(
	ikaClient: CoreIkaClient,
	args: ComposeFutureSignArgs,
): Promise<TransactionObjectArgument> {
	const dWallet = args.dWallet;
	const kind = dWallet.kind;

	const verifiedPresignCap =
		args.verifiedPresignCap ??
		(args.buildVerifiedPresignCap
			? args.buildVerifiedPresignCap(args.ikaTx, args.presign)
			: args.ikaTx.verifyPresignCap({ presign: args.presign }));

	const baseArgs = {
		verifiedPresignCap,
		presign: args.presign,
		message: args.message,
		hashScheme: args.hash,
		signatureScheme: args.signatureAlgorithm,
		ikaCoin: args.ikaCoin,
		suiCoin: args.suiCoin,
	};

	if (kind === 'imported-key-shared') {
		return args.ikaTx.requestFutureSignWithImportedKey({
			dWallet: dWallet.raw as unknown as ImportedSharedDWallet,
			...baseArgs,
		} as unknown as Parameters<typeof args.ikaTx.requestFutureSignWithImportedKey>[0]);
	}
	if (kind === 'imported-key') {
		const encShareId = args.encryptedShareId ?? dWallet.encryptedShareId;
		if (!encShareId) {
			throw new Error('imported-key requestFutureSign requires `encryptedShareId`.');
		}
		const encShare = await ikaClient.getEncryptedUserSecretKeyShare(encShareId);
		return args.ikaTx.requestFutureSignWithImportedKey({
			dWallet: dWallet.raw as unknown as ImportedKeyDWallet,
			encryptedUserSecretKeyShare: encShare,
			...baseArgs,
		} as unknown as Parameters<typeof args.ikaTx.requestFutureSignWithImportedKey>[0]);
	}
	if (kind === 'shared') {
		return args.ikaTx.requestFutureSign({
			dWallet: dWallet.raw as unknown as SharedDWallet,
			...baseArgs,
		} as unknown as Parameters<typeof args.ikaTx.requestFutureSign>[0]);
	}
	// zero-trust
	const encShareId = args.encryptedShareId ?? dWallet.encryptedShareId;
	if (!encShareId) {
		throw new Error('zero-trust requestFutureSign requires `encryptedShareId`.');
	}
	const encShare = await ikaClient.getEncryptedUserSecretKeyShare(encShareId);
	return args.ikaTx.requestFutureSign({
		dWallet: dWallet.raw as unknown as ZeroTrustDWallet,
		encryptedUserSecretKeyShare: encShare,
		...baseArgs,
	} as unknown as Parameters<typeof args.ikaTx.requestFutureSign>[0]);
}

export interface ComposeCompleteFutureSignArgs {
	readonly ikaTx: IkaTransaction;
	readonly dWallet: SuiDWallet;
	readonly partialCapId: string;
	readonly message: Uint8Array;
	readonly curve: Curve;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly hash: Hash;
	readonly ikaCoin: TransactionObjectArgument;
	readonly suiCoin: TransactionObjectArgument;
	readonly dWalletCap?: string;
	readonly buildApproval?: BuildApprovalHook;
	/** Pre-built approval. Takes precedence over `buildApproval`. */
	readonly messageApproval?: TransactionObjectArgument;
}

/**
 * Compose the Phase-2 `request_sign_with_partial_user_signature` Move
 * call into an in-flight `IkaTransaction`. Useful when releasing the
 * future sign as part of a larger PTB (e.g. a multisig vote tx that
 * also burns escrow tokens, updates state, etc.).
 */
export function composeCompleteFutureSign(args: ComposeCompleteFutureSignArgs): void {
	const isImported =
		args.dWallet.kind === 'imported-key' || args.dWallet.kind === 'imported-key-shared';
	const capRef = args.dWalletCap ?? args.dWallet.dWalletCapId;

	if (isImported) {
		const approval =
			args.messageApproval ??
			args.buildApproval?.(args.ikaTx, capRef) ??
			args.ikaTx.approveImportedKeyMessage({
				dWalletCap: capRef,
				curve: args.curve,
				signatureAlgorithm: args.signatureAlgorithm,
				hashScheme: args.hash,
				message: args.message,
			});
		args.ikaTx.futureSignWithImportedKey({
			partialUserSignatureCap: args.partialCapId,
			importedKeyMessageApproval: approval,
			ikaCoin: args.ikaCoin,
			suiCoin: args.suiCoin,
		});
	} else {
		const approval =
			args.messageApproval ??
			args.buildApproval?.(args.ikaTx, capRef) ??
			args.ikaTx.approveMessage({
				dWalletCap: capRef,
				curve: args.curve,
				signatureAlgorithm: args.signatureAlgorithm,
				hashScheme: args.hash,
				message: args.message,
			});
		args.ikaTx.futureSign({
			partialUserSignatureCap: args.partialCapId,
			messageApproval: approval,
			ikaCoin: args.ikaCoin,
			suiCoin: args.suiCoin,
		});
	}
}
