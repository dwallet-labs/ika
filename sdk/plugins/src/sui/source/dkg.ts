// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import {
	createRandomSessionIdentifier,
	IkaTransaction,
	prepareDKGAsync,
	prepareImportedKeyDWalletVerification,
} from '@ika.xyz/sdk';
import type {
	IkaClient as CoreIkaClient,
	ImportedKeyDWallet,
	ImportedSharedDWallet,
	SharedDWallet,
	UserShareEncryptionKeys,
	ZeroTrustDWallet,
} from '@ika.xyz/sdk';
import { Transaction } from '@mysten/sui/transactions';

import type { SuiDWallet } from './dwallet.js';
import { findEvent, parseDkgEvent, parseImportedKeyEvent } from './events.js';
import type { makeExec, makePay } from './execute.js';
import type {
	PrepareDKGInput,
	PrepareDKGOutput,
	RequestImportedKeyInput,
	RequestImportedKeyOutput,
	RequestSharedDKGInput,
	RequestZeroTrustDKGInput,
	RevealUserSecretShareInput,
	SuiSourceDefaults,
} from './types.js';
import { ensureUsekRegistered, resolveUsek } from './usek.js';
import type { UsekRegistrationCache } from './usek.js';
import { wrapDWallet } from './wrap.js';

/** Sleep that rejects immediately when the signal aborts. */
function abortableSleep(ms: number, signal?: AbortSignal): Promise<void> {
	if (signal?.aborted) return Promise.reject(new Error('aborted'));
	return new Promise<void>((resolve, reject) => {
		const t = setTimeout(() => {
			signal?.removeEventListener('abort', onAbort);
			resolve();
		}, ms);
		const onAbort = () => {
			clearTimeout(t);
			reject(new Error('aborted'));
		};
		signal?.addEventListener('abort', onAbort, { once: true });
	});
}

/**
 * Race a promise against an AbortSignal. The underlying call continues in the
 * background (true cancellation requires upstream support), but the awaiter
 * returns immediately on abort.
 */
function withAbort<T>(p: Promise<T>, signal?: AbortSignal): Promise<T> {
	if (!signal) return p;
	if (signal.aborted) return Promise.reject(new Error('aborted'));
	return new Promise<T>((resolve, reject) => {
		const onAbort = () => reject(new Error('aborted'));
		signal.addEventListener('abort', onAbort, { once: true });
		p.then(
			(v) => {
				signal.removeEventListener('abort', onAbort);
				resolve(v);
			},
			(err) => {
				signal.removeEventListener('abort', onAbort);
				reject(err);
			},
		);
	});
}

/** Per-call context the plugin factory hands to each DKG building block. */
export interface DKGCtx {
	readonly defaults: SuiSourceDefaults;
	readonly ikaClient: CoreIkaClient;
	readonly pay: ReturnType<typeof makePay>;
	readonly exec: ReturnType<typeof makeExec>;
	readonly usekCache: UsekRegistrationCache;
}

/** Run the user-side DKG WASM and produce the payload submitted in `requestDKG`. */
export async function prepareDKG(ctx: DKGCtx, input: PrepareDKGInput): Promise<PrepareDKGOutput> {
	const keys = resolveUsek(ctx.defaults, input.userShareEncryptionKeys, 'prepareDKG');
	const sessionIdentifier = input.sessionIdentifier ?? createRandomSessionIdentifier();
	const senderAddress = input.senderAddress ?? ctx.defaults.signerAddress;
	const result = await prepareDKGAsync(
		ctx.ikaClient,
		input.curve,
		keys,
		sessionIdentifier,
		senderAddress,
	);
	return {
		userDKGMessage: result.userDKGMessage,
		userSecretKeyShare: result.userSecretKeyShare,
		userPublicOutput: result.userPublicOutput,
		encryptedUserShareAndProof: result.encryptedUserShareAndProof,
		sessionIdentifier,
	};
}

/** Zero-trust DKG: network DKG, user-side accept of the encrypted share, then wait for `Active`. */
export async function requestDKG(
	ctx: DKGCtx,
	input: RequestZeroTrustDKGInput,
): Promise<SuiDWallet> {
	const keys = resolveUsek(ctx.defaults, input.userShareEncryptionKeys, 'requestDKG');
	await ensureUsekRegistered({
		userShareEncryptionKeys: keys,
		curve: input.curve,
		defaults: ctx.defaults,
		ikaClient: ctx.ikaClient,
		exec: ctx.exec,
		cache: ctx.usekCache,
	});

	const netKey = await getOrFetchNetKey(ctx, input.networkEncryptionKeyId);

	const tx = new Transaction();
	tx.setSender(ctx.defaults.signerAddress);
	const p = ctx.pay(tx);
	const ikaTx = new IkaTransaction({
		ikaClient: ctx.ikaClient,
		transaction: tx,
		userShareEncryptionKeys: keys,
	});
	const sessionId = ikaTx.registerSessionIdentifier(input.sessionIdentifier);
	const [cap] = await ikaTx.requestDWalletDKG({
		dkgRequestInput: input.dkgRequestInput,
		curve: input.curve,
		dwalletNetworkEncryptionKeyId: netKey,
		ikaCoin: p.ika,
		suiCoin: p.sui,
		sessionIdentifier: sessionId,
	});
	// Cap goes to `capRecipient` (when set) so a different account than the
	// DKG-funding signer can take ownership. Otherwise it lands at the
	// signer alongside the leftover fee coins via `p.finalize(cap)`.
	if (input.capRecipient) {
		tx.transferObjects([cap], input.capRecipient);
		p.finalize();
	} else {
		p.finalize(cap);
	}
	const result = await ctx.exec(tx);
	const dkgEv = parseDkgEvent(findEvent(result, 'DWalletDKGRequestEvent'));
	const dWalletId = dkgEv.event_data.dwallet_id;

	const encShareId = extractEncryptedShareId(dkgEv);
	if (!encShareId) {
		throw new Error('zero-trust DKG event missing encrypted_user_secret_key_share_id');
	}

	const awaiting = (await ctx.ikaClient.getDWalletInParticularState(
		dWalletId,
		'AwaitingKeyHolderSignature',
		{ timeout: ctx.defaults.timeouts.dkg, interval: 2000, signal: input.signal },
	)) as ZeroTrustDWallet;

	const acceptTx = new Transaction();
	acceptTx.setSender(ctx.defaults.signerAddress);
	const acceptIkaTx = new IkaTransaction({
		ikaClient: ctx.ikaClient,
		transaction: acceptTx,
		userShareEncryptionKeys: keys,
	});
	await acceptIkaTx.acceptEncryptedUserShare({
		dWallet: awaiting,
		userPublicOutput: input.dkgRequestInput.userPublicOutput,
		encryptedUserSecretKeyShareId: encShareId,
	});
	await ctx.exec(acceptTx);

	const raw = (await ctx.ikaClient.getDWalletInParticularState(dWalletId, 'Active', {
		timeout: ctx.defaults.timeouts.dkg,
		interval: 2000,
		signal: input.signal,
	})) as ZeroTrustDWallet;
	return wrapDWallet(raw, encShareId);
}

/** Shared DKG: no encrypted share or accept step; the dWallet goes directly to `Active`. */
export async function requestDKGWithPublicShare(
	ctx: DKGCtx,
	input: RequestSharedDKGInput,
): Promise<SuiDWallet> {
	const keys = resolveUsek(
		ctx.defaults,
		input.userShareEncryptionKeys,
		'requestDKGWithPublicShare',
	);
	await ensureUsekRegistered({
		userShareEncryptionKeys: keys,
		curve: input.curve,
		defaults: ctx.defaults,
		ikaClient: ctx.ikaClient,
		exec: ctx.exec,
		cache: ctx.usekCache,
	});

	const netKey = await getOrFetchNetKey(ctx, input.networkEncryptionKeyId);

	const tx = new Transaction();
	tx.setSender(ctx.defaults.signerAddress);
	const p = ctx.pay(tx);
	const ikaTx = new IkaTransaction({
		ikaClient: ctx.ikaClient,
		transaction: tx,
		userShareEncryptionKeys: keys,
	});
	const sessionId = ikaTx.registerSessionIdentifier(input.sessionIdentifier);
	const [cap] = await ikaTx.requestDWalletDKGWithPublicUserShare({
		publicKeyShareAndProof: input.publicKeyShareAndProof,
		publicUserSecretKeyShare: input.publicUserSecretKeyShare,
		userPublicOutput: input.userPublicOutput,
		curve: input.curve,
		dwalletNetworkEncryptionKeyId: netKey,
		ikaCoin: p.ika,
		suiCoin: p.sui,
		sessionIdentifier: sessionId,
	});
	if (input.capRecipient) {
		tx.transferObjects([cap], input.capRecipient);
		p.finalize();
	} else {
		p.finalize(cap);
	}
	const result = await ctx.exec(tx);
	const dkgEv = parseDkgEvent(findEvent(result, 'DWalletDKGRequestEvent'));
	const raw = (await ctx.ikaClient.getDWalletInParticularState(
		dkgEv.event_data.dwallet_id,
		'Active',
		{ timeout: ctx.defaults.timeouts.dkg, interval: 2000, signal: input.signal },
	)) as SharedDWallet;
	return wrapDWallet(raw);
}

/** Imported-key DKG: verification request followed by user-side accept of the encrypted share. */
export async function requestImportedKeyVerification(
	ctx: DKGCtx,
	input: RequestImportedKeyInput,
): Promise<RequestImportedKeyOutput> {
	const keys = resolveUsek(
		ctx.defaults,
		input.userShareEncryptionKeys,
		'requestImportedKeyVerification',
	);
	await ensureUsekRegistered({
		userShareEncryptionKeys: keys,
		curve: input.curve,
		defaults: ctx.defaults,
		ikaClient: ctx.ikaClient,
		exec: ctx.exec,
		cache: ctx.usekCache,
	});

	const sessionIdentifier = input.sessionIdentifier ?? createRandomSessionIdentifier();
	const senderAddress = input.senderAddress ?? ctx.defaults.signerAddress;
	const importInput = await prepareImportedKeyDWalletVerification(
		ctx.ikaClient,
		input.curve,
		sessionIdentifier,
		senderAddress,
		keys,
		input.importedKey,
	);

	const tx = new Transaction();
	tx.setSender(ctx.defaults.signerAddress);
	const p = ctx.pay(tx);
	const ikaTx = new IkaTransaction({
		ikaClient: ctx.ikaClient,
		transaction: tx,
		userShareEncryptionKeys: keys,
	});
	const sessionId = ikaTx.registerSessionIdentifier(sessionIdentifier);
	const cap = await ikaTx.requestImportedKeyDWalletVerification({
		importDWalletVerificationRequestInput: importInput,
		curve: input.curve,
		signerPublicKey: keys.getSigningPublicKeyBytes(),
		sessionIdentifier: sessionId,
		ikaCoin: p.ika,
		suiCoin: p.sui,
	});
	if (input.capRecipient) {
		tx.transferObjects([cap], input.capRecipient);
		p.finalize();
	} else {
		p.finalize(cap);
	}
	const result = await ctx.exec(tx);
	const ev = parseImportedKeyEvent(findEvent(result, 'DWalletImportedKeyVerificationRequestEvent'));
	const dWalletId = ev.event_data.dwallet_id;
	const encShareId = ev.event_data.encrypted_user_secret_key_share_id as string;

	const awaiting = (await ctx.ikaClient.getDWalletInParticularState(
		dWalletId,
		'AwaitingKeyHolderSignature',
		{ timeout: ctx.defaults.timeouts.dkg, interval: 2000, signal: input.signal },
	)) as ImportedKeyDWallet;

	const acceptTx = new Transaction();
	acceptTx.setSender(ctx.defaults.signerAddress);
	const acceptIkaTx = new IkaTransaction({
		ikaClient: ctx.ikaClient,
		transaction: acceptTx,
		userShareEncryptionKeys: keys,
	});
	await acceptIkaTx.acceptEncryptedUserShare({
		dWallet: awaiting,
		userPublicOutput: importInput.userPublicOutput,
		encryptedUserSecretKeyShareId: encShareId,
	});
	await ctx.exec(acceptTx);

	// Uses `timeouts.dkg` (same logical step + budget as the zero-trust
	// post-accept wait). `shareVerify` is reserved for the
	// `revealUserSecretShare` promotion polling.
	const active = (await ctx.ikaClient.getDWalletInParticularState(dWalletId, 'Active', {
		timeout: ctx.defaults.timeouts.dkg,
		interval: 2000,
		signal: input.signal,
	})) as ImportedKeyDWallet;

	return {
		dWallet: wrapDWallet(active, encShareId),
		encryptedShareId: encShareId,
		userPublicOutput: importInput.userPublicOutput,
	};
}

/**
 * Publish the user's secret share on chain, promoting an imported-key dWallet
 * to imported-key-shared.
 *
 * SECURITY: irreversible. Once published, anyone with the dWallet cap can sign
 * without the user's participation. Callers must pass
 * `acknowledge: 'i-understand-this-is-irreversible'`.
 */
export async function revealUserSecretShare(
	ctx: DKGCtx,
	args: RevealUserSecretShareInput,
): Promise<SuiDWallet> {
	if (args.acknowledge !== 'i-understand-this-is-irreversible') {
		throw new Error(
			'revealUserSecretShare is irreversible. Pass `acknowledge: "i-understand-this-is-irreversible"` to confirm. ' +
				'Once published, anyone with the dWallet cap can sign without you.',
		);
	}
	// The Move side only accepts this call against `imported-key` dWallets.
	// Guarding here avoids decrypting the share in memory and paying 0.5 IKA
	// before the on-chain abort.
	if (args.dWallet.kind !== 'imported-key') {
		throw new Error(
			`revealUserSecretShare only applies to 'imported-key' dWallets, got '${args.dWallet.kind}'. ` +
				`Zero-trust dWallets cannot be promoted to shared; create them with ` +
				`\`createDWallet({ kind: 'shared', ... })\` from the start.`,
		);
	}
	const keys = resolveUsek(ctx.defaults, args.userShareEncryptionKeys, 'revealUserSecretShare');
	const encShareId = args.encryptedShareId ?? args.dWallet.encryptedShareId;
	if (!encShareId) {
		throw new Error(
			'revealUserSecretShare: no `encryptedShareId`. Pass one explicitly or use a dWallet handle that carries it.',
		);
	}
	const encShare = await ctx.ikaClient.getEncryptedUserSecretKeyShare(encShareId);
	const pp = await ctx.ikaClient.getProtocolPublicParameters(args.dWallet.raw);
	const decShare = await keys.decryptUserShare(args.dWallet.raw, encShare, pp);

	const tx = new Transaction();
	tx.setSender(ctx.defaults.signerAddress);
	const p = ctx.pay(tx);
	const ikaTx = new IkaTransaction({
		ikaClient: ctx.ikaClient,
		transaction: tx,
		userShareEncryptionKeys: keys,
	});
	ikaTx.makeDWalletUserSecretKeySharesPublic({
		dWallet: args.dWallet.raw as ImportedKeyDWallet,
		secretShare: decShare.secretShare,
		ikaCoin: p.ika,
		suiCoin: p.sui,
	});
	p.finalize();
	await ctx.exec(tx);

	const start = Date.now();
	const timeoutAt = start + ctx.defaults.timeouts.shareVerify;
	while (Date.now() < timeoutAt) {
		if (args.signal?.aborted) throw new Error('revealUserSecretShare: aborted');
		// `getDWallet` does not accept a signal. Race it against abort so a
		// hung RPC does not delay cancellation until the next iteration.
		const cur = await withAbort(ctx.ikaClient.getDWallet(args.dWallet.id), args.signal);
		if (cur.public_user_secret_key_share && cur.kind === 'imported-key-shared') {
			return wrapDWallet(cur as ImportedSharedDWallet, encShareId);
		}
		await abortableSleep(2000, args.signal);
	}
	throw new Error(
		`revealUserSecretShare: dWallet ${args.dWallet.id} never promoted to imported-key-shared`,
	);
}

/**
 * Recovery primitive for a dWallet stuck in `AwaitingKeyHolderSignature` after
 * `requestDKG` or `requestImportedKeyVerification` partially succeeded (network
 * DKG completed, accept step failed). Re-submits the accept tx and waits for
 * `Active`.
 *
 * SECURITY: `userPublicOutput` MUST match the value used in the original
 * prepareDKG call. Passing a different value lets a compromised caller accept
 * under their key and obtain signing rights. Persist the prepareDKG output
 * alongside the dWallet id if you need to support recovery.
 */
export interface AcceptEncryptedShareInput {
	readonly dWalletId: string;
	readonly userPublicOutput: Uint8Array;
	/**
	 * Required. The encrypted share id captured at DKG time. The dWallet's
	 * chain state does not expose this directly (it lives in an ObjectTable
	 * keyed by id), so the original DKG or import event is the canonical
	 * source. Persist this value alongside the dWallet id if recovery may
	 * ever be needed.
	 */
	readonly encryptedShareId: string;
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	readonly signal?: AbortSignal;
}

export async function acceptEncryptedShare(
	ctx: DKGCtx,
	input: AcceptEncryptedShareInput,
): Promise<SuiDWallet> {
	const keys = resolveUsek(ctx.defaults, input.userShareEncryptionKeys, 'acceptEncryptedShare');

	// A previous accept call may have succeeded on chain but had its post-tx
	// wait time out during indexing. Short-circuit on `Active` so the recovery
	// primitive does not block on `AwaitingKeyHolderSignature` for the full
	// DKG timeout when the dWallet is already done.
	const current = await ctx.ikaClient.getDWallet(input.dWalletId);
	if (current.state.$kind === 'Active') {
		return wrapDWallet(current, input.encryptedShareId);
	}
	if (current.state.$kind !== 'AwaitingKeyHolderSignature') {
		throw new Error(
			`acceptEncryptedShare: dWallet ${input.dWalletId} is in state ` +
				`'${current.state.$kind}', expected 'AwaitingKeyHolderSignature' or 'Active'. ` +
				`This is a chain-state inconsistency; consult ika.sui.client for the raw state.`,
		);
	}

	// Recovery is a fast re-submit, not a full DKG round-trip, so
	// `shareVerify` (5min default) is the right budget rather than `dkg`
	// (10min default). The caller is expected to invoke this only after the
	// original DKG completed on chain.
	const awaitingRaw = await ctx.ikaClient.getDWalletInParticularState(
		input.dWalletId,
		'AwaitingKeyHolderSignature',
		{ timeout: ctx.defaults.timeouts.shareVerify, interval: 2000, signal: input.signal },
	);
	// Only zero-trust and imported-key dWallets ever pass through
	// `AwaitingKeyHolderSignature`. If the chain reports any other kind in
	// this state, the cast below would be a type lie and the subsequent
	// `acceptEncryptedUserShare` would abort with an opaque Move error.
	if (awaitingRaw.kind !== 'zero-trust' && awaitingRaw.kind !== 'imported-key') {
		throw new Error(
			`acceptEncryptedShare: dWallet ${input.dWalletId} has kind '${awaitingRaw.kind}', ` +
				`but only 'zero-trust' or 'imported-key' need the accept step. Did you call this ` +
				`on the wrong id?`,
		);
	}
	const awaiting = awaitingRaw as ZeroTrustDWallet | ImportedKeyDWallet;

	const encShareId = input.encryptedShareId;

	const acceptTx = new Transaction();
	acceptTx.setSender(ctx.defaults.signerAddress);
	const acceptIkaTx = new IkaTransaction({
		ikaClient: ctx.ikaClient,
		transaction: acceptTx,
		userShareEncryptionKeys: keys,
	});
	await acceptIkaTx.acceptEncryptedUserShare({
		dWallet: awaiting,
		userPublicOutput: input.userPublicOutput,
		encryptedUserSecretKeyShareId: encShareId,
	});
	await ctx.exec(acceptTx);

	const raw = (await ctx.ikaClient.getDWalletInParticularState(input.dWalletId, 'Active', {
		timeout: ctx.defaults.timeouts.shareVerify,
		interval: 2000,
		signal: input.signal,
	})) as ZeroTrustDWallet | ImportedKeyDWallet;
	return wrapDWallet(raw, encShareId);
}

// Helpers.

async function getOrFetchNetKey(ctx: DKGCtx, override?: string): Promise<string> {
	if (override) return override;
	const k = await ctx.ikaClient.getLatestNetworkEncryptionKey();
	return k.id;
}

function extractEncryptedShareId(dkgEv: ReturnType<typeof parseDkgEvent>): string | undefined {
	// `event_data.user_secret_key_share` is a BCS-typed Move enum
	// (`UserSecretKeyShareEventType`) with an `Encrypted` variant carrying
	// the id. Branching on the `$kind` discriminator means a Move struct
	// rename surfaces as a compile-time error instead of a silent undefined.
	const share = dkgEv.event_data.user_secret_key_share;
	if (share.$kind !== 'Encrypted') {
		// Shared (public-share) path: no encrypted share id by design.
		return undefined;
	}
	return share.Encrypted.encrypted_user_secret_key_share_id;
}
