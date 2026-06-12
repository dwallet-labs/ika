// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { createUserSignMessageWithPublicOutput } from '@ika.xyz/sdk';
import type {
	IkaClient as CoreIkaClient,
	Curve,
	Hash,
	Presign,
	SignatureAlgorithm,
	UserShareEncryptionKeys,
} from '@ika.xyz/sdk';

import type { SuiDWallet } from './dwallet.js';
import type { SuiSourceDefaults } from './types.js';
import { resolveUsek } from './usek.js';

/**
 * Compute the user's centralized-party contribution for a sign WITHOUT
 * submitting anything on chain. The returned `userSignMessage` binds the
 * `dWallet`, the user share, the `presign`, and the `message` together —
 * what a destination plugin's `prepareSign` produced.
 *
 * Use this when the on-chain `request_sign` call doesn't go through the
 * plugin's own `requestSign` flow — e.g. a Move multisig contract calls
 * `request_sign` as the dWallet's owner after vote approval, or a
 * future-sign Move call captures the user-sign-message now and the
 * coordinator releases the signature later.
 *
 * For shared and imported-key-shared dWallets the user secret share is
 * publicly readable from chain (`dWallet.raw.public_user_secret_key_share`),
 * so no USEK is required. For zero-trust and imported-key dWallets the
 * share is encrypted on chain; this method fetches the encrypted share via
 * `encryptedShareId` (or `dWallet.encryptedShareId`) and decrypts it with
 * the source's `userShareEncryptionKeys` (or the per-call override).
 *
 * Pair with the destination's `prepareSign(...)` (which produces the
 * `message`) and `assembleSign(...)` (which takes the network's signature
 * once it lands) to express the full custom-contract sign loop.
 */
export interface PrepareSignInput {
	readonly dWallet: SuiDWallet;
	readonly message: Uint8Array;
	readonly curve: Curve;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly hash: Hash;
	readonly presign: Presign;
	/** Required for zero-trust / imported-key when not on the dWallet handle. */
	readonly encryptedShareId?: string;
	/** Per-call USEK override for zero-trust / imported-key dWallets. */
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
}

export interface PrepareSignOutput {
	/**
	 * Centralized-party sign message bytes. Hand this to whatever Move
	 * mechanism gates the actual Ika `request_sign` call (multisig
	 * contract, future-sign release, sponsored relay, ...).
	 */
	readonly userSignMessage: Uint8Array;
	/** Echoed for convenience so callers don't have to re-thread the presign. */
	readonly presign: Presign;
}

export interface PrepareSignCtx {
	readonly defaults: SuiSourceDefaults;
	readonly ikaClient: CoreIkaClient;
}

export async function prepareSignMessage(
	ctx: PrepareSignCtx,
	input: PrepareSignInput,
): Promise<PrepareSignOutput> {
	const dWallet = input.dWallet;
	const raw = dWallet.raw;
	const protocolPP = await ctx.ikaClient.getProtocolPublicParameters(raw);
	const publicOutput = extractPublicOutput(raw);

	const userSecretKeyShare = await resolveUserSecretShare(ctx, input, protocolPP);

	const completed = input.presign.state.Completed;
	if (!completed) {
		throw new Error(
			'sui source: prepareSignMessage requires a Completed presign. ' +
				"Pass `presign` from `ikaClient.getPresignInParticularState(id, 'Completed')`.",
		);
	}

	const userSignMessage = await createUserSignMessageWithPublicOutput(
		protocolPP,
		publicOutput,
		userSecretKeyShare,
		Uint8Array.from(completed.presign),
		input.message,
		// The SDK's generic constraints validate at compile time when called
		// from a context that knows the curve. Here we accept the union and
		// pass through — the WASM call validates the combination too and
		// throws on mismatches.
		input.hash as never,
		input.signatureAlgorithm as never,
		input.curve as never,
	);

	return { userSignMessage, presign: input.presign };
}

function extractPublicOutput(raw: SuiDWallet['raw']): Uint8Array {
	// Active and AwaitingKeyHolderSignature states both carry public_output;
	// signing requires Active so we narrow here. Callers that pass a non-Active
	// dWallet handle hit a clearer error downstream than from the WASM call.
	const state = (raw as { state: { Active?: { public_output: number[] | Uint8Array } } }).state;
	const active = state?.Active?.public_output;
	if (!active) {
		throw new Error('sui source: prepareSignMessage requires an Active dWallet');
	}
	return Uint8Array.from(active);
}

async function resolveUserSecretShare(
	ctx: PrepareSignCtx,
	input: PrepareSignInput,
	protocolPublicParameters: Uint8Array,
): Promise<Uint8Array> {
	const dWallet = input.dWallet;
	const raw = dWallet.raw;
	const kind = dWallet.kind;

	// Shared variants: the secret share is public on chain.
	if (kind === 'shared' || kind === 'imported-key-shared') {
		const share = (raw as { public_user_secret_key_share?: number[] | Uint8Array | null })
			.public_user_secret_key_share;
		if (!share || (Array.isArray(share) && share.length === 0)) {
			throw new Error(
				`sui source: ${kind} dWallet missing public_user_secret_key_share. ` +
					`Re-fetch the dWallet from chain.`,
			);
		}
		return Uint8Array.from(share);
	}

	// Zero-trust / imported-key: encrypted share + USEK decryption.
	const usek = resolveUsek(ctx.defaults, input.userShareEncryptionKeys, 'prepareSignMessage');
	const encShareId = input.encryptedShareId ?? dWallet.encryptedShareId;
	if (!encShareId) {
		throw new Error(
			`sui source: ${kind} prepareSignMessage requires \`encryptedShareId\`. ` +
				`Pass it explicitly or use a dWallet handle that carries it.`,
		);
	}
	const encShare = await ctx.ikaClient.getEncryptedUserSecretKeyShare(encShareId);
	const { secretShare } = await usek.decryptUserShare(raw, encShare, protocolPublicParameters);
	return secretShare;
}
