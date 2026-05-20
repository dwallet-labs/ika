// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Curve, Hash, SignatureAlgorithm } from '@ika.xyz/sdk';
import type { DWallet, IkaContext } from '@ika.xyz/sdk/plugin';
import { PublicKey } from '@solana/web3.js';

import type { SolanaAddressCache } from './address.js';
import type {
	SolanaPrepareSignResult,
	SolanaSignedTx,
	SolanaSignInput,
	SolanaSignPrep,
} from './types.js';

/**
 * Build the bytes-to-sign for a Solana payload WITHOUT submitting anything
 * on chain. Returns `{ prep, preimage, plan }`: `prep` for `assembleSign`,
 * `preimage` + `plan` for the Move flow that gates the actual
 * `request_sign` call. See the bitcoin destination's docs for the typical
 * hand-off flow — the shape is the same across destinations.
 *
 * For Ed25519, the network signs the raw bytes (Ed25519 internally hashes
 * with SHA-512). The plugin passes `hash: SHA512` to indicate the EdDSA
 * path; the MPC does not apply a separate pre-hash on top of EdDSA's
 * internal one.
 */
export async function prepareSign(
	dWallet: DWallet,
	input: SolanaSignInput,
	cache: SolanaAddressCache,
): Promise<SolanaPrepareSignResult> {
	if (dWallet.curve !== Curve.ED25519) {
		throw new Error(`solana destination requires ED25519 curve, got ${dWallet.curve}`);
	}
	const preimage = input.kind === 'transaction' ? input.tx.message.serialize() : input.message;
	const pubkey = await cache.publicKey(dWallet.publicOutput);
	return {
		prep: { sender: pubkey.toBase58(), input },
		preimage,
		plan: {
			curve: Curve.ED25519,
			signatureAlgorithm: SignatureAlgorithm.EdDSA,
			hash: Hash.SHA512,
		},
	};
}

/**
 * Apply the network's 64-byte Ed25519 signature to the prepared payload.
 *
 * For `kind: 'transaction'`, the prepared `VersionedTransaction` is mutated
 * in place via `addSignature(...)` (matches `@solana/web3.js` conventions —
 * don't reuse the transaction after assemble). For `kind: 'message'` the
 * signature is wrapped on its own with the sender address.
 */
export async function assembleSign(
	prep: SolanaSignPrep,
	signature: Uint8Array,
): Promise<SolanaSignedTx> {
	if (prep.input.kind === 'transaction') {
		const pubkey = new PublicKey(prep.sender);
		prep.input.tx.addSignature(pubkey, signature);
		return {
			chain: 'solana',
			payload: {
				kind: 'transaction',
				transaction: prep.input.tx,
				signature,
				sender: prep.sender,
			},
		};
	}
	return {
		chain: 'solana',
		payload: { kind: 'message', signature, sender: prep.sender },
	};
}

/**
 * Sign a Solana transaction or arbitrary bytes through the active source.
 * Accepts the abstract `DWallet` so the destination works against any source
 * plugin. Throws if the dWallet's curve is not Ed25519.
 *
 * In `transaction` mode, `input.tx.addSignature(...)` mutates the caller's
 * transaction in place. This matches @solana/web3.js conventions. Callers
 * should not reuse the transaction object after signing.
 *
 * Equivalent to `prepareSign` → `ctx.source.signMessage` → `assembleSign`.
 */
export async function signCore(
	ctx: IkaContext,
	dWallet: DWallet,
	input: SolanaSignInput,
	cache: SolanaAddressCache,
): Promise<SolanaSignedTx> {
	if (!ctx.source) {
		throw new Error('solana destination: no source plugin registered');
	}
	const { prep, preimage, plan } = await prepareSign(dWallet, input, cache);

	const result = await ctx.source.signMessage({
		dWallet,
		message: preimage,
		curve: plan.curve,
		signatureAlgorithm: plan.signatureAlgorithm,
		hash: plan.hash,
		...(input.userShareEncryptionKeys
			? { userShareEncryptionKeys: input.userShareEncryptionKeys }
			: {}),
		...(input.presign ? { presign: input.presign } : {}),
		...(input.encryptedShareId ? { encryptedShareId: input.encryptedShareId } : {}),
		...(input.dWalletCap ? { dWalletCap: input.dWalletCap } : {}),
		...(input.buildApproval ? { buildApproval: input.buildApproval } : {}),
		...(input.buildVerifiedPresignCap
			? { buildVerifiedPresignCap: input.buildVerifiedPresignCap }
			: {}),
	} as Parameters<typeof ctx.source.signMessage>[0]);

	return assembleSign(prep, result.signature);
}
