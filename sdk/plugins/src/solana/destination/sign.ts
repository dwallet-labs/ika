// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Curve, Hash, SignatureAlgorithm } from '@ika.xyz/sdk';
import type { DWallet, IkaContext } from '@ika.xyz/sdk/plugin';

import { type SolanaAddressCache } from './address.js';
import type { SolanaSignedTx, SolanaSignInput } from './types.js';

/**
 * Sign a Solana transaction or arbitrary bytes through the active source.
 * Accepts the abstract `DWallet` so the destination works against any source
 * plugin. Throws if the dWallet's curve is not Ed25519.
 *
 * In `transaction` mode, `input.tx.addSignature(...)` mutates the caller's
 * transaction in place. This matches @solana/web3.js conventions. Callers
 * should not reuse the transaction object after signing.
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
	if (dWallet.curve !== Curve.ED25519) {
		throw new Error(`solana destination requires ED25519 curve, got ${dWallet.curve}`);
	}

	const messageBytes =
		input.kind === 'transaction' ? input.tx.message.serialize() : input.message;

	// Forward source-specific overrides. The cast is required because
	// `ctx.source.signMessage` names only the base shape; the Sui source reads
	// these fields, other sources ignore unknown fields by contract.
	const result = await ctx.source.signMessage({
		dWallet,
		message: messageBytes,
		curve: Curve.ED25519,
		signatureAlgorithm: SignatureAlgorithm.EdDSA,
		hash: Hash.SHA512,
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
	const signature = result.signature;
	const pubkey = await cache.publicKey(dWallet.publicOutput);
	const sender = pubkey.toBase58();

	if (input.kind === 'transaction') {
		input.tx.addSignature(pubkey, signature);
		return {
			chain: 'solana',
			payload: { kind: 'transaction', transaction: input.tx, signature, sender },
		};
	}
	return {
		chain: 'solana',
		payload: { kind: 'message', signature, sender },
	};
}
