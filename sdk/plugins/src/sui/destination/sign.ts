// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { messageWithIntent } from '@mysten/sui/cryptography';
import { toBase64 } from '@mysten/sui/utils';
import { blake2b } from '@noble/hashes/blake2.js';
import { Curve, Hash, SignatureAlgorithm } from '@ika.xyz/sdk';
import type { DWallet, IkaContext } from '@ika.xyz/sdk/plugin';

import { SUI_SCHEME_FLAG, type SuiAddressCache } from './address.js';
import type { SuiSignedTx, SuiSignInput } from './types.js';

/** Sui uses one (sigAlgo, hash) tuple per scheme. Callers do not pick this. */
export function signatureAlgorithmForCurve(curve: Curve): SignatureAlgorithm {
	switch (curve) {
		case Curve.ED25519:
			return SignatureAlgorithm.EdDSA;
		case Curve.SECP256K1:
			return SignatureAlgorithm.ECDSASecp256k1;
		case Curve.SECP256R1:
			return SignatureAlgorithm.ECDSASecp256r1;
		default:
			throw new Error(`Sui destination does not support curve ${curve}`);
	}
}

export function hashForCurve(curve: Curve): Hash {
	switch (curve) {
		case Curve.ED25519:
			return Hash.SHA512;
		case Curve.SECP256K1:
		case Curve.SECP256R1:
			return Hash.SHA256;
		default:
			throw new Error(`Sui destination does not support curve ${curve}`);
	}
}

/**
 * Sui serialized-signature wire format: `[scheme_flag (1B)][signature][publicKey]`,
 * base64-encoded. Inlined to avoid constructing a fake `PublicKey` instance just
 * to satisfy `toSerializedSignature`, which only reads the scheme flag and raw
 * key bytes.
 */
function encodeSuiSerializedSignature(
	flag: number,
	signature: Uint8Array,
	publicKey: Uint8Array,
): string {
	const out = new Uint8Array(1 + signature.length + publicKey.length);
	out[0] = flag;
	out.set(signature, 1);
	out.set(publicKey, 1 + signature.length);
	return toBase64(out);
}

/**
 * Build the bytes-to-sign, request a signature from the active source, and pack
 * the result into a Sui serialized signature. Accepts the abstract `DWallet`
 * so the destination works against any source plugin.
 */
export async function signCore(
	ctx: IkaContext,
	dWallet: DWallet,
	input: SuiSignInput,
	cache: SuiAddressCache,
): Promise<SuiSignedTx> {
	if (!ctx.source) {
		throw new Error('sui destination: no source plugin registered');
	}
	const flag = SUI_SCHEME_FLAG[dWallet.curve];
	if (flag === undefined || flag === 0xff) {
		throw new Error(
			`sui destination does not support curve ${dWallet.curve}. ` +
				`Supported: ED25519, SECP256K1, SECP256R1.`,
		);
	}

	const bytes =
		input.kind === 'transaction'
			? await input.tx.build({ client: input.suiClient })
			: input.message;

	const scope: 'TransactionData' | 'PersonalMessage' =
		input.kind === 'transaction' ? 'TransactionData' : 'PersonalMessage';
	const intentMessage = messageWithIntent(scope, bytes);
	const digest = blake2b(intentMessage, { dkLen: 32 });

	// Forward source-specific overrides. They are typed on `SuiSignInput` but
	// flow through `ctx.source.signMessage`, which names only the base shape;
	// the cast is required. The Sui source reads these fields; non-Sui sources
	// ignore unknown fields by contract.
	const result = await ctx.source.signMessage({
		dWallet,
		message: digest,
		curve: dWallet.curve,
		signatureAlgorithm: signatureAlgorithmForCurve(dWallet.curve),
		hash: hashForCurve(dWallet.curve),
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

	// publicKey and suiAddress are served from the per-instance cache. Both
	// depend on the same derivation, so repeated signs with this dWallet cost
	// one WASM call plus one blake2b after the first miss.
	const publicKey = await cache.publicKey(dWallet.curve, dWallet.publicOutput);
	const signature = encodeSuiSerializedSignature(flag, result.signature, publicKey);
	const sender = await cache.suiAddress(dWallet.curve, dWallet.publicOutput);

	return { chain: 'sui', payload: { bytes, signature, sender } };
}
