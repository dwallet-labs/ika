// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Curve, Hash, SignatureAlgorithm } from '@ika.xyz/sdk';
import type { DWallet, IkaContext } from '@ika.xyz/sdk/plugin';
import {
	concat,
	hashDomain,
	hashMessage,
	hashStruct,
	hashTypedData,
	keccak256,
	recoverAddress,
	serializeSignature,
	serializeTransaction,
	stringToBytes,
} from 'viem';
import type { Hex } from 'viem';

import type { EthereumAddressCache } from './address.js';
import type {
	EthereumPrepareSignResult,
	EthereumSignedPayload,
	EthereumSignedTx,
	EthereumSignInput,
	EthereumSignPrep,
} from './types.js';

function bytesToHex(b: Uint8Array): Hex {
	return ('0x' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')) as Hex;
}

function hexToBytes(hex: Hex): Uint8Array {
	const h = hex.startsWith('0x') ? hex.slice(2) : hex;
	const out = new Uint8Array(h.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = parseInt(h.substr(i * 2, 2), 16);
	}
	return out;
}

/**
 * Build the pre-keccak bytes + digest + dWallet address WITHOUT submitting
 * anything on chain. Returns `{ prep, preimage, plan }`: `prep` for
 * `assembleSign`, `preimage` + `plan` for the Move flow that gates the
 * actual `request_sign` call. See the bitcoin destination's docs for the
 * typical hand-off flow — the shape is the same across destinations.
 *
 * `sign()` composes `prepareSign` → `ctx.source.signMessage` →
 * `assembleSign`. Use prepare/assemble directly when the sign request
 * doesn't go through the source plugin (multisig, future-sign, sponsored).
 */
export async function prepareSign(
	dWallet: DWallet,
	input: EthereumSignInput,
	cache: EthereumAddressCache,
): Promise<EthereumPrepareSignResult> {
	if (dWallet.curve !== Curve.SECP256K1) {
		throw new Error(`ethereum destination does not support curve ${dWallet.curve}. Use SECP256K1.`);
	}
	const sender = await cache.address(dWallet.curve, dWallet.publicOutput);
	return {
		prep: {
			digest: digestForInput(input),
			sender,
			input,
		},
		preimage: preHashForInput(input),
		plan: {
			curve: Curve.SECP256K1,
			signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
			hash: Hash.KECCAK256,
		},
	};
}

/**
 * Apply the network's 64-byte `(r || s)` signature to a prepared payload.
 * For `transaction` mode, recovers `yParity` by trying both candidates and
 * serializes the signed RLP. For `message` / `typedData`, packs `(r, s, v)`
 * into the 65-byte hex signature viem's recovery helpers expect.
 *
 * Throws if neither yParity recovers to the prepared sender — that means
 * the signature does not verify against the dWallet's public key
 * (protocol-level bug, not ambiguity).
 */
export async function assembleSign(
	prep: EthereumSignPrep,
	signature: Uint8Array,
): Promise<EthereumSignedTx> {
	const payload = await assembleEthereumPayload(prep.input, signature, prep.sender, prep.digest);
	return { chain: 'ethereum', payload };
}

/**
 * One-shot sign: composes `prepareSign` → `ctx.source.signMessage` →
 * `assembleSign`. Existing callers stay unchanged; this is the same
 * implementation factored through the new primitives.
 */
export async function signCore(
	ctx: IkaContext,
	dWallet: DWallet,
	input: EthereumSignInput,
	cache: EthereumAddressCache,
): Promise<EthereumSignedTx> {
	if (!ctx.source) {
		throw new Error('ethereum destination: no source plugin registered');
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

/**
 * Turn a raw 64-byte `(r || s)` MPC signature into the publishable / signed
 * payload for the given input mode. Use this directly from non-custodial
 * orchestrators that already have the signature in hand (fetched from
 * `ikaClient.getSignInParticularState`, replayed from storage, etc.) — the
 * destination plugin reuses this helper internally.
 *
 * Recovers yParity by trying both values and accepting the one that
 * recovers to `expectedSender`. Throws if neither does — that indicates the
 * MPC signature does not verify against the dWallet's public key.
 */
export async function assembleEthereumPayload(
	input: EthereumSignInput,
	signature: Uint8Array,
	expectedSender: Hex,
	digest?: Hex,
): Promise<EthereumSignedPayload> {
	if (signature.length !== 64) {
		throw new Error(
			`ethereum destination: expected 64-byte (r||s) signature, got ${signature.length}`,
		);
	}
	const r = bytesToHex(signature.subarray(0, 32));
	const s = bytesToHex(signature.subarray(32, 64));
	const resolvedDigest = digest ?? digestForInput(input);
	const yParity = await resolveYParity(resolvedDigest, expectedSender, r, s);

	if (input.kind === 'transaction') {
		const serialized = serializeTransaction(input.tx, { r, s, yParity });
		const hash = keccak256(serialized);
		return { kind: 'transaction', serialized, hash, sender: expectedSender };
	}
	return {
		kind: input.kind === 'message' ? 'message' : 'typedData',
		signature: serializeSignature({ r, s, yParity }),
		sender: expectedSender,
	};
}

function digestForInput(input: EthereumSignInput): Hex {
	if (input.kind === 'transaction') {
		return keccak256(serializeTransaction(input.tx));
	}
	if (input.kind === 'message') {
		return hashMessage(
			typeof input.message === 'string' ? input.message : { raw: bytesToHex(input.message) },
		);
	}
	return hashTypedData(input.typedData);
}

/**
 * The bytes the MPC network keccak256s before signing. For each mode this
 * is the input to keccak256 inside `digestForInput`, i.e. the unsigned-tx
 * RLP, the EIP-191 prefix-and-message blob, or the EIP-712 0x1901+domain
 * +struct blob. Sending these (with `hash: KECCAK256`) yields a signature
 * that recovers from `digest`.
 */
function preHashForInput(input: EthereumSignInput): Uint8Array {
	if (input.kind === 'transaction') {
		return hexToBytes(serializeTransaction(input.tx));
	}
	if (input.kind === 'message') {
		const msgBytes =
			typeof input.message === 'string' ? stringToBytes(input.message) : input.message;
		// EIP-191 / personal_sign prefix layout. Matches viem's `hashMessage`
		// pre-keccak input: `0x19` + "Ethereum Signed Message:\n" + decimal
		// length + raw message bytes.
		const prefix = stringToBytes(`\x19Ethereum Signed Message:\n${msgBytes.length}`);
		const out = new Uint8Array(prefix.length + msgBytes.length);
		out.set(prefix, 0);
		out.set(msgBytes, prefix.length);
		return out;
	}
	// EIP-712: pre-hash = 0x1901 || domainSeparator || hashStruct(message).
	// viem's hashTypedData applies keccak256 over exactly this blob.
	const { domain = {}, message, primaryType, types } = input.typedData;
	const allTypes = {
		EIP712Domain: types?.EIP712Domain ?? [],
		...types,
	};
	const parts: Hex[] = ['0x1901', hashDomain({ domain, types: allTypes })];
	if (primaryType !== 'EIP712Domain') {
		parts.push(hashStruct({ data: message, primaryType: primaryType as string, types: allTypes }));
	}
	return hexToBytes(concat(parts) as Hex);
}

/**
 * Recover the signer address under each yParity and return the one matching
 * the dWallet's address. Throws when neither matches — that means the MPC
 * produced an (r, s) that does not verify against the dWallet's public key,
 * which is a protocol-level bug, not a recovery ambiguity.
 */
async function resolveYParity(digest: Hex, sender: Hex, r: Hex, s: Hex): Promise<0 | 1> {
	const senderLower = sender.toLowerCase();
	for (const yParity of [0, 1] as const) {
		try {
			const recovered = await recoverAddress({
				hash: digest,
				signature: serializeSignature({ r, s, yParity }),
			});
			if (recovered.toLowerCase() === senderLower) return yParity;
		} catch {
			continue;
		}
	}
	throw new Error(
		`ethereum destination: neither yParity recovered to dWallet address ${sender}. ` +
			`Signature does not verify against the dWallet's public key.`,
	);
}
