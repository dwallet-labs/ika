// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type {
	Curve,
	Hash,
	IkaTransaction,
	Presign,
	SignatureAlgorithm,
	UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import type { DWallet, SignedTx } from '@ika.xyz/sdk/plugin';
import type { TransactionObjectArgument } from '@mysten/sui/transactions';
import type { VersionedTransaction } from '@solana/web3.js';

/** Solana addresses must come from Ed25519 dWallets. */
export type SolanaSupportedCurve = 'ED25519';

/**
 * Per-call overrides forwarded verbatim to the active source's `signMessage`.
 * Mirrors `SuiSignOverrides`; kept as a separate type so destinations do not
 * import each other's types.
 */
export interface SolanaSignOverrides {
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	readonly presign?: Presign;
	readonly encryptedShareId?: string;
	/** dWalletCap object id override (transferred cap, multisig-held cap, etc.). */
	readonly dWalletCap?: string;
	/** Custom message-approval builder for sponsored or multisig approval flows. */
	readonly buildApproval?: (ikaTx: IkaTransaction, defaultCap: string) => TransactionObjectArgument;
	/** Custom presign-cap verifier builder for pre-verified caps from upstream flows. */
	readonly buildVerifiedPresignCap?: (
		ikaTx: IkaTransaction,
		presign: Presign,
	) => TransactionObjectArgument;
}

export type SolanaSignInput = (
	| { readonly kind: 'transaction'; readonly tx: VersionedTransaction }
	| { readonly kind: 'message'; readonly message: Uint8Array }
) &
	SolanaSignOverrides;

/**
 * Discriminated payload returned from `ika.solana.sign(...)`. The publisher
 * refuses message-mode payloads at compile time; message mode produces off-chain
 * auth signatures that are not broadcastable.
 */
export type SolanaSignedPayload =
	| {
			readonly kind: 'transaction';
			readonly transaction: VersionedTransaction;
			readonly signature: Uint8Array;
			readonly sender: string;
	  }
	| {
			readonly kind: 'message';
			readonly signature: Uint8Array;
			readonly sender: string;
	  };

/** Subset of `SolanaSignedPayload` that can be broadcast (transaction variant only). */
export type SolanaPublishablePayload = Extract<SolanaSignedPayload, { kind: 'transaction' }>;

export type SolanaSignedTx = SignedTx<'solana', SolanaSignedPayload>;
export type SolanaPublishableTx = SignedTx<'solana', SolanaPublishablePayload>;

/**
 * Flat input shape for `ika.solana.sign(...)`. The dWallet's curve is narrowed
 * to Ed25519; passing any other curve is a compile-time error.
 */
export type SolanaSignArgs = SolanaSignInput & {
	readonly dWallet: DWallet<SolanaSupportedCurve>;
};

/**
 * Solana always signs `(ED25519, EdDSA, SHA512)`. The plan field exists so
 * the prepare/assemble shape is symmetric with the other destinations.
 */
export interface SolanaSignPlan {
	readonly curve: Curve;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly hash: Hash;
}

/**
 * Assemble context. `input` is kept so `assembleSign` can mutate the
 * right `VersionedTransaction` (for `kind: 'transaction'`) or wrap the
 * signature alone (`kind: 'message'`). `preimage` and `plan` live in the
 * {@link SolanaPrepareSignResult}.
 */
export interface SolanaSignPrep {
	readonly sender: string;
	readonly input: SolanaSignInput;
}

/**
 * Return shape of `prepareSign`: assemble context plus the handoff data
 * (`preimage`, `plan`) for the Move flow that gates the actual
 * `request_sign` call.
 */
export interface SolanaPrepareSignResult {
	/** Assemble context to pass to `assembleSign(prep, signature)`. */
	readonly prep: SolanaSignPrep;
	/** Raw message bytes the Ed25519 signer hashes internally with SHA-512. */
	readonly preimage: Uint8Array;
	/** (curve, signatureAlgorithm, hash) the MPC will use. */
	readonly plan: SolanaSignPlan;
}

export type SolanaPrepareSignArgs = SolanaSignInput & {
	readonly dWallet: DWallet<SolanaSupportedCurve>;
};
