// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { VersionedTransaction } from '@solana/web3.js';
import type { TransactionObjectArgument } from '@mysten/sui/transactions';
import type { IkaTransaction, Presign, UserShareEncryptionKeys } from '@ika.xyz/sdk';
import type { DWallet, SignedTx } from '@ika.xyz/sdk/plugin';

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
	readonly buildApproval?: (
		ikaTx: IkaTransaction,
		defaultCap: string,
	) => TransactionObjectArgument;
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
