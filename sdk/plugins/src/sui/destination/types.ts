// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import type { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';
import type { IkaTransaction, Presign, UserShareEncryptionKeys } from '@ika.xyz/sdk';
import type { DWallet, SignedTx } from '@ika.xyz/sdk/plugin';

/** Curves Sui can sign with. RISTRETTO is excluded; passing it is a compile-time error. */
export type SuiSupportedCurve = 'ED25519' | 'SECP256K1' | 'SECP256R1';

/**
 * Per-call overrides forwarded verbatim to `ctx.source.signMessage(...)`. They
 * let callers customize per-sign without dropping to the source's lower-level
 * `requestSign` API.
 */
export interface SuiSignOverrides {
	/** Override the source's default USEK (multi-tenant servers, per-user keys). */
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	/** Skip auto-fetch and use a pre-completed presign. */
	readonly presign?: Presign;
	/**
	 * Encrypted share id for zero-trust and imported-key dWallets. Required when
	 * the dWallet handle was not created with one.
	 */
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

/**
 * Discriminated input for `ika.sui.sign(...)`:
 *   - `transaction`: caller supplies a `Transaction` plus the RPC client used to
 *     build it (needed to BCS-encode the transaction data). Intent scope is
 *     `TransactionData`.
 *   - `message`: caller supplies raw bytes. Intent scope is `PersonalMessage`
 *     for off-chain auth use cases.
 *
 * Both modes accept the `SuiSignOverrides` fields per-call.
 */
export type SuiSignInput = (
	| { readonly kind: 'transaction'; readonly tx: Transaction; readonly suiClient: SuiJsonRpcClient }
	| { readonly kind: 'message'; readonly message: Uint8Array }
) &
	SuiSignOverrides;

export interface SuiSignedPayload {
	/** TransactionData bytes (transaction path) OR the original message bytes (message path). */
	readonly bytes: Uint8Array;
	/** Sui-format serialized signature, base64. Ready for executeTransaction. */
	readonly signature: string;
	/** Sender Sui address (matches the dWallet's derived address). */
	readonly sender: string;
}

export type SuiSignedTx = SignedTx<'sui', SuiSignedPayload>;

/**
 * Flat input shape for `ika.sui.sign(...)`. The dWallet's curve is narrowed
 * to `SuiSupportedCurve` so passing an unsupported curve is a compile-time
 * error.
 */
export type SuiSignArgs = SuiSignInput & {
	readonly dWallet: DWallet<SuiSupportedCurve>;
};
