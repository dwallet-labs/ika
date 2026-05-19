// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { Hex, TransactionSerializable, TypedDataDefinition } from 'viem';
import type { TransactionObjectArgument } from '@mysten/sui/transactions';
import type { IkaTransaction, Presign, UserShareEncryptionKeys } from '@ika.xyz/sdk';
import type { DWallet, SignedTx } from '@ika.xyz/sdk/plugin';

/** Ethereum addresses come from secp256k1 only. */
export type EthereumSupportedCurve = 'SECP256K1';

/**
 * Per-call overrides forwarded verbatim to the active source's `signMessage`.
 * Mirrors `SuiSignOverrides` / `SolanaSignOverrides`; kept separate so chain
 * destinations do not import each other's types.
 */
export interface EthereumSignOverrides {
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

/**
 * Three sign modes:
 *   - `transaction`: unsigned EIP-1559 / EIP-2930 / legacy tx via viem
 *     `TransactionSerializable`. Plugin keccak-hashes the serialized
 *     unsigned form, signs, fixes recovery id, returns serialized signed
 *     bytes ready for `eth_sendRawTransaction`.
 *   - `message`: EIP-191 personal_sign. Plugin prefixes
 *     `\x19Ethereum Signed Message:\n<len>` before hashing.
 *   - `typedData`: EIP-712 typed-data hash via viem `hashTypedData`.
 *
 * All three accept `EthereumSignOverrides` per-call.
 */
export type EthereumSignInput = (
	| { readonly kind: 'transaction'; readonly tx: TransactionSerializable }
	| { readonly kind: 'message'; readonly message: Uint8Array | string }
	| { readonly kind: 'typedData'; readonly typedData: TypedDataDefinition }
) &
	EthereumSignOverrides;

export type EthereumSignedPayload =
	| {
			readonly kind: 'transaction';
			/** RLP-serialized signed transaction, ready for `eth_sendRawTransaction`. */
			readonly serialized: Hex;
			/** keccak256 of the signed transaction. Equals the on-chain tx hash. */
			readonly hash: Hex;
			readonly sender: Hex;
	  }
	| {
			readonly kind: 'message' | 'typedData';
			/** 65-byte signature: r (32) || s (32) || v (1) as hex. */
			readonly signature: Hex;
			readonly sender: Hex;
	  };

/** Subset that can be broadcast: `transaction` variant only. */
export type EthereumPublishablePayload = Extract<EthereumSignedPayload, { kind: 'transaction' }>;

export type EthereumSignedTx = SignedTx<'ethereum', EthereumSignedPayload>;
export type EthereumPublishableTx = SignedTx<'ethereum', EthereumPublishablePayload>;

/**
 * Flat input shape for `ika.ethereum.sign(...)`. The dWallet's curve is
 * narrowed to secp256k1; passing any other curve is a compile-time error.
 */
export type EthereumSignArgs = EthereumSignInput & {
	readonly dWallet: DWallet<EthereumSupportedCurve>;
};
