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
import type { Hex, TransactionSerializable, TypedDataDefinition } from 'viem';

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
	readonly buildApproval?: (ikaTx: IkaTransaction, defaultCap: string) => TransactionObjectArgument;
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

/**
 * The (curve, signatureAlgorithm, hash) triple the MPC will use. Ethereum
 * always uses `(SECP256K1, ECDSASecp256k1, KECCAK256)` regardless of which
 * sign mode; the plan field exists so the prepare/assemble shape is
 * symmetric with the other destinations.
 */
export interface EthereumSignPlan {
	readonly curve: Curve;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly hash: Hash;
}

/**
 * Assemble context for an Ethereum sign — what `assembleSign` needs to
 * resolve yParity (via `digest` + `sender`) and serialize the signed
 * payload (via `input` for `tx` / `message` / `typedData`). No `preimage`
 * or `plan` here; those live in {@link EthereumPrepareSignResult}.
 */
export interface EthereumSignPrep {
	readonly digest: Hex;
	readonly sender: Hex;
	readonly input: EthereumSignInput;
}

/**
 * Return shape of `prepareSign`: assemble context plus the handoff data
 * (`preimage`, `plan`) for the Move flow that gates the actual
 * `request_sign` call.
 */
export interface EthereumPrepareSignResult {
	/** Assemble context to pass to `assembleSign(prep, signature)`. */
	readonly prep: EthereumSignPrep;
	/** Pre-keccak bytes the MPC hashes-then-signs. */
	readonly preimage: Uint8Array;
	/** (curve, signatureAlgorithm, hash) the MPC will use. */
	readonly plan: EthereumSignPlan;
}

export type EthereumPrepareSignArgs = EthereumSignInput & {
	readonly dWallet: DWallet<EthereumSupportedCurve>;
};
