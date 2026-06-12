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
import type { Psbt } from 'bitcoinjs-lib';

import type { BitcoinMode, BitcoinNetwork, BitcoinSupportedCurve, P2trBundle } from './address.js';

export type { BitcoinMode, BitcoinNetwork, BitcoinSupportedCurve } from './address.js';

export interface BitcoinSignOverrides {
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	readonly presign?: Presign;
	readonly encryptedShareId?: string;
	readonly dWalletCap?: string;
	readonly buildApproval?: (ikaTx: IkaTransaction, defaultCap: string) => TransactionObjectArgument;
	readonly buildVerifiedPresignCap?: (
		ikaTx: IkaTransaction,
		presign: Presign,
	) => TransactionObjectArgument;
}

/**
 * Discriminated input for `ika.bitcoin.sign(...)`:
 *
 *   - `psbt`     The plugin reads/updates a PSBT input, computes the right
 *                sighash preimage for the requested mode, asks the source
 *                to sign, and applies the signature back into the PSBT. The
 *                resulting payload carries the finalized tx hex ready for
 *                broadcast.
 *   - `preimage` Caller supplies a raw preimage already constructed
 *                elsewhere (e.g. a multisig contract that pre-validates
 *                signatures). Returns just the raw schnorr/ECDSA signature.
 *                Useful when the assembled tx isn't built on this side.
 */
export type BitcoinSignInput = (
	| {
			readonly kind: 'psbt';
			readonly psbt: Psbt;
			readonly inputIndex: number;
			readonly mode: BitcoinMode;
			readonly network: BitcoinNetwork;
			/** Optional sighash type override; defaults are mode-specific. */
			readonly hashType?: number;
	  }
	| {
			readonly kind: 'preimage';
			readonly preimage: Uint8Array;
			readonly mode: BitcoinMode;
	  }
) &
	BitcoinSignOverrides;

export type BitcoinPsbtPayload = {
	readonly kind: 'psbt';
	readonly psbt: Psbt;
	readonly signedTxHex: string;
	readonly txid: string;
	readonly network: BitcoinNetwork;
	readonly mode: BitcoinMode;
	readonly sender: string;
};

export type BitcoinPreimagePayload = {
	readonly kind: 'preimage';
	readonly signature: Uint8Array;
	readonly mode: BitcoinMode;
};

export type BitcoinSignedPayload = BitcoinPsbtPayload | BitcoinPreimagePayload;

/** Only PSBT-mode payloads can be broadcast. */
export type BitcoinPublishablePayload = Extract<BitcoinSignedPayload, { kind: 'psbt' }>;

export type BitcoinSignedTx = SignedTx<'bitcoin', BitcoinSignedPayload>;
export type BitcoinPublishableTx = SignedTx<'bitcoin', BitcoinPublishablePayload>;

export interface BitcoinAddressOptions {
	readonly mode: BitcoinMode;
	readonly network: BitcoinNetwork;
}

export type BitcoinSignArgs = BitcoinSignInput & {
	readonly dWallet: DWallet<BitcoinSupportedCurve>;
};

/**
 * The (curve, signatureAlgorithm, hash) triple the MPC network will use for
 * the signature. Useful when handing the preimage to a custom Move contract
 * (multisig, future-sign, sponsored) that needs to construct a matching
 * Ika sign request: the contract submits `{message: prep.preimage,
 * curve: prep.plan.curve, signature_algorithm: prep.plan.signatureAlgorithm,
 * hash_scheme: prep.plan.hash}` to the coordinator.
 */
export interface BitcoinSignPlan {
	readonly curve: Curve;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly hash: Hash;
}

/**
 * Assemble context for a PSBT input — exactly what `assembleSign` needs to
 * apply a signature and produce the broadcast-ready tx. Reconstruct this
 * directly at execute-time (e.g. when the PSBT comes back from an on-chain
 * multisig contract) without re-running `prepareSign`. `psbt`,
 * `compressedPubkey`, and `p2trBundle` are referenced, not cloned — don't
 * mutate the PSBT between obtaining the prep and calling `assembleSign`.
 */
export interface BitcoinPsbtPrep {
	readonly kind: 'psbt';
	readonly mode: BitcoinMode;
	readonly network: BitcoinNetwork;
	readonly sender: string;
	readonly psbt: Psbt;
	readonly inputIndex: number;
	readonly hashType: number;
	readonly compressedPubkey: Uint8Array;
	readonly p2trBundle: P2trBundle | undefined;
}

/**
 * Assemble context for `kind: 'preimage'` — `assembleSign` just packages
 * the signature with the mode into the `preimage` payload variant.
 */
export interface BitcoinPreimagePrep {
	readonly kind: 'preimage';
	readonly mode: BitcoinMode;
}

export type BitcoinSignPrep = BitcoinPsbtPrep | BitcoinPreimagePrep;

/**
 * Return shape of `prepareSign`. Separates the assemble context (`prep`)
 * from the data you hand off externally (`preimage`, `plan`) so the prep
 * type carries only what `assembleSign` actually reads. When reconstructing
 * a prep from persisted state at assemble-time, callers build a
 * `BitcoinSignPrep` directly without needing to re-derive the preimage.
 */
export interface BitcoinPrepareSignResult {
	/** Assemble context to pass to `assembleSign(prep, signature)`. */
	readonly prep: BitcoinSignPrep;
	/**
	 * Bytes the MPC hashes-then-signs. Hand to whatever Move flow gates
	 * the actual `request_sign` call (multisig vote, future-sign, ...).
	 */
	readonly preimage: Uint8Array;
	/** (curve, signatureAlgorithm, hash) the MPC will use. */
	readonly plan: BitcoinSignPlan;
}

export type BitcoinPrepareSignArgs = BitcoinSignInput & {
	readonly dWallet: DWallet<BitcoinSupportedCurve>;
};
