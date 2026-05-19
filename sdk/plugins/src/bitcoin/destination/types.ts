// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { Psbt } from 'bitcoinjs-lib';
import type { TransactionObjectArgument } from '@mysten/sui/transactions';
import type { IkaTransaction, Presign, UserShareEncryptionKeys } from '@ika.xyz/sdk';
import type { DWallet, SignedTx } from '@ika.xyz/sdk/plugin';

import type { BitcoinMode, BitcoinNetwork, BitcoinSupportedCurve } from './address.js';

export type { BitcoinMode, BitcoinNetwork, BitcoinSupportedCurve } from './address.js';

export interface BitcoinSignOverrides {
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	readonly presign?: Presign;
	readonly encryptedShareId?: string;
	readonly dWalletCap?: string;
	readonly buildApproval?: (
		ikaTx: IkaTransaction,
		defaultCap: string,
	) => TransactionObjectArgument;
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
