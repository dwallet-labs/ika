// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

export { btc } from './plugin.js';
export type {
	BitcoinDestinationClientExtend,
	BitcoinDestinationDWalletExtend,
} from './plugin.js';
export type {
	BitcoinAddressOptions,
	BitcoinMode,
	BitcoinNetwork,
	BitcoinPreimagePayload,
	BitcoinPsbtPayload,
	BitcoinPublishablePayload,
	BitcoinPublishableTx,
	BitcoinSignArgs,
	BitcoinSignedPayload,
	BitcoinSignedTx,
	BitcoinSignInput,
	BitcoinSignOverrides,
	BitcoinSupportedCurve,
} from './types.js';
export {
	createBitcoinAddressCache,
	deriveBitcoinAddress,
	deriveAddressByMode,
	buildP2trScriptPath,
	buildCheckSigScript,
	hash160,
	networkParams,
	toXOnlyPubkey,
	TAPSCRIPT_LEAF_VERSION,
	type BitcoinAddressCache,
	type P2trBundle,
} from './address.js';
export {
	buildLegacyPreimage,
	p2pkhScript,
	type LegacyPreimageArgs,
} from './preimage/legacy.js';
export {
	buildBip143Preimage,
	p2wpkhScriptCode,
	type Bip143Args,
	SIGHASH_ALL,
	SIGHASH_NONE,
	SIGHASH_SINGLE,
	SIGHASH_ANYONECANPAY,
} from './preimage/bip143.js';
export {
	buildBip341Preimage,
	computeTapLeafHash,
	type Bip341Args,
} from './preimage/bip341.js';
