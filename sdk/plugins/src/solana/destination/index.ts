// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

export { solana } from './plugin.js';
export { assembleSign, prepareSign } from './sign.js';
export type { SolanaDestinationClientExtend, SolanaDestinationDWalletExtend } from './plugin.js';
export type {
	SolanaPrepareSignArgs,
	SolanaPrepareSignResult,
	SolanaPublishablePayload,
	SolanaPublishableTx,
	SolanaSignArgs,
	SolanaSignedPayload,
	SolanaSignedTx,
	SolanaSignInput,
	SolanaSignOverrides,
	SolanaSignPlan,
	SolanaSignPrep,
	SolanaSupportedCurve,
} from './types.js';
export { deriveSolanaPublicKey } from './address.js';
