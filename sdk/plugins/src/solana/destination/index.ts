// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

export { solana } from './plugin.js';
export type {
	SolanaDestinationClientExtend,
	SolanaDestinationDWalletExtend,
} from './plugin.js';
export type {
	SolanaPublishablePayload,
	SolanaPublishableTx,
	SolanaSignArgs,
	SolanaSignedPayload,
	SolanaSignedTx,
	SolanaSignInput,
	SolanaSignOverrides,
	SolanaSupportedCurve,
} from './types.js';
export { deriveSolanaPublicKey } from './address.js';
