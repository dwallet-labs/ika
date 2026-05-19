// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

export { sui } from './plugin.js';
export type {
	SuiDestinationClientExtend,
	SuiDestinationDWalletExtend,
} from './plugin.js';
export type {
	SuiSignArgs,
	SuiSignedPayload,
	SuiSignedTx,
	SuiSignInput,
	SuiSignOverrides,
	SuiSupportedCurve,
} from './types.js';
export { deriveSuiAddress, SUI_SCHEME_FLAG, SUI_SCHEME_NAME } from './address.js';
export { signatureAlgorithmForCurve as suiSignatureAlgorithmForCurve, hashForCurve as suiHashForCurve } from './sign.js';
