// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Convenience aggregator: re-exports everything Sui-related from one path.
// Consumers may also import from the more specific subpaths.
//
// The source exposes `prepareSignMessage` (user-side centralized-party
// sign message) and the destination exposes `prepareSign` + `assembleSign`
// (chain-specific preimage + signature wrap). The destination pair is
// re-exported under aliases here to match the convention:
//
//   import { prepareSignMessage } from '@ika.xyz/plugins/sui/source';
//   import { prepareSign, assembleSign } from '@ika.xyz/plugins/sui/destination';
export * from './source/index.js';
export {
	sui,
	assembleSign as suiAssembleSign,
	prepareSign as suiPrepareSign,
	deriveSuiAddress,
	SUI_SCHEME_FLAG,
	SUI_SCHEME_NAME,
	suiSignatureAlgorithmForCurve,
	suiHashForCurve,
} from './destination/index.js';
export type {
	SuiDestinationClientExtend,
	SuiDestinationDWalletExtend,
	SuiPrepareSignArgs,
	SuiPrepareSignResult,
	SuiSignArgs,
	SuiSignedPayload,
	SuiSignedTx,
	SuiSignInput,
	SuiSignOverrides,
	SuiSignPlan,
	SuiSignPrep,
	SuiSupportedCurve,
} from './destination/index.js';
export * from './publisher/index.js';
