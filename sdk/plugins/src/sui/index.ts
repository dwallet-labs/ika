// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Convenience aggregator: re-exports everything Sui-related from one path.
// Consumers may also import from the more specific subpaths.
//
// `prepareSign` and `assembleSign` are named identically on the source and
// destination but do different things (source produces the
// user-sign-message; destination builds the chain-specific preimage /
// wraps the signature). They're re-exported under disambiguated aliases
// here. Reach for the subpath when you need both:
//
//   import { prepareSign, assembleSign } from '@ika.xyz/plugins/sui/source';
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
