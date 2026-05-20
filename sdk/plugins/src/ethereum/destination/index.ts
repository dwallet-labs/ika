// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

export { eth } from './plugin.js';
export { assembleEthereumPayload, assembleSign, prepareSign } from './sign.js';
export type {
	EthereumDestinationClientExtend,
	EthereumDestinationDWalletExtend,
} from './plugin.js';
export type {
	EthereumPrepareSignArgs,
	EthereumPrepareSignResult,
	EthereumPublishablePayload,
	EthereumPublishableTx,
	EthereumSignArgs,
	EthereumSignedPayload,
	EthereumSignedTx,
	EthereumSignInput,
	EthereumSignOverrides,
	EthereumSignPlan,
	EthereumSignPrep,
	EthereumSupportedCurve,
} from './types.js';
export {
	createEthereumAddressCache,
	deriveEthereumAddress,
	type EthereumAddressCache,
} from './address.js';
