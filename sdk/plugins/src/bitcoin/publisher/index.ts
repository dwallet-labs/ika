// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

export { bitcoinPublisher, defaultEsploraUrl } from './plugin.js';
export type { BitcoinPublisherOptions } from './plugin.js';
// Re-export the publishable types so callers that only import from the
// `/publisher` subpath can name the payload + network types without a
// second import from `/destination`.
export type {
	BitcoinNetwork,
	BitcoinPublishablePayload,
	BitcoinPublishableTx,
} from '../destination/types.js';
