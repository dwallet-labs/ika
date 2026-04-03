// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * OWS error codes per the specification, extended with Ika-specific codes.
 * @see https://docs.openwallet.sh/
 */
export enum OWSErrorCode {
	WALLET_NOT_FOUND = 'WALLET_NOT_FOUND',
	CHAIN_NOT_SUPPORTED = 'CHAIN_NOT_SUPPORTED',
	INVALID_INPUT = 'INVALID_INPUT',
	CAIP_PARSE_ERROR = 'CAIP_PARSE_ERROR',
	CURVE_MISMATCH = 'CURVE_MISMATCH',
	PASSPHRASE_REQUIRED = 'PASSPHRASE_REQUIRED',
	EXPORT_FAILED = 'EXPORT_FAILED',
	MPC_TIMEOUT = 'MPC_TIMEOUT',
	SIGNING_FAILED = 'SIGNING_FAILED',
	DKG_FAILED = 'DKG_FAILED',
	PRESIGN_FAILED = 'PRESIGN_FAILED',
	POLICY_DENIED = 'POLICY_DENIED',
	VAULT_ERROR = 'VAULT_ERROR',
	NOT_INITIALIZED = 'NOT_INITIALIZED',
}

export class OWSError extends Error {
	constructor(
		public readonly code: OWSErrorCode,
		message: string,
		public readonly cause?: unknown,
	) {
		super(`[${code}] ${message}`);
		this.name = 'OWSError';
	}
}
