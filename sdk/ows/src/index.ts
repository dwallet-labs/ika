// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * @ika.xyz/odws — Open dWallet Standard (OdWS) backed by Ika dWallet MPC signing.
 *
 * @packageDocumentation
 */

// ─── Provider ────────────────────────────────────────────────────────────
export { IkaOWSProvider } from './client/provider.js';

// ─── Local Policy Filters ────────────────────────────────────────────────
export { PolicyEngine } from './policy/index.js';
export type {
	PolicyFunction,
	PolicyContext,
	PolicyResult,
	DeclarativePolicy,
	DeclarativePolicyRules,
	OnChainPolicy,
} from './policy/index.js';

// ─── Executor ────────────────────────────────────────────────────────────
export { OWSExecutor } from './client/executor.js';
export type { TxEvent, TxResult } from './client/executor.js';

// ─── Presign Pool ────────────────────────────────────────────────────────
export { PresignPool } from './client/presign-pool.js';

// ─── Chain Mapping ───────────────────────────────────────────────────────
export {
	resolveChainParams,
	parseChainId,
	isChainSupported,
	getSupportedChains,
	namespacesForCurve,
	SUPPORTED_NAMESPACES,
} from './chain/chains.js';
export type { ChainSigningParams } from './chain/chains.js';

// ─── Address Derivation ──────────────────────────────────────────────────
export { deriveAddress, deriveAccountsForCurve, deriveTaprootAddress } from './chain/address.js';

// ─── Crypto Utilities ────────────────────────────────────────────────────
export {
	hexToBytes,
	bytesToHex,
	ed25519SeedToPrivateKey,
	generateMnemonic,
	isValidMnemonic,
	derivePrivateKeyFromMnemonic,
	DERIVATION_PATHS,
} from './crypto/index.js';

// ─── Types ───────────────────────────────────────────────────────────────
export type {
	ChainId,
	WalletKind,
	IkaWalletInfo,
	SignResult,
	SendResult,
	IkaOWSProviderConfig,
	IkaVaultEntry,
	MnemonicVaultEntry,
	DkgVaultEntry,
	ImportedKeyVaultEntry,
	PresignPoolEntry,
	CreateDWalletOptions,
	ImportPrivateKeyOptions,
	SignOptions,
	PolicyEngineConfig,
	PolicyEngineCreateResult,
	PolicyAccessGrantResult,
	PolicyRuleType,
	RuleConfig,
	RateLimitRuleConfig,
	ExpiryRuleConfig,
	SenderAllowlistRuleConfig,
	AllowedAlgorithmsRuleConfig,
	SpendingBudgetRuleConfig,
	TargetFilterRuleConfig,
	TimeDelayRuleConfig,
} from './types.js';

// ─── Policy Engine Transaction Builders ──────────────────────────────────
export * as policyEngineTx from './tx/policy-engine.js';

// ─── REST Server ─────────────────────────────────────────────────────────
export { handleRequest, startServer } from './server/index.js';
export type { IkaOWSServerConfig, OWSRequest, OWSResponse } from './server/index.js';

// ─── Vault Backup ────────────────────────────────────────────────────────
export { exportVault, importVault } from './vault/index.js';

// ─── Errors ──────────────────────────────────────────────────────────────
export { OWSError, OWSErrorCode } from './errors.js';
