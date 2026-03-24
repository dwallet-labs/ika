// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * @ika.xyz/ows — OWS-compatible wallet standard backed by Ika dWallet MPC signing.
 *
 * No dependency on @open-wallet-standard/core — everything implemented natively
 * with proper two-layer policy enforcement (local + on-chain).
 *
 * @packageDocumentation
 */

// ─── Provider ────────────────────────────────────────────────────────────
export { IkaOWSProvider } from './provider.js';

// ─── Mnemonic Utilities ──────────────────────────────────────────────────
export { generateMnemonic, isValidMnemonic, deriveAddressFromMnemonic } from './mnemonic.js';

// ─── Policy Engine ───────────────────────────────────────────────────────
export { PolicyEngine } from './policy.js';
export type {
	PolicyFunction,
	PolicyContext,
	PolicyResult,
	DeclarativePolicy,
	DeclarativePolicyRules,
	OnChainPolicy,
} from './policy.js';

// ─── Executor ────────────────────────────────────────────────────────────
export { OWSExecutor } from './executor.js';
export type { TxEvent, TxResult } from './executor.js';

// ─── Presign Pool ────────────────────────────────────────────────────────
export { PresignPool } from './presign-pool.js';

// ─── Chain Mapping ───────────────────────────────────────────────────────
export {
	resolveChainParams,
	parseChainId,
	isChainSupported,
	getSupportedChains,
	namespacesForCurve,
	SUPPORTED_NAMESPACES,
} from './chains.js';
export type { ChainSigningParams } from './chains.js';

// ─── Address Derivation ──────────────────────────────────────────────────
export { deriveAddress, deriveAccountsForCurve } from './address.js';

// ─── Crypto Utilities ────────────────────────────────────────────────────
export { encryptMnemonic, decryptMnemonic, derivePrivateKeyFromMnemonic } from './crypto.js';

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
	PresignPoolEntry,
	CreateWalletOptions,
	CreateDWalletOptions,
	ImportMnemonicOptions,
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
export { handleRequest, startServer } from './server.js';
export type { IkaOWSServerConfig, OWSRequest, OWSResponse } from './server.js';

// ─── Errors ──────────────────────────────────────────────────────────────
export { OWSError, OWSErrorCode } from './errors.js';
