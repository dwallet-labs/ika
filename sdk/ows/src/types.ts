// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { Keypair } from '@mysten/sui/cryptography';

import type { Curve, Hash, IkaConfig, SignatureAlgorithm } from '@ika.xyz/sdk';

/**
 * CAIP-2 chain identifier (e.g., "eip155:1", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp").
 * @see https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md
 */
export type ChainId = string;

/** Wallet kind discriminant. */
export type WalletKind = 'mnemonic' | 'dkg' | 'imported_key';

// ─── Vault Entry Types ───────────────────────────────────────────────────

/** Persisted presign reference. */
export interface PresignPoolEntry {
	presignId: string;
	signatureAlgorithm: SignatureAlgorithm;
	createdAt: string;
}

/** Fields common to all vault entries. */
interface IkaVaultEntryBase {
	owsVersion: 1;
	provider: 'ika';
	/** UUID v4 local wallet identifier. */
	id: string;
	name: string;
	kind: WalletKind;
	/** On-chain dWallet object ID. */
	dwalletId: string;
	/** dWallet capability object ID (proves ownership). */
	dwalletCapId: string;
	curve: Curve;
	/** Serialized UserShareEncryptionKeys (hex). */
	userShareKeysHex: string;
	/** Encrypted user secret key share object ID. */
	encryptedUserSecretKeyShareId: string;
	/** Hex-encoded public key from the dWallet. */
	publicKeyHex: string;
	/** Network encryption key ID used during creation. */
	networkEncryptionKeyId: string;
	/** ISO 8601 creation timestamp. */
	createdAt: string;
	/** Pre-created presign IDs for this wallet. */
	presignIds: PresignPoolEntry[];
}

/** Vault entry for a mnemonic-backed imported-key dWallet. */
export interface MnemonicVaultEntry extends IkaVaultEntryBase {
	kind: 'mnemonic';
	/** Base64-encoded AES-256-GCM ciphertext of the mnemonic. */
	encryptedMnemonic: string;
	/** Hex-encoded scrypt salt. */
	encryptionSalt: string;
	/** Hex-encoded GCM nonce. */
	encryptionNonce: string;
}

/** Vault entry for a pure DKG dWallet (no private key). */
export interface DkgVaultEntry extends IkaVaultEntryBase {
	kind: 'dkg';
}

/** Vault entry for an imported private key dWallet. */
export interface ImportedKeyVaultEntry extends IkaVaultEntryBase {
	kind: 'imported_key';
}

/** Discriminated union of all vault entry types. */
export type IkaVaultEntry = MnemonicVaultEntry | DkgVaultEntry | ImportedKeyVaultEntry;

// ─── Public Wallet Info ──────────────────────────────────────────────────

/** Wallet info returned by list/get operations. */
export interface IkaWalletInfo {
	id: string;
	name: string;
	kind: WalletKind;
	accounts: Array<{ chainId: ChainId; address: string }>;
	createdAt: string;
	dwalletId: string;
	dwalletCapId: string;
	curve: Curve;
	publicKeyHex: string;
}

/** Result from a signing operation. Matches OWS SignResult. */
export interface SignResult {
	signature: string;
	recoveryId?: number;
}

/** Result from a sign-and-send operation. Matches OWS SendResult. */
export interface SendResult {
	txHash: string;
}

// ─── Provider Config ─────────────────────────────────────────────────────

export interface IkaOWSProviderConfig {
	/** Ika network. */
	network: 'testnet' | 'mainnet';
	/** Ed25519 keypair — signs Sui txs and seeds encryption keys. */
	keypair: Keypair;
	/** Sui RPC URL override. */
	suiRpcUrl?: string;
	/** Ika config override (packages + objects). */
	ikaConfig?: IkaConfig;
	/** Vault directory. Defaults to ~/.ows/ika/. */
	vaultPath?: string;
	/** Default MPC polling timeout in ms. Default: 300000 (5 min). */
	mpcTimeout?: number;
	/** Default MPC polling interval in ms. Default: 2000. */
	mpcPollInterval?: number;
	/** On-chain policy engine config. When set, signing goes through the
	 *  policy engine instead of calling approve_message directly. */
	policyEngine?: PolicyEngineConfig;
}

// ─── Operation Options ───────────────────────────────────────────────────

/** Options for creating a pure DKG wallet. */
export interface CreateDWalletOptions {
	/** Cryptographic curve. Defaults to SECP256K1. */
	curve?: Curve;
	/** MPC timeout override in ms. */
	timeout?: number;
}

/** Options for importing a private key. */
export interface ImportPrivateKeyOptions {
	/** Cryptographic curve. Defaults to SECP256K1. */
	curve?: Curve;
	/** MPC timeout override in ms. */
	timeout?: number;
}

/** Options for signing operations. */
export interface SignOptions {
	/** Override the default hash algorithm for this chain. */
	hashOverride?: Hash;
	/** Override the default signature algorithm for this chain. */
	signatureAlgorithmOverride?: SignatureAlgorithm;
	/** Polling timeout in ms. */
	timeout?: number;
	/** Polling interval in ms. */
	interval?: number;
	/** Declared transaction value (required when spending_budget rule is active). */
	declaredValue?: bigint | number;
	/** Declared target address bytes (required when target_filter rule is active). */
	declaredTarget?: Uint8Array;
}

// ─── Policy Engine Config ────────────────────────────────────────────────

/** On-chain policy engine configuration. */
export interface PolicyEngineConfig {
	/** Package ID of the deployed ika_ows_policy contract. */
	packageId: string;
	/** Object ID of the shared PolicyEngine. */
	engineId: string;
	/** Object ID of the PolicyAccessCap held by this agent. */
	accessCapId: string;
	/** Active rules registered on the engine. */
	rules: PolicyRuleType[];
}

/** Supported built-in rule types. */
export type PolicyRuleType =
	| 'rate_limit'
	| 'expiry'
	| 'sender_allowlist'
	| 'allowed_algorithms'
	| 'spending_budget'
	| 'target_filter'
	| 'time_delay';

/** Rule configurations for engine setup. */
export interface RateLimitRuleConfig {
	type: 'rate_limit';
	/** Max signatures per window. */
	maxPerWindow: number;
	/** Window duration in milliseconds. */
	windowMs: number;
}

export interface ExpiryRuleConfig {
	type: 'expiry';
	/** Timestamp (ms) after which signing is blocked. */
	expiryMs: number;
}

export interface SenderAllowlistRuleConfig {
	type: 'sender_allowlist';
	/** Allowed Sui addresses. */
	allowed: string[];
}

export interface AllowedAlgorithmsRuleConfig {
	type: 'allowed_algorithms';
	/** Allowed (signatureAlgorithm, hashScheme) pairs as u32 numbers. */
	pairs: Array<{ signatureAlgorithm: number; hashScheme: number }>;
}

export interface SpendingBudgetRuleConfig {
	type: 'spending_budget';
	/** Max cumulative value per window. */
	maxPerWindow: number;
	/** Max value per transaction (0 = no per-tx limit). */
	maxPerTx: number;
	/** Window duration in milliseconds. */
	windowMs: number;
}

export interface TargetFilterRuleConfig {
	type: 'target_filter';
	/** Allowed target addresses (raw bytes as hex). */
	allowedTargets?: string[];
	/** Blocked target addresses (raw bytes as hex). */
	blockedTargets?: string[];
}

export interface TimeDelayRuleConfig {
	type: 'time_delay';
	/** Delay in milliseconds between commit and reveal. */
	delayMs: number;
}

/** Union of all rule configs. */
export type RuleConfig =
	| RateLimitRuleConfig
	| ExpiryRuleConfig
	| SenderAllowlistRuleConfig
	| AllowedAlgorithmsRuleConfig
	| SpendingBudgetRuleConfig
	| TargetFilterRuleConfig
	| TimeDelayRuleConfig;

/** Result of creating a policy engine. */
export interface PolicyEngineCreateResult {
	/** Object ID of the created PolicyEngine (shared). */
	engineId: string;
	/** Object ID of the PolicyAdminCap (transferred to creator). */
	adminCapId: string;
	/** Transaction digest. */
	digest: string;
}

/** Result of granting access to a policy engine. */
export interface PolicyAccessGrantResult {
	/** Object ID of the created PolicyAccessCap. */
	accessCapId: string;
	/** Transaction digest. */
	digest: string;
}
