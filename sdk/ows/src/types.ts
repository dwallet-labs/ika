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
export type WalletKind = 'mnemonic' | 'dkg';

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

/** Vault entry for a pure DKG dWallet (no mnemonic). */
export interface DkgVaultEntry extends IkaVaultEntryBase {
	kind: 'dkg';
}

/** Discriminated union of all vault entry types. */
export type IkaVaultEntry = MnemonicVaultEntry | DkgVaultEntry;

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
}

// ─── Operation Options ───────────────────────────────────────────────────

/** Options for creating a mnemonic-backed wallet. */
export interface CreateWalletOptions {
	/** Cryptographic curve. Defaults to SECP256K1. */
	curve?: Curve;
	/** BIP-39 word count (12 or 24). */
	words?: number;
	/** MPC timeout override in ms. */
	timeout?: number;
}

/** Options for creating a pure DKG wallet. */
export interface CreateDWalletOptions {
	/** Cryptographic curve. Defaults to SECP256K1. */
	curve?: Curve;
	/** MPC timeout override in ms. */
	timeout?: number;
}

/** Options for importing from mnemonic. */
export interface ImportMnemonicOptions {
	/** Cryptographic curve. Defaults to SECP256K1. */
	curve?: Curve;
	/** BIP-44 account index. Defaults to 0. */
	index?: number;
	/** MPC timeout override in ms. */
	timeout?: number;
}

/** Options for importing from private key. */
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
}
