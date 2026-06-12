// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type {
	Curve,
	Hash,
	IkaConfig,
	IkaTransaction,
	Network,
	Presign,
	SignatureAlgorithm,
	UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import type { BaseSignResult, SignMessageInput } from '@ika.xyz/sdk/plugin';
import type { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import type { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import type { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

import type { SuiDWallet } from './dwallet.js';

// =============================================================================
// Signer abstraction
// =============================================================================
//
// The source plugin needs to (a) know which Sui address is paying for and
// owning the coordinator operations and (b) submit signed transactions. In
// a backend / node script that's an `Ed25519Keypair`. In a browser / dApp
// Kit context the user has only an address plus a `signAndExecuteTransaction`
// function returned by `useSignAndExecuteTransaction()`. Both shapes are
// accepted via `SuiSigner`; the plugin normalizes internally.

/**
 * Minimum shape the plugin needs out of an executed transaction: events from
 * the produced PTB (used to parse `PresignRequestEvent`, `SignRequestEvent`,
 * etc.). dApp Kit's mutation must be called with `options: { showEvents:
 * true }` so the events array is populated.
 *
 * `digest` is optional but recommended — consumers that submit follow-up
 * txs depending on this one (analytics, retries, polling) need it. The
 * SDK's keypair-mode executor populates it; wallet-signer integrations
 * should pass it through from their hook return.
 */
export interface SuiTxExecutionResult {
	readonly digest?: string;
	readonly events?: Array<{
		readonly eventType: string;
		readonly bcs?: number[] | Uint8Array | null;
	}> | null;
}

/**
 * Wallet-style signer (dApp Kit, custom hardware wallet, multisig wrapper,
 * etc.). `signAndExecuteTransaction` MUST return a result whose `events`
 * include the on-chain Move events for the executed PTB; otherwise the
 * source plugin cannot parse DKG / presign / sign event ids.
 */
export interface SuiWalletSigner {
	readonly address: string;
	signAndExecuteTransaction(tx: Transaction): Promise<SuiTxExecutionResult>;
}

export type SuiSigner = Ed25519Keypair | SuiWalletSigner;

/** Type guard: the user passed an `Ed25519Keypair`, not a wallet signer. */
export function isEd25519Keypair(s: SuiSigner): s is Ed25519Keypair {
	return typeof (s as Ed25519Keypair).getPublicKey === 'function';
}

// Source plugin options.

/** Per-operation polling timeouts in milliseconds. */
export interface SuiSourceTimeouts {
	readonly dkg?: number;
	readonly presign?: number;
	readonly sign?: number;
	readonly shareVerify?: number;
}

export interface SuiSourceOptions {
	readonly network: Network;
	/**
	 * Pays for and owns every coordinator transaction. Either an
	 * `Ed25519Keypair` (server-side flow — the plugin signs+executes via
	 * `suiClient`) or a `SuiWalletSigner` (browser / dApp Kit flow — the
	 * caller's `signAndExecuteTransaction` callback is invoked for each
	 * tx). Mix-and-match per dWallet by constructing one `suiSource` per
	 * signer.
	 */
	readonly signer: SuiSigner;
	/**
	 * Override the sender address recorded on every coordinator PTB and used
	 * as the recipient of leftover IKA/SUI fee coins. Defaults to the
	 * keypair's Sui address (Ed25519Keypair case) or `signer.address`
	 * (wallet case). Override only when you intentionally want the tx
	 * sender to differ from the signing key, e.g. sponsored-tx wrappers.
	 */
	readonly signerAddress?: string;
	/**
	 * Default user-share encryption keys for zero-trust and imported-key flows.
	 * Optional; every relevant building block also accepts a per-call override.
	 */
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	/** Custom Sui RPC client. If omitted, one is built from `network` and `rpcUrl`. */
	readonly suiClient?: SuiJsonRpcClient;
	/** Custom RPC URL. Ignored when `suiClient` is provided. */
	readonly rpcUrl?: string;
	/**
	 * Override the IkaConfig (packages + objects). Used for localnet / custom
	 * deployments where `getNetworkConfig(network)` doesn't apply. The
	 * `network` field is still required for the Sui client factory but is
	 * otherwise ignored when this is set.
	 */
	readonly config?: IkaConfig;
	/** Per-op IKA fee budget in MIST. Default `500_000_000` (0.5 IKA). */
	readonly ikaFeePerOp?: bigint;
	/** SUI gas split per op in MIST. Default `1_000_000`. */
	readonly suiGasPerOp?: bigint;
	/** Settling buffer between submitting a tx and querying its derived objects. Default 2000ms. */
	readonly postTxSleepMs?: number;
	/** Per-op polling timeouts. Defaults: dkg=600s, presign=300s, sign=300s, shareVerify=300s. */
	readonly timeouts?: SuiSourceTimeouts;
}

export interface ResolvedTimeouts {
	readonly dkg: number;
	readonly presign: number;
	readonly sign: number;
	readonly shareVerify: number;
}

export interface SuiSourceDefaults {
	/**
	 * Normalized executor for the configured signer. Returns the executed
	 * transaction's events. Keypair-mode signers go through
	 * `suiClient.signAndExecuteTransaction` with `include: { events: true }`;
	 * wallet-mode signers call the user-supplied
	 * `signAndExecuteTransaction` directly.
	 */
	readonly signAndExecute: (tx: Transaction) => Promise<SuiTxExecutionResult>;
	readonly signerAddress: string;
	readonly userShareEncryptionKeys: UserShareEncryptionKeys | undefined;
	readonly ikaFee: bigint;
	readonly suiGas: bigint;
	readonly postTxSleepMs: number;
	readonly suiClient: SuiJsonRpcClient;
	readonly config: IkaConfig;
	readonly timeouts: ResolvedTimeouts;
}

// SignMessage input/output for the Sui source.

export interface SuiSignMessageInput extends SignMessageInput<SuiDWallet> {
	/**
	 * Encrypted user secret key share id, used for zero-trust and imported-key
	 * signing. Defaults to `dWallet.encryptedShareId` if present on the handle.
	 */
	readonly encryptedShareId?: string;
	/** Override the user-share encryption keys for this single call. */
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	/** Pre-computed presign. If omitted, the source requests one. */
	readonly presign?: Presign;
	/** Override the cap object id used for approval. See `RequestSignInput`. */
	readonly dWalletCap?: string;
	/** Custom approval builder. See `BuildApprovalHook`. */
	readonly buildApproval?: BuildApprovalHook;
	/** Custom presign-cap verifier. See `BuildVerifiedPresignCapHook`. */
	readonly buildVerifiedPresignCap?: BuildVerifiedPresignCapHook;
}

export interface SuiSignResult extends BaseSignResult {
	/** Move SignSession object id. */
	readonly signId: string;
}

// DKG building-block inputs.

export interface PrepareDKGInput {
	readonly curve: Curve;
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	readonly sessionIdentifier?: Uint8Array;
	readonly senderAddress?: string;
	readonly signal?: AbortSignal;
}

export interface PrepareDKGOutput {
	readonly userDKGMessage: Uint8Array;
	readonly userSecretKeyShare: Uint8Array;
	readonly userPublicOutput: Uint8Array;
	readonly encryptedUserShareAndProof: Uint8Array;
	readonly sessionIdentifier: Uint8Array;
}

/**
 * Optional cap-recipient override on DKG-class inputs. The `dWalletCap`
 * returned by the DKG defaults to going to the tx sender (the configured
 * signer). When DKG is paid for by one account but the resulting dWallet
 * is meant to be controlled by another (e.g. backend creates dWallet for
 * an end-user), set `capRecipient` so the cap lands at the controller's
 * address directly. Pairs cleanly with `ika.sui.withSigner(other)` for
 * "sign as a different account later" flows.
 */
interface CapRecipientOverride {
	readonly capRecipient?: string;
}

export interface RequestZeroTrustDKGInput extends CapRecipientOverride {
	readonly dkgRequestInput: PrepareDKGOutput;
	readonly curve: Curve;
	readonly sessionIdentifier: Uint8Array;
	readonly networkEncryptionKeyId?: string;
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	readonly signal?: AbortSignal;
}

export interface RequestSharedDKGInput extends CapRecipientOverride {
	readonly publicKeyShareAndProof: Uint8Array;
	readonly publicUserSecretKeyShare: Uint8Array;
	readonly userPublicOutput: Uint8Array;
	readonly curve: Curve;
	readonly sessionIdentifier: Uint8Array;
	readonly networkEncryptionKeyId?: string;
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	readonly signal?: AbortSignal;
}

export interface RequestImportedKeyInput extends CapRecipientOverride {
	readonly importedKey: Uint8Array;
	readonly curve: Curve;
	readonly sessionIdentifier?: Uint8Array;
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	readonly senderAddress?: string;
	readonly signal?: AbortSignal;
}

export interface RequestImportedKeyOutput {
	readonly dWallet: SuiDWallet;
	readonly encryptedShareId: string;
	readonly userPublicOutput: Uint8Array;
}

/**
 * Promotes an imported-key dWallet to imported-key-shared by publishing the
 * user's secret share on chain. IRREVERSIBLE: once published, anyone with the
 * dWallet cap can sign without the user. Callers must pass
 * `acknowledge: 'i-understand-this-is-irreversible'`.
 */
export interface RevealUserSecretShareInput {
	readonly dWallet: SuiDWallet;
	readonly acknowledge: 'i-understand-this-is-irreversible';
	readonly encryptedShareId?: string;
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	readonly signal?: AbortSignal;
}

// Presign building-block inputs. Two flavours: global (per curve and algo)
// and per-dWallet (required for imported-key ECDSA).

export interface RequestGlobalPresignInput {
	readonly curve: Curve;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly networkEncryptionKeyId?: string;
	readonly signal?: AbortSignal;
}

export interface RequestPresignInput {
	readonly dWallet: SuiDWallet;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly signal?: AbortSignal;
}

// Sign building-block input.

/**
 * Hook for fully custom approval construction. Invoked when the plugin needs a
 * `MessageApproval` (or `ImportedKeyMessageApproval` for imported-key dWallets).
 * Return the `TransactionObjectArgument` from your own logic: delegate to a
 * multisig-issued cap, attach a sponsored approval from another Move module, or
 * call `ikaTx.approveMessage({ dWalletCap: customCap, ... })`.
 *
 * If omitted, the plugin builds the standard approval from `dWalletCap` (or
 * `dWallet.dWalletCapId`).
 */
export type BuildApprovalHook = (
	ikaTx: IkaTransaction,
	defaultCap: string,
) => TransactionObjectArgument;

/** Hook for pre-verifying the presign cap with custom logic. */
export type BuildVerifiedPresignCapHook = (
	ikaTx: IkaTransaction,
	presign: Presign,
) => TransactionObjectArgument;

export interface RequestSignInput {
	readonly dWallet: SuiDWallet;
	readonly message: Uint8Array;
	readonly curve: Curve;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly hash: Hash;
	/** Pre-completed presign. Optional; when omitted the plugin auto-selects per dWallet kind and sig algo. */
	readonly presign?: Presign;
	readonly encryptedShareId?: string;
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	/**
	 * Override the cap object id used for message approval. Defaults to
	 * `dWallet.dWalletCapId`. Useful when the cap has been transferred to a
	 * different holder (multisig, contract) than the dWallet's original owner.
	 *
	 * Object-id strings only. For tx-internal `TransactionObjectArgument` caps
	 * (e.g. a cap returned by a prior DKG in the same PTB), use
	 * `ika.sui.transaction(...)` with `ika.sui.compose.sign(...)` and a
	 * pre-built `messageApproval`.
	 */
	readonly dWalletCap?: string;
	/** Custom message approval builder. See `BuildApprovalHook`. */
	readonly buildApproval?: BuildApprovalHook;
	/** Custom presign-cap verifier builder. See `BuildVerifiedPresignCapHook`. */
	readonly buildVerifiedPresignCap?: BuildVerifiedPresignCapHook;
	readonly signal?: AbortSignal;
}

// High-level createDWallet input. Accepts overrides including a pre-computed
// `dkgRequestInput` so callers may skip the prepareDKG round-trip.

export interface CreateDWalletInput {
	readonly curve: Curve;
	readonly kind: 'zero-trust' | 'shared' | 'imported-key' | 'imported-key-shared';
	/** Required for imported-key kinds. Caller-supplied scalar in the curve's format. */
	readonly importedKey?: Uint8Array;
	readonly sessionIdentifier?: Uint8Array;
	readonly networkEncryptionKeyId?: string;
	readonly userShareEncryptionKeys?: UserShareEncryptionKeys;
	/**
	 * Pre-computed DKG payload. When provided, prepareDKG is skipped. Useful
	 * when prepareDKG was run out-of-band (e.g. on another device) and is now
	 * being submitted.
	 */
	readonly dkgRequestInput?: PrepareDKGOutput;
	/** Acknowledgement required for the irreversible `imported-key-shared` promotion. */
	readonly acknowledge?: 'i-understand-this-is-irreversible';
	/**
	 * Direct the resulting `dWalletCap` to a specific address. Defaults to
	 * the configured signer's address. Set this when the account paying
	 * for DKG is not the account that should control signing later (e.g.
	 * backend funds DKG, end-user wallet receives the cap and signs).
	 */
	readonly capRecipient?: string;
	readonly signal?: AbortSignal;
}
